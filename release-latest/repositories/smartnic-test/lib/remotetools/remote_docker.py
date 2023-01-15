import logging
import docker
from time import sleep

from retrying import retry

from lib.config import get_config
from lib.remotetools.bird_service.bird import CfgBird

LOGGER = logging.getLogger(__name__)


class RemoteDockerError(Exception):
    pass


class RemoteDocker(CfgBird):
    def __init__(self, img_name: str = None, command: str = None, **params):
        self.client: docker.DockerClient = None
        self.container: docker.client.ContainerCollection = None
        self.image: docker.client.ImageCollection = None
        self.img_name = img_name
        self.command = command
        self.params = params

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.del_docker_service()

    def get_client(self, ip_host: str = None, port_host: str = None) -> None:
        if not (ip_host or port_host):
            base_url = 'unix://var/run/docker.sock'
        else:
            base_url = f'tcp://{ip_host}:{port_host}'
        try:
            self.client = docker.DockerClient(
                base_url=base_url)
            LOGGER.debug(f"Connected to docker daemon, url {base_url}")
        except docker.errors.APIError as error:
            LOGGER.error(f"Cannot get docker client: {base_url}")
            raise RemoteDockerError from error

    def pull_image(self, **params) -> None:
        LOGGER.debug(f"Start pulling img: {self.img_name}")
        try:
            self._pull_image(
                f"{get_config().get('docker_registry')}/{self.img_name}",
                **params)
        except docker.errors.APIError:
            LOGGER.warning(f"Unable to pull {self.img_name} docker image from "
                           f"private registry, defaulting to docker.io")
            self._pull_image(self.img_name, **params)
        LOGGER.debug(f"Successfully pulled image {self.img_name} with "
                     f"id {self.image.id}")

    def _pull_image(self, img_name, **params):
        image = self.client.images.pull(img_name, **params)
        self._set_image(image)

    def _set_image(self, image):
        if isinstance(image, list):
            assert len(image) == 1, (f"Ambiguous parameters, docker "
                                     f"hasn't returned a single image:{image}")
            self.image = image[-1]
        else:
            self.image = image

    def run_container(self) -> None:
        try:
            LOGGER.debug(f"params: {self.img_name}")
            self.container = self.client.containers.run(image=self.image.id,
                                                        command=self.command,
                                                        **self.params)
            sleep(3)  # Waiting for a boot up Nginx service
            LOGGER.debug((f"Initial logs from container:\n"
                          f"{self.container.logs()}"))
            LOGGER.debug(f"Success run container of id {self.container}")
        except docker.errors.APIError as error:
            LOGGER.error(f"Cannot run {self.img_name} docker image with cmd:"
                         f" {self.command}")
            raise RemoteDockerError() from error

    def get_container_status(self):
        inspect_dict = self.client.api.inspect_container(self.container.id)
        if inspect_dict.get("State"):
            return inspect_dict["State"]["Status"]

    @retry(wait_fixed=1000, stop_max_attempt_number=20)
    def is_running(self) -> bool:
        if "running" not in self.get_container_status():
            raise RemoteDockerError(
                f"Not running container! [{self.get_container_status()}]")
        return True

    def remove_container(self):
        try:
            LOGGER.debug(f"Try remove container {self.container.id}")
            self.container.stop()
            self.container.remove(force=True)
            LOGGER.debug(f"Removed container {self.container.id}")
            self.container = None
        except docker.errors.APIError as error:
            LOGGER.warning(error)

    def remove_image(self):
        try:
            LOGGER.debug(f"Try remove image {self.image.id}")
            self.client.images.remove(image=self.image.id, force=True)
            LOGGER.debug(f"Removed image {self.image.id}")
            self.image = None
        except docker.errors.APIError as error:
            LOGGER.warning(error)

    def del_docker_service(self) -> None:
        try:
            if self.container:
                self.remove_container()
        except docker.errors.NotFound:
            LOGGER.warning(f"No such container: {self.container}")
        try:
            if self.image:
                self.remove_image()
        except docker.errors.NotFound:
            LOGGER.warning(f"No such image: {self.img_name}")

    def get_host_exposed_port(self,
                              container_port: int,
                              proto: str = 'tcp') -> int:
        self.container.reload()
        port_key = f'{container_port}/{proto}'
        exposed_ports = self.container.ports.get(port_key)
        if not exposed_ports:
            raise ValueError(
                f'Port {port_key} is not opened on {self.container.id}')
        exposed_port = exposed_ports[0].get('HostPort')
        if not exposed_port:
            raise ValueError(
                f'No ports associated with container '
                f'{self.container.id}:{port_key} are opened on host')
        return int(exposed_port)

    def __del__(self):
        self.del_docker_service()