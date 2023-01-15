import logging
from typing import TYPE_CHECKING

import jinja2
from compose.cli.command import project_from_options
from compose.cli.main import TopLevelCommand

if TYPE_CHECKING:
    from . import Machine

LOGGER = logging.getLogger(__name__)


class Docker:
    def __init__(self, host_ssh: 'Machine', container_name: str,
                 project_directory: str,
                 port: int = 2375, options: dict = None):
        self.container_name = container_name
        self.options = options or {"--no-deps": False,
                                   "--detach": True,
                                   "--abort-on-container-exit": False,
                                   "--always-recreate-deps": True,
                                   "SERVICE": "",
                                   "--scale": "",
                                   "--remove-orphans": False,
                                   "--no-recreate": False,
                                   "--force-recreate": True,
                                   "--build": False,
                                   '--no-build': False,
                                   '--no-color': False,
                                   "--no-log-prefix": False,
                                   "--rmi": "none",
                                   "--volumes": "",
                                   "--follow": False,
                                   "--timestamps": False,
                                   "--tail": "all",
                                   "--host": f"{host_ssh.ip_mgmt}:{port}"
                                   }
        self.project = project_from_options(project_directory, self.options)
        self.compose_cmd = TopLevelCommand(self.project)
        self.host_ssh = host_ssh

    @staticmethod
    def create_docker_compose_yaml(tmplt_path: str, output_file: str = None,
                                   **kwargs) -> None:
        env = jinja2.Environment(loader=jinja2.FileSystemLoader('./'))
        template = env.get_template(tmplt_path)
        compose_file = template.render(kwargs)
        LOGGER.debug(f"Docker-compose file:\n {compose_file}")
        if output_file:
            with open(output_file, "w+") as cfg_file:
                cfg_file.write(compose_file)
                LOGGER.debug(f"Docker-compose writen as: {output_file}")

    def cmd_exec(self, cmd: str) -> str:
        stdout, stderr = self.host_ssh.get_sudo_cmd_output(
            f"docker exec {self.container_name} {cmd}")
        if stderr:
            raise IOError(stderr)
        return stdout

    def compose_up(self) -> None:
        self.compose_cmd.up(self.options)

    def compose_down(self) -> None:
        self.compose_cmd.down(self.options)