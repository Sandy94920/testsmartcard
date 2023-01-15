import os
import logging
import subprocess
from time import sleep
from typing import Dict, NamedTuple, TYPE_CHECKING, Any, Union
import rpyc

if TYPE_CHECKING:
    from lib.daemon.daemon_hub import DaemonHub
    from .vm import Vm
    from .compute import Compute

LOGGER = logging.getLogger(__name__)


class DaemonHubConnections(NamedTuple):
    client: 'DaemonHub'
    hub: 'DaemonHub'


class DaemonHubError(Exception):
    pass


def _connect_daemon_hub(hostname: str, port: int) -> 'rpyc.connect':
    probe_conn = 0
    while probe_conn <= 3:
        try:
            _conn = rpyc.connect(hostname, port=port)
            LOGGER.info(
                f"Daemon Hub, connection success to host {hostname}, {port}")
            return _conn
        except ConnectionRefusedError as error:
            probe_conn += 1
            LOGGER.warning(
                f"Try connect to daemon hub host, probe {probe_conn}, "
                f"error at probe of connection: {error}")
            sleep(1)
    raise DaemonHubError(
        f"Can't start Daemon Hub in {hostname}")


def _start_remote_daemon_hub_via_ssh(host: Union['Vm', 'Compute'], port: int,
                                     hostname: str, log_server: str = None
                                     ) -> tuple[Any, Any]:
    log_server_param = ""
    if log_server:
        log_server_param = f" --log-server {log_server}"
    LOGGER.info(
        f"Try start Daemon Hub on {host.ssh.base_address} host")
    daemon_hub_path = 'daemon_hub.py'

    daemon_hub_path = os.path.join(
        host.tmp_daemon_dir.name, daemon_hub_path)
    cmd = (f"{host.python_path} "
           f"{daemon_hub_path} --port {port}"
           f"{log_server_param} --hostname {hostname}")
    stdout, stderr = host.get_sudo_cmd_streams(cmd)[1:]
    LOGGER.info("Start Daemon Hub server")
    return stdout, stderr


def start_daemon_hub_in_host(hostname: str, port: int = 18861,
                             host: 'Vm' = None,
                             log_server: str = None) -> 'DaemonHub':
    if host is not None:
        _, _ = _start_remote_daemon_hub_via_ssh(host=host,
                                                port=port,
                                                hostname=hostname,
                                                log_server=log_server)
    return _connect_daemon_hub(hostname=hostname, port=port)


def stop_daemon_hub_in_host(conn: 'DaemonHub') -> None:
    try:
        conn.root.shutdown_server()
    except EOFError:
        LOGGER.info("Daemon Hub server is shutdown")


def async_rpyc(func):
    return rpyc.async_(func)


def get_container_logs(container: str) -> None:
    LOGGER.info(f"Start logs for container {container}")
    # max logs lines produced during tcp handshake is 10
    proc = subprocess.run(['docker', 'logs', '--tail', '10', container],
                          stdout=subprocess.PIPE)
    for line in proc.stdout.decode('utf-8').strip().split('\n'):
        LOGGER.info(line)
    LOGGER.info(f"End logs for container {container}")


class DaemonHubs:
    def __init__(self,  log_port: int, runner_ip: str):
        self.hubs: Dict['Vm', DaemonHubConnections] = {}
        self._log_port = log_port
        self._runner_ip = runner_ip

    @property
    def hosts(self) -> list['Vm']:
        return list(self.hubs.keys())

    def connect(self, *connections: 'Vm') -> None:
        if self.hubs:
            raise DaemonHubError('Connections already exist.'
                                 'Connections are not cleared properly.')
        try:
            for conn in connections:
                client = start_daemon_hub_in_host(
                    host=conn,
                    hostname=conn.ip_mgmt,
                    log_server=f"{self._runner_ip}:{self._log_port}")
                hub = client.root
                self.hubs[conn] = DaemonHubConnections(client=client, hub=hub)
        except Exception as error:
            LOGGER.error(error, exc_info=True)
            self.teardown()
            raise error

    def teardown(self) -> None:
        for hub in self.hubs.values():
            stop_daemon_hub_in_host(hub.client)

    def get_hubs(self) -> tuple['DaemonHub', ...]:
        return tuple(hub.hub for hub in self.hubs.values())