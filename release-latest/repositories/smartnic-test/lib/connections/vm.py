import logging
import os
from tempfile import TemporaryDirectory
from typing import NamedTuple, Union, TYPE_CHECKING, Optional

from retrying import retry

from .machine import Machine, Interface, reconnect

if TYPE_CHECKING:
    from . import SSHConn

LOGGER = logging.getLogger(__name__)
VM_CONN_TIMEOUT = 120
VM_CONN_RECONNECTION_TIME = 5
PYTHON_PATH = "/usr/bin/python3"


class VMerror(Exception):
    pass


class Interfaces(NamedTuple):
    iface1: Interface
    iface2: Interface


class Vm(Machine):
    """
    Class representation of virtual machines present on the compute nodes.
    """
    def __init__(self,
                 iface: str,
                 ssh_conn: 'SSHConn',
                 second_iface: Optional[str] = None):
        self.python_path: str = PYTHON_PATH
        self._ssh = ssh_conn
        self._interfaces: Interfaces = self.setup_interfaces(
            iface1=iface, iface2=second_iface)
        self.hostname: str = self.get_hostname()
        self.tmp_daemon_dir = TemporaryDirectory()

    @property
    def iface1(self) -> Interface:
        return self._interfaces.iface1

    @property
    def iface2(self) -> Interface:
        return self._interfaces.iface2

    def setup_interfaces(self, iface1: str,
                         iface2: Union[str, None]) -> Interfaces:
        ifaces = self.setup_interfaces_list([iface1, iface2])
        return Interfaces(ifaces[0], ifaces[1])

    def get_interface_by_index(self, idx: int) -> Interface:
        try:
            return self._interfaces[idx]
        except IndexError:
            raise VMerror(f"No such index interface {idx} for "
                          f"virtual machine {self.hostname}")

    def transfer_files_from_vm(self, local_dir: str, remote_file: str,
                               delete_remote: bool = True) -> None:
        local_path = os.path.join(local_dir, remote_file)
        with self.open_sftp() as vm_sftp:
            LOGGER.info(f"Copy file: {remote_file} from remote host: {vm_sftp} "
                        f"to path: {local_path}")
            try:
                vm_sftp.stat(remote_file)
            except FileNotFoundError as err:
                raise VMerror(f"Unable to find file {remote_file} "
                              f"on remote host") from err
            vm_sftp.get(remotepath=remote_file,
                        localpath=local_path)
            if delete_remote:
                vm_sftp.remove(remote_file)

    @retry(wait_fixed=VM_CONN_RECONNECTION_TIME*1000,
           stop_max_delay=VM_CONN_TIMEOUT*1000)
    def reconnect(self) -> None:
        try:
            LOGGER.info(f"Trying to reconnect to VM {self.hostname}")
            self._ssh = reconnect(self.ssh)
        except Exception as error:
            LOGGER.error(f'Reconnection to VM {self.hostname} '
                         f'failure: {error}', exc_info=True)
            raise VMerror(f"Unable to reconnect to VM {self.hostname}")