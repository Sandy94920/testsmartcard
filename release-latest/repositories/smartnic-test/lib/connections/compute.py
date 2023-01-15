import logging
from os.path import expanduser
from tempfile import TemporaryDirectory
from typing import Optional

from retrying import retry

from .machine import Machine
from .ssh_conn import SSHConn
from .vm import Vm, PYTHON_PATH
from lib.utils import transfer_files_from_host_folder_to_vm_cn

LOGGER = logging.getLogger(__name__)
VM_CONN_TIMEOUT = 120
VM_CONN_RECONNECTION_TIME = 5


class ComputeError(Exception):
    pass


class Compute(Machine):
    """
    Class keeping a connection to compute machine. Inherits functionalities
    (e.g. command execution methods) from Machine class.
    """

    def __init__(
            self,
            intel_pac_phy_addr_pci: Optional[str],
            ssh_conn: SSHConn,
            vms: dict = None,
            ifaces: list = None):
        """
        Connect to compute with ip address `ip`.

        :param intel_pac_phy_addr_pci
            pci physical address
        :param ssh_conn
        :param vms
            dict with information about VMs accessible from this compute
            default - no vms
            e.g.
            {
                'vm1': {
                    'ip': '12.0.0.4',
                    'ssh_user': 'vagrant',
                    'ssh_key': 'keys/id_rsa'
                },
                ...
            }
        """
        self._ssh = ssh_conn
        self._vms_config = vms if vms is not None else {}
        self._vm_connections: list[Vm] = []
        self.intel_pac_phy_addr_pci = intel_pac_phy_addr_pci
        self.python_path: str = PYTHON_PATH
        self.tmp_daemon_dir = TemporaryDirectory()
        self.interfaces = self.setup_interfaces_list(
            ifaces) if ifaces is not None else None

    @property
    def vm1(self) -> Vm:
        return self._vm_connections[0]

    @property
    def vm2(self) -> Vm:
        return self._vm_connections[1]

    @property
    def vm3(self) -> Vm:
        return self._vm_connections[2]

    def _cn_virsh_status_interfaces_of_vm(self, vm_name: str) -> None:
        cmd_virsh_domiflist_all = f"virsh domifaddr {vm_name} --source agent"
        stdout, stderr = self.get_sudo_cmd_output(cmd_virsh_domiflist_all)
        LOGGER.info(f"{vm_name}- Virtual Machine interfaces:\n"
                    f"{stderr or stdout}")

    def create_vms(self, vms_names: list) -> None:
        for vm_name in vms_names:
            vm = self._initialize_vm(vm_name=vm_name)
            self._vm_connections.append(vm)

    def _initialize_vm(self, vm_name: str) -> Vm:
        self._cn_virsh_status_interfaces_of_vm(vm_name)
        vm_ssh = self.get_vm_ssh(vm_name)
        transfer_files_from_host_folder_to_vm_cn(vm_ssh)
        return vm_ssh

    def get_vm_ssh(self, name: str) -> Vm:
        """
        Get SSHConn object associated to VM with name `name`.
        """
        try:
            vm = self._vms_config[name]
            ssh_conn = self._connect_to_vm(
                ip_mgmt=vm['ip_mgmt'],
                port=vm['port'],
                passw=vm.get('passw'),
                username=vm.get('ssh_user'),
                key=expanduser(
                    vm.get("ssh_key")) if vm.get("ssh_key") else None)
            vm_connection = Vm(
                iface=vm.get('iface'),
                second_iface=vm.get('second_iface'),
                ssh_conn=ssh_conn)
        except KeyError:
            raise ComputeError(f"Virtual Machine of the name {name} "
                               f"installed on cn doesn't "
                               f"exists in config file: config/*.yml")
        return vm_connection

    def stop_vm_via_virsh(self, vm_ssh: Vm) -> None:
        LOGGER.info(f'Stop vm: {vm_ssh.hostname}')
        cmd = f"virsh destroy {vm_ssh.hostname}"
        stdout, stderr = self.get_sudo_cmd_output(cmd)
        if stderr:
            raise ComputeError(f"Problem with stopping vm "
                               f"{self.ip_mgmt}, stderr: {stderr}")

    def start_vm_via_virsh(self, vm_ssh: Vm) -> None:
        LOGGER.info(f'Start vm: {vm_ssh.hostname}')
        cmd = f"virsh start {vm_ssh.hostname}"
        stdout, stderr = self.get_sudo_cmd_output(cmd)
        if stderr:
            raise ComputeError(f"Problem with starting vm "
                               f"{self.ip_mgmt}, stderr: {stderr}")
        LOGGER.info(f"Waiting to boot-up {vm_ssh.hostname} "
                    f"virtual machine. Timeout {VM_CONN_TIMEOUT} sec")
        vm_ssh.reconnect()

    def get_iface_ip(self, iface: str, ip_version: str) -> Optional[str]:
        is_ipv6 = self.is_ipv6(ip_version)
        if is_ipv6:
            return None  # Compute does not have IPv6
        return super().get_iface_ip(iface, ip_version)

    def get_interface(self, idx):
        try:
            return self.interfaces[idx]  # type: ignore
        except IndexError:
            raise Exception(f"No such index interface {idx} for "
                            f"cn {self.ip_mgmt}")

    @staticmethod
    @retry(wait_fixed=VM_CONN_RECONNECTION_TIME * 1000,
           stop_max_delay=VM_CONN_TIMEOUT * 1000)
    def _connect_to_vm(ip_mgmt: str,
                       port: int,
                       passw: Optional[str] = None,
                       username: Optional[str] = None,
                       key: Optional[str] = None) -> SSHConn:
        try:
            LOGGER.info("Trying to directly connect to VM")
            ssh = SSHConn.connect(
                address=ip_mgmt,
                port=port,
                username=username,
                password=passw,
                key=key)
        except Exception as error:
            LOGGER.error(f'Connection to {ip_mgmt} VM failure: {error}',
                         exc_info=True)
            raise ComputeError(f"Unable to connect {ip_mgmt}")
        return ssh