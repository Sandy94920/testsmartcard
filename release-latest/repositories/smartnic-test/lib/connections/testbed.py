import logging
import os

from . import Compute, SSHConn
from lib.utils import transfer_files_from_host_folder_to_vm_cn

LOGGER = logging.getLogger(__name__)


class TestBedError(Exception):
    pass


class TestBed:
    def __init__(self, config: dict):
        self._connections: list[Compute] = []
        self._init_compute_connections(config)

    @property
    def cn1(self) -> Compute:
        return self.get_cn_connection_by_index(0)

    @property
    def cn2(self) -> Compute:
        return self.get_cn_connection_by_index(1)

    def _init_controller_connection(self, config: dict) -> None:
        if config.get('controller') is not None:
            controller_ssh = self._get_compute_ssh(['controller'], config)
            transfer_files_from_host_folder_to_vm_cn(
                ssh_conn=controller_ssh)

    def _create_cn(self, cn_config: tuple, config: dict) -> Compute:
        cn_name, cn_data = cn_config
        cn_ssh = self._get_compute_ssh(['compute', cn_name], config)
        transfer_files_from_host_folder_to_vm_cn(ssh_conn=cn_ssh,
                                                 folder='lib/cn_scripts')
        cn_ssh.create_vms(vms_names=list(cn_data['vms'].keys()))
        return cn_ssh

    def _init_compute_connections(self, config: dict) -> None:
        for iter_cn, cn_data in enumerate(config["compute"].items()):
            cn_ssh = self._create_cn(cn_config=cn_data, config=config)
            self._connections.append(cn_ssh)
        self._init_controller_connection(config)

    def get_cn_connection_by_index(self, cn_idx: int) -> Compute:
        try:
            if self._connections:
                return self._connections[cn_idx]
        except IndexError:
            raise Exception(f"Compute Node of the index {cn_idx} doesn't "
                            f"exists in config file: config/*.yml")
        else:
            raise TestBedError(
                "Before calling to get_cn_connection(), requires initialize: "
                "init_compute_connections() method.")

    @staticmethod
    def _get_compute_ssh(name_path: list[str], config: dict) -> Compute:
        cmpt = config
        for name in name_path:
            cmpt = cmpt[name]
        LOGGER.info(f"Try connect to: {name_path[-1]}::{cmpt['ip_mgmt']}")
        ssh_conn = SSHConn.connect(
            address=cmpt["ip_mgmt"],
            port=cmpt["port"],
            password=cmpt.get("passw"),
            username=cmpt.get("ssh_user"),
            key=(os.path.expanduser(cmpt["ssh_key"])
                 if cmpt.get("ssh_key") else None))
        return Compute(
            vms=cmpt.get("vms"),
            intel_pac_phy_addr_pci=cmpt.get("intel_pac_phy_addr_pci"),
            ssh_conn=ssh_conn,
            ifaces=cmpt.get('int_vf_interfaces'))