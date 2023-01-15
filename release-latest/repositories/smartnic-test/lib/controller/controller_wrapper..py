class ControllerWrapperError(Exception):
    pass


class ControllerWrapper:
    def __init__(self, config: dict):
        self._config = config
        self._controller: Optional[Controller] = None

    @property
    def controller(self) -> Controller:
        if self._controller is None:
            self._controller = Controller(self._get_controller_config())
        return self._controller

    def _get_controller_config(self):
        try:
            return self._config["controller"]
        except KeyError:
            raise ControllerWrapperError(
                "No 'controller' configuration found in the yaml file")

    def get_data_plane_name_by_idx(self, dp_idx: int = None) -> str:
        try:
            controller_config = self._get_controller_config()[
                "data_plane_networks_names"]
        except KeyError:
            raise ControllerWrapperError(
                "Please add your configuration controller to yaml file")
        else:
            if dp_idx is not None:
                return controller_config[dp_idx]
            return controller_config

    def get_controller_conn(self) -> Compute:
        cmpt = self._get_controller_config()
        LOGGER.info(f"Try connect to controller:{cmpt['ip_mgmt']}")
        ssh_conn = SSHConn.connect(
            address=cmpt["ip_mgmt"],
            port=cmpt["port"],
            password=cmpt.get("passw"),
            username=cmpt.get("ssh_user"),
            key=(expanduser(cmpt.get("ssh_key"))
                 if cmpt.get("ssh_key") else None))
        return Compute(
            ssh_conn=ssh_conn,
            vms=cmpt.get("vms"),
            intel_pac_phy_addr_pci=cmpt.get("intel_pac_phy_addr_pci"))
