from lib.remotetools.remote_app import RunExternalApp


class RunExternalDpdkApp(RunExternalApp):
    def __init__(self, *args, **kwargs):
        self.config: dict = kwargs.pop('config', {})
        super().__init__(*args, **kwargs)
        self._generate_dpdkapp_cmd_opts()

    def _generate_dpdkapp_cmd_opts(self) -> None:
        if self.config.get("pci_addr") is not None:
            for pci in self.config["pci_addr"].values():
                self.cmd_opts.append(f"-w pci:{pci}")

        if self.config.get("log_level") is not None:
            for opt in self.config["log_level"]:
                self.cmd_opts.append(f"--log-level={opt}")

        if self.config.get("s") is not None:
            self.cmd_opts.append(f"-s {self.config['s']}")

        if self.config.get("vdev") is not None:
            vdev_cmd = "--vdev net_n3k0"
            if self.config["vdev"].get("mgmt") is not None:
                vdev_cmd = ','.join(
                    [vdev_cmd, f"mgmt={str(self.config['vdev']['mgmt'])}"])
            if self.config["vdev"].get("pf") is not None:
                vdev_cmd = ','.join(
                    [vdev_cmd, f"pf={str(self.config['vdev']['pf'])}"])
            if self.config["vdev"].get("vfs") is not None:
                vdev_cmd = ','.join(
                    [vdev_cmd, f"vfs={str(self.config['vdev']['vfs'])}"])
            self.cmd_opts.append(vdev_cmd)

    def _generate_dpdkapp_cmd(self) -> str:
        cmd = " ".join(self.cmd_opts)
        path_cmd = f'{self.config["dpdk_bin_path"]}/{cmd}'
        return path_cmd

    def start_with_taskset(self, expected_line: str) -> None:
        cmd = " ".join([
            'sudo',
            'taskset 0xffffffffffff',
            self._generate_dpdkapp_cmd()])
        self.start(cmd=cmd, expected_line=expected_line)

    def start_with_buffering(self, expected_line: str) -> None:
        cmd = f'sudo bash -c \"stdbuf -oL {self._generate_dpdkapp_cmd()}\"'
        self.start(cmd=cmd, expected_line=expected_line)