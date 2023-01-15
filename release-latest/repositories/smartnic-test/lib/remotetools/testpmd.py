import logging
from typing import TYPE_CHECKING, Union

from lib.remotetools.remote_dpdk_app import RunExternalDpdkApp
from lib.remotetools.testpmd_utils import (
    testpmd_set_decap_command, testpmd_flow_command)

if TYPE_CHECKING:
    from lib.remotetools.flow import Flow
    from lib.connections import Machine

LOGGER = logging.getLogger(__name__)


class TestPMD(RunExternalDpdkApp):
    PROMPT = "testpmd> \r\n"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs, app_name="testpmd")
        self._generate_testpmd_cmd()

    def _generate_testpmd_cmd(self) -> None:
        # Separate testpmd options from eal options
        self.cmd_opts.append("--")

        eth_peer_0 = ','.join(map(str, self.config.get('eth_peer_0', [])))
        eth_peer_1 = ','.join(map(str, self.config.get('eth_peer_1', [])))
        testpmd_cmds_opts = {
            "nb_of_cores": f"--nb-cores={self.config.get('nb_of_cores')}",
            "rx_queue": f"--rxq={self.config.get('rx_queue')}",
            "rx_desc": f"--rxd={self.config.get('rx_desc')}",
            "tx_queue": f"--txq={self.config.get('tx_queue')}",
            "tx_desc": f"--txd={self.config.get('tx_desc')}",
            "eth_peer_0": f"--eth-peer={eth_peer_0}",
            "eth_peer_1": f"--eth-peer={eth_peer_1}",
            "forward_mode": f"--forward-mode={self.config.get('forward_mode')}",
            "cmd_file": f"--cmdline-file={self.config.get('cmd_file')}"
        }

        for key, value in testpmd_cmds_opts.items():
            if self.config.get(key) is not None:
                self.cmd_opts.append(value)

        if self.config.get("interactive", False):
            self.cmd_opts.append("-i")

    def _read_till_prompt(self, prompt: str) -> list[str]:
        self.stdin.write("\n")
        self.stdin.flush()
        output: list[str] = []
        while True:
            line = self.stdout.readline()
            LOGGER.info(" ".join(line.split()))
            if prompt in line:
                return output
            else:
                output.append(line)

    def _execute_cmd(self, cmd: str) -> list[str]:
        LOGGER.debug(f'Writing {cmd}')
        self.stdin.write(cmd)
        self.stdin.flush()
        lines = self._read_till_prompt(self.PROMPT)
        lines.pop()
        return lines

    def _try_closing_gracefully(self) -> None:
        LOGGER.info(f'Stopping {self.app_name}')
        cmd = "quit\n"
        self.stdin.write(cmd)
        self.stdin.flush()
        while True:
            line = self.stdout.readline()
            if "Bye..." in line:
                return

    def add_flow(self, flow: 'Flow') -> None:
        for cmd in [testpmd_set_decap_command, testpmd_flow_command]:
            cmd_line = cmd(flow)
            lines = self._execute_cmd(
                cmd_line + "\n") if cmd_line is not None else []
            if "Bad arguments\n" in lines:
                raise ValueError(f"Wrong Testpmd arguments in: {cmd_line}")

    def set_interactive_mac_addr(self, port: Union[int, str], mac_addr: str
                                 ) -> None:
        LOGGER.info(f'Set defualt mac addres to: {mac_addr}')
        cmd = f'mac_addr set {str(port)} {mac_addr}\n'
        self._execute_cmd(cmd)

    def set_interactive_fwd_mac(self) -> None:
        LOGGER.info('Set fwd mac in interactive mode')
        cmd_set_fwd_mac = 'set fwd mac\n'
        cmd_start_fwd_mac = 'start\n'
        self._execute_cmd(cmd_set_fwd_mac)
        self._execute_cmd(cmd_start_fwd_mac)


def start_testpmd(ssh: 'Machine', config_testpmd: dict, taskset: bool = True
                  ) -> 'TestPMD':
    expected_line = "Checking link statuses...\n"
    if config_testpmd.get("cmd_file") is not None:
        expected_line = "Read CLI commands"

    app = TestPMD(ssh, config=config_testpmd)
    if taskset:
        app.start_with_taskset(expected_line=expected_line)
    else:
        app.start_with_buffering(expected_line=expected_line)
    return app