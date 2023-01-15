import logging
from socket import timeout as socket_timeout
from time import sleep, time
from typing import TYPE_CHECKING, Optional

from lib.utils import get_content

if TYPE_CHECKING:
    from lib.connections import Machine
    from paramiko.channel import (ChannelStdinFile,
                                  ChannelFile,
                                  ChannelStderrFile)

LOGGER = logging.getLogger(__name__)


class ExternalAppException(Exception):
    pass


class RunExternalApp:
    def __init__(self, vm_ssh: 'Machine', app_name: str):
        self.vm_ssh = vm_ssh
        self.stdin: Optional['ChannelStdinFile'] = None
        self.stdout: Optional['ChannelFile'] = None
        self.stderr: Optional['ChannelStderrFile'] = None
        self.app_name = app_name
        self.cmd_opts = [self.app_name]

    def remote_trigger_app(self, cmd: str) -> None:
        timeout_expected_line = 30
        LOGGER.info(cmd)
        self.stdin, self.stdout, self.stderr = self.vm_ssh.get_cmd_streams(
            cmd,
            timeout=timeout_expected_line)

    def get_output_of_stdout(self, expected_line: str) -> None:
        try:
            for line in self.stdout:  # type: ignore
                LOGGER.info(" ".join(line.split()))
                if expected_line in line:
                    LOGGER.info("Remote app started")
                    return
        except socket_timeout:
            raise ExternalAppException(
                f"Application launch failed. "
                f"Not found expected_line: '{expected_line}' "
                f"of the timeout 30 seconds")
        else:
            raise ExternalAppException(get_content(self.stderr))

    def start(self, cmd: str, expected_line: str) -> None:
        self.remote_trigger_app(cmd=cmd)
        self.get_output_of_stdout(expected_line=expected_line)

    def stop(self) -> None:
        try:
            self._try_closing_gracefully()
        except:  # noqa F401
            self.kill()

    def _try_closing_gracefully(self) -> None:
        raise NotImplementedError

    def _pgrep_process(self) -> list:
        cmd = f"pgrep {self.app_name}"
        _, stdout, stderr = self.vm_ssh.get_cmd_streams(cmd)
        stderr = stderr.read()
        if stderr:
            LOGGER.warning(
                f"Pgrep for {self.app_name} return some error: {stderr}")
        return list(stdout)

    def _kill_process(self, pid: list, option: str) -> None:
        cmd = f"kill -{option} {' '.join([str(_).rstrip() for _ in pid])}"
        _, stdout, stderr = self.vm_ssh.get_sudo_cmd_streams(cmd)
        stdout, stderr = stdout.read().decode(), stderr.read().decode()
        LOGGER.debug(
            f'{self.app_name} killed (pid: {pid}) return stdout: '
            f'{stdout}, stderr: {stderr}.')
        return

    def kill(self, timeout: int = 60, option: str = "SIGKILL",
             interval: int = 1) -> None:
        end = time() + timeout
        while time() < end:
            pgrep_pid = self._pgrep_process()
            if pgrep_pid:
                self._kill_process(pgrep_pid, option=option)
            else:
                LOGGER.info(f"External app {self.app_name} is closed")
                return
            sleep(interval)
        raise ExternalAppException(f"Cannot close external app {self.app_name}")

