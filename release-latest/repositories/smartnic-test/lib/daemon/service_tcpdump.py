""" This script has to be compatible with python 3.6 """
import logging.handlers
from datetime import datetime
from time import sleep
from typing import Dict, Optional, Union
import os
import shlex
import signal
import subprocess

from logging_tools import add_socket_handler


LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)


TCPDUMP_COMMAND = ('sudo tcpdump --packet-buffered -n -c 1000 '
                   '--interface {iface} -w {file}')
TCPDUMP_FILE_TEMLPATE = '{test_name}_{vm}_{interface}_{timestamp}.pcap'


class Tcpdump:
    def __init__(self, log_handler_host: Optional[str] = None,
                 log_handler_port: Optional[int] = None):
        add_socket_handler(LOGGER, log_handler_host, log_handler_port)
        self._tcpdump_process: Optional[subprocess.Popen] = None
        self._filename: Optional[str] = None

    def __del__(self) -> None:
        if self._tcpdump_process is not None:
            self._tcpdump_process.kill()

    def set_filename(self, filename: str) -> None:
        self._filename = filename

    def set_filename_from_template(self, test_name: str, vm: str, interface: str
                                   ) -> None:
        self._filename = TCPDUMP_FILE_TEMLPATE.format(
            test_name=test_name,
            vm=vm,
            interface=interface,
            timestamp=datetime.utcnow().strftime("%H-%M-%S"),
        )

    @property
    def filename(self) -> str:
        if self._filename is None:
            raise RuntimeError('Filename not yet set')
        return self._filename

    def finish_capture(self) -> Dict[str, Union[str, Optional[int]]]:
        if self._tcpdump_process is None:
            raise RuntimeError('Tcpdump process is not running')
        LOGGER.info('Finishing Tcpdump')
        self._tcpdump_process.send_signal(signal.SIGINT)
        try:
            stdout, stderr = self._tcpdump_process.communicate(timeout=5)
        except subprocess.TimeoutExpired as err:
            LOGGER.info(f'Failed to stop Tcpdump process: {err}, retrying')
            self._tcpdump_process.kill()
            stdout, stderr = self._tcpdump_process.communicate(timeout=3)

        retcode = self._tcpdump_process.poll()
        self._tcpdump_process = None

        LOGGER.debug(f'TCPDUMP RESULTS:\n'
                     f'STDOUT: {stdout}\n'
                     f'STDERR: {stderr}\n'
                     f'RETCODE: {retcode}')
        return {
            'stdout': stdout,
            'stderr': stderr,
            'retcode': retcode
        }

    def start_capture(self, iface: str = 'eth1') -> None:
        if self._tcpdump_process is not None:
            raise RuntimeError('Tcpdump process already running')
        LOGGER.info(f'Starting tcpdump on iface {iface}')
        args = shlex.split(
            TCPDUMP_COMMAND.format(iface=iface, file=self.filename))
        self._tcpdump_process = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=os.setpgrp,
        )
        sleep(0.1)
        LOGGER.debug('Started tcpdump')