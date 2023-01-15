import logging
import socket
import struct
from typing import Optional, TYPE_CHECKING

from lib.remotetools.remote_dpdk_app import RunExternalDpdkApp
from lib.remotetools.n3ktt_utils import n3ktt_command

import capnp
from lib.remotetools.n3ktt_protocol import protocol_capnp

if TYPE_CHECKING:
    from lib.remotetools.flow import Flow
    from lib.connections import Machine

LOGGER = logging.getLogger(__name__)


class N3ktt(RunExternalDpdkApp):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs, app_name="dpdk-n3ktt")
        self._generate_n3ktt_cmd()
        self.__socket: Optional[socket.socket] = None

    @property
    def _socket(self) -> socket.socket:
        if self.__socket is None:
            raise RuntimeError()
        return self.__socket

    def _send_with_length(self, buf) -> None:
        header = struct.pack('>H', len(buf))
        nbytes = self._socket.send(header)
        LOGGER.info(f'Sent {nbytes} bytes: {str(header)}')

        nbytes = self._socket.send(buf)
        LOGGER.info(f'Sent {nbytes} bytes: {str(buf)}')

    def _recv_with_length(self) -> None:
        buf = self._socket.recv(2)
        LOGGER.info(f'Received {len(buf)} bytes: {str(buf)}')

        if len(buf) > 0:
            length = struct.unpack('>H', buf)[0]
            buf = self._socket.recv(length)
            LOGGER.info(f'Received {length} bytes: {str(buf)}')

            cmd = protocol_capnp.Command.from_bytes_packed(buf)
            LOGGER.info(f'Received command: {cmd.msgtype}')

    def _generate_n3ktt_cmd(self) -> None:
        # Separate n3ktt options from eal options
        self.cmd_opts.append("--")

        if self.config.get("n3ktt") is not None:
            self.cmd_opts.append(f"-t { str(self.config['n3ktt']['port']) }")

    def _send_cmd(self, cmd: capnp.lib.capnp._DynamicStructBuilder) -> None:
        if self.__socket is None:
            self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.connect(
                (self.config['n3ktt']['ipmgmt'],
                 self.config['n3ktt']['port']))
            self.config['n3ktt']['port'] += 1

        self._send_with_length(cmd.to_bytes_packed())
        self._recv_with_length()

    def _try_closing_gracefully(self) -> None:
        LOGGER.info(f'Stopping {self.app_name}')
        command_close = protocol_capnp.FlowDefinition.new_message()
        command_close.msgtype = 'kill'
        self._send_cmd(command_close)
        self._socket.close()

    def add_flow(self, flow: 'Flow', multi: int = 0) -> None:
        result = n3ktt_command(flow, multi)
        self._send_cmd(result)


def start_n3ktt(ssh: 'Machine', config: dict, taskset: bool = True) -> N3ktt:
    expected_line = f"Bind to TCP port { str(config['n3ktt']['port']) }\n"
    app = N3ktt(ssh, config=config)
    if taskset:
        app.start_with_taskset(expected_line=expected_line)
    else:
        app.start_with_buffering(expected_line=expected_line)
    return app