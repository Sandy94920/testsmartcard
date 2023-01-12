import paramiko
import logging
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from paramiko.channel import (ChannelStdinFile,
                                  ChannelFile,
                                  ChannelStderrFile)

logging.getLogger('paramiko').setLevel(logging.INFO)
logger = logging.getLogger(__name__)


class SSHConnError(Exception):
    pass


class SSHConn:
    """
    Class representing an SSH connection to other machines. Allows command
    execution and file manipulation through SFTP client on remote machines.

    Example use case:
        base_connection = SSHConn.connect("10.7.0.162",
                                          username="centos",
                                          key="keys/id_rsa")
        print(base_connection.get_cmd_output('hostname')[0])
    """

    def __init__(self,
                 ssh_client: 'paramiko.client.SSHClient',
                 base_address: str,
                 port: int,
                 username: str = None,
                 key: str = None,
                 password: str = None,
                 timeout: int = None):
        self.base_address = base_address
        self.ssh_client = ssh_client
        self.port = port
        self.username = username
        self.key = key
        self.password = password
        self.timeout = timeout

    def __del__(self):
        if self.ssh_client:
            self.ssh_client.close()

    def get_host_address(self):
        return self.base_address

    @classmethod
    def connect(cls,
                address: str,
                port: int,
                password: str = None,
                username: str = None,
                key: str = None,
                timeout: Optional[int] = 30) -> 'SSHConn':
        """
        Create a new SSHConn object.

        :param address:
            machine's address to connect to
        :param port:
            machine's port to connect to
        :param username:
            username to authenticate as
        :param key:
            path to the file with private key for authentication
        :param password:
            password for authentication
        :param timeout:
            timeout for the TCP connect
        """
        client = paramiko.client.SSHClient()
        client.set_missing_host_key_policy(paramiko.client.AutoAddPolicy)
        logger.debug(f'Trying to establish connection to host "{address}"')
        client.connect(
            address,
            port,
            username=username,
            key_filename=key,
            password=password,
            timeout=timeout,
            allow_agent=False,
            look_for_keys=False)
        logger.debug(f'Connection to host "{address}" established')
        return cls(client, address, port, username, key, password, timeout)

    @classmethod
    def connect_with_handle(cls, client):
        """
        Create a new SSHConn object using already created SSHConn.

        :param client:
            SSHConn object to use
        """
        return cls(client.ssh_client, client.get_host_address(), client.port)

    # asynchronous
    def create_cmd_channel(self, cmd: str, timeout: int = 120
                           ) -> paramiko.Channel:
        """
        Execute command and return paramiko's channel.

        :param cmd:
            command to run
        :param timeout:
            seconds to wait for any event on stdin/stdout/stderr objects after
            write/read operations before raising `socket.timeout` exception
            set to `None` for no timeout

        :return
            channel corresponding to the command
        """
        logger.debug(f'Creating a new channel executing "{cmd}" on'
                     f'host "{self.get_host_address()}"')
        transport = self.ssh_client.get_transport()
        if transport is None:
            raise SSHConnError('Cannot create new channel')

        if not transport.is_active():
            self.ssh_client.connect(
                self.base_address,
                self.port,
                username=self.username,
                key_filename=self.key,
                password=self.password,
                timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False)
        transport_channel = self.ssh_client.get_transport()
        if transport_channel is None:
            raise SSHConnError('Cannot create new channel')
        channel = transport_channel.open_session()
        channel.exec_command(cmd)
        channel.settimeout(timeout)
        logger.debug(f"New channel executing '{cmd}' on host '"
                     f"{self.get_host_address()}' created")
        return channel

    # asynchronous
    def get_cmd_streams(self, cmd: str, timeout: int = 120
                        ) -> tuple['ChannelStdinFile',
                                   'ChannelFile',
                                   'ChannelStderrFile']:
        """
        Execute command and creates file-like objects for writing to stdin
        and reading from stdout/stderr.

        :param cmd:
            command to run
        :param timeout:
            seconds to wait for any event on stdin/stdout/stderr objects after
            write/read operations before raising `socket.timeout` exception
            set to `None` for no timeout

        :return
            the stdin, stdout, and stderr of the executing command, as a
            3-tuple
        """
        channel = self.create_cmd_channel(cmd, timeout=timeout)
        logger.debug(f'Creating file-like objects for writing and'
                     f'reading for command "{cmd}" on host'
                     f' "{self.get_host_address()}"')
        stdin = channel.makefile_stdin('w')
        stdout = channel.makefile()
        stderr = channel.makefile_stderr()
        logger.debug(f'File-like objects for command "{cmd}" on'
                     f'host "{self.get_host_address()}" created')
        return (stdin, stdout, stderr)

    # synchronous
    def get_cmd_output(self, cmd: str, timeout: int = 120,
                       log_output: bool = False) -> tuple[str, str]:
        """
        Execute a command.

        :param cmd:
            command to run
        :param timeout:
            seconds to wait for any event on stdin/stdout/stderr objects after
            write/read operations before raising `socket.timeout` exception
            set to `None` for no timeout
        :param log_output:
            set to true if the output of the command should be logged.
            Default is false

        :return
            decoded to utf-8 stdout and stderr, as a 2-tuple
        """
        stdout, stderr = self.get_cmd_streams(cmd, timeout=timeout)[1:]

        logger.debug(f'Waiting for command "{cmd}" output'
                     f'on host "{self.get_host_address()}"')
        out = stdout.read()
        err = stderr.read()
        logger.debug(f'Received execution output for command'
                     f'"{cmd}" on host'
                     f'"{self.get_host_address()}"')
        out_log, err_log = out.decode('utf-8'), err.decode('utf-8')
        if log_output:
            logger.debug(f'Command stdout: {out_log}')
            logger.debug(f'Command stderr: {err_log}')
        return out_log, err_log

    def open_sftp(self) -> 'paramiko.SFTPClient':
        """
        Open an SFTP session on the SSH server

        :return
            a new paramiko's SFTPClient session object
        """
        logger.debug(f'Opening SFTP session on host'
                     f'"{self.get_host_address()}"')
        sftp = self.ssh_client.open_sftp()
        logger.debug(f'SFTP session created on host'
                     f'"{self.get_host_address()}"')
        return sftp