import logging
from functools import wraps
from typing import TYPE_CHECKING, Union, Optional
from ipaddress import IPv4Address, IPv6Address, AddressValueError
from socket import error as SocketError

from netaddr import (mac_unix_expanded, EUI)
from time import sleep

if TYPE_CHECKING:
    from . import SSHConn
    from paramiko import SFTPClient
    from paramiko.channel import (ChannelStdinFile,
                                  ChannelFile,
                                  ChannelStderrFile)

LOGGER = logging.getLogger(__name__)
CMD_GET_IPv4_ADDRESS = ("/sbin/ifconfig {iface} | grep 'inet' | "
                        "cut -d: -f2 | awk '{{print $2}}'")
CMD_GET_IPv6_ADDRESS = ("/sbin/ifconfig {iface} | grep 'inet6' | "
                        " awk '{{print $2}}' | grep -v ^fe80")


class MachineError(Exception):
    pass


class ReconnectError(Exception):
    pass


class InterfaceError(Exception):
    pass


def reconnect(current_ssh_conn: 'SSHConn', try_reconnect: int = 0) -> 'SSHConn':
    LOGGER.info(f"Try reconnect ({try_reconnect}/4) to host "
                f"{current_ssh_conn.base_address} "
                f"after connection reset by peer")
    return current_ssh_conn.connect(
        address=current_ssh_conn.base_address,
        port=current_ssh_conn.port,
        username=current_ssh_conn.username,
        key=current_ssh_conn.key,
        password=current_ssh_conn.password,
        timeout=current_ssh_conn.timeout)


def reconnect_after_err_conn_reset_by_peer(f):
    @wraps(f)
    def func(self, *args, **kwargs):
        for try_reconnet in range(1, 4):
            try:
                return f(self, *args, **kwargs)
            except SocketError as sock_err:
                LOGGER.error(f"Try reconnect at error from ssh_conn "
                             f"{sock_err}", exc_info=True)
                self._ssh = reconnect(
                    current_ssh_conn=self.ssh,
                    try_reconnect=try_reconnet)
            sleep(try_reconnet)
        raise ReconnectError(f"Can't create new connection to host "
                             f"{self.ip_mgmt}")
    return func


class Interface:
    def __init__(self,
                 name: str = None,
                 ip_addr: str = None,
                 ipv6_addr: str = None,
                 mac_addr: str = None):
        self.name = name
        self.ipv4 = ip_addr
        self.ipv6 = ipv6_addr
        self.mac_addr = mac_addr

    def get_ip(self, ip_version: str) -> str:
        ip = self.ipv6 if ip_version == 'ip6' else self.ipv4
        if ip is None:
            raise InterfaceError(f'Interface {self.name} has no {ip_version}')
        return ip


class Machine:
    """
    Base class for other classes machine classes. Contains basic
    functionalities (e.g. command execution methods).
    """
    _ssh: Optional['SSHConn'] = None

    @property
    def ssh(self) -> 'SSHConn':
        if self._ssh is None:
            raise RuntimeError(f'No SSH set yet for {self}')
        return self._ssh

    @property
    def ip_mgmt(self) -> str:
        return self.ssh.base_address

    def open_sftp(self) -> 'SFTPClient':
        LOGGER.info(
            f'Open sftp connection to the {self.ip_mgmt} host.')
        return self.ssh.open_sftp()

    def create_cmd_channel(self, cmd, **kwargs):
        LOGGER.info(
            f'Create channel to {self.ip_mgmt} host for cmd:{cmd}.')
        return self.ssh.create_cmd_channel(cmd, **kwargs)

    @reconnect_after_err_conn_reset_by_peer
    def get_cmd_output(self, cmd: str, log_output: bool = False, **kwargs
                       ) -> tuple[str, str]:
        LOGGER.info(
            f'Getting output from cmd: {cmd} on host {self.ip_mgmt}.')
        return self.ssh.get_cmd_output(cmd, log_output=log_output, **kwargs)

    @reconnect_after_err_conn_reset_by_peer
    def get_cmd_streams(self, cmd: str, **kwargs) -> tuple['ChannelStdinFile',
                                                           'ChannelFile',
                                                           'ChannelStderrFile']:
        LOGGER.info(
            f'Getting streams for cmd: {cmd} on host {self.ip_mgmt}.')
        return self.ssh.get_cmd_streams(cmd, **kwargs)

    @reconnect_after_err_conn_reset_by_peer
    def get_sudo_cmd_streams(self, cmd: str, **kwargs
                             ) -> tuple['ChannelStdinFile',
                                        'ChannelFile',
                                        'ChannelStderrFile']:
        LOGGER.info(f'Getting sudo streams for cmd: {cmd} '
                    f'on host {self.ip_mgmt}.')
        return self.ssh.get_cmd_streams(' '.join(['sudo', cmd]), **kwargs)

    @reconnect_after_err_conn_reset_by_peer
    def get_sudo_cmd_output(self, cmd: str, log_output: bool = False, **kwargs
                            ) -> tuple[str, str]:
        LOGGER.info(f'Getting sudo output for cmd: {cmd} '
                    f'on host {self.ip_mgmt}.')
        return self.ssh.get_cmd_output(
            ' '.join(['sudo', cmd]), log_output=log_output, **kwargs)

    def _parse_ipv4(self, address: str) -> Union[bool, IPv4Address]:
        try:
            addr = IPv4Address(address.rstrip('\n'))
        except AddressValueError:
            return False
        else:
            return addr

    def _parse_ipv6(self, address: str) -> Union[bool, IPv6Address]:
        try:
            addr = IPv6Address(address.rstrip('\n'))
        except AddressValueError:
            return False
        else:
            return addr

    def is_ipv6(self, ip_version: str) -> bool:
        if ip_version == 'ip6':
            return True
        return False

    def get_iface_ip(self, iface: str, ip_version: str) -> Optional[str]:
        is_ipv6 = self.is_ipv6(ip_version)

        cmd = CMD_GET_IPv6_ADDRESS if is_ipv6 else CMD_GET_IPv4_ADDRESS
        stdout, _ = self.get_cmd_output(
            cmd.format(iface=iface), log_output=True)

        addr = self._parse_ipv6(stdout) if is_ipv6 else self._parse_ipv4(stdout)
        if addr is False:
            self.get_cmd_output("/sbin/ifconfig", log_output=True)
            raise AddressValueError(f"No such {ip_version} address "
                                    f"for {iface} iface")

        LOGGER.debug(f'Found {addr} {ip_version} address on {iface}')
        return str(addr)

    def get_iface_mac(self, iface: str) -> str:
        cmd = (f"/sbin/ifconfig {iface} | grep 'ether' |"
               f" awk '{{print $2}}'")
        stdout, stderr = self.get_cmd_output(cmd, log_output=True)
        if stderr:
            raise MachineError(f"No such mac address for {iface} iface")
        mac = EUI(stdout.rstrip('\n'))
        mac.dialect = mac_unix_expanded
        LOGGER.debug(f'Found {mac} mac address on {iface}')
        return str(mac)

    def setup_interfaces_list(self, iface_names) -> list[Interface]:
        return [Interface(name=iface,
                          ip_addr=self.get_iface_ip(iface, ip_version='ip'),
                          ipv6_addr=self.get_iface_ip(iface, ip_version='ip6'),
                          mac_addr=self.get_iface_mac(iface))
                if iface else Interface() for iface in iface_names]

    def get_hostname(self) -> str:
        LOGGER.info(f"Try get hostname from {self.ip_mgmt}")
        stdout, stderr = self.get_cmd_output('hostname', log_output=True)
        if stderr:
            raise MachineError(f"Error getting host name: {stderr}")
        LOGGER.info(f"Obtained hostname: {stdout}")
        return stdout.rsplit()[0]