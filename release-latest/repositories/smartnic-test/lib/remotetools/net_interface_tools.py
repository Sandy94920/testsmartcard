import logging
from typing import TYPE_CHECKING
from lib.connections import TestBedError
from lib.utils import (
    get_ip_addr_without_prefix,
    get_iptables_command,
    is_ipv6_address)

if TYPE_CHECKING:
    from lib.connections import Machine
    from lib.connections import Vm

LOGGER = logging.getLogger(__name__)


def iface_down(cpt_ssh: 'Machine', iface: str = "eth2") -> None:
    cmd = f"ifdown {iface}"
    stdout, stderr = cpt_ssh.get_sudo_cmd_output(cmd)
    (LOGGER.error(stderr)
     if stderr else LOGGER.info(f"Iface {iface} down: {stdout}"))


def add_routing(cpt_ssh: 'Machine',
                ip_public_ipam: str,
                ip_gateway: str,
                iface: str = "eth1") -> None:
    LOGGER.info(f"Try add routing {ip_public_ipam}, {ip_gateway}")
    ip_family = 'inet6' if is_ipv6_address(ip_gateway) else 'inet'
    cmd = (f"ip --family {ip_family} route add {ip_public_ipam} "
           f"via {ip_gateway} dev {iface}")
    _, err = cpt_ssh.get_sudo_cmd_output(cmd)
    (LOGGER.error(err) if err else LOGGER.info(f"Add routing via cmd: {cmd}"))


def del_routing(cpt_ssh: 'Machine',
                ip_public_ipam: str,
                ip_gateway: str,
                iface: str = "eth1") -> None:
    ip_family = 'inet6' if is_ipv6_address(ip_gateway) else 'inet'
    cmd = (f"ip --family {ip_family} route delete {ip_public_ipam} "
           f"via {ip_gateway} dev {iface}")
    _, err = cpt_ssh.get_sudo_cmd_output(cmd)
    (LOGGER.error(err)
     if err else LOGGER.info(f"Del routing via cmd: {iface}"))


def iface_up(cpt_ssh: 'Machine', iface: str = "eth2") -> None:
    cmd = f"ifup {iface}"
    stdout, stderr = cpt_ssh.get_sudo_cmd_output(cmd)
    (LOGGER.error(stderr)
     if stderr else LOGGER.info(f"Iface {iface} up: {stdout}"))


def get_ip_address_by_iface_name(cpt_ssh: 'Machine', iface: str) -> str:
    cmd = f"ip address | grep --before-context=1 {iface}"
    stdout, stderr = cpt_ssh.get_sudo_cmd_output(cmd)
    ip_addr = stdout.split()[-6].split('/')[0]
    (LOGGER.error(stderr)
     if stderr else LOGGER.info(f"Iface {iface} up: {ip_addr}"))
    return ip_addr


def deactive_net_interfaces(*ssh_connections: 'Machine',
                            iface: str = "eth2") -> None:
    for ssh_conn in ssh_connections:
        iface_down(cpt_ssh=ssh_conn, iface=iface)


def add_policy_to_iptables(host: 'Machine',
                           direction: str,
                           proto: str,
                           ip_addr: str,
                           type_of_flag: str,
                           flags: str,
                           policy: str) -> None:
    ip_version = is_ipv6_address(ip_addr)
    iptables_command = get_iptables_command(ip_version)
    cmd = (f"{iptables_command} --append {direction} --protocol {proto} "
           f"--{type_of_flag} {flags} {flags} --source {ip_addr} "
           f"--jump {policy}")
    LOGGER.info(f"Add policy to iptables {cmd}")
    stdout, stderr = host.get_sudo_cmd_output(cmd)
    (LOGGER.error(stderr)
     if stderr else LOGGER.info(stdout))


def del_policy_from_iptables(host: 'Machine',
                             direction: str,
                             proto: str,
                             ip_addr: str,
                             type_of_flag: str,
                             flags: str,
                             policy: str) -> None:
    ip_version = is_ipv6_address(ip_addr)
    iptables_command = get_iptables_command(ip_version)
    cmd = (f"{iptables_command} --delete {direction} --protocol {proto} "
           f"--{type_of_flag} {flags} {flags} --source {ip_addr} "
           f"--jump {policy}")
    LOGGER.info(f"Del policy from iptables {cmd}")
    stdout, stderr = host.get_sudo_cmd_output(cmd)
    (LOGGER.error(stderr) if stderr else LOGGER.info(stdout))


def get_value_mqs(cpt_ssh: 'Vm') -> int:
    cmd = f"ethtool --show-channels {cpt_ssh.get_interface_by_index(0).name}"
    stdout, stderr = cpt_ssh.get_sudo_cmd_output(cmd)
    if stderr:
        raise Exception(stderr)
    output_mqs = int(stdout.split()[13])
    LOGGER.info(output_mqs)
    return output_mqs


def check_kernel_version(cpt_ssh: 'Machine', req_version: int) -> None:
    cmd = "uname --kernel-release"
    stdout, err = cpt_ssh.get_cmd_output(cmd)
    try:
        current_kernel_version = int(''.join(filter(
            str.isdigit, stdout.split('.')[2])))
    except IndexError:
        raise TestBedError("can't get the kernel version")

    if current_kernel_version < req_version:
        raise TestBedError(
            f"Requires minimum Kernel version to "
            f"tests: {req_version}. Current: {current_kernel_version}")
    (LOGGER.error(err)
     if err
     else LOGGER.info(f"Current Kernel version: {current_kernel_version}"))


def set_mtu_configuration(cpt_ssh: 'Machine',
                          iface_config_mtu: str,
                          set_mtu: int) -> None:
    check_kernel_version(cpt_ssh, req_version=1062)
    cmd = f"ip link set dev {iface_config_mtu} mtu {str(set_mtu)}"
    LOGGER.info(f"Set MTU to: {set_mtu} in the iface: {iface_config_mtu}")
    stdout, err = cpt_ssh.get_sudo_cmd_output(cmd)
    (LOGGER.error(err) if err else LOGGER.info(stdout))


def add_ip_address(cpt_ssh: 'Machine',
                   ip_public_ipam: str,
                   iface: str = "eth1") -> None:
    LOGGER.info(f"Try add ip address {ip_public_ipam}")
    ip_addr_without_prefix = get_ip_addr_without_prefix(ip_public_ipam)
    ip_family = 'inet6' if is_ipv6_address(ip_addr_without_prefix) else 'inet'
    cmd = (f"ip --family {ip_family} address add {ip_public_ipam} "
           f"dev {iface}")
    _, err = cpt_ssh.get_sudo_cmd_output(cmd)
    (LOGGER.error(err)
     if err else LOGGER.info(f"Added ip address via cmd: {cmd}"))


def del_ip_address(cpt_ssh: 'Machine',
                   ip_public_ipam: str,
                   iface: str = "eth1") -> None:
    LOGGER.info(f"Try add ip address {ip_public_ipam}")
    ip_addr_without_prefix = get_ip_addr_without_prefix(ip_public_ipam)
    ip_family = 'inet6' if is_ipv6_address(ip_addr_without_prefix) else 'inet'
    cmd = (f"ip --family {ip_family} address delete {ip_public_ipam} "
           f"dev {iface}")
    _, err = cpt_ssh.get_sudo_cmd_output(cmd)
    (LOGGER.error(err)
     if err else LOGGER.info(f"Added ip address via cmd: {cmd}"))