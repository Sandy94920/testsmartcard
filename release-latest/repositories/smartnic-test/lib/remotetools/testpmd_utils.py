import logging
from typing import TYPE_CHECKING, Optional

from lib.remotetools.flow import L2Strip, L2Change, L2Insert, Flow

if TYPE_CHECKING:
    from lib.remotetools.flow import SimpleKey


LOGGER = logging.getLogger(__name__)


class TestpmdError(Exception):
    pass


def testpmd_set_decap_command(flow: 'Flow') -> Optional[str]:
    if not flow.outer_key.l4_proto == 'udp':
        LOGGER.info("Testpmd decap command does not apply "
                    "for other protocols than UDP.")
        return None

    if flow.outer_key.is_ipv4():
        return (
            f"set raw_decap 0 eth / ipv4 / {flow.outer_key.l4_proto}"
            f" / mpls / end_set\nset raw_decap 1 eth / end_set"
        )
    elif flow.outer_key.is_ipv6():
        return (
            f"set raw_decap 0 eth / ipv6 / {flow.outer_key.l4_proto}"
            f" / mpls / end_set\nset raw_decap 1 eth / end_set"
        )
    else:
        raise TestpmdError("IP version not recognized.")


def _testpmd_command_mpls_label(flow: 'Flow') -> str:
    return (f"mpls label is {flow.mpls_label} / "
            + _testpmd_key_command(flow.inner_key)) if flow.mpls_label else ""


def _testpmd_command_l2_change_strip(flow: 'Flow') -> str:
    cmd_l2_change = ""
    if flow.l2_change and isinstance(flow.l2_change, L2Change):
        cmd_l2_change += (
            f"set_mac_src mac_addr {flow.l2_change.hdr.mac_src} / "
            f"set_mac_dst mac_addr {flow.l2_change.hdr.mac_dst} / ")
    elif flow.l2_change and isinstance(flow.l2_change, L2Strip):
        cmd_l2_change += "raw_decap index 1 / "
    return cmd_l2_change


def _testpmd_command_dec_ttl(flow: 'Flow') -> str:
    return "dec_ttl / " if flow.decr_ttl else ""


def _testpmd_key_command(key: 'SimpleKey') -> str:
    command = ""
    if key.mac_src is not None:
        command += f"eth src is {key.mac_src} "
        command += f"dst is {key.mac_dst} type is 0x0800 / "
    if key.is_ipv4():
        command += "ipv4"
    elif key.is_ipv6():
        command += "ipv6"
    else:
        raise TestpmdError("IP version not recognized.")
    command += f" src is {key.ip_src} "
    command += f"dst is {key.ip_dst} proto is "
    if key.l4_proto == "udp":
        command += "17 / udp "
    elif key.l4_proto == "tcp":
        command += "6 / tcp "
    else:
        raise TestpmdError("Protocol not supported.")
    command += f"src is {key.l4_port_src} "
    command += f"dst is {key.l4_port_dst} / "
    return command


def testpmd_flow_command(flow: 'Flow') -> str:
    if flow.outer_key.l4_proto not in ['udp', 'tcp']:
        raise TestpmdError("Testpmd command does not apply. "
                           "Protocol not supported.")
    encap_cmd = ""
    command = f"flow create 0 pattern port_id id is {flow.key_port_id} / "
    command += _testpmd_key_command(flow.outer_key)
    command += _testpmd_command_mpls_label(flow)
    command += "end actions "
    if flow.drop:
        command += "drop / end"
        return command
    command += _testpmd_command_l2_change_strip(flow)
    command += _testpmd_command_dec_ttl(flow)
    if flow.mpls_udp_encap:
        encap_key = flow.mpls_udp_encap["key"]
        if encap_key.is_ipv4():
            ip_version = "ipv4"
        elif encap_key.is_ipv6():
            ip_version = "ipv6"
        else:
            raise TestpmdError("IP version not recognized.")
        encap_cmd = (
            f"set raw_encap 0 eth src is {encap_key.mac_src} "
            f"dst is {encap_key.mac_dst} "
            f" / {ip_version} src is {encap_key.ip_src} dst is "
            f"{encap_key.ip_dst} / "
            f"udp src is {encap_key.l4_port_src} "
            f"dst is {encap_key.l4_port_dst} / "
            f"mpls label is {flow.mpls_udp_encap['mpls_label']} / end_set")
        command += "raw_encap index 0 / "
    if flow.mpls_label:
        command += "raw_decap index 0 / "
    if flow.l2_change and isinstance(flow.l2_change, L2Insert):
        encap_cmd = (
            f"set raw_encap 0 "
            f"eth src is {flow.l2_change.hdr.mac_src} "
            f"dst is {flow.l2_change.hdr.mac_dst} "
            f"type is 0x0800 / end_set"
        )
        command += "raw_encap index 0 / "

    command += f"port_id id {flow.target_port_id} / end"
    return (encap_cmd + "\n" if encap_cmd != "" else "") + command