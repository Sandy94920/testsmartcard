import logging
from enum import IntEnum
from netaddr import EUI
from typing import Any, TYPE_CHECKING
from struct import unpack, pack
from socket import inet_aton, inet_ntoa

import scapy
import scapy.contrib
import scapy.contrib.mpls
import scapy.fields
import scapy.layers
import scapy.layers.inet
import scapy.layers.l2
import scapy.layers.inet
import scapy.layers.inet6
import scapy.layers.vxlan

from scapy.data import IP_PROTOS
import capnp  # noqa: F401
from lib.remotetools.n3ktt_protocol import protocol_capnp

from lib.remotetools.flow import L2Strip, L2Change, L2Insert, Flow, SimpleKey
from lib.utils import ipv4_from_str, ipv6_from_str, mpls_label_from_int

if TYPE_CHECKING:
    from capnp.lib.capnp import _DynamicStructBuilder


LOGGER = logging.getLogger(__name__)


class N3kttError(Exception):
    pass


def _update_capnp_definition(key: 'SimpleKey',
                             destination: '_DynamicStructBuilder') -> None:
    if key.is_ipv4():
        destination.init('ipv4')
        destination.ipv4.srcIP = ipv4_from_str(key.ip_src)
        destination.ipv4.dstIP = ipv4_from_str(key.ip_dst)
    elif key.is_ipv6():
        destination.init('ipv6')
        destination.ipv6.srcIP = ipv6_from_str(key.ip_src)
        destination.ipv6.dstIP = ipv6_from_str(key.ip_dst)
    else:
        raise N3kttError("IP version not recognized.")


def _n3ktt_pattern_intra(flow: 'Flow', cmd: Any) -> None:
    cmd.portID = flow.key_port_id
    cmd.pattern.inner.srcMAC = list(EUI(flow.outer_key.mac_src).words)
    cmd.pattern.inner.dstMAC = list(EUI(flow.outer_key.mac_dst).words)

    if flow.outer_key.vlan_tci:
        vlan, prio = flow.outer_key.vlan_tci
        cmd.pattern.inner.vlanTCI = vlan_tci(vlan, prio)

    cmd.pattern.inner.srcPort = int(flow.outer_key.l4_port_src)
    cmd.pattern.inner.dstPort = int(flow.outer_key.l4_port_dst)

    _update_capnp_definition(flow.outer_key, cmd.pattern.inner)

    if flow.outer_key.l4_proto == "tcp":
        cmd.pattern.inner.protocol = IP_PROTOS.tcp
    elif flow.outer_key.l4_proto == "udp":
        cmd.pattern.inner.protocol = IP_PROTOS.udp
    else:
        raise N3kttError("Wrong protocol.")


def _n3ktt_pattern_inter(flow: 'Flow', cmd: Any) -> bool:
    inner_ethkey = False
    cmd.portID = flow.key_port_id
    cmd.pattern.outer.srcMAC = list(EUI(flow.outer_key.mac_src).words)
    cmd.pattern.outer.dstMAC = list(EUI(flow.outer_key.mac_dst).words)

    _update_capnp_definition(flow.outer_key, cmd.pattern.outer)

    cmd.pattern.outer.protocol = IP_PROTOS.udp
    cmd.pattern.outer.srcPort = int(flow.outer_key.l4_port_src)
    cmd.pattern.outer.dstPort = int(flow.outer_key.l4_port_dst)

    if flow.mpls_label:
        cmd.pattern.mplsLabelTCS = mpls_label_from_int(flow.mpls_label)

    if flow.inner_key.mac_src and flow.inner_key.mac_dst:
        cmd.pattern.inner.srcMAC = list(EUI(flow.inner_key.mac_src).words)
        cmd.pattern.inner.dstMAC = list(EUI(flow.inner_key.mac_dst).words)
        inner_ethkey = True

    if flow.inner_key.vlan_tci:
        vlan, prio = flow.inner_key.vlan_tci
        cmd.pattern.inner.vlanTCI = vlan_tci(vlan, prio)

    if flow.inner_key.ip_src and flow.inner_key.ip_dst:
        _update_capnp_definition(flow.inner_key, cmd.pattern.inner)

        if flow.inner_key.l4_proto == "tcp":
            cmd.pattern.inner.protocol = IP_PROTOS.tcp
        elif flow.inner_key.l4_proto == "udp":
            cmd.pattern.inner.protocol = IP_PROTOS.udp
        else:
            raise N3kttError("Wrong protocol.")

        if flow.inner_key.l4_port_src and flow.inner_key.l4_port_dst:
            cmd.pattern.inner.srcPort = int(flow.inner_key.l4_port_src)
            cmd.pattern.inner.dstPort = int(flow.inner_key.l4_port_dst)

    return inner_ethkey


def _n3ktt_action(flow: 'Flow', cmd: Any, has_inner_ethkey: bool = False
                  ) -> None:
    if flow.drop:
        cmd.actions.drop = True
    else:
        if flow.l2_change and isinstance(flow.l2_change, L2Change):
            cmd.actions.srcMAC = list(EUI(flow.l2_change.hdr.mac_src).words)
            cmd.actions.dstMAC = list(EUI(flow.l2_change.hdr.mac_dst).words)
        elif flow.l2_change and isinstance(flow.l2_change, L2Insert):
            cmd.actions.decapData = scapy.compat.raw(
                scapy.layers.l2.Ether() /
                scapy.layers.inet.IP() /
                scapy.layers.inet.UDP() /
                scapy.contrib.mpls.MPLS())
            cmd.actions.encapData = scapy.compat.raw(
                scapy.layers.l2.Ether(src=flow.l2_change.hdr.mac_src,
                                      dst=flow.l2_change.hdr.mac_dst))
        elif flow.l2_change and isinstance(flow.l2_change, L2Strip):
            cmd.actions.decapData = scapy.compat.raw(
                scapy.layers.l2.Ether())
        elif has_inner_ethkey:
            cmd.actions.decapData = scapy.compat.raw(
                scapy.layers.l2.Ether() /
                scapy.layers.inet.IP() /
                scapy.layers.inet.UDP() /
                scapy.contrib.mpls.MPLS())
        if flow.vlan:
            cmd.actions.vlan = int(flow.vlan)
            if flow.vlan != VlanType.STRIP:
                vlan, prio = flow.vlan_tci
                cmd.actions.vlanTCI = vlan_tci(vlan, prio)
        if flow.decr_ttl:
            cmd.actions.decraseTTL = True

        if flow.mpls_udp_encap:
            cmd.actions.encapData = scapy.compat.raw(
                scapy.layers.l2.Ether(
                    src=flow.mpls_udp_encap['key'].mac_src,
                    dst=flow.mpls_udp_encap['key'].mac_dst) /
                scapy.layers.inet.IP(
                    src=flow.mpls_udp_encap['key'].ip_src,
                    dst=flow.mpls_udp_encap['key'].ip_dst) /
                scapy.layers.inet.UDP(
                    sport=flow.mpls_udp_encap['key'].l4_port_src,
                    dport=flow.mpls_udp_encap['key'].l4_port_dst) /
                scapy.contrib.mpls.MPLS(
                    label=flow.mpls_udp_encap['mpls_label']))

        cmd.actions.dstPortID = flow.target_port_id


def n3ktt_command(flow: 'Flow', multi_flow_number: int = 0) -> Any:
    if flow.outer_key.l4_proto not in ['udp', 'tcp']:
        raise N3kttError("N3KTT does not apply.")

    if multi_flow_number == 0:
        command = protocol_capnp.FlowDefinition.new_message()
        command.msgtype = 'addFlow'

        if (isinstance(flow.outer_key, SimpleKey) and
                (flow.inner_key is None)):
            _n3ktt_pattern_intra(flow, command)
            _n3ktt_action(flow, command)
        elif (isinstance(flow.outer_key, SimpleKey) and
                isinstance(flow.inner_key, SimpleKey)):
            if _n3ktt_pattern_inter(flow, command):
                _n3ktt_action(flow, command, has_inner_ethkey=True)
            else:
                _n3ktt_action(flow, command)
    else:
        command = protocol_capnp.PerformanceTestConfiguration.new_message()
        command.msgtype = 'doPerformanceTesting'
        command.whatToChange = 'dstIP'
        command.cleanup = False
        command.count = multi_flow_number

        if (isinstance(flow.outer_key, SimpleKey) and
                (flow.inner_key is None)):
            _n3ktt_pattern_intra(flow, command.flow)
            _n3ktt_action(flow, command.flow)
        elif (isinstance(flow.outer_key, SimpleKey) and
                isinstance(flow.inner_key, SimpleKey)):
            if _n3ktt_pattern_inter(flow, command.flow):
                _n3ktt_action(flow, command.flow, has_inner_ethkey=True)
            else:
                _n3ktt_action(flow, command.flow)
    return command


def assert_flow_in_list(local: 'Flow',
                        remote: list,
                        ingress: bool = False,
                        expected_flows: int = -1) -> None:
    expected_len = 1 if expected_flows == -1 else expected_flows
    if isinstance(local, Flow) and isinstance(remote, list):
        assert len(remote) == expected_len
        assert (local.create_ingress_template() if ingress else local) in remote
    else:
        assert False


def assert_flow_lists_match(local: list['Flow'],
                            remote: list,
                            ingress: bool = False,
                            expected_flows: int = -1) -> None:
    expected_len = len(local) if expected_flows == -1 else expected_flows
    if isinstance(local, list) and isinstance(remote, list):
        assert len(remote) == expected_len
        for fl in local:
            assert (fl.create_ingress_template() if ingress else fl) in remote
    else:
        assert False


def vlan_tci(vid, pcp):
    return int(vid | (pcp << 13))


class VlanType(IntEnum):
    """Vlan action type"""
    NONE = 0,
    INSERT = 1,
    MODIFY = 2,
    STRIP = 3


def ip_to_int(addr):
    return unpack("!I", inet_aton(addr))[0]


def int_to_ip(addr):
    return inet_ntoa(pack("!I", addr))