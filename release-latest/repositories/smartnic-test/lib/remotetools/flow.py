import logging
import re
from copy import deepcopy
from typing import Any, Optional

from scapy.all import (
    IPField,
    IP6Field,
)
from scapy.layers.inet import TCP, UDP, IP
from scapy.layers.vxlan import VXLAN
from scapy.layers.inet6 import IPv6
from scapy.contrib.mpls import MPLS
from scapy.layers.l2 import Ether, Dot1Q
from scapy.packet import Packet

from lib.remotetools.traffic_tools import PacketStructure


LOGGER = logging.getLogger(__name__)

# http://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses
IPV4SEG = r'(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])'
IPV4ADDR = r'(?:(?:' + IPV4SEG + r'\.){3,3}' + IPV4SEG + r')'
IPV6SEG = r'(?:(?:[0-9a-fA-F]){1,4})'
IPV6GROUPS = (
    r'(?:' + IPV6SEG + r':){7,7}' + IPV6SEG,
    r'(?:' + IPV6SEG + r':){1,7}:',
    r'(?:' + IPV6SEG + r':){1,6}:' + IPV6SEG,
    r'(?:' + IPV6SEG + r':){1,5}(?::' + IPV6SEG + r'){1,2}',
    r'(?:' + IPV6SEG + r':){1,4}(?::' + IPV6SEG + r'){1,3}',
    r'(?:' + IPV6SEG + r':){1,3}(?::' + IPV6SEG + r'){1,4}',
    r'(?:' + IPV6SEG + r':){1,2}(?::' + IPV6SEG + r'){1,5}',
    IPV6SEG + r':(?:(?::' + IPV6SEG + r'){1,6})',
    r':(?:(?::' + IPV6SEG + r'){1,7}|:)',
    r'fe80:(?::' + IPV6SEG + r'){0,4}%[0-9a-zA-Z]{1,}',
    r'::(?:ffff(?::0{1,4}){0,1}:){0,1}[^\s:]' + IPV4ADDR,
    r'(?:' + IPV6SEG + r':){1,4}:[^\s:]' + IPV4ADDR,
)
IPV6ADDR = '|'.join(['(?:{})'.format(g) for g in IPV6GROUPS[::-1]])
IPV4ADDRESS = re.compile(IPV4ADDR)
IPV6ADDRESS = re.compile(IPV6ADDR)


class FlowError(Exception):
    pass


class IgnoredKey:
    """
    SimpleKey and Flow class attributes set to object of this class
    indicate to ignore it during comparison.
    """
    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return repr('Ignored Key')


def _compare_with_ignore(obj, cmp_obj):
    """ Don't compare ignored keys """
    if not isinstance(cmp_obj, obj.__class__):
        return False
    for attr in vars(obj):
        attr_obj = getattr(obj, attr)
        attr_cmp_obj = getattr(cmp_obj, attr)
        if (isinstance(attr_obj, IgnoredKey)
                or isinstance(attr_cmp_obj, IgnoredKey)):
            continue
        elif (isinstance(attr_obj, str)
                and isinstance(attr_cmp_obj, str)
                and IPV4ADDRESS.match(attr_obj)
                and IPV4ADDRESS.match(attr_cmp_obj)):
            ipv4_attr_obj = IPField('IP', None).h2i(None, attr_obj)
            ipv4_attr_cmp_obj = IPField('IP', None).h2i(None, attr_cmp_obj)
            if ipv4_attr_obj != ipv4_attr_cmp_obj:
                return False
            continue
        elif (isinstance(attr_obj, str)
                and isinstance(attr_cmp_obj, str)
                and IPV6ADDRESS.match(attr_obj)
                and IPV6ADDRESS.match(attr_cmp_obj)):
            ipv6_attr_obj = IP6Field('IP6', None).h2i(None, attr_obj)
            ipv6_attr_cmp_obj = IP6Field('IP6', None).h2i(None, attr_cmp_obj)
            if ipv6_attr_obj != ipv6_attr_cmp_obj:
                return False
            continue
        elif attr_obj == attr_cmp_obj:
            continue
        else:
            return False
    return True


class L2Strip:
    def __init__(self, key_dict: dict = None):
        if key_dict is None:
            key_dict = {}

    def __eq__(self, other):
        return _compare_with_ignore(self, other)

    def __str__(self):
        return f'{vars(self)}'

    def __repr__(self):
        return f'L2Strip({vars(self)})'

    def _serialize(self):
        return [f"{k}: {v}" for k, v in vars(self).items() if v is not None]


class L2Insert:
    def __init__(self, key_dict: dict = None):
        if key_dict is None:
            key_dict = {}
        self.hdr = key_dict.get("hdr")

    @classmethod
    def base_on_json(cls, json_key: dict):
        ret = cls()
        ret.hdr = EthHeader.base_on_json(json_key)
        return ret

    def __eq__(self, other):
        return _compare_with_ignore(self, other)

    def __str__(self):
        return f'{vars(self)}'

    def __repr__(self):
        return f'L2Insert({vars(self)})'

    def _serialize(self) -> list[str]:
        return [f"{k}: {v}" for k, v in vars(self).items() if v is not None]


class L2Change:
    def __init__(self, key_dict: dict = None):
        if key_dict is None:
            key_dict = {}
        self.hdr = key_dict.get("hdr")

    @classmethod
    def base_on_json(cls, json_key):
        ret = cls()
        ret.hdr = EthHeader.base_on_json(json_key)
        return ret

    def __eq__(self, other):
        return _compare_with_ignore(self, other)

    def __str__(self):
        return f'{vars(self)}'

    def __repr__(self):
        return f'L2Change({vars(self)})'

    def _serialize(self) -> list[str]:
        return [f"{k}: {v}" for k, v in vars(self).items() if v is not None]


class EthHeader:
    def __init__(self, key_dict: dict = None):
        if key_dict is None:
            key_dict = {}
        self.mac_src = key_dict.get("mac_src")
        self.mac_dst = key_dict.get("mac_dst")

    @classmethod
    def base_on_json(cls, json_key: dict) -> 'EthHeader':
        ret = cls()
        ret.mac_src = json_key["smac"]
        ret.mac_dst = json_key["dmac"]
        return ret

    def __eq__(self, other):
        return _compare_with_ignore(self, other)

    def __str__(self):
        return f'{vars(self)}'

    def __repr__(self):
        return f'EthHeader({vars(self)})'

    def _serialize(self) -> list[str]:
        return [f"{k}: {v}" for k, v in vars(self).items() if v is not None]


class SimpleKey:
    def __init__(self, key_dict: dict = None):
        if key_dict is None:
            key_dict = {}
        self.mac_src: Optional[str] = key_dict.get("mac_src")
        self.mac_dst: Optional[str] = key_dict.get("mac_dst")
        self.ip_src: Optional[str] = key_dict.get("ip_src")
        self.ip_dst: Optional[str] = key_dict.get("ip_dst")
        self.l4_port_src: Optional[str] = key_dict.get("l4_port_src")
        self.l4_port_dst: Optional[str] = key_dict.get("l4_port_dst")
        self.l4_proto: Optional[str] = key_dict.get("l4_proto")
        self.vlan_tci: Optional[list] = key_dict.get("vlan_tci")

    @classmethod
    def base_on_traffic(cls, traffic_definition: dict) -> 'SimpleKey':
        key = cls({
            "mac_src": traffic_definition.get("smac"),
            "mac_dst": traffic_definition.get("dmac"),
            "ip_src": traffic_definition.get("ip_src"),
            "ip_dst": traffic_definition.get("ip_dst"),
            "l4_proto": traffic_definition.get("proto"),
            "l4_port_src": traffic_definition.get("sport"),
            "l4_port_dst": traffic_definition.get("dport")})
        return key

    @classmethod
    def base_on_packet(cls, packet: Packet) -> 'SimpleKey':
        traffic_definition = PacketStructure(packet).get_params_dict()
        key = cls({
            "mac_src": traffic_definition.get("smac"),
            "mac_dst": traffic_definition.get("dmac"),
            "ip_src": traffic_definition.get("ip_src"),
            "ip_dst": traffic_definition.get("ip_dst"),
            "l4_proto": traffic_definition.get("proto"),
            "l4_port_src": traffic_definition.get("sport"),
            "l4_port_dst": traffic_definition.get("dport")})
        return key

    @classmethod
    def base_on_json(cls, json_key: dict) -> 'SimpleKey':
        ret = cls()
        if json_key.get("eth", None) is not None:
            ret.mac_src = json_key["eth"]["smac"]
            ret.mac_dst = json_key["eth"]["dmac"]
        if (json_key.get("vlan", None) is not None
                and json_key["vlan"].get("type", None) is None):
            ret.vlan_tci = [json_key["vlan"]["vid"], json_key["vlan"]["pcp"]]
        if json_key.get("ipv4", None) is not None:
            ret.ip_src = json_key["ipv4"]["src"]
            ret.ip_dst = json_key["ipv4"]["dst"]
        elif json_key.get("ipv6", None) is not None:
            ret.ip_src = json_key["ipv6"]["src"]
            ret.ip_dst = json_key["ipv6"]["dst"]
        else:
            raise FlowError("IP version not recognized.")
        if json_key.get("TCP", None) is not None:
            ret.l4_proto = "tcp"
            ret.l4_port_src = json_key["TCP"]["sport"]
            ret.l4_port_dst = json_key["TCP"]["dport"]
        elif json_key.get("UDP", None) is not None:
            ret.l4_proto = "udp"
            ret.l4_port_src = json_key["UDP"]["sport"]
            ret.l4_port_dst = json_key["UDP"]["dport"]
        else:
            raise FlowError("Wrong l4 protocol in json.")
        return ret

    def __eq__(self, other):
        return _compare_with_ignore(self, other)

    def __str__(self):
        return f'{vars(self)}'

    def __repr__(self):
        return f'SimpleKey({vars(self)})'

    def _serialize(self) -> list[str]:
        return [f"{k}: {v}" for k, v in vars(self).items() if v is not None]

    def is_ipv4(self) -> bool:
        if not isinstance(self.ip_src, str) or not isinstance(self.ip_dst, str):
            return False
        if IPV4ADDRESS.match(self.ip_src) and IPV4ADDRESS.match(self.ip_dst):
            return True
        return False

    def is_ipv6(self) -> bool:
        if not isinstance(self.ip_src, str) or not isinstance(self.ip_dst, str):
            return False
        if IPV6ADDRESS.match(self.ip_src) and IPV6ADDRESS.match(self.ip_dst):
            return True
        return False

    def reversed(self) -> 'SimpleKey':
        key = deepcopy(self)
        key.mac_src, key.mac_dst = self.mac_dst, self.mac_src
        key.ip_src, key.ip_dst = self.ip_dst, self.ip_src
        key.l4_port_src, key.l4_port_dst = self.l4_port_dst, self.l4_port_src
        return key

    def to_pkt(self) -> Packet:
        pkt = Ether(src=self.mac_src,
                    dst=self.mac_dst)

        if self.vlan_tci:
            vlan, prio = self.vlan_tci
            pkt /= Dot1Q(vlan=vlan, prio=prio)

        if self.is_ipv4():
            pkt /= IP(src=self.ip_src,
                      dst=self.ip_dst)
        elif self.is_ipv6():
            pkt /= IPv6(src=self.ip_src,
                        dst=self.ip_dst)
        else:
            raise FlowError("IP version not recognized.")

        if self.l4_proto == "udp":
            pkt /= UDP(sport=self.l4_port_src,
                       dport=self.l4_port_dst)
        elif self.l4_proto == "tcp":
            pkt /= TCP(sport=self.l4_port_src,
                       dport=self.l4_port_dst)
        else:
            raise FlowError("Wrong protocol.")

        if (self.mac_src is None) or (self.mac_dst is None):
            # L3 packet, removing eth Ethernet header
            return pkt[1:]

        return pkt

    class Flow:
        def __init__(self, flow_dict: dict = None):
            if flow_dict is None:
                flow_dict = {}
            self.key_port_id = flow_dict.get("key_port_id")
            self.outer_key = flow_dict.get("outer_key")
            self.inner_key = flow_dict.get("inner_key")
            self.target_port_id = flow_dict.get("target_port_id")
            self.drop = flow_dict.get("drop")
            self.decr_ttl = flow_dict.get("decr_ttl", False)
            self.mpls_udp_encap = flow_dict.get("mpls_udp_encap")
            self.mpls_label = flow_dict.get("mpls_label")
            self.vxlan_vni = flow_dict.get("vxlan_vni")
            self.vlan = flow_dict.get("vlan")
            self.vlan_tci = flow_dict.get("vlan_tci")
            if flow_dict.get("modify_l2_src", None) is None:
                self.l2_change = flow_dict.get("l2_change")
            else:
                self.l2_change = L2Change({
                    "hdr": EthHeader({
                        "mac_src": flow_dict.get("modify_l2_src"),
                        "mac_dst": flow_dict.get("modify_l2_dst"),
                        "ethtype": "0x0800"
                    }),
                })

        @classmethod
        def base_on_mpls_traffic_profile(
                cls,
                outer_key: dict = None,
                inner_key: dict = None,
                mpls_udp_encap: dict = None,
                mpls_label: int = None,
                modify_l2_src: str = None,
                modify_l2_dst: str = None,
                **params) -> 'Flow':
            flow: dict[str, Any] = {**params, 'key_port_id': IgnoredKey(),
                                    'target_port_id': IgnoredKey()}
            if outer_key is not None:
                if isinstance(outer_key, Packet):
                    flow["outer_key"] = SimpleKey.base_on_packet(
                        packet=outer_key)
                else:
                    flow["outer_key"] = SimpleKey.base_on_traffic(outer_key)
            if inner_key is not None:
                if isinstance(inner_key, Packet):
                    flow["inner_key"] = SimpleKey.base_on_packet(
                        packet=inner_key)
                else:
                    flow["inner_key"] = SimpleKey.base_on_traffic(inner_key)
            if mpls_udp_encap is not None:
                flow["mpls_udp_encap"] = {}
                _mpls_label = mpls_udp_encap.get('mpls_label')
                if _mpls_label:
                    del mpls_udp_encap['mpls_label']
                flow["mpls_udp_encap"]["key"] = SimpleKey.base_on_traffic(
                    traffic_definition=mpls_udp_encap)
                flow["mpls_udp_encap"]["mpls_label"] = _mpls_label
            if mpls_label is not None:
                flow.update({"mpls_label": mpls_label})
            if modify_l2_src is not None:
                if mpls_label is not None:
                    flow["l2_change"] = L2Insert({
                        "hdr": EthHeader({
                            "mac_src": modify_l2_src,
                            "mac_dst": modify_l2_dst,
                            "ethtype": "0x0800"
                        }),
                    })
                else:
                    flow["l2_change"] = L2Change({
                        "hdr": EthHeader({
                            "mac_src": modify_l2_src,
                            "mac_dst": modify_l2_dst,
                            "ethtype": "0x0800"
                        }),
                    })
            _final_flow = cls(flow)
            LOGGER.debug(f"Flow base on traffic profile:\n {_final_flow}")
            return _final_flow

        @classmethod
        def base_on_json_flow(cls, json_flow: dict) -> 'Flow':
            ret = cls()
            ret.key_port_id = json_flow["key"]["in_port"]
            ret.outer_key = SimpleKey.base_on_json(json_flow["key"])
            if json_flow["key"].get("tunnel", None) is not None:
                ret.inner_key = ret.outer_key
                ret.outer_key = SimpleKey()
                ret.mpls_label = json_flow["key"]["tunnel"]["MPLSoUDP"]["label"]
                ret.outer_key.ip_src = json_flow["key"]["tunnel"]["ipv4"]["src"]
                ret.outer_key.ip_dst = json_flow["key"]["tunnel"]["ipv4"]["dst"]

            if json_flow["action"]["type"] == "drop":
                ret.drop = True
                return ret
            if json_flow["action"].get("vlan") is not None:
                vlan_types = {
                    "none": 0,
                    "insert": 1,
                    "modify": 2,
                    "strip": 3,
                }
                ret.vlan = vlan_types[json_flow["action"]["vlan"]["type"]]
                if json_flow["action"]["vlan"]["type"] != "strip":
                    ret.vlan_tci = [json_flow["action"]["vlan"]
                                    ["vid"], json_flow["action"]["vlan"]["pcp"]]
            ret.target_port_id = json_flow["action"]["out_port"]
            ret.decr_ttl = json_flow["action"].get("decr_ttl", False)
            if json_flow["action"].get("modified_l2") is not None:
                ret.l2_change = (
                    L2Change.base_on_json(json_flow["action"]["modified_l2"]))
            elif json_flow["action"].get("inserted_l2") is not None:
                ret.l2_change = (
                    L2Insert.base_on_json(json_flow["action"]["inserted_l2"]))
            elif json_flow["action"].get("strip_l2", False) is True:
                ret.l2_change = L2Strip({})
            if json_flow["action"]["type"] == "MPLSoUDP":
                ret.mpls_udp_encap = {}
                ret.mpls_udp_encap["key"] = (
                    SimpleKey.base_on_json(json_flow["action"]))
                ret.mpls_udp_encap["mpls_label"] = (
                    json_flow["action"]["MPLSoUDP"]["label"])

            return ret

        def __eq__(self, other):
            return _compare_with_ignore(self, other)

        def __str__(self):
            return f'{vars(self)}'

        def __repr__(self):
            return f'Flow({vars(self)})'

        def _serialize(self) -> list[str]:
            return [f"{k}: {v}" for k, v in vars(self).items() if v is not None]

        def create_ingress_template(self) -> 'Flow':
            flow_tmplt = deepcopy(self)
            if (flow_tmplt.outer_key is not None
                    and flow_tmplt.inner_key is not None):
                flow_tmplt.outer_key.mac_src = IgnoredKey()
                flow_tmplt.outer_key.mac_dst = IgnoredKey()
                flow_tmplt.outer_key.l4_port_src = IgnoredKey()
                flow_tmplt.outer_key.l4_port_dst = IgnoredKey()
                flow_tmplt.outer_key.l4_proto = IgnoredKey()
            else:
                raise FlowError(
                    "Ingress flows should have both inner and outer key defined")
            return flow_tmplt

        def to_pkt(flow) -> Packet:
            if (isinstance(flow.outer_key, SimpleKey) and
                    (flow.inner_key is None)):
                return flow.outer_key.to_pkt()
            elif (isinstance(flow.outer_key, SimpleKey) and
                  isinstance(flow.inner_key, SimpleKey)):
                outer_layers = flow.outer_key.to_pkt()
                inner_layers = flow.inner_key.to_pkt()
                encap_layer = None

                if flow.mpls_label is not None:
                    encap_layer = MPLS(label=flow.mpls_label)
                elif flow.vxlan_vni is not None:
                    encap_layer = VXLAN(vni=flow.vxlan_vni)
                else:
                    return None

                return outer_layers / encap_layer / inner_layers

            return None