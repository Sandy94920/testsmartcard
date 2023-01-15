""" This script has to be compatible with python 3.6 """
import logging
from random import randint
from ipaddress import ip_address
from typing import Optional, Callable, Tuple

from scapy.error import Scapy_Exception
from scapy.layers.dhcp import BOOTP, DHCP                     # noqa: F401
from scapy.layers.inet import TCP, ICMP, UDP, IP              # noqa: F401
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest        # noqa: F401
from scapy.contrib.mpls import MPLS                           # noqa: F401
from scapy.layers.l2 import ARP, Ether, Dot1Q                 # noqa: F401
from scapy.layers.sctp import SCTP
from scapy.packet import Packet, fuzz, Raw
from scapy.sendrecv import sniff, send, sendp, srp
from scapy.volatile import RandString

from logging_tools import add_socket_handler

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)

PROTO_PKT = {
    'tcp': TCP,
    'udp': UDP,
    'icmp': ICMP,
    'icmp6': ICMPv6EchoRequest,
    'sctp': SCTP,
    'arp': ARP,
    'dhcp': DHCP
}


def is_ipv6_address(address: str) -> bool:
    if ip_address(address).version == 6:
        return True
    return False


def has_icmpv6_layer(packet: Packet) -> bool:
    if packet.haslayer(ICMPv6EchoRequest):
        return True
    return False


class Sniffer:
    def __init__(self,
                 ip_source: str,
                 protocol: str,
                 iface_name: Optional[str],
                 number_of_pkt: int,
                 timeout: int,
                 ip_version: str,
                 token: str = None,
                 log_handler_host: Optional[str] = None,
                 log_handler_port: Optional[int] = None):
        add_socket_handler(LOGGER, log_handler_host, log_handler_port)
        self.ip_source = ip_source
        self.protocol = protocol.lower()
        self.number_of_pkt = number_of_pkt
        self.token = token
        self.iface_name = iface_name
        self.timeout = timeout
        self.filter_host: str = ' '.join(
            [self.protocol, 'and', ip_version, 'src', 'host', self.ip_source])

    @staticmethod
    def _lfilter_for_protocol(token: str) -> Callable:
        token_bytes = token.encode()

        def lfilter(pkt):
            try:
                if has_icmpv6_layer(pkt):
                    pkt_data = pkt[ICMPv6EchoRequest].data[:len(token_bytes)]
                    return pkt_data == token_bytes
                return pkt.load[:len(token_bytes)] == token_bytes
            except AttributeError:
                return None

        return lfilter

    @staticmethod
    def _get_payload(pkt):
        icmpv6_pkt = has_icmpv6_layer(pkt)
        try:
            if icmpv6_pkt:
                return pkt[ICMPv6EchoRequest].data
            return pkt.load
        except AttributeError:
            return ''

    def _search_pkt_stream(self):
        recv_pkt = [_ for _ in sniff(
            iface=self.iface_name,
            filter=self.filter_host,
            lfilter=(
                self._lfilter_for_protocol(self.token) if self.token else None),
            count=self.number_of_pkt,
            timeout=20)]
        protocol_payloads = [
            self._get_payload(p) for p in recv_pkt]
        LOGGER.debug(f"Sniffed packets: {protocol_payloads}")

        length_payload = sum(map(len, protocol_payloads))
        number_of_pkt = len(recv_pkt)

        return number_of_pkt, length_payload

    def start_sniff(self) -> Tuple[int, int]:
        LOGGER.info(
            f"Start sniffing interface: {self.iface_name},"
            f"protocol: {self.protocol}, ip_source: {self.ip_source}")
        try:
            number_of_pkt, length_payload = self._search_pkt_stream()
            LOGGER.info(f"End sniffing {self.ip_source}")
            return number_of_pkt, length_payload
        except Scapy_Exception as e:
            LOGGER.error(
                f"Scappy's sniff has failed. Error: {e}", exc_info=True)
            return 0, 0


class TrafficSender:
    def __init__(self, iface: str, log_handler_host: Optional[str] = None,
                 log_handler_port: Optional[int] = None):
        add_socket_handler(LOGGER, log_handler_host, log_handler_port)
        self.interface = iface
        self.rand_ports: bool = False
        self.sum_length_pkt: int = 0
        self.sum_length_pkt_l2: int = 0
        self.pkt_counter: int = 0

    @staticmethod
    def add_token_to_payload(token: str):
        return ''.join([token, str(RandString(size=3))]).encode()

    def increase_counter_size_packets(self, data, cnt=1):
        if has_icmpv6_layer(data):
            self.sum_length_pkt += cnt * len(data[ICMPv6EchoRequest].data)
        else:
            self.sum_length_pkt += cnt * len(data.load)
        self.sum_length_pkt_l2 += cnt * len(Ether() / data)

    def add_ports(self, proto_layer: Packet):
        if proto_layer.haslayer(ICMP) or has_icmpv6_layer(proto_layer):
            return proto_layer
        if proto_layer.sport == 0 or proto_layer.dport == 0:
            self.rand_ports = True

        source_port = (proto_layer.sport if proto_layer.sport
                       else randint(40000, 60000))
        destination_port = (proto_layer.dport if proto_layer.dport
                            else randint(40000, 60000))
        proto_layer[1].sport = (source_port + self.pkt_counter if
                                self.rand_ports else source_port)
        proto_layer[1].dport = (destination_port + self.pkt_counter
                                if self.rand_ports else destination_port)
        self.pkt_counter += 1
        return proto_layer

    def generator_pkt(self, packet: Packet, num_pkt: int = 1,
                      pkt_size: int = 64, token: str = "",
                      trigger_fuzz: bool = False):
        for i, pkt in enumerate(packet * num_pkt):
            if has_icmpv6_layer(pkt):
                pkt[ICMPv6EchoRequest].data = self.add_token_to_payload(token)
            else:
                pkt.load = self.add_token_to_payload(token)
            pkt = self.add_ports(proto_layer=pkt)
            # TODO: Refactor the resize_packet method to return constans
            # requested size
            pkt = self.resize_packet(packet=pkt, pkt_size=pkt_size)
            self.increase_counter_size_packets(pkt)
            if trigger_fuzz and i % 2:
                yield fuzz(pkt.copy())
            yield pkt

    def send_pkt(self, packet: str, num_pkt=1, pkt_size: int = 64,
                 interval=0.001, token: str = "", trigger_fuzz: bool = False
                 ) -> Tuple[int, int]:
        scapy_packet = eval(packet)
        obj_gen_pkt = self.generator_pkt(scapy_packet, num_pkt, pkt_size, token,
                                         trigger_fuzz)
        send(obj_gen_pkt, verbose=0, iface=self.interface,
             inter=interval)
        output = (self.sum_length_pkt, self.sum_length_pkt_l2)
        LOGGER.debug(f"Sending packet finished. Output: {output}")
        return output

    def send_pkt_l2(self, packet: str, num_pkt=1, pkt_size: int = 64,
                    interval=0.001, token: str = "") -> int:
        scapy_packet = eval(packet)
        if token:
            scapy_packet.add_payload(self.add_token_to_payload(token))
        scapy_packet = self.add_ports(scapy_packet)
        scapy_packet = self.resize_packet(scapy_packet, pkt_size)
        self.increase_counter_size_packets(scapy_packet.payload, num_pkt)
        LOGGER.info(
            f"Start sending {num_pkt} l2_pkt={scapy_packet.command()}")
        sendp(scapy_packet, verbose=False, count=num_pkt,
              iface=self.interface, inter=interval)
        LOGGER.info(f"End sending {num_pkt} l2_pkt "
                    f"with size: {pkt_size}")
        return num_pkt

    def send_l2_and_response(self, packet: str, interval=0.001):
        scapy_packet = eval(packet)
        LOGGER.info(f"Start sending l2_pkt with response: pkt={packet}")
        ans, unans = srp(scapy_packet, timeout=3, verbose=False,
                         iface=self.interface, inter=interval)
        LOGGER.info("End sending l2_pkt with response")
        return len(ans) > 0

    @staticmethod
    def resize_packet(packet, pkt_size):
        if not has_icmpv6_layer(packet) and not packet.haslayer(Raw):
            packet = packet / Raw()
        pkt_len = len(packet if packet.haslayer(Ether) else Ether() / packet)
        if pkt_len >= pkt_size:
            return packet
        if not has_icmpv6_layer(packet):
            packet.load = packet.load + (b"X" * (pkt_size - pkt_len))
        else:
            packet[ICMPv6EchoRequest].data = packet[ICMPv6EchoRequest].data + (
                    b"X" * (pkt_size - pkt_len))
        return packet