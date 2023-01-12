import logging
from time import sleep
from ast import literal_eval
from random import randint
from typing import NamedTuple, TYPE_CHECKING, Any, Optional

import inspect
import scapy
from scapy.base_classes import Packet_metaclass
from scapy.contrib.mpls import MPLS
from scapy.layers.inet import TCP, UDP, IP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.layers.sctp import SCTP
from scapy.main import load_contrib
from scapy.packet import Packet, Raw
from scapy.volatile import RandString

from lib.utils import get_content
from lib.connections.daemon_hubs import async_rpyc

if TYPE_CHECKING:
    from lib.daemon.daemon_hub import DaemonHub
    from lib.daemon.service_scapy import Sniffer, TrafficSender
    from lib.daemon.service_tcp import TcpServer, TcpClient
    from rpyc import AsyncResult

LOGGER = logging.getLogger(__name__)
# DCCP could be added here also if needed
TRANSPORT_LAYERS = [TCP, UDP, SCTP]


def get_random_string(length: int) -> str:
    numbers = [randint(ord('0'), ord('9')) for x in range(length)]
    chars = [chr(x) for x in numbers]
    return ''.join(chars)


class ErrorPacketStreamLib(Exception):
    pass


class ErrorPacketStructure(Exception):
    pass


class SendPacketResults(NamedTuple):
    packets_sent: int = 0
    sum_len: int = 0
    sum_len_l2: int = 0
    response: bool = False


def reverse_pkt(pkt: Packet) -> Packet:
    """
        reverse given packet and return it
    """
    packet_structure = PacketStructure(pkt)
    result_packet = PacketStructure(pkt)
    if pkt.haslayer(Ether):
        result_packet.smac = packet_structure.dmac
        result_packet.dmac = packet_structure.smac
    result_packet.ip_src = packet_structure.ip_dst
    result_packet.ip_dst = packet_structure.ip_src
    if packet_structure.highest_protocol_layer in ["UDP", "TCP"]:
        result_packet.sport = packet_structure.dport
        result_packet.dport = packet_structure.sport
    return result_packet.packet_copy


def calc_statistic_packets(
        all_pkts_stats_vrouter_pre: dict[str, tuple[int, ...]],
        all_pkts_stats_vrouter_post: dict[str, tuple[int, ...]],
        type_transfer: str,
        type_of_get_data: str) -> int:
    if type_of_get_data == "bytes":
        get_data_vrouter = 1
    elif type_of_get_data == "packets":
        get_data_vrouter = 0
    else:
        raise ErrorPacketStreamLib(
            f"Incorrectly type_of_get_data {type_of_get_data}")

    diff_nb_captured_vrouter_pkts = (
            all_pkts_stats_vrouter_post[type_transfer][get_data_vrouter] -
            all_pkts_stats_vrouter_pre[type_transfer][get_data_vrouter])

    LOGGER.info(
        f"diff_nb_captured_vrouter_pkts: {diff_nb_captured_vrouter_pkts}")
    return diff_nb_captured_vrouter_pkts


def check_drop_statistics_pkts(
        all_drops_stats_vrouter_pre: dict[str, Any],
        all_drops_stats_vrouter_post: dict[str, Any]
        ) -> int:
    drops_pre: int = all_drops_stats_vrouter_pre["drops"]
    drops_post: int = all_drops_stats_vrouter_post["drops"]
    return drops_post - drops_pre


def calc_statistic_error_pkts(
        all_error_stats_vrouter_pre: dict[str, Any],
        all_error_stats_vrouter_post: dict[str, Any],
        expected_nb_of_error_pkts: int,
        type_transfer: str):
    drops_pre = all_error_stats_vrouter_pre[type_transfer][2]
    drops_post = all_error_stats_vrouter_post[type_transfer][2]

    return True if drops_post == (
            drops_pre + expected_nb_of_error_pkts) else False


class PacketStructure:
    def __init__(self, packet: Packet):
        self._packet = packet.copy()
        LOGGER.debug(f"SCAPY VERSION:{scapy.VERSION}")
        LOGGER.debug(inspect.getfile(self._packet.__class__))
        LOGGER.debug(f"packet:{self._packet.command() if packet else None}")
        LOGGER.debug(
            f"self._packet:{self._packet.command() if self._packet else None}")

    def get_params_dict(self) -> dict[str, str]:
        params = ["ip_src", "ip_dst", "sport", "dport", "smac", "dmac"]
        result_dict = {"proto": self.highest_protocol_layer.lower()}
        for param in params:
            try:
                result_dict[param] = self.__getattribute__(param)
            except ErrorPacketStructure:
                LOGGER.debug(f"Trying to get {param} from packet "
                             f"{self._packet.command()}")
        return result_dict

    def raise_for_no_layer(self, layer: Packet_metaclass):
        if not self._packet.haslayer(layer):
            raise ErrorPacketStructure(
                f"Cant get {layer.name} layer in packet:\n"
                f"{self._packet.show()}")

    def assert_has_any_layer(self, layers: list[Packet_metaclass]):
        LOGGER.debug(f"PACKET LAYERS: {self._packet.layers()}")
        LOGGER.debug(f"LAYERS: {layers}")
        if not any([self._packet.haslayer(layer) for layer in layers]):
            raise ErrorPacketStructure(
                f"Cant get {[layer.name for layer in layers]} layer in packet:"
                f"\n{self._packet.show()}")

    @property
    def packet_copy(self) -> Packet:
        return self._packet.copy()

    @property
    def ip_src(self) -> str:  # type: ignore
        self.assert_has_any_layer([IP, IPv6])
        if IP in self._packet:
            return self._packet[IP].src
        elif IPv6 in self._packet:
            return self._packet[IPv6].src

    @ip_src.setter
    def ip_src(self, src: str):
        self.assert_has_any_layer([IP, IPv6])
        if IP in self._packet:
            self._packet[IP].src = src
        elif IPv6 in self._packet:
            self._packet[IPv6].src = src

    @property
    def ip_dst(self) -> str:  # type: ignore
        self.assert_has_any_layer([IP, IPv6])
        if IP in self._packet:
            return self._packet[IP].dst
        elif IPv6 in self._packet:
            return self._packet[IPv6].dst

    @ip_dst.setter
    def ip_dst(self, dst: str):
        self.assert_has_any_layer([IP, IPv6])
        if IP in self._packet:
            self._packet[IP].dst = dst
        elif IPv6 in self._packet:
            self._packet[IPv6].dst = dst

    @property
    def smac(self) -> str:
        self.raise_for_no_layer(Ether)
        return self._packet[Ether].src

    @smac.setter
    def smac(self, src: str):
        self.raise_for_no_layer(Ether)
        self._packet[Ether].src = src

    @property
    def dmac(self) -> str:
        self.raise_for_no_layer(Ether)
        return self._packet[Ether].dst

    @dmac.setter
    def dmac(self, dst: str):
        self.raise_for_no_layer(Ether)
        self._packet[Ether].dst = dst

    @property
    def sport(self) -> str:
        self.assert_has_any_layer(TRANSPORT_LAYERS)
        return self._packet.sport

    @sport.setter
    def sport(self, sport: str):
        self.assert_has_any_layer(TRANSPORT_LAYERS)
        self._packet.sport = sport

    @property
    def dport(self) -> str:
        self.assert_has_any_layer(TRANSPORT_LAYERS)
        return self._packet.dport

    @dport.setter
    def dport(self, dport: str):
        self.assert_has_any_layer(TRANSPORT_LAYERS)
        self._packet.dport = dport

    @property
    def highest_protocol_layer(self) -> str:
        def recursive_payload_layer(packet: Packet) -> str:
            if not packet.payload or isinstance(packet.payload, Raw):
                if packet.name == 'ICMPv6 Echo Request':
                    return 'icmp6'
                return packet.name
            else:
                return recursive_payload_layer(packet.payload)
        return recursive_payload_layer(self._packet)

    def build_mpls_pkt(self, ip_src, ip_dst):
        load_contrib("mpls")
        mpls_eth = Ether(type=0x8847)
        mpls_lables = (MPLS(label=16, s=0, ttl=255)
                       / MPLS(label=18, s=0, ttl=255)
                       / MPLS(label=18, s=0, ttl=255)
                       / MPLS(label=16, s=1, ttl=255))
        mpls_ip = IP(src=ip_src, dst=ip_dst)
        return mpls_eth / mpls_lables / mpls_ip

    def update_packet_payload(self, token: str):
        self._packet.load = ''.join([token, str(RandString(size=2))]).encode()

    def resize_packet(self, pkt_size: int):
        if not self._packet.haslayer(Raw):
            self._packet = self._packet / Raw()
        pkt_len = len(self._packet if self._packet.haslayer(Ether)
                      else Ether() / self._packet)
        if pkt_len > pkt_size:
            raise ErrorPacketStructure(
                "Reduce packet not supported. Consider packet payload change "
                "(token) to fit the size, or increase packet_size.\n"
                f"current_size:{pkt_len}\nexpected size: {pkt_size}\n"
                f"Full packet:\n {self._packet.show()}")
        self._packet.load = self._packet.load + (b"X" * (pkt_size - pkt_len))


class TrafficGenerator:
    def __init__(self,
                 sender_hub: 'DaemonHub' = None,
                 sniffer_hub: 'DaemonHub' = None):
        self.sender_hub = sender_hub
        self.sniffer_hub = sniffer_hub

    def send_packet(self, interface: str, packet: Packet, num_pkt: int = 1,
                    pkt_size: int = 0, token: str = "", resp: bool = False,
                    fuzz: bool = False) -> SendPacketResults:
        sender = StandaloneSender(self.sender_hub, interface)
        result = sender.send_packet(packet, num_pkt, pkt_size, interval=0.001,
                                    token=token, resp=resp, fuzz=fuzz)
        LOGGER.debug(result)
        return result

    def transfer_packets_between_vms(
            self, sender_iface: str, packet: Packet, num_pkt: int,
            pkt_size: int = 64, fuzz: bool = False, second_iface: str = None,
            token: str = "") -> tuple[int, int, int]:
        pkt_to_send = packet.copy()
        if packet.haslayer(Ether):
            pkt_to_send = pkt_to_send.payload
        packet_structure = PacketStructure(packet)
        token = token or get_random_string(length=8)
        if not second_iface:
            second_iface = sender_iface
        bpf_header_name = 'ip6' if packet.haslayer(IPv6) else 'ip'
        sniffer = StandaloneSniffer(
            self.sniffer_hub, packet_structure.ip_src,
            bpf_header_name, second_iface, num_pkt,
            packet_structure.highest_protocol_layer, token=token)
        sniffer.start()
        send_result = self.send_packet(sender_iface, pkt_to_send,
                                       num_pkt=num_pkt,
                                       pkt_size=pkt_size,
                                       token=token,
                                       fuzz=fuzz)
        recv_counter_pkt, received_payload_len = sniffer.dump()

        return send_result.sum_len, recv_counter_pkt, received_payload_len

    def insert_flow(self, interface: str, packet: Packet) -> None:
        self.send_packet(interface, packet, num_pkt=1)
        sleep(1)


class TcpSession:
    def __init__(self,
                 tcp_client_hub: 'DaemonHub',
                 tcp_server_hub: 'DaemonHub',
                 interface: str,
                 packet: Packet,
                 timeout_response: int = 1,
                 timeout_server: int = 10,
                 nb_pkts_syn: int = 1,
                 num_pkt_of_payload: int = 1,
                 payload: Optional[str] = None,
                 server_count_pkts: int = 1,
                 packet_size: int = 0,
                 listen_bind_interface_addr: Optional[str] = None):
        self._tcp_client_hub = tcp_client_hub
        self._tcp_server_hub = tcp_server_hub
        packet_structure = PacketStructure(packet)
        self._ip_src = packet_structure.ip_src
        self._ip_dst = packet_structure.ip_dst
        self._sport = packet_structure.sport
        self._dport = packet_structure.dport
        self._interface = interface
        self._nb_pkts_syn = nb_pkts_syn
        self._num_pkt_of_payload = num_pkt_of_payload
        self._payload = payload or get_random_string(length=8)
        self._server_count_pkts = server_count_pkts
        self._timeout_response = timeout_response
        self._timeout_server = timeout_server
        self._packet_size = packet_size
        self._listen_bind_interface_addr = listen_bind_interface_addr
        self._tcp_client: 'TcpClient' = None
        self._tcp_server_listen: 'TcpServer' = None

    def __enter__(self) -> tuple['TcpClient', 'TcpServer']:
        return self._get_session()

    def __exit__(self,  exc_type, exc_val, exc_tb):
        self._tcp_client.send_fin()
        self._tcp_client.send_last_ack()
        LOGGER.info(f"Server output: {dict(self._tcp_server_listen.value)}")

    def _start_server(self) -> 'TcpServer':
        return self._tcp_server_hub.run_tcp_server(
            server_addr=(self._ip_dst if
                         self._listen_bind_interface_addr is None
                         else self._listen_bind_interface_addr),
            listen_port=self._dport,
            count_pkts=self._server_count_pkts,
            timeout_server=self._timeout_server)

    def _start_client(self) -> 'TcpClient':
        return self._tcp_client_hub.get_tcp_client(
            ip_src=self._ip_src,
            ip_dst=self._ip_dst,
            src_port=self._sport,
            dst_port=self._dport,
            interface=self._interface,
            packet_size=self._packet_size,
            num_pkt_of_payload=self._num_pkt_of_payload,
            payload=self._payload,
            nb_pkts_syn=self._nb_pkts_syn,
            timeout=self._timeout_response)

    def _get_session(self) -> tuple['TcpClient', 'TcpServer']:
        tcp_server = self._start_server()
        self._tcp_server_listen = async_rpyc(tcp_server.listen)()
        sleep(1)
        self._tcp_client = self._start_client()
        return self._tcp_client, self._tcp_server_listen


def get_dump_of_output_sniffer(stderr, stdout):
    stderr = get_content(stderr).split()
    if stderr:
        raise ErrorPacketStreamLib(" ".join(stderr))
    else:
        for line in get_content(stdout).split('\n'):
            if line.startswith("(") and line.endswith(")"):
                recv_counter_pkt, received_payload_len = literal_eval(line)
                LOGGER.info(
                    f'Received payload len {received_payload_len} bytes and'
                    f'count pkt: {recv_counter_pkt}')
            elif line.startswith("[sniff]"):
                LOGGER.info(line)
    try:
        return recv_counter_pkt, received_payload_len
    except UnboundLocalError:
        LOGGER.error(
            f'Output returned by the sniffer daemon did not contain expected'
            f'data. Output: {get_content(stdout)}')
        return 0, 0


class StandaloneSniffer:
    def __init__(self,
                 sniffer_hub: 'DaemonHub',
                 ip_src: str,
                 ip_version: str,
                 interface: str,
                 num_pkt: int,
                 proto: str,
                 token: str = None,
                 timeout: int = 10):
        self.sniffer: 'Sniffer' = sniffer_hub.get_sniffer(
            ip_src, proto, ip_version=ip_version, interface=interface,
            num_pkt=num_pkt, token=token, timeout=timeout)
        self._output: 'AsyncResult' = None

    def start(self) -> None:
        self._output = async_rpyc(self.sniffer.start_sniff)()
        sleep(2)

    def dump(self) -> tuple[int, int]:
        return self._output.value


class StandaloneSender:
    def __init__(self, sender_hub: 'DaemonHub', interface: str):
        self.sender: 'TrafficSender' = sender_hub.get_traffic_sender(interface)

    def send_packet(
            self, packet: Packet, num_pkt: int = 1, pkt_size: int = 64,
            interval: float = 0.001, fuzz: bool = False,
            resp: bool = False, token: str = "") -> SendPacketResults:
        LOGGER.debug(f"Getting send method for packet: {packet.command()}")
        if packet.haslayer(Ether):
            if resp:
                return SendPacketResults(
                    response=self.sender.send_l2_and_response(packet.command(),
                                                              interval))
            else:
                return SendPacketResults(packets_sent=self.sender.send_pkt_l2(
                    packet.command(), num_pkt, pkt_size, interval, token))
        else:
            sum_len, sum_len_l2 = self.sender.send_pkt(
                packet.command(), num_pkt, pkt_size, interval, token, fuzz)
            return SendPacketResults(sum_len=sum_len, sum_len_l2=sum_len_l2)