""" This script has to be compatible with python 3.6 """
import logging
import socket
from random import randrange
from typing import Union, Optional, Dict
from scapy.all import (
    TCP,
    sr1,
    send,
    IP,
    IPv6,
    Raw,
    Ether,
    sr,
    Packet
)

from logging_tools import add_socket_handler
from service_scapy import is_ipv6_address

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)

BUFFER_SIZE = 1024


class ErrorServiceTcp(Exception):
    pass


class TcpServer:
    def __init__(self,
                 server_addr: str,
                 listen_port: int,
                 count_pkts: int,
                 timeout_server: int,
                 log_handler_host: Optional[str] = None,
                 log_handler_port: Optional[int] = None,
                 buffer_size: int = 1024):
        add_socket_handler(LOGGER, log_handler_host, log_handler_port)
        self.connected: bool = False
        self.buffer_size = buffer_size
        self.server_addr = server_addr
        self.listen_port = int(listen_port)
        self.count_pkts = count_pkts
        self.timeout_server = timeout_server
        self.server_connected: socket.socket = self.connect()

    def connect(self) -> socket.socket:
        LOGGER.info(
            f"Initialize connection to {self.server_addr}:{self.listen_port}")

        is_ipv6 = is_ipv6_address(self.server_addr)
        af_inet = socket.AF_INET6 if is_ipv6 else socket.AF_INET

        address_info = socket.getaddrinfo(
            self.server_addr, self.listen_port, af_inet)[0][-1]

        server = socket.socket(af_inet, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.settimeout(self.timeout_server)
        server.bind(address_info)
        LOGGER.info("Connection initialized")
        return server

    def listen(self) -> Dict[str, int]:
        received_pkts = 0
        sum_len_of_payload = 0
        try:
            LOGGER.info("Start listen")
            self.server_connected.listen(1)
            connection, client_address = self.server_connected.accept()
            LOGGER.info(f"Client: {client_address}")
            while True:
                payload = connection.recv(BUFFER_SIZE)
                if payload:
                    received_pkts += 1
                    sum_len_of_payload += len(payload)
                else:
                    break
            LOGGER.info("End listen")
            connection.close()
        except socket.timeout:
            LOGGER.warning("No packets received within allowed timeout")
            pass
        return {
            "packets": received_pkts,
            "payload_bytes": sum_len_of_payload}


class TcpClient:
    def __init__(self,
                 ip_src: str,
                 ip_dst: str,
                 dst_port: int,
                 src_port: int,
                 interface: str,
                 num_pkt_of_payload: int = 1,
                 payload: str = "",
                 packet_size: int = 0,
                 nb_pkts_syn: int = 1,
                 timeout: int = 1,
                 log_handler_host: Optional[str] = None,
                 log_handler_port: Optional[int] = None):
        add_socket_handler(LOGGER, log_handler_host, log_handler_port)
        self.packet_size = packet_size
        self.num_pkt_of_payload = num_pkt_of_payload
        self.payload = payload
        self.ip_src = ip_src
        self.ip_dst = ip_dst
        self.dst_port = int(dst_port)
        self.src_port = int(src_port)
        self.interface = interface
        self.nb_pkts_syn = nb_pkts_syn
        self.seq_num = randrange(0, 2 ** 32)
        self.ip: Union[IP, IPv6] = None
        self.synack: Packet = None
        self.ack_num: int = 0
        self.ack: Packet = None
        self.finack: Packet = None
        self.timeout = timeout

    def resize_packet(self, packet: Packet) -> Packet:
        pkt_len = len(packet)
        if pkt_len >= self.packet_size:
            return packet / self.payload
        return packet / ("X" * (self.packet_size - pkt_len))

    def build_pkt_payload(self):
        for pkt in range(self.num_pkt_of_payload):
            push_data_pkt = self.ip / TCP(
                sport=self.src_port, dport=self.dst_port, flags="PA",
                seq=self.seq_num, ack=self.ack_num)
            push_data_pkt = self.resize_packet(packet=push_data_pkt)
            self.seq_num += len(push_data_pkt[Raw])
            self.payload = str(int(self.payload) + 1)
            yield push_data_pkt

    def send_data(self) -> Packet:
        # interval and timeout prevent del sniffer before recv all responses
        sniff_timeout = 10
        interval = 0.001
        push_data_pkt = self.build_pkt_payload()
        return sr(push_data_pkt, timeout=sniff_timeout, iface=self.interface,
                  inter=interval, verbose=1)

    def run_handshake(self) -> None:
        self.send_syn()
        self.send_ack()
        LOGGER.info("Session established")
        self.send_data()
        self.send_fin()
        self.send_last_ack()
        LOGGER.info("Disconnected")

    def send_syn(self) -> None:
        ip_header = IPv6 if is_ipv6_address(self.ip_src) else IP

        self.ip = ip_header(src=self.ip_src, dst=self.ip_dst)
        syn = TCP(sport=self.src_port, dport=self.dst_port, flags="S",
                  seq=self.seq_num)
        LOGGER.info("Sending SYN")
        synack = sr1(self.ip / syn * self.nb_pkts_syn, iface=self.interface,
                     timeout=self.timeout, verbose=0)
        self.seq_num += 1
        try:
            self.ack_num = synack[TCP].seq + 1
        except TypeError:
            raise ErrorServiceTcp("No response to sent SYN flag")
        else:
            LOGGER.info(f"Sent SYN len {len(Ether() / self.ip / syn)}")
            if not synack[TCP].flags & 0x12 == 0x12:
                raise ErrorServiceTcp("SYNACK response was incorrect")
            self.synack = synack

    def send_ack(self) -> None:
        ack = TCP(sport=self.src_port, dport=self.dst_port, flags="A",
                  seq=self.seq_num, ack=self.ack_num)
        LOGGER.info("Sending ACK")
        sr1(self.ip / ack, iface=self.interface, verbose=0,
            timeout=self.timeout)
        LOGGER.info(f"Sent ACK len {len(Ether() / self.ip / ack)}")
        self.ack = ack

    def send_fin(self) -> None:
        fin = self.ip / TCP(sport=self.src_port, dport=self.dst_port,
                            flags="FA", seq=self.seq_num, ack=self.ack_num)
        LOGGER.info("Sending FIN")
        finack = sr1(fin, iface=self.interface, verbose=0,
                     timeout=self.timeout)
        self.seq_num += 1
        try:
            self.ack_num = finack[TCP].seq + 1
        except TypeError:
            LOGGER.info("No response for send finack seq")
        else:
            LOGGER.info("Sent FIN")
            self.finack = finack

    def send_last_ack(self) -> Packet:
        lastack = self.ip / TCP(sport=self.src_port, dport=self.dst_port,
                                flags="A", seq=self.seq_num, ack=self.ack_num)
        LOGGER.info("Sending last ACK")
        send(lastack, iface=self.interface, verbose=0)
        LOGGER.info("Sent last ACK")
        return lastack