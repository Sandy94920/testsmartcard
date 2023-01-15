""" This script has to be compatible with python 3.6 """
import logging.handlers
from time import sleep
from typing import Union, Optional
from scapy.all import (
    DNS,
    DNSQR,
    DNSRR,
    IP,
    IPv6,
    send,
    AsyncSniffer,
    sr1,
    UDP)

from logging_tools import add_socket_handler
from service_scapy import is_ipv6_address

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)


class Client:
    def __init__(self,
                 dns_server_ip: str,
                 iface: str,
                 nb_pkts: int = 1,
                 log_handler_host: Optional[str] = None,
                 log_handler_port: Optional[int] = None):
        add_socket_handler(LOGGER, log_handler_host, log_handler_port)
        self.dns_server_ip = dns_server_ip
        self.iface = iface
        self.nb_pkts = nb_pkts

    def request_url(self, url: str) -> Union[bool, str]:
        ip_header = IPv6 if is_ipv6_address(self.dns_server_ip) else IP

        dns_req = (
            ip_header(dst=self.dns_server_ip) /
            UDP(dport=53) /
            DNS(rd=1, qd=DNSQR(qname=url)))
        answer = sr1(dns_req*self.nb_pkts,
                     verbose=1,
                     timeout=2,
                     iface=self.iface)
        LOGGER.info(f"Getting {url} from DNS client.")
        if answer is not None:
            return answer[DNSQR].qname.decode()
        return False


class Server:
    def __init__(self,
                 dns_server_ip: str,
                 url: str = "smartnic.test.dns.com",
                 iface: str = "lo",
                 log_handler_host: str = None,
                 log_handler_port: int = None,
                 bpf_filter: str = None,
                 dns_udp_port: int = 53):
        add_socket_handler(LOGGER, log_handler_host, log_handler_port)
        self.iface = iface
        self.dns_server_ip = dns_server_ip
        self.bpf_filter = (
            bpf_filter if bpf_filter is not None else
            f"udp port {dns_udp_port} and ip dst {dns_server_ip}")
        self.url = url
        self.dns_udp_port = dns_udp_port
        self.dns_server: AsyncSniffer = self.main()

    def _forward_dns(self, orig_pkt: Union[IP, IPv6]):
        LOGGER.info(f"Forwarding: {orig_pkt[DNSQR].qname}")

        is_ipv6 = is_ipv6_address(orig_pkt)
        ip_header = IPv6 if is_ipv6 else IP
        ip = IPv6(dst='2001:4860:4860::8888') if is_ipv6 else IP(dst='8.8.8.8')

        response = sr1((
            ip /
            UDP(sport=orig_pkt[UDP].sport) /
            DNS(rd=1, id=orig_pkt[DNS].id,
                qd=DNSQR(qname=orig_pkt[DNSQR].qname))
        ), verbose=0)
        resp_pkt = (
            ip_header(dst=orig_pkt[IP].src, src=self.dns_server_ip) /
            UDP(dport=orig_pkt[UDP].sport) /
            DNS())
        resp_pkt[DNS] = response[DNS]
        send(resp_pkt, verbose=0)
        return f"Responding to {orig_pkt[ip_header].src}"

    def _get_response(self, pkt: Union[IP, IPv6]):
        ip_header = IPv6 if is_ipv6_address(pkt) else IP

        if (DNS in pkt and pkt[DNS].opcode == 0 and
                pkt[DNS].ancount == 0):
            if self.url in str(pkt["DNS Question Record"].qname):
                spf_resp = (
                    ip_header(dst=pkt[ip_header].src) /
                    UDP(dport=pkt[UDP].sport, sport=self.dns_udp_port) /
                    DNS(id=pkt[DNS].id,
                        ancount=1,
                        an=(DNSRR(rrname=pkt[DNSQR].qname,
                                  rdata=self.dns_server_ip) /
                            DNSRR(rrname="", rdata=self.dns_server_ip))))
                send(spf_resp, verbose=0, iface=self.iface)
                return f"Spoofed DNS Response Sent: {pkt[ip_header].src}"
            return self._forward_dns(pkt)

    def kill(self) -> None:
        LOGGER.info(
            f"Try stop DNS server in {self.dns_server_ip} host")
        output = self.dns_server.stop()
        LOGGER.info(f"Response from DNS server {output}")

    def main(self) -> AsyncSniffer:
        LOGGER.info("Try to start DNS server")
        _async_sniff = AsyncSniffer(filter=self.bpf_filter,
                                    prn=self._get_response,
                                    iface=self.iface)
        _async_sniff.start()
        sleep(5)
        LOGGER.info("Started DNS server")
        return _async_sniff

    def __resp__(self):
        return self.dns_server