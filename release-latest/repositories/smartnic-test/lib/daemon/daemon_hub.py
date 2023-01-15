""" This script has to be compatible with python 3.6 """
import argparse
import logging.handlers
from typing import TYPE_CHECKING, List

import rpyc

from service_dns import Server as DnsServer, Client as DnsClient
from service_scapy import Sniffer, TrafficSender
from service_tcp import TcpServer, TcpClient
from service_tcpdump import Tcpdump
from logging_tools import (add_socket_handler, get_log_handler_host,
                           get_log_handler_port, is_any_socket_handler,
                           remove_socket_handlers)

if TYPE_CHECKING:
    from rpyc.utils.server import ThreadedServer

LOGGER = logging.getLogger(__name__)

__SERVERS_OBJ: List['ThreadedServer'] = []


def _local_shutdown_server():
    for _server in __SERVERS_OBJ:
        LOGGER.info(f"Attempting to close server {_server}")
        LOGGER.debug(f"clients: {_server.clients}")
        _server.close()
        LOGGER.info(f"Server {_server} closed")


class DaemonHub(rpyc.Service):
    @staticmethod
    def shutdown_server():
        _local_shutdown_server()

    @staticmethod
    def run_dns_server(iface: str, dns_server_ip: str, **params) -> DnsServer:
        return DnsServer(iface=iface, dns_server_ip=dns_server_ip,
                         log_handler_host=get_log_handler_host(LOGGER),
                         log_handler_port=get_log_handler_port(LOGGER),
                         **params)

    @staticmethod
    def get_dns_client(dns_server_ip: str, iface: str) -> DnsClient:
        return DnsClient(dns_server_ip=dns_server_ip, iface=iface,
                         log_handler_host=get_log_handler_host(LOGGER),
                         log_handler_port=get_log_handler_port(LOGGER))

    @staticmethod
    def run_tcp_server(
            server_addr: str,
            listen_port: int,
            count_pkts: int = 1,
            timeout_server: int = 10,
            **params) -> TcpServer:
        return TcpServer(
            server_addr=server_addr,
            listen_port=listen_port,
            count_pkts=count_pkts,
            timeout_server=timeout_server,
            log_handler_host=get_log_handler_host(LOGGER),
            log_handler_port=get_log_handler_port(LOGGER),
            **params)

    @staticmethod
    def get_tcp_client(
            ip_src: str,
            ip_dst: str,
            src_port: int,
            dst_port: int,
            interface: str,
            packet_size: int = 0,
            num_pkt_of_payload: int = 1,
            payload: str = "",
            nb_pkts_syn: int = 1,
            timeout: int = 1) -> TcpClient:
        return TcpClient(
            ip_src=ip_src,
            ip_dst=ip_dst,
            src_port=src_port,
            dst_port=dst_port,
            interface=interface,
            packet_size=packet_size,
            num_pkt_of_payload=num_pkt_of_payload,
            payload=payload,
            nb_pkts_syn=nb_pkts_syn,
            timeout=timeout,
            log_handler_host=get_log_handler_host(LOGGER),
            log_handler_port=get_log_handler_port(LOGGER))

    @staticmethod
    def get_sniffer(ip_src: str,
                    proto: str,
                    ip_version: str,
                    interface: str = None,
                    num_pkt: int = 1,
                    token: str = None,
                    timeout: int = 10) -> Sniffer:
        return Sniffer(
            ip_src, proto, interface, num_pkt,
            timeout, ip_version, token,
            log_handler_host=get_log_handler_host(LOGGER),
            log_handler_port=get_log_handler_port(LOGGER))

    @staticmethod
    def get_traffic_sender(interface: str) -> TrafficSender:
        return TrafficSender(interface,
                             log_handler_host=get_log_handler_host(LOGGER),
                             log_handler_port=get_log_handler_port(LOGGER))

    @staticmethod
    def get_tcpdump() -> Tcpdump:
        return Tcpdump(log_handler_host=get_log_handler_host(LOGGER),
                       log_handler_port=get_log_handler_port(LOGGER))

    @property
    def logger(self) -> logging.Logger:
        return LOGGER


if __name__ == "__main__":
    from rpyc.utils.server import ThreadedServer  # noqa: F811

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--log-server",
        help="address:port for log receiver server, "
             "usually main pytest ip",
        type=str,
        required=False)
    parser.add_argument(
        "--hostname",
        help="bind to ip address",
        type=str,
        required=True)
    parser.add_argument(
        "--port",
        help="listen port for RCP service",
        type=int,
        required=True)
    args = parser.parse_args()
    try:
        log_server = vars(args).get('log_server')
        if log_server:
            if is_any_socket_handler(LOGGER):
                LOGGER.warning("Multiple logging socket handler! "
                               "Only one socket handler supported! "
                               "New handler would be ignored! ")
            else:
                LOGGER.setLevel(logging.DEBUG)
                ip, port = log_server.split(":")
                add_socket_handler(LOGGER, ip, port)

        async_server = ThreadedServer(
            DaemonHub,
            protocol_config={
                'allow_public_attrs': True},
            port=vars(args)['port'],
            logger=LOGGER,
            hostname=vars(args)['hostname'])
        __SERVERS_OBJ.append(async_server)
        async_server.start()
    except Exception as e:
        LOGGER.error(e)
    finally:
        if log_server:
            remove_socket_handlers(LOGGER)