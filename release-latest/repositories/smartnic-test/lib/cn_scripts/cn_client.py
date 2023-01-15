"""
This script has to be standalone because we copy it to Compute and execute it
remotely so we do not want any dependencies and this file needs to be
compatible with python 3.6.
"""
import argparse
import logging
from subprocess import Popen, PIPE
from typing import Optional, IO, Dict
import sys

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter(
    '[cn_client] %(asctime)s %(levelname)s %(message)s '
    '(%(filename)s:%(funcName)s:%(lineno)s)')
handler.setFormatter(formatter)
LOGGER.addHandler(handler)


def get_vrouter_stats(vif: str, type_flows: str) -> Dict:
    LOGGER.info("Start vrouter stats retrieval")
    vrouter_stats = Popen(
        ['docker', 'exec', 'vrouter_vrouter-agent-dpdk_1',
         'vif', '--get', str(vif)],
        stdout=PIPE)
    LOGGER.info(f"End vrouter stats retrieval. Output: {vrouter_stats.stdout}")
    return parse_stats(stats=vrouter_stats.stdout, type_flows=type_flows)


def parse_stats(stats: Optional[IO[bytes]], type_flows: str) -> Dict:
    """
        PCI: 0000:13:00.0 (Speed 1000, Duplex 1) NH: 4
            Type:Physical HWaddr:00:50:56:8c:fe:39 IPaddr:0.0.0.0
            Vrf:0 Mcast Vrf:65535 Flags:L3L2VpEr QOS:-1 Ref:12
        GET this RX line --> RX device packets:493788  bytes:664215023 errors:0
            RX port   packets:493788 errors:0
            RX queue  packets:491736 errors:0
            RX queue errors to lcore 0 0 0 0 0 0 0 0 0 0 0 0
            Fabric Interface: 0000:13:00.0  Status: UP  Driver: net_e1000_em
            RX packets:493788  bytes:662239871 errors:0
            TX packets:87753  bytes:5867893 errors:0
            Drops:324
            TX queue  packets:51948 errors:0
            TX port   packets:87753 errors:0
        GET this TX line --> TX device packets:87753  bytes:6035947 errors:0
    """
    if type_flows == "offload":
        find_in_line = "device"
    else:
        find_in_line = "packets"

    vrouter_stats = list(map(str, stats))  # type: ignore
    tx_pkts = _parse_pkts(vrouter_stats, find_in_line, is_tx=True)
    rx_pkts = _parse_pkts(vrouter_stats, find_in_line, is_tx=False)
    drops = _parse_drops(vrouter_stats, find_in_line)
    return {"tx": tx_pkts, "rx": rx_pkts, "drops": drops}


def _parse_pkts(vrouter_stats, find_in_line, is_tx):
    pkt_direction = 'TX' if is_tx else 'RX'
    try:
        tx_pkts = tuple(map(
            lambda x: x.split(":")[-1].replace("\\n'", ""),
            [stat.split()[-3:] for stat in vrouter_stats
                if ' '.join([pkt_direction, find_in_line]) in stat][-1]))
    except IndexError:
        tx_pkts = (-1, -1, -1)
    return tx_pkts


def _parse_drops(vrouter_stats, find_in_line):
    try:
        drops = [stat.split(":")[-1].split()[0].replace("\\n'", "")
                 for stat in vrouter_stats if 'Drops' in stat][0]
    except IndexError:
        drops = -1
    return drops


if __name__ == "__main__":
    PARSER = argparse.ArgumentParser()
    PARSER.add_argument(
        "--vif", help="destination ip address", required=True)
    PARSER.add_argument(
        "--type_flows", default="offload",
        help="Get flows from device or slow path")
    ARGS = PARSER.parse_args()
    print(get_vrouter_stats(**vars(ARGS)))