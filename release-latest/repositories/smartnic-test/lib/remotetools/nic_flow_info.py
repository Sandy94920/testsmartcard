import logging
import re
from time import sleep
from typing import TYPE_CHECKING, Optional

from scapy.packet import Packet

from lib.remotetools.traffic_tools import PacketStructure

LOGGER = logging.getLogger(__name__)

if TYPE_CHECKING:
    from lib.connections import Machine


class NICPassThroughModeIssue(Exception):
    pass


def execute_n3kflow_dump(cpt_ssh: 'Machine', optional_param: str = "") -> str:
    stdout, stderr = cpt_ssh.get_sudo_cmd_output(
        f"docker exec vrouter_vrouter-agent-dpdk_1 n3kflow-dump"
        f" --proc-type secondary --no-pci"
        f" -- --device-name 0000:1d:00.0 --table-type flow {optional_param}")
    if stderr:
        LOGGER.error(stderr)
    return stdout


def pac_get_number_of_flows(cpt_ssh: 'Machine') -> int:
    LOGGER.info("Check number of flows stats.")
    match = re.search(
        r"(?<=total_entries = )\d+", execute_n3kflow_dump(cpt_ssh,
                                                          optional_param="-t"))
    if match:
        return int(match.group())
    LOGGER.error("Couldn't get number of flows from card")
    return -1


def pac_get_flow_list(cpt_ssh: 'Machine') -> list:
    LOGGER.info("Regular Expression flows Parser")
    return re.findall(r">flow_id=.*\s.*\s.*", execute_n3kflow_dump(cpt_ssh))


def pac_get_flow_stats(cpt_ssh: 'Machine', packet: Packet) -> Optional[dict]:
    packet_structure = PacketStructure(packet)
    flow = packet_structure.get_params_dict()
    LOGGER.info(f"Check flow {flow} stats.")
    stdout = execute_n3kflow_dump(cpt_ssh)
    LOGGER.debug(f'Flow_dump output:\n{stdout}')
    flow_stats = {"packets": 0, "bytes": 0, "encap": None}
    match = re.search(r"stats"                       # stats string
                      r"\(bytes_cnt=(\d+),"          # bytes counter int
                      r"packet_cnt=(\d+)"            # packet counter int
                      r".*\n.*"                      # all char ecsaped new line
                      r"\(src={},dst={}\),"          # specify src and dst addr
                      r"\w+"                         # any word char
                      r"\(sport={},dport={}\)"       # specify ports
                      r"".format(re.escape(flow["ip_src"]),
                                 re.escape(flow["ip_dst"]),
                                 re.escape(str(flow["sport"])),
                                 re.escape(str(flow["dport"]))),
                      stdout, re.VERBOSE)

    match_encap = re.search(r"(?<=ENCAP).*(MPLSoUDP|MPLSoGRE|VXLAN)", stdout)
    match_vni = re.search(r'VXLAN\(vni=(\d+)\)', stdout)
    if match:
        flow_stats["bytes"] = int(match.group(1))
        flow_stats["packets"] = int(match.group(2))
        if match_encap:
            flow_stats["encap"] = str(match_encap.group(1))  # type: ignore
            if flow_stats["encap"] == "VXLAN":
                assert isinstance(int(match_vni.group(1)), int)  # type: ignore
        return flow_stats
    return None


def pac_timout_to_del_flow_fin_ack(default: int = 4*60) -> None:
    LOGGER.info(f'Waiting to del flow from n3k: {default} s.')
    sleep(default)


def is_issue_n3k_in_pass_through_mode(verify_n3k_dump: bool, mx_scenario: str
                                      ) -> bool:
    if not verify_n3k_dump and mx_scenario.find("ab") != -1:
        return True
    return False