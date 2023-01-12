import logging
import re
from collections import namedtuple
import socket
from time import time, sleep
from typing import (Any, Dict, List, NamedTuple, Optional, Tuple, Union,
                    TYPE_CHECKING)

from parsimonious.nodes import NodeVisitor, Node, RegexNode
from scapy.packet import Packet

from lib.remotetools.traffic_tools import PacketStructure
from lib.remotetools.vrouter_parser.vrouter_gramars import vrouter_flows_grammar

if TYPE_CHECKING:
    from lib.connections import Machine

LOGGER = logging.getLogger(__name__)
FlowIndex = namedtuple('FlowIndex', ['s_index', 'd_index'])
FlowsEntires = namedtuple(
    'FlowsEntires',
    ['created', 'added', 'deleted', 'changed',
     'processed', 'used_overflow_entries'])


class FlowStats(NamedTuple):
    packets: int
    bytes: int

    def __sub__(self, other: 'FlowStats') -> 'FlowStats':
        return FlowStats(
            self.packets - other.packets, self.bytes - other.bytes)


class FiveTuple:
    PARAMS = ['s_ip', 's_port', 'd_ip', 'd_port', 'proto']

    def __init__(self, s_ip: Optional[str] = None,
                 s_port: Optional[int] = None,
                 d_ip: Optional[str] = None,
                 d_port: Optional[int] = None,
                 proto: Union[int, str, None] = None):
        self.s_ip = s_ip
        self.s_port = s_port
        self.d_ip = d_ip
        self.d_port = d_port
        self.proto = proto  # type: ignore[assignment]

    @property
    def proto(self) -> Optional[int]:
        return self.__proto

    @proto.setter
    def proto(self, proto: Union[int, str, None]) -> None:
        if proto is None:
            self.__proto = None
        else:
            try:
                self.__proto = int(proto)
            except ValueError:
                # workaround for socket library issue on Linux
                if proto == 'icmp6':
                    proto = 'ipv6-icmp'
                self.__proto = socket.getprotobyname(str(proto))

    def __repr__(self):
        params = [f"{param}: {getattr(self, param)}" for param in self.PARAMS]
        return f"FiveTuple({', '.join(params)})"

    def __eq__(self, other: Any) -> bool:
        """2 FiveTuples considered equal if all PARAMS are equal"""
        for param in self.PARAMS:
            try:
                ours_param = getattr(self, param)
                other_param = getattr(other, param)
                if ours_param != other_param:
                    return False
            except AttributeError:
                return False
        return True

    def matches(self, other: 'FiveTuple') -> bool:
        """Checks if 2 FiveTuples parameters' match, with None used
        as a wildcard"""
        for param in self.PARAMS:
            ours_param = getattr(self, param)
            other_param = getattr(other, param)
            if all([ours_param is not None, other_param is not None,
                    ours_param != other_param]):
                return False
        return True

    def reversed(self) -> "FiveTuple":
        return FiveTuple(self.d_ip, self.d_port,
                         self.s_ip, self.s_port, self.proto)

    @classmethod
    def from_pkt_definition(cls, pkt_definition: Packet) -> "FiveTuple":
        def _parse_port(port: Optional[str]) -> Optional[int]:
            return int(port) if port is not None else None
        packet_structure = PacketStructure(pkt_definition)
        pkt_definition_dict = packet_structure.get_params_dict()
        return cls(
            s_ip=pkt_definition_dict.get("ip_src"),
            s_port=_parse_port(pkt_definition_dict.get("sport")),
            d_ip=pkt_definition_dict.get("ip_dst"),
            d_port=_parse_port(pkt_definition_dict.get("dport")),
            proto=pkt_definition_dict.get('proto'))


class VrouterParserException(Exception):
    ...


class MirrorIndexValueError(Exception):
    ...


class VRouterFlows:
    def __init__(self, entries: FlowsEntires,
                 flows: Optional[List["VRouterFlow"]] = None):
        self.entries = entries
        self.flows = flows or list()

    def __repr__(self) -> str:
        return f'{self.entries}:\n{self.flows}'

    def get_number_of_flows(self) -> int:
        return len(self.flows)

    def filter_flows_by_five_tuple(
            self, five_tuple: FiveTuple,
            flow_rev: bool = False) -> List["VRouterFlow"]:
        return [flow for flow in self.flows
                if (flow_rev and flow.five_touple.reversed().matches(five_tuple)
                    or flow.five_touple.matches(five_tuple))]

    def get_flows_stats(self) -> FlowStats:
        stats = [flow.get_flow_stats() for flow in self.flows]
        return FlowStats(
            packets=sum(stat.packets for stat in stats),
            bytes=sum(stat.bytes for stat in stats))

    def get_number_of_packets(self) -> int:
        return sum(flow.get_number_of_packets() for flow in self.flows)

    def get_mirror_indexes(self) -> List[Optional[int]]:
        return [flow.get_mirror_index() for flow in self.flows]


class VRouterFlow:
    def __init__(self, flow_index: FlowIndex,
                 five_touple: FiveTuple,
                 options: Optional[Dict[str, str]] = None):
        self.five_touple = five_touple
        self.flow_index = flow_index
        self.options = options or {}

    def __repr__(self) -> str:
        return f'{self.flow_index}: {self.five_touple}\noptions: {self.options}'

    def get_mirror_index(self) -> Optional[int]:
        if "mirror_index" not in self.options.keys():
            return None
        try:
            return int(self.options['mirror_index'])
        except TypeError as e:
            msg = f'Error while parsing mirror index: {e}'
            LOGGER.warning(msg)
            raise MirrorIndexValueError(msg)

    def get_flow_stats(self) -> FlowStats:
        stats = self.options.get("stats")
        if stats is None:
            return FlowStats(0, 0)
        stats_match = re.search(r"[^\d]*(\d+)\/(\d+).*", stats)
        if stats_match is None:
            raise RuntimeError(f'Could not get flow stats for {self}')
        return FlowStats(int(stats_match.group(1)), int(stats_match.group(2)))

    def get_number_of_packets(self) -> int:
        return self.get_flow_stats().packets

    def get_action(self) -> Optional[str]:
        return self.options.get('action')

    def get_sport(self) -> Optional[int]:
        sport = self.options.get('sport')
        if sport is None:
            return None
        return int(sport)


class VrouterFlowParser(NodeVisitor):
    ENTRIES_HEADER = ['created', 'added', 'deleted', 'changed',
                      'processed', 'used']
    OPTIONS_KEYS = ['gen', 'knh', 'action', 'flags', 'tcp', 'qos', 'snh',
                    'stats', 'mirror_index', 'sport', 'ttl', 'sinfo']
    REGEX_NODES = ['ip', 'any_but_comma', 'any_but_rpar', 'any_but_lpar',
                   'stats_data']

    def visit_expr(self, _, visited_children: List[Any]) -> VRouterFlows:
        return VRouterFlows(
            entries=visited_children[1],
            flows=visited_children[2])

    def visit_entries_line(self, _, visited_children: List[Any]
                           ) -> FlowsEntires:
        _, _, *entries, _ = visited_children
        return FlowsEntires(*entries)

    def visit_flows(self, _, visited_children: List[VRouterFlow]
                    ) -> List[VRouterFlow]:
        return visited_children

    def visit_flow_entry(self, _, visited_children: List[Any]) -> VRouterFlow:
        index, five_touple = visited_children[0]
        options = visited_children[1]
        return VRouterFlow(
            flow_index=index,
            five_touple=five_touple,
            options=options)

    def visit_flow_info(self, _, visited_children: List[Any]
                        ) -> Tuple[FlowIndex, FiveTuple]:
        flow_index = visited_children[1]
        s_ip, s_port = visited_children[2]
        d_ip, d_port = visited_children[5]
        proto = visited_children[4]
        five_touple = FiveTuple(s_ip, s_port, d_ip, d_port, proto)
        return flow_index, five_touple

    def visit_flow_options(self, _, visited_children: List[Any]
                           ) -> Dict[str, str]:
        return visited_children[2]

    def visit_key_vals(self, _, visited_children: List[Any]) -> Dict[str, str]:
        key_vals = {}
        for children_key_val in visited_children:
            key_vals.update(children_key_val)
        return key_vals

    def visit_key_val(self, _, visited_children: List[Any]) -> Dict[str, str]:
        return visited_children[1]

    def visit_keys(self, _, visited_children: List[Any]) -> List[Any]:
        return visited_children

    def visit_number(self, node: RegexNode, _) -> int:
        return int(node.text)

    def visit_address(self, _, visited_children: List[Any]) -> Tuple[str, int]:
        return visited_children[1], visited_children[-1]

    def visit_port(self, node: RegexNode, _) -> int:
        return int(node.text)

    def visit_proto_number(self, node: RegexNode, _) -> int:
        return int(node.text)

    def visit_optional_number(self, node: RegexNode, _) -> Optional[int]:
        if not node.text:
            return None
        return int(node.text)

    def visit_index(self, _, visited_children: List[Any]) -> FlowIndex:
        return FlowIndex(visited_children[0], visited_children[-1])

    def visit_proto(self, _, visited_children: List[Any]) -> int:
        return visited_children[0]

    def generic_visit(self, node: Union[Node, RegexNode],
                      visited_children: List[Any]) -> Any:
        if node.expr_name in self.ENTRIES_HEADER:
            return visited_children[-2]
        if node.expr_name in self.OPTIONS_KEYS:
            return node.expr_name, visited_children[-1]
        if node.expr_name in self.REGEX_NODES:
            return node.text


class VrouterParser:
    VROUTER_CMD_BASE = "contrail-tools"

    def __init__(self, ssh_conn: 'Machine'):
        self.ssh_conn = ssh_conn

    def get_flows(self, flow_match: Optional[FiveTuple] = None,
                  flow_rev: bool = False, check_mirror: bool = False
                  ) -> VRouterFlows:
        LOGGER.info('Getting flows from vrouter')
        cmd = f'{self.VROUTER_CMD_BASE} "flow -l"'
        out, err = self.ssh_conn.get_sudo_cmd_output(cmd, log_output=True)
        tree = vrouter_flows_grammar.parse(out)
        flows = VrouterFlowParser().visit(tree)
        if flow_match is not None:
            LOGGER.debug(f'Filtering flows by {flow_match}')
            flows.flows = flows.filter_flows_by_five_tuple(flow_match, flow_rev)
        LOGGER.info(f'Found flows: {flows}')
        if check_mirror:
            LOGGER.info("Checking Mirror Indexes in Vrouter flows")
            assert all([isinstance(m_index, int)
                        for m_index in flows.get_mirror_indexes()])
        return flows

    @staticmethod
    def count_mirrored_index(flows: VRouterFlows) -> int:
        return sum([1 if isinstance(m_index, int) else 0
                    for m_index in flows.get_mirror_indexes()])

    def get_number_of_flows(self, flow_match: Optional[FiveTuple] = None
                            ) -> int:
        return self.get_flows(flow_match).get_number_of_flows()

    def get_number_of_packets(self, flow_match: Optional[FiveTuple] = None
                              ) -> int:
        return self.get_flows(flow_match).get_number_of_packets()

    def get_number_of_packets_force(self) -> int:
        cmd = f'{self.VROUTER_CMD_BASE} flow -l | grep "<=>" | wc -l'
        out, err = self.ssh_conn.get_sudo_cmd_output(cmd, log_output=False)
        LOGGER.info(f"Number of packets: {int(out)}")
        return int(out)

    def get_flows_stats(self, flow_match: Optional[FiveTuple] = None
                        ) -> FlowStats:
        return self.get_flows(flow_match).get_flows_stats()

    def wait_for_nb_of_flows(self, nb, flow_match: Optional[FiveTuple] = None,
                             timeout: int = 30, interval: int = 2,
                             force: bool = False) -> None:
        LOGGER.info(f"Waiting {timeout} seconds for {nb} flows on vrouter")
        end = time() + timeout
        while time() < end:
            flows_found = (self.get_number_of_packets_force() if force else
                           self.get_number_of_flows(flow_match))
            if flows_found == nb:
                LOGGER.info(f'Flows number {flows_found} is matching expected '
                            f'number {nb}. Finished waiting.')
                return
            LOGGER.info(f'Flows number {flows_found} is not matching expected '
                        f'number {nb}. Retrying after {interval} seconds.')
            sleep(interval)
        raise TimeoutError(f"Number of flows didn't reach {nb}.")

    @staticmethod
    def flow_stats_diff(first_flow: List[VRouterFlow],
                        second_flow: List[VRouterFlow]
                        ) -> Dict[FlowIndex, FlowStats]:
        diff = {flow.flow_index: flow.get_flow_stats() for flow in second_flow}
        for flow in first_flow:
            pre = diff.get(flow.flow_index, FlowStats(0, 0))
            diff[flow.flow_index] = pre - flow.get_flow_stats()
        return diff