import os
import json
import logging
from typing import Optional, TYPE_CHECKING

from lib.remotetools.flow import Flow

if TYPE_CHECKING:
    from lib.connections import Machine

LOGGER = logging.getLogger(__name__)
N3K_DUMP_DOCKER_EXEC = 'docker exec vrouter_vrouter-agent-dpdk_1 n3kflow-dump'
CMD_GET_N3K_FLOWS = ("{n3k_dump} --proc-type secondary --no-pci "
                     "-- --device-name {device_name} --table-type flow -j")


def _get_n3k_dump(path: Optional[str]) -> str:
    __app_name = "n3kflow-dump"
    if path is not None:
        LOGGER.debug("Run n3k dump from dpdk binary file")
        return os.path.join(path, __app_name)
    LOGGER.debug("Run n3k dump from docker")
    return N3K_DUMP_DOCKER_EXEC


def get_n3k_flows(
        ssh_conn: 'Machine',
        device_name: str,
        dpdk_bin_path: str = None) -> list['Flow']:
    cmd = CMD_GET_N3K_FLOWS.format(
        n3k_dump=_get_n3k_dump(dpdk_bin_path), device_name=device_name)
    stdout, stderr = ssh_conn.get_sudo_cmd_output(cmd)
    if stderr:
        LOGGER.warning(stderr)
    lines = stdout.split("\n")
    while lines[0].strip() != "{":
        lines = lines[1:]
    flows = json.loads("\n".join(lines))["flows"]
    LOGGER.debug(f"JSON DUMP:\n {flows}")
    test_flows = list(map(Flow.base_on_json_flow, flows))
    LOGGER.debug(f"N3k-dump flows list: {test_flows}")
    return test_flows


def get_n3k_flow_stats(
        ssh_conn,
        device_name,
        dpdk_bin_path=None):
    cmd = (f"{_get_n3k_dump(dpdk_bin_path)} --proc-type secondary --no-pci "
           f"-- --device-name {device_name} "
           f"--table-type flow -j")
    stdout, stderr = ssh_conn.get_sudo_cmd_output(cmd)
    if stderr:
        LOGGER.warning(stderr)
    lines = stdout.split("\n")
    while lines[0].strip() != "{":
        lines = lines[1:]

    flows = json.loads("\n".join(lines))["flows"]
    LOGGER.debug(f"JSON DUMP:\n {flows}")
    stats = [flow['flow-stats'] for flow in flows]
    LOGGER.debug(f"N3k-dump stats list: {stats}")
    return stats