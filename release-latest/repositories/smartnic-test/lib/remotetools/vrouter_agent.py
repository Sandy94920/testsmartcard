import os
import logging
import requests
from time import sleep
from typing import TYPE_CHECKING
from xml.etree import ElementTree
from distutils.util import strtobool

from lib.remotetools.vrouter_parser import VrouterParser
from lib.remotetools.vrouter_tools import get_virtual_machine_vrf

if TYPE_CHECKING:
    from lib.connections import Machine

LOGGER = logging.getLogger(__name__)


class ErrorAgentRestApi(ValueError):
    pass


def _get_module_from_agent_introspect(url_module, value, ip_compute_node):
    LOGGER.debug(f"Try get value name: {value}. From module: {url_module}")
    url = os.path.join(f'http://{ip_compute_node}:8085', url_module)
    response = requests.get(url)
    tree = ElementTree.fromstring(response.content)
    for xml_type in tree.iter():
        value_of_module = xml_type.findtext(value)
        if value_of_module is not None:
            LOGGER.debug(f"Find '{value}:{value_of_module}'")
            return value_of_module
    raise ErrorAgentRestApi(f"No such attr '{value}' in {url}")


def get_status_health_check(service_uuid: str,
                            ip_compute_node: str,
                            max_sync_time: int = 5) -> bool:
    url = f'Snh_HealthCheckSandeshReq?uuid={service_uuid}'
    probe_sync = 0
    while probe_sync < max_sync_time:
        sleep(1)
        health_check_status = _get_module_from_agent_introspect(
            url_module=url,
            value="active",
            ip_compute_node=ip_compute_node)
        if strtobool(health_check_status):
            return True
        probe_sync += 1
    return False


def get_mpls_label_for_l2_traffic(cpt_ssh: 'Machine',
                                  ip_src: str,
                                  mac_dst: str) -> int:
    vm_vrf = get_virtual_machine_vrf(
        cpt_ssh=cpt_ssh,
        ip_src=ip_src)
    url = (f"Snh_BridgeRouteReq?"
           f"vrf_index={str(vm_vrf)}&"
           f"mac={mac_dst}"
           f"&stale=")
    mpls_label = _get_module_from_agent_introspect(
        url_module=url,
        value="label",
        ip_compute_node=cpt_ssh.ip_mgmt)
    if mpls_label == -1:
        LOGGER.warning(
            f"MPLS label for this flow is set to {mpls_label}, "
            f"check encapsulation in the controller.")
    LOGGER.info(
        f"Mpls label {mpls_label} for flow ip_src {ip_src} "
        f"mac_dst {mac_dst} gathered from vrouter agent.")
    return int(mpls_label)


def get_mpls_label_for_l3_traffic(cpt_ssh: 'Machine',
                                  ip_src: str,
                                  ip_dst: str) -> int:
    vm_vrf = get_virtual_machine_vrf(
        cpt_ssh=cpt_ssh,
        ip_src=ip_src)
    url = (f"Snh_Inet4UcRouteReq?"
           f"vrf_index={str(vm_vrf)}&"
           f"src_ip={ip_dst}&"  # contrail has incorrect var name
           f"prefix_len=32&"
           f"stale=")
    mpls_label = _get_module_from_agent_introspect(
        url_module=url,
        value="label",
        ip_compute_node=cpt_ssh.ip_mgmt)
    if mpls_label == -1:
        LOGGER.warning(
            f"MPLS label for this flow is set to {mpls_label}, "
            f"check encapsulation in the controller.")
    LOGGER.info(
        f"Mpls label {mpls_label} for flow ip_src {ip_src} "
        f"gathered from vrouter agent.")
    return int(mpls_label)


def clear_flows_in_vrouter_agent(cpt_ssh: 'Machine') -> None:
    cn_ip_address = cpt_ssh.ip_mgmt
    response = requests.get(
        f"http://{cn_ip_address}:8085/Snh_DeleteAllFlowRecords?")
    if response.status_code == 200:
        LOGGER.info("Delete flows request successfully sent to vRouter agent")
    else:
        raise ErrorAgentRestApi(
            f"Unable to send request to delete flows for vRoueter Agent "
            f"code {response.status_code}")
    VrouterParser(cpt_ssh).wait_for_nb_of_flows(nb=0, timeout=60, force=True)