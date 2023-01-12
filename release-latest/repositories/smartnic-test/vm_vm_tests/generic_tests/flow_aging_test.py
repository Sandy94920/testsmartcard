import logging
from random import randint
from time import sleep

import allure
from pytest import mark, param
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from lib.remotetools.nic_flow_info import pac_get_number_of_flows
from lib.remotetools.traffic_tools import TrafficGenerator
from lib.remotetools.vrouter_parser import (VrouterParser, FiveTuple)
from lib.utils import (Topology,
                       get_ip_version)

LOGGER = logging.getLogger(__name__)
FLOW_AGING_TIME = 3*60
# 25% Dealy for communication of vrouter Agent at upload flows to n3k
DELAY_TIME_VROUTER_AGENT_SEND_DATA = (FLOW_AGING_TIME * 25 // 100)

pytestmark = [
    mark.env(Topology.vm_vm),
    mark.parametrize('ip_header', [param(IP, marks=mark.ipv4),
                                   param(IPv6, marks=mark.ipv6)]),
    mark.single_compute_node
]


@mark.tc_id("0.2.1")
def test_pac_flow_hw_aging(test_bed, verify_n3k_dump, daemon_hubs_generator,
                           encapsulation, clear_vrouter_flows, ip_header):
    """
    TEST FLOWS INSERTION ON Intel PAC

    TEST PURPOSE:
        The purpose of the test is to verify if the previously installed
        flows are expired after certain amount of time.

    TEST DESCRIPTION:
        This test case uses two tools, the first one to create and
        send sample packet. Second one to dump flows.

    TEST SEQUENCE:
        1. vm_client on VM1 sends sample TCP packet to VM2 in order to add
           flows to Intel PAC.
        2. Compute node invokes tool to retrieve number of flows from Intel PAC.
        3. Test runner verifies number of flows retrieved in step 2.
        4. Test runner waits given time.
        5. Test runner verifies if the number of installed flows equals 0.

    EXPECTED RESULT:
        1. All generated packets must be sent without any errors
        2. Number of flows after sending sample packet must be greater or equal
           to 2 and flow and reverse flows has to match the signature of the
           packet that has been sent.
    """
    # Given
    # define packet
    ip_version = get_ip_version(ip_header)
    ip_src = test_bed.cn1.vm1.iface1.get_ip(ip_version=ip_version)
    ip_dst = test_bed.cn1.vm2.iface1.get_ip(ip_version=ip_version)

    pkt_definition = (
        Ether(
            src=test_bed.cn1.vm1.iface1.mac_addr,
            dst=test_bed.cn1.vm2.iface1.mac_addr)
        / ip_header(
            src=ip_src,
            dst=ip_dst)
        / UDP(
            sport=randint(40000, 65000),
            dport=5555)
        / Raw())
    LOGGER.info(f"packet definition: {pkt_definition}")
    # When
    daemon_vm1 = daemon_hubs_generator(test_bed.cn1.vm1)[0]
    # send packets cn_1 vm_1 -> cn1 -vm2
    traffic_generator = TrafficGenerator(sender_hub=daemon_vm1)
    traffic_generator.send_packet(
        test_bed.cn1.vm1.iface1.name,
        pkt_definition)
    # wait to make sure the flows were added
    sleep(2)
    # THEN
    # retrieve number of Intel PAC flows
    if verify_n3k_dump:
        total_number_of_flows = pac_get_number_of_flows(test_bed.cn1)
        assert total_number_of_flows >= 2, (
            f"Expected nb of flows after "
            f" insertion: {2}, actual "
            f"{total_number_of_flows}")
        # wait for flow to expire
        LOGGER.info(
            f"Waiting for flows to expire in N3K. Timeout: "
            f"{FLOW_AGING_TIME + DELAY_TIME_VROUTER_AGENT_SEND_DATA} sec.")
        # First check after half of full time expire flows
        LOGGER.info("Waiting for a first check of flows")
        sleep((FLOW_AGING_TIME + DELAY_TIME_VROUTER_AGENT_SEND_DATA) // 2)
        total_number_of_flows = pac_get_number_of_flows(test_bed.cn1)
        assert total_number_of_flows >= 2, (
            f"Expected nb of flows after half"
            f" the time: {2}, actual "
            f"{total_number_of_flows}")
        # Second check after half of full time expire flows
        LOGGER.info("Waiting for a second check of flows")
        sleep((FLOW_AGING_TIME + DELAY_TIME_VROUTER_AGENT_SEND_DATA) // 2)
        # retrieve number of Intel PAC flows
        total_number_of_flows = pac_get_number_of_flows(test_bed.cn1)
        assert total_number_of_flows == 0, (
            f"Expected nb of flows after time:"
            f" {0}, actual {total_number_of_flows}")


@allure.issue('NIC-1649', 'Not all flows registered, fix in HCL fw')
@mark.tc_id("0.2.2")
def test_flow_aging(test_bed, clear_vrouter_flows, daemon_hubs_generator,
                    ip_header):
    """
    TEST FLOWS INSERTION ON vRouter

    TEST PURPOSE:
        The purpose of the test is to verify if the previously installed
        flows are expired after certain amount of time.

    TEST DESCRIPTION:
        This test case uses two tools, the first one to create and send
        sample packet. Second one to dump and remove flows.

    TEST SEQUENCE:
        1. vm_client on VM1 sends sample TCP packet to VM2 in order to add
           flows to vRouter.
        2. Compute node invokes tool to retrieve number of flows
           from vRouter.
        3. Test runner verifies number of flows retrieved in step 2.
        4. Test runner waits given time.
        5. Test runner verifies if the number of installed flows equals 0.

    EXPECTED RESULT:
        1. All generated packets must be sent without any errors
        2. Number of flows after sending sample packet must be greater or equal
           to 2 and flow and reverse flows has to match the signature of the
           packet that has been sent.
   """
    # define packet
    ip_version = get_ip_version(ip_header)
    ip_src = test_bed.cn1.vm1.iface1.get_ip(ip_version=ip_version)
    ip_dst = test_bed.cn1.vm2.iface1.get_ip(ip_version=ip_version)

    pkt_definition = (
        Ether(
            src=test_bed.cn1.vm1.iface1.mac_addr,
            dst=test_bed.cn1.vm2.iface1.mac_addr)
        / ip_header(
            src=ip_src,
            dst=ip_dst)
        / UDP(
            sport=randint(40000, 65000),
            dport=5555)
        / Raw())
    flow = FiveTuple.from_pkt_definition(pkt_definition)
    LOGGER.info(f"packet definition: {pkt_definition}")
    # When
    daemon_vm1 = daemon_hubs_generator(test_bed.cn1.vm1)[0]
    # send packets cn_1 vm_1 -> cn1 -vm2
    traffic_generator = TrafficGenerator(sender_hub=daemon_vm1)
    traffic_generator.send_packet(
        test_bed.cn1.vm1.iface1.name,
        pkt_definition)
    # wait to make sure the flows were added
    sleep(2)
    # THEN
    # retrieve number of Intel PAC flows
    parser = VrouterParser(test_bed.cn1)
    current_flows = parser.get_flows(
        flow_match=flow, flow_rev=True).get_number_of_flows()

    assert current_flows == 2, (f"Expected nb of flows after "
                                f" insertion: {2}, actual "
                                f"{current_flows}")
    # wait for flow to expire
    LOGGER.info(
        f"Waiting for flows to expire in vRouter. Timeout:"
        f"{FLOW_AGING_TIME + DELAY_TIME_VROUTER_AGENT_SEND_DATA} sec.")
    # First check after half of full time expire flows
    LOGGER.info("Waiting for a first check of flows")
    sleep((FLOW_AGING_TIME + DELAY_TIME_VROUTER_AGENT_SEND_DATA) // 2)

    current_flows = parser.get_flows(
        flow_match=flow, flow_rev=True).get_number_of_flows()
    assert current_flows == 2, (f"Expected nb of flows after "
                                f"half the time: {2}, actual "
                                f"{current_flows}")
    # Second check after half of full time expire flows
    LOGGER.info("Waiting for a second check of flows")
    sleep((FLOW_AGING_TIME + DELAY_TIME_VROUTER_AGENT_SEND_DATA) // 2)

    current_flows = parser.get_flows(
        flow_match=flow, flow_rev=True).get_number_of_flows()
    # retrieve number of Intel PAC flows
    assert current_flows == 0, (f"Expected nb of flows after "
                                f"time: {0}, actual "
                                f"{current_flows}")