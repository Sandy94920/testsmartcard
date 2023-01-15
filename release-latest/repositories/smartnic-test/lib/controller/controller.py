from ipaddress import ip_address, ip_network
import json
import logging
import math
from copy import deepcopy
from enum import Enum
from time import sleep
from typing import Optional

import jxmlease
import requests
import yaml
from vnc_api import (
    vnc_api,
    exceptions)

LOGGER = logging.getLogger(__name__)


class ApiControllerError(Exception):
    pass


class SetupTests:
    """
    Enum of possibility setup tests, based
    on the yaml file
    """
    bird = {"setup": "setup_bird"}
    nginx = {"setup": "setup_nginx"}
    allow_traffic_between_diffrent_network = {
        "setup": 1,
        "type_policy": "multiple_vrf"}
    drop_pkts_deny_one_network_tcp = {
        "setup": "drop_pkts_deny_one_network_tcp",
        "type_policy": "drop_pkts_offload"}
    drop_pkts_deny_one_network_udp = {
        "setup": "drop_pkts_deny_one_network_udp",
        "type_policy": "drop_pkts_offload"}
    drop_pkts_deny_one_network_any = {
        "setup": "drop_pkts_deny_one_network_any",
        "type_policy": "drop_pkts_offload"}
    bgp_as_a_service_1_1_6 = {
        "setup": "setup_bgp_as_a_service_tc_id_1_1_6"}


class BGPSessionStatus(Enum):
    """
    Enum of network connections possibility
    """
    teardown = "Teardown"
    establish = "Established"
    idle = "Idle"
    connect = "Connect"
    active = "Active"
    unknown = "unknown"


class Controller:
    '''
    The Class provides many various
    methods for changing the configuration in the
    Contrail Controller via external vnc_api lib.

    :param controller_cfg: The controller_cfg is used for
     passing new settings to the controller from the yaml file cfg.
    :type controller_cfg: dict
    '''

    def __init__(self, controller_cfg: dict):
        self.config = controller_cfg
        self._config: Optional[dict] = None
        self._post_cfg_ctrl: dict = {}
        self.client: vnc_api.VncApi = self.connect()

    def __call__(self):
        self._config = deepcopy(self.config)
        if len(self._post_cfg_ctrl) > 0:
            LOGGER.info("Backup 'post_cfg_ctrl' config erase")
            self._post_cfg_ctrl.clear()
        return self

    def connect(self) -> vnc_api.VncApi:
        return vnc_api.VncApi(api_server_host=self.config["ip_mgmt"])

    def validate_encap_list(self, encap_list: list[str]) -> list[str]:
        reference_names = {
            "vxlan": "VXLAN",
            "mplsoudp": "MPLSoUDP",
            "mplsogre": "MPLSoGRE"}
        return [reference_names[name_of_protocol.lower()]
                for name_of_protocol in encap_list]

    def cfg_priorities_encapsulation(self, cfg_priority_encap: list[str]
                                     ) -> None:
        cfg_priority_encap = self.validate_encap_list(
            encap_list=cfg_priority_encap)
        fq_name = self.config["global_cfg_controller"]["fq_name"]
        vrouter_config = vnc_api.GlobalVrouterConfig(fq_name=fq_name)
        vrouter_config.set_encapsulation_priorities(
            vnc_api.EncapsulationPrioritiesType(
                encapsulation=cfg_priority_encap))
        self.client.global_vrouter_config_update(vrouter_config)
        LOGGER.debug(
            f"Setup priorities encapsulation to: "
            f"{cfg_priority_encap}")

    def create_bgp_router(self, key_names: list[str] = None) -> None:
        cfg_bgp_router = self._filter_cfg_by_keys(
            key_names=key_names,
            parent_dict="bgp_router")
        self._post_cfg_ctrl.update({"bgp_router": {}})

        for router_name, cfg_bgp in cfg_bgp_router.items():
            fq_name = cfg_bgp.pop("fq_name")
            bgp_params = vnc_api.BgpRouterParams(**cfg_bgp)
            ip_fabric_ri = self.client.routing_instance_read(fq_name=fq_name)
            router = vnc_api.BgpRouter(name=router_name,
                                       parent_obj=ip_fabric_ri)
            router.set_bgp_router_parameters(bgp_params)
            _uuid = self.client.bgp_router_create(router)
            self._post_cfg_ctrl["bgp_router"][router_name] = _uuid
            LOGGER.info(
                f"Added new BGP Router to Controller, uuid: {_uuid}")

    def disable_bgp_router(self, name):
        self._toggle_bgp_router_state(name=name, disable=True)

    def enable_bgp_router(self, name):
        self._toggle_bgp_router_state(name=name, disable=False)

    def _toggle_bgp_router_state(self, name, disable):
        LOGGER.debug(f'{"Disabling" if disable else "Enabling"} '
                     f'bgp_router {name}')
        routers = self._post_cfg_ctrl.get("bgp_router")
        if routers is None:
            raise RuntimeError('No bgp routers were created yet')
        router_id = routers.get(name)
        if router_id is None:
            raise RuntimeError(f'Bgp router with name {name} not created yet')
        router = self.client.bgp_router_read(id=router_id)
        params = router.get_bgp_router_parameters()
        params.set_admin_down(disable)
        router.set_bgp_router_parameters(params)
        self.client.bgp_router_update(router)
        LOGGER.info(f'BGP Router {name} was '
                    f'{"disabled" if disable else "enabled"}')

    def del_bgp_router(self) -> None:
        post_cfg_ctrl = self._post_cfg_ctrl.get("bgp_router")
        if post_cfg_ctrl:
            for _, _uuid in post_cfg_ctrl.items():
                self.client.bgp_router_delete(id=_uuid)
                LOGGER.info(
                    f"Removed BGP Router from Controller, uuid: {_uuid}")

    def create_physical_router(self, key_names: list[str] = None) -> None:
        cfg_physical_router = self._filter_cfg_by_keys(
            key_names=key_names,
            parent_dict="physical_router")
        self._post_cfg_ctrl.update({"physical_router": {}})

        for router_name, cfg_phy_rt in cfg_physical_router.items():
            bgp_ref_fq_name = cfg_phy_rt.pop("ref_bgp_router_name", None)
            virtual_networks = cfg_phy_rt.pop("virtual_networks", None)

            pr = vnc_api.PhysicalRouter(name=bgp_ref_fq_name[-1],
                                        display_name=bgp_ref_fq_name[-1])
            # Set attrybutes params to obj instance
            for name_of_attr, attr_val in cfg_phy_rt.items():
                setattr(pr, name_of_attr, attr_val)
            # Add bgp router to physical_router
            if bgp_ref_fq_name:
                bgp_router = self.client.bgp_router_read(
                    fq_name=bgp_ref_fq_name)
                pr.set_bgp_router(bgp_router)
            if virtual_networks:
                for virtual_network in virtual_networks.values():
                    vn = self.client.virtual_network_read(
                        fq_name=virtual_network)
                    pr.add_virtual_network(vn)
            _uuid = self.client.physical_router_create(pr)
            self._post_cfg_ctrl["physical_router"][router_name] = _uuid
            LOGGER.info(
                f"Added new Physical Router to Controller, uuid: {_uuid}")

    def del_physical_router(self) -> None:
        past_physical_router = self._post_cfg_ctrl.get("physical_router")
        if past_physical_router:
            for _, _uuid in past_physical_router.items():
                self.client.physical_router_delete(id=_uuid)
                LOGGER.info(
                    f"Removed Physical Router from Controller, uuid: {_uuid}")

    def get_bgp_peers_status(self, peer_names: list[str]
                             ) -> list[BGPSessionStatus]:
        statuses: dict[str, BGPSessionStatus] = {
            peer_name: BGPSessionStatus.teardown for peer_name in peer_names}
        url = (f'http://{self.config["ip_mgmt"]}:8083/'
               f'Snh_BgpNeighborReq')
        LOGGER.debug(f'Getting bgp peer statuses with url: {url}')
        resp = requests.get(url=url)
        if resp.status_code != 200:
            raise ApiControllerError(
                f'Failed to read the bgp peers status. Response code: '
                f'{resp.status_code}, msg: {resp.text}')
        result = jxmlease.parse(resp.text)
        neighbor_list = result['BgpNeighborListResp']['neighbors']['list']
        neighbors = neighbor_list.get('BgpNeighborResp', [])
        if neighbor_list.xml_attrs['size'] == '1':
            neighbors = [neighbors]
        for neighbor in neighbors:
            peer_name = str(neighbor['peer'])
            if peer_name in peer_names:
                try:
                    statuses[peer_name] = BGPSessionStatus(neighbor['state'])
                except ValueError:
                    statuses[peer_name] = BGPSessionStatus.unknown
        return list(statuses.values())

    def wait_for_bgp_status_peers(self,
                                  expected_session_status: BGPSessionStatus,
                                  peer_names: list[str],
                                  timeout: int = 60,
                                  interval: int = 5) -> None:
        LOGGER.debug(f'Waiting for peers: {peer_names} to become '
                     f'{expected_session_status}')
        statuses = []
        for _ in range(math.ceil(timeout / interval)):
            statuses = self.get_bgp_peers_status(peer_names)
            if all(status == expected_session_status for status in statuses):
                LOGGER.info(f'All bgp peers {peer_names} are '
                            f'{expected_session_status}')
                break
            LOGGER.debug(f'Not all bgp peers are {expected_session_status}: '
                         f'{statuses}. Retrying after {interval} seconds')
            sleep(interval)
        else:
            raise TimeoutError(
                f'Bgp peers statuses {statuses} are not '
                f'{expected_session_status} after {timeout} seconds of '
                f'retrying')

    def create_logical_router(self, key_names: list[str] = None) -> None:
        cfg_logical_router = self._filter_cfg_by_keys(
            key_names=key_names,
            parent_dict="logical_router")
        self._post_cfg_ctrl.update({"logical_router": {}})

        fq_name = cfg_logical_router.pop("fq_name", None)
        LOGGER.info(f"FQ name logical router {fq_name}")
        project = self.client.project_read(fq_name=fq_name)

        for router_name, cfg_router in cfg_logical_router.items():
            lr = vnc_api.LogicalRouter(name=router_name,
                                       parent_obj=project)
            lr.set_display_name(router_name)
            if cfg_router.get("route_target"):
                rtgt_list = vnc_api.RouteTargetList(
                    route_target=cfg_router.get("route_target"))
                lr.set_configured_route_target_list(rtgt_list)
            if cfg_router.get("vxlan_network_identifier"):
                lr.set_vxlan_network_identifier(
                    str(cfg_router.get("vxlan_network_identifier")))
            if cfg_router.get("extend_physical_router"):
                pr = self.client.physical_router_read(
                    fq_name=cfg_router["extend_physical_router"]["fq_name"])
                lr.set_physical_router(pr)
            _uuid = self.client.logical_router_create(lr)
            self._post_cfg_ctrl["logical_router"][router_name] = _uuid
            LOGGER.info(
                f"Added new Logical Router to Controller, uuid: {_uuid}")

    def remove_virtual_interface_of_instance_ip(
            self, vmi_refs, logical_router):
        for vi in vmi_refs:
            vmi_obj = self.client.virtual_machine_interface_read(id=vi["uuid"])
            logical_router.del_virtual_machine_interface(vmi_obj)
            ip_instance_back_ref = vmi_obj.get_instance_ip_back_refs()
            if ip_instance_back_ref:
                for instance_ip in ip_instance_back_ref:
                    self.client.instance_ip_delete(id=instance_ip["uuid"])
            self.client.virtual_machine_interface_delete(id=vi["uuid"])

    def del_logical_router(self) -> None:
        past_logical_router = self._post_cfg_ctrl.get("logical_router")
        if past_logical_router:
            for _, _uuid in past_logical_router.items():
                lr = self.client.logical_router_read(id=_uuid)
                self.client.logical_router_delete(id=_uuid)
                vmi_refs = lr.get_virtual_machine_interface_refs()
                if vmi_refs:
                    self.remove_virtual_interface_of_instance_ip(
                        vmi_refs=vmi_refs,
                        logical_router=lr)
                LOGGER.info(
                    f"Removed Logical Router from Controller, uuid: {_uuid}")

    def create_routing(self, key_names: list[str] = None) -> None:
        cfg_routing = self._filter_cfg_by_keys(
            key_names=key_names,
            parent_dict="routing").copy()
        self._post_cfg_ctrl.update({"routing": {}})

        fq_name = cfg_routing.pop("fq_name", None)
        project = self.client.project_read(fq_name=fq_name)
        for routing_name, routing_cfg in cfg_routing.items():
            rt = vnc_api.RouteTable(name=routing_name,
                                    parent_obj=project)
            rt.set_display_name(routing_name)
            routes = vnc_api.RouteTableType()
            for _, prefix_cfg in routing_cfg.items():
                route = vnc_api.RouteType(
                    prefix=prefix_cfg["prefix"],
                    next_hop=prefix_cfg["next_hop"],
                    next_hop_type=prefix_cfg["next_hop_type"])
                routes.add_route(route)
                rt.set_routes(routes)
            _uuid = self.client.route_table_create(rt)
            self._post_cfg_ctrl["routing"][routing_name] = _uuid
            LOGGER.info(
                f"Added new Routing to Controller, uuid: {_uuid}")

    def del_routing(self) -> None:
        past_routing = self._post_cfg_ctrl.get("routing")
        if past_routing:
            for _, _uuid in past_routing.items():
                self.client.route_table_delete(id=_uuid)
                LOGGER.info(
                    f"Removed Routing from Controller, uuid: {_uuid}")

    def add_route_target_list_to_vn(self, route_target_list, vn):
        # Convert object to list
        try:
            rtl_obj = vn.get_route_target_list()
            rtl_list = rtl_obj.get_route_target()
        except AttributeError:
            rtl_list = []
        # Save past object to restore dict config
        self._post_cfg_ctrl.update({f"rtl_{vn.name}": rtl_obj})
        # Create a new list containing all values
        rtl_list = rtl_list + route_target_list
        # Add new list to current config virtual netowrk
        new_rtl = vnc_api.RouteTargetList(route_target=rtl_list)
        vn.set_route_target_list(new_rtl)

    def add_export_route_target_list_to_vn(self, export_route_target_list, vn):
        # Convert object to list
        try:
            ertl_obj = vn.get_export_route_target_list()
            ertl_list = ertl_obj.get_route_target()
        except AttributeError:
            ertl_list = []
        # Save past object to restore dict config
        self._post_cfg_ctrl.update({f"ertl_{vn.name}": ertl_obj})
        # Create a new list containing all values
        ertl_list = ertl_list + export_route_target_list
        # Add new list to current config virtual netowrk
        new_ertl = vnc_api.RouteTargetList(route_target=ertl_list)
        vn.set_export_route_target_list(new_ertl)

    def add_import_route_target_list_to_vn(self, import_route_target_list, vn):
        # Convert object to list
        try:
            irtl_obj = vn.get_import_route_target_list()
            irtl_list = irtl_obj.get_route_target()
        except AttributeError:
            irtl_list = []
        # Save past object to restore dict config
        self._post_cfg_ctrl.update({f"irtl_{vn.name}": irtl_obj})
        # Create a new list containing all values
        irtl_list = irtl_list + import_route_target_list
        # Add new list to current config virtual netowrk
        new_irtl = vnc_api.RouteTargetList(route_target=irtl_list)
        vn.set_import_route_target_list(new_irtl)

    def cfg_virtual_network(self, key_names: list[str] = None) -> None:
        cfg_virtual_networks = self._filter_cfg_by_keys(
            key_names=key_names,
            parent_dict="cfg_virtual_networks")

        for _, vn_cfg in cfg_virtual_networks.items():
            vn = self.client.virtual_network_read(fq_name=vn_cfg["fq_name"])
            ref_route_table = vn_cfg.get("route_table")
            if ref_route_table:
                rt = self.client.route_table_read(
                    fq_name=vn_cfg["route_table"])
                vn.add_route_table(rt)
                vn_cfg["route_table_uuid"] = str(rt.uuid)
            route_target_list = vn_cfg.get("route_target_list")
            if route_target_list:
                self.add_route_target_list_to_vn(
                    route_target_list=route_target_list,
                    vn=vn)
            import_route_target_list = vn_cfg.get("import_route_target_list")
            if import_route_target_list:
                self.add_import_route_target_list_to_vn(
                    import_route_target_list=import_route_target_list,
                    vn=vn)
            export_route_target_list = vn_cfg.get(
                "export_route_target_list")
            if export_route_target_list:
                self.add_export_route_target_list_to_vn(
                    export_route_target_list=export_route_target_list,
                    vn=vn)
            self.client.virtual_network_update(vn)
            LOGGER.info("Configured Virtual Network in the Controller")

    def restore_virtual_network(self, key_names: list[str] = None) -> None:
        cfg_virtual_networks = self._filter_cfg_by_keys(
            key_names=key_names,
            parent_dict="cfg_virtual_networks")

        if cfg_virtual_networks:
            for _, vn_cfg in cfg_virtual_networks.items():
                vn = self.client.virtual_network_read(
                    fq_name=vn_cfg["fq_name"])
                # Remove ipam from virtual network
                ipam = vn_cfg.get("ipam")
                if ipam:
                    ipam_uuid = ipam.get("uuid")
                    if ipam_uuid:
                        vn_ipam = self.client.network_ipam_read(id=ipam_uuid)
                        vn.del_network_ipam(vn_ipam)
                # Remove route table from virtual network
                if vn_cfg.get("route_table_uuid"):
                    rt_uuid = vn_cfg.get("route_table_uuid")
                    if rt_uuid:
                        rt = self.client.route_table_read(id=rt_uuid)
                        vn.del_route_table(rt)
                # Remove route_target_list from virtual network
                if vn_cfg.get("route_target_list"):
                    vn.route_target_list = (
                        self._post_cfg_ctrl.get(f"rtl_{vn.name}"))
                # Remove import route_target_list from virtual network
                if vn_cfg.get("import_route_target_list"):
                    vn.import_route_target_list = (
                        self._post_cfg_ctrl.get(f"irtl_{vn.name}"))
                # Remove export route_target_list from virtual network
                if vn_cfg.get("export_route_target_list"):
                    vn.export_route_target_list = (
                        self._post_cfg_ctrl.get(f"ertl_{vn.name}"))
                # Restore Virtual Netowrk
                self.client.virtual_network_update(vn)
                LOGGER.info(
                    "Restored Virtual Network configuration in the Controller")

    def cfg_virtual_machine_interface(self, key_names=None):
        cfg_vm_iface = self._filter_cfg_by_keys(
            key_names=key_names,
            parent_dict="cfg_virtual_machine_interfaces")

        for _, vn_cfg in cfg_vm_iface.items():
            vmi = self.client.virtual_machine_interface_read(
                fq_name=vn_cfg["fq_name"])
            alwd_addrs_pairs_cfg = vn_cfg.get("allowed_address_pairs")
            if alwd_addrs_pairs_cfg:
                prefix, prefix_len = alwd_addrs_pairs_cfg["cidr"].split('/')
                addr_pair = vnc_api.AllowedAddressPairs(
                    allowed_address_pair=[
                        vnc_api.AllowedAddressPair(
                            ip=vnc_api.SubnetType(prefix, prefix_len),
                            mac=alwd_addrs_pairs_cfg["mac"],
                            address_mode=alwd_addrs_pairs_cfg["address_mode"])
                    ])
                vmi.set_virtual_machine_interface_allowed_address_pairs(
                    addr_pair)
            self.client.virtual_machine_interface_update(vmi)
            LOGGER.info(
                "Configured Virtual Network Interface in the Controller")

    def restore_virtual_machine_interface(self, key_names=None):
        cfg_vm_iface = self._filter_cfg_by_keys(
            key_names=key_names,
            parent_dict="cfg_virtual_machine_interfaces")

        if cfg_vm_iface:
            for _, vn_cfg in cfg_vm_iface.items():
                vmi = self.client.virtual_machine_interface_read(
                    fq_name=vn_cfg["fq_name"])
                vmi.virtual_machine_interface_allowed_address_pairs = []
                self.client.virtual_machine_interface_update(vmi)
                LOGGER.info(
                    "Restored Virtual Network configuration Interface"
                    "in the Controller")

    def _get_instance_ip(self, instance_parms):
        instance_ip_uuid = instance_parms["uuid"]
        inst_ip_obj = self.client.instance_ip_read(id=instance_ip_uuid)
        return inst_ip_obj.instance_ip_address

    def get_interface_obj(self, ip_addr):

        def _filter_instance_ip(instance_param):
            if (instance_param is not None and
                    self._get_instance_ip(instance_param) == ip_addr):
                return instance_param
            return False

        vmil = self.client.virtual_machine_interfaces_list()
        for interface in vmil["virtual-machine-interfaces"]:
            uuid_interface = interface["uuid"]
            interface_obj = self.client.virtual_machine_interface_read(
                id=uuid_interface)
            instance_params = interface_obj.get_instance_ip_back_refs()
            if instance_params is not None:
                if next(filter(_filter_instance_ip, instance_params), False):
                    return interface_obj
        raise Exception("Virtual Interface doesn't exists")

    def add_mirror_to_virtual_interface(self,
                                        setup: int,
                                        traffic_direction_mirror: str) -> None:
        cfg_mirror = self.config["mirror"][setup]
        LOGGER.debug(f"Setup Mirroring in Controller of config:{cfg_mirror}")
        interface_obj = self.get_interface_obj(
            ip_addr=cfg_mirror["floating_ip_fixed_ip_address"])
        mirror_obj = vnc_api.MirrorActionType(
            routing_instance=cfg_mirror["routing_instance"],
            analyzer_name=cfg_mirror["analyzer_name"],
            analyzer_ip_address=cfg_mirror["analyzer_ip_address"],
            analyzer_mac_address=cfg_mirror["analyzer_mac_address"],
            juniper_header=cfg_mirror["juniper_header"],
            nh_mode=cfg_mirror["nh_mode"],
            nic_assisted_mirroring=cfg_mirror["nic_assisted_mirroring"])
        interface_type = vnc_api.InterfaceMirrorType(
            traffic_direction=traffic_direction_mirror,
            mirror_to=mirror_obj)
        interface_obj.set_virtual_machine_interface_properties(
            vnc_api.VirtualMachineInterfacePropertiesType(
                interface_mirror=interface_type))
        self.client.virtual_machine_interface_update(
            interface_obj)

    def del_mirroring_from_virtual_interface(self, setup: int) -> None:
        cfg_mirror = self.config["mirror"][setup]
        interface_obj = self.get_interface_obj(
            ip_addr=cfg_mirror["floating_ip_fixed_ip_address"])
        obj_properties = interface_obj.virtual_machine_interface_properties
        try:
            obj_mirror = obj_properties.get_interface_mirror()
        except AttributeError:
            obj_mirror = None
        finally:
            self.del_mirror_instance_from_obj(
                obj_mirror=obj_mirror,
                interface_obj=interface_obj,
                obj_properties=obj_properties,
                analyzer_name=cfg_mirror["analyzer_name"])

    def get_analyzer_name(self, obj_properties):
        try:
            obj_an = obj_properties.interface_mirror.mirror_to.analyzer_name
        except AttributeError:
            obj_an = None
        return obj_an

    def del_mirror_instance_from_obj(self, obj_mirror, interface_obj,
                                     obj_properties, analyzer_name):
        obj_an = self.get_analyzer_name(obj_properties=obj_properties)
        if (obj_mirror and obj_an == analyzer_name):
            interface_obj.set_virtual_machine_interface_properties(
                vnc_api.VirtualMachineInterfacePropertiesType(
                    interface_mirror=None))
            self.client.virtual_machine_interface_update(interface_obj)
            LOGGER.info(" ".join(["Mirroring from virtual interface:",
                                  interface_obj.display_name,
                                  " removed"]))
        else:
            LOGGER.info(" ".join(["Mirroring for a Virtual Interface: ",
                                  interface_obj.display_name,
                                  "doesn't exists"]))

    def create_new_policy_via_json(self, type_policy: str, setup: str) -> None:
        cfg_setup = self.config["policy"][type_policy][setup]
        cfg_policy = cfg_setup["params_policy"]
        try:
            header = {"content-type": "application/json; charset=UTF-8"}
            url = "".join(
                ["http://", self.config["ip_mgmt"], ":8082/network-policys"])
            respone = requests.post(
                url=url, headers=header, data=json.dumps(cfg_policy))
            LOGGER.info(
                f"Create new policy: "
                f"{json.loads(respone.text)['network-policy']['uuid']}")
        except ValueError:
            LOGGER.error(f"Cannot create a policy: {json.loads(respone.text)}")

    def add_policy_to_networks(self, type_policy: str, setup: str) -> None:
        cfg_setup = self.config["policy"][type_policy][setup]
        cfg_policy = cfg_setup["params_policy"]
        fq_name_vns = cfg_setup["setup_to_virtual_networks"]
        fq_name_policy = cfg_policy["network-policy"]["fq_name"]
        for _, fq_name_vn in fq_name_vns.items():
            vn = self.client.virtual_network_read(
                fq_name=fq_name_vn)
            policy_obj = self.client.network_policy_read(
                fq_name=fq_name_policy)
            vn.add_network_policy(policy_obj,
                                  vnc_api.VirtualNetworkPolicyType(
                                      sequence=vnc_api.SequenceType(0, 0)))
            self.client.virtual_network_update(vn)
            LOGGER.info(f"Added policy {policy_obj.name} "
                        f"to virtual network {vn.name}")

    def del_policy_from_network(self, type_policy: str, setup: str) -> None:
        cfg_setup = self.config["policy"][type_policy][setup]
        cfg_policy = cfg_setup["params_policy"]
        fq_name_vns = cfg_setup["setup_to_virtual_networks"]
        fq_name_policy = cfg_policy["network-policy"]["fq_name"]
        for _, fq_name_vn in fq_name_vns.items():
            vn = self.client.virtual_network_read(fq_name=fq_name_vn)
            policy_obj = self.client.network_policy_read(
                fq_name=fq_name_policy)
            vn.del_network_policy(policy_obj)
            self.client.virtual_network_update(vn)
            LOGGER.info(f"Removed the policy {policy_obj.name} "
                        f"from virtual network {vn.name}")

    def del_network_policy(self, type_policy: str, setup: str) -> None:
        cfg_setup = self.config["policy"][type_policy][setup]
        cfg_policy = cfg_setup["params_policy"]
        fq_name_policy = cfg_policy["network-policy"]["fq_name"]
        self.client.network_policy_delete(fq_name=fq_name_policy)
        LOGGER.info(f"Removed the policy {fq_name_policy}")

    def get_project(self, setup):
        fq_name = self.config["floating"][setup]["project"]
        return self.client.project_read(fq_name=fq_name)

    def add_permissions_floating_ip(self, setup):
        cfg_perms = self.config["floating"][setup]["permissions"]
        owner = cfg_perms["owner"]
        owner_access = cfg_perms["owner_access"]
        tenant_access = cfg_perms["tenant_access"]
        return vnc_api.PermType2(
            owner=owner,
            owner_access=owner_access,
            share=[vnc_api.ShareType(tenant=self.get_project(setup).get_uuid(),
                                     tenant_access=tenant_access)])

    def create_ipam(self, setup: int) -> None:
        new_ipam = self.config["floating"][setup]["new_ipam"]
        fq_name = new_ipam["fq_name"]
        parent_type = new_ipam["parent_type"]
        ipam_type = vnc_api.NetworkIpam(parent_type=parent_type,
                                        fq_name=fq_name)
        self.client.network_ipam_create(ipam_type)

    def ipam_subnet_type(self, setup):
        cfg_ipam_subnet = self.config["floating"][setup]["new_ipam"]
        default_gateway = cfg_ipam_subnet["subnet"]["default_gateway"]
        subnet, prefix = cfg_ipam_subnet["subnet"]["address"].split("/")
        dhcp = cfg_ipam_subnet["subnet"]["enable_dhcp"]
        return vnc_api.IpamSubnetType(
            default_gateway=default_gateway,
            subnet=vnc_api.SubnetType(subnet, prefix),
            enable_dhcp=dhcp)

    def add_ipam_to_virtual_network(self, setup: int) -> None:
        cfg_setup = self.config["floating"][setup]
        fq_name_ipam = cfg_setup["new_ipam"]["fq_name"]
        fq_name_vn = cfg_setup["virtual_network"]
        ipam_obj = self.client.network_ipam_read(fq_name=fq_name_ipam)
        vn = self.client.virtual_network_read(fq_name=fq_name_vn)
        vn.add_network_ipam(
            ipam_obj,
            vnc_api.VnSubnetsType([self.ipam_subnet_type(setup)]))
        self.client.virtual_network_update(vn)

    def add_floating_ip_pools(self, setup):
        cfg_setup = self.config["floating"][setup]
        fq_name_vn = cfg_setup["virtual_network"]
        ip_pool_name = cfg_setup["ip_pool"]["name"]
        permissions = self.add_permissions_floating_ip(setup)
        vn = self.client.virtual_network_read(fq_name=fq_name_vn)
        fip_pool_obj = vnc_api.FloatingIpPool(parent_obj=vn,
                                              name=ip_pool_name,
                                              perms2=permissions)
        self.client.floating_ip_pool_create(fip_pool_obj)
        return fip_pool_obj

    def create_floating_ip(self, setup: int) -> None:
        cfg_setup = self.config["floating"][setup]
        floating_ip_fixed = cfg_setup["floating_ip_fixed_ip_address"]
        floating_ip_name = cfg_setup["floating_ip_name"]
        floating_ip_public = cfg_setup["floating_ip_public"]
        parent_type = cfg_setup["parent_type"]

        interface_obj = self.get_interface_obj(ip_addr=floating_ip_fixed)

        fip = vnc_api.FloatingIp(
            floating_ip_address=floating_ip_public,
            name=floating_ip_name,
            parent_type=parent_type,
            parent_obj=self.add_floating_ip_pools(setup),
            floating_ip_fixed_ip_address=floating_ip_fixed)
        fip.add_project(ref_obj=self.get_project(setup))
        fip.add_virtual_machine_interface(interface_obj)
        self.client.floating_ip_create(fip)

    def remove_floating_ip(self, setup: int) -> None:
        cfg_setup = self.config["floating"][setup]
        fq_name = cfg_setup["virtual_network"].copy()
        fq_name.append(cfg_setup["ip_pool"]["name"])
        fq_name.append(cfg_setup["floating_ip_name"])
        try:
            self.client.floating_ip_delete(fq_name=fq_name)
        except exceptions.NoIdError:
            LOGGER.warning("No such floating ip")

    def remove_floating_ip_pool(self, setup):
        cfg_setup = self.config["floating"][setup]
        fq_name = cfg_setup["virtual_network"].copy()
        fq_name.append(cfg_setup["ip_pool"]["name"])
        try:
            self.client.floating_ip_pool_delete(fq_name=fq_name)
        except exceptions.NoIdError:
            LOGGER.warning("No such floating ip pool")

    def remove_network_ipam_from_virtual_network(self, setup):
        cfg_setup = self.config["floating"][setup]
        fq_name = cfg_setup["virtual_network"]
        fq_name_ipam = cfg_setup["new_ipam"]["fq_name"]
        try:
            vn = self.client.virtual_network_read(fq_name=fq_name)
            ipam_obj = self.client.network_ipam_read(fq_name=fq_name_ipam)
            vn.del_network_ipam(ipam_obj)
            self.client.virtual_network_update(vn)
        except exceptions.NoIdError:
            LOGGER.warning("No such netowrk ipam in the virtual network")

    def remove_network_ipam(self, setup):
        cfg_setup = self.config["floating"][setup]
        fq_name_ipam = cfg_setup["new_ipam"]["fq_name"]
        try:
            self.client.network_ipam_delete(fq_name=fq_name_ipam)
        except exceptions.NoIdError:
            LOGGER.warning("No such netowrk ipam")

    def create_health_check_service(self, setup):
        cfg_setup = self.config["service_health_check"][setup].copy()
        self._post_cfg_ctrl.update({"service_health_check": {}})
        LOGGER.debug(
            f"Try add new Service Health Check:\n {yaml.dump(cfg_setup)}")
        fq_name = cfg_setup.pop("fq_name")

        service_health_check = vnc_api.ServiceHealthCheck()
        service_health_check.fq_name = fq_name
        service_health_check.set_display_name(fq_name[-1])
        service_health_check_param = vnc_api.ServiceHealthCheckType(
            **cfg_setup["properties"])
        service_health_check.set_service_health_check_properties(
            service_health_check_param)
        _uuid = self.client.service_health_check_create(service_health_check)
        if cfg_setup.get("virtual_interface"):
            self.add_health_check_service_to_virtual_interface(
                obj_service_health_check=service_health_check,
                ip_virtual_interface=cfg_setup["virtual_interface"])
        self._post_cfg_ctrl["service_health_check"][setup] = _uuid
        return _uuid

    def remove_health_check_service(self, setup):
        cfg_setup = self.config["service_health_check"][setup].copy()
        past_routing = self._post_cfg_ctrl.get("service_health_check")
        if past_routing:
            for _, _uuid in past_routing.items():
                LOGGER.info(f"Try remove Service Health Check "
                            f"from Controller, uuid: {_uuid}")
                if cfg_setup.get("virtual_interface"):
                    self.del_health_check_service_from_virtual_interface(
                        uuid_helath_check_service=_uuid,
                        ip_virtual_interface=cfg_setup["virtual_interface"])
                self.client.service_health_check_delete(id=_uuid)
                LOGGER.info(f"Removed Service Health Check "
                            f"from Controller, uuid: {_uuid}")

    def add_health_check_service_to_virtual_interface(self,
                                                      obj_service_health_check,
                                                      ip_virtual_interface):
        obj_vi = self.get_interface_obj(
            ip_addr=ip_virtual_interface)
        LOGGER.info(
            f"Try add Service Health Check {obj_service_health_check.uuid} "
            f"to virtual machine interface {obj_vi.uuid}")
        obj_vi.set_service_health_check(obj_service_health_check)
        self.client.virtual_machine_interface_update(obj_vi)
        LOGGER.info(
            f"Added Service Health Check {obj_service_health_check.uuid} "
            f"to virtual machine interface {obj_vi.uuid}")

    def del_health_check_service_from_virtual_interface(
            self, uuid_helath_check_service, ip_virtual_interface):
        obj_vi = self.get_interface_obj(ip_addr=ip_virtual_interface)
        obj_service_health_check = self.client.service_health_check_read(
            id=uuid_helath_check_service)
        LOGGER.info(
            f"Try remove Service Health Check {obj_service_health_check.uuid} "
            f"to virtual machine interface {obj_vi.uuid}")
        obj_vi.del_service_health_check(obj_service_health_check)
        self.client.virtual_machine_interface_update(obj_vi)
        LOGGER.info(
            f"Removed Service Health Check {obj_service_health_check.uuid} "
            f"to virtual machine interface {obj_vi.uuid}")

    def get_ipam_refs_of_network(self,
                                 network_name,
                                 fq_ipam=[
                                     "default-domain",
                                     "admin",
                                     'default-network-ipam']):
        net = self.client.virtual_network_read(
            fq_name=["default-domain", "admin", network_name])
        ipam_refs = net.get_network_ipam_refs()
        for ipam in ipam_refs:
            if ipam['to'] == fq_ipam:
                LOGGER.info(
                    f"Found ipam refs {ipam} for network {network_name}")
                return ipam
        LOGGER.warning(f"No such ipam refs in netowrk {network_name}")

    def get_ipam_subnet_of_network(self, network_name, ip_addr):
        _ipam_refs = self.get_ipam_refs_of_network(
            network_name=network_name)
        for ipam_subnet in _ipam_refs['attr'].ipam_subnets:
            cidr = '/'.join(
                [ipam_subnet.subnet.ip_prefix,
                 str(ipam_subnet.subnet.ip_prefix_len)])
            if ip_address(ip_addr) in ip_network(cidr):
                LOGGER.info(f"Found Ipam subnet for network {network_name}")
                return ipam_subnet
        LOGGER.info(f"No such ipam subnet in network {network_name}")
        return False

    def get_ipam_ip_prefix_of_network(self, network_name, ip_addr):
        _ipam_ip_prefix = self.get_ipam_subnet_of_network(
            network_name=network_name,
            ip_addr=ip_addr)
        if _ipam_ip_prefix:
            LOGGER.info(
                f"Found ipam ip prefix {_ipam_ip_prefix.subnet.ip_prefix} "
                f" for network {network_name}")
            return (
                f"{_ipam_ip_prefix.subnet.ip_prefix}/"
                f"{_ipam_ip_prefix.subnet.ip_prefix_len}")
        raise ApiControllerError(
            f"No such ip prefix for network {network_name}")

    def get_default_gateway_by_ip(self, network_name, ip_addr):
        _ipam_subnet = self.get_ipam_subnet_of_network(
            network_name=network_name,
            ip_addr=ip_addr)
        if _ipam_subnet:
            LOGGER.info(f"Default gateway: {_ipam_subnet.default_gateway}"
                        f" for network name: {network_name}")
            return _ipam_subnet.default_gateway
        raise ApiControllerError(f"No such gateway for network {network_name}")

    def add_bgp_as_a_service_to_virtual_interface(self,
                                                  ip_virtual_interface,
                                                  bgp_service_obj=None,
                                                  bgp_service_uuid=None):
        if bgp_service_uuid is None and bgp_service_obj is None:
            raise ApiControllerError(
                "Please add args: 'bgp_service_obj' or 'bgp_service_uuid'")
        obj_vi = self.get_interface_obj(ip_addr=ip_virtual_interface)
        bgp_service_obj = (
            bgp_service_obj if bgp_service_obj is not None
            else self.client.bgp_as_a_service_read(id=bgp_service_uuid))
        LOGGER.info(f"Try add BGP as a service {bgp_service_obj.uuid} "
                    f"to virtual machine interface {obj_vi.uuid}")
        bgp_service_obj.add_virtual_machine_interface(obj_vi)
        self.client.bgp_as_a_service_update(bgp_service_obj)
        LOGGER.info(f"Added BGP as a service {bgp_service_obj.uuid} "
                    f"to virtual machine interface {obj_vi.uuid}")

    def remove_bgp_as_a_service(self, setup, ip_virtual_interface):
        bgp_service_uuid = self._post_cfg_ctrl["bgp_as_a_service"][setup]
        bgp_service_obj = self.client.bgp_as_a_service_read(
            id=bgp_service_uuid)
        LOGGER.info(f"Try remove BGP as a service "
                    f"from Controller, uuid: {bgp_service_uuid}")
        if bgp_service_obj.get_virtual_machine_interface_refs():
            self.del_bgp_as_a_service_from_virtual_interface(
                bgp_service_uuid=bgp_service_uuid,
                ip_virtual_interface=ip_virtual_interface)
        self.client.bgp_as_a_service_delete(id=bgp_service_uuid)
        LOGGER.info(f"Removed BGP as a service "
                    f"from Controller, uuid: {bgp_service_uuid}")

    def del_bgp_as_a_service_from_virtual_interface(self,
                                                    bgp_service_uuid,
                                                    ip_virtual_interface):
        obj_vi = self.get_interface_obj(ip_addr=ip_virtual_interface)
        bgp_service_obj = self.client.bgp_as_a_service_read(
            id=bgp_service_uuid)
        LOGGER.info(f"Try remove BGP as a service {bgp_service_obj.uuid} "
                    f"from virtual machine interface {obj_vi.uuid}")
        bgp_service_obj.del_virtual_machine_interface(obj_vi)
        self.client.bgp_as_a_service_update(bgp_service_obj)
        LOGGER.info(f"Removed BGP as a service {bgp_service_obj.uuid} "
                    f"from virtual machine interface {obj_vi.uuid}")

    def create_bgp_service(self, setup):
        cfg_setup = self.config["bgp_as_a_service"][setup].copy()
        self._post_cfg_ctrl.update({"bgp_as_a_service": {}})
        LOGGER.debug(f"Try add new BGP as a service:\n {yaml.dump(cfg_setup)}")
        fq_name = cfg_setup.pop("fq_name")

        cfg_setup_prop = cfg_setup.get("properties")

        bgp_service_obj = vnc_api.BgpAsAService()
        bgp_service_obj.fq_name = fq_name
        bgp_service_obj.set_display_name(fq_name[-1])

        if cfg_setup_prop is not None:
            bgp_service_obj.set_autonomous_system(
                cfg_setup_prop.get("autonomous_system"))
            bgp_service_obj.set_bgpaas_shared(
                cfg_setup_prop.get("bgpaas_shared"))
            bgp_service_obj.set_bgpaas_ipv4_mapped_ipv6_nexthop(
                cfg_setup_prop.get("bgpaas_ipv4_mapped_ipv6_nexthop"))
            bgp_service_obj.set_bgpaas_suppress_route_advertisement(
                cfg_setup_prop.get("bgpaas_suppress_route_advertisement"))
        if cfg_setup.get("bgpaas_session_attributes"):
            bgp_service_obj.set_bgpaas_session_attributes(
                self.add_bgpaas_session_attributes(
                    config=cfg_setup.get("bgpaas_session_attributes")))
        _uuid = self.client.bgp_as_a_service_create(bgp_service_obj)
        self._post_cfg_ctrl["bgp_as_a_service"][setup] = _uuid
        return _uuid

    def add_route_origin_override(self, config):
        bgp_route_origin_override = vnc_api.RouteOriginOverride()
        bgp_route_origin_override.set_origin_override(
            config.get("origin_override"))
        bgp_route_origin_override.set_origin(config.get("origin"))

    def add_prefix_limit(self, config):
        bgp_prefix_limit = vnc_api.BgpPrefixLimit()
        bgp_prefix_limit.set_maximum(config.get("maximum", 0))
        return bgp_prefix_limit

    def _get_bgp_family_attributes(self,
                                   config: dict,
                                   address_family: Optional[str]
                                   ) -> vnc_api.BgpFamilyAttributes:
        bgp_family_attr = vnc_api.BgpFamilyAttributes()
        bgp_family_attr.set_address_family(address_family)
        bgp_family_attr.set_loop_count(config.get("loop_count"))
        if config.get("prefix_limit"):
            bgp_family_attr.set_prefix_limit(self.add_prefix_limit(
                config.get("prefix_limit")))
        return bgp_family_attr

    def add_bgp_family_attributes(self, config: dict) -> list[
        vnc_api.BgpFamilyAttributes]:
        bgp_family_attributes = []
        address_family = config.get("address_family")
        if isinstance(address_family, list):
            for family in address_family:
                family_attribute = self._get_bgp_family_attributes(
                    config=config, address_family=family)
                bgp_family_attributes.append(family_attribute)
        if not isinstance(address_family, list):
            family_attribute = self._get_bgp_family_attributes(
                config=config, address_family=address_family)
            bgp_family_attributes.append(family_attribute)
        return bgp_family_attributes

    def add_bgpaas_session_attributes(self, config):
        bgp_session_attr = vnc_api.BgpSessionAttributes()
        bgp_session_attr.set_admin_down(
            config.get("admin_down", False))
        bgp_session_attr.set_passive(
            config.get("passive", False))
        bgp_session_attr.set_as_override(
            config.get("as_override", False))
        bgp_session_attr.set_hold_time(
            config.get("hold_time", 0))
        bgp_session_attr.set_loop_count(
            config.get("loop_count", 0))
        bgp_session_attr.set_local_autonomous_system(
            config.get("local_autonomous_system", 0))
        if config.get("address_families"):
            family = config.get("address_families").get("family")
            if family is not None:
                family_obj = vnc_api.AddressFamilies()
                for family_element in family:
                    family_obj.add_family(family_element)
                    bgp_session_attr.set_address_families(family_obj)
        if config.get("family_attributes"):
            bgp_session_attr.set_family_attributes(
                self.add_bgp_family_attributes(
                    config.get("family_attributes")))
        if config.get("route_origin_override"):
            bgp_session_attr.set_route_origin_override(
                self.add_route_origin_override(
                    config.get("route_origin_override")))
        return bgp_session_attr

    def get_default_bgp_router(self):
        bgp_routers = self.client.bgp_routers_list().get("bgp-routers")
        if bgp_routers:
            for bgp_router in bgp_routers:
                if bgp_router.get("fq_name").count("__default__"):
                    return bgp_router
        raise ApiControllerError("Please add default BGP router to controller")

    def get_bgp_router_autonomous_system(self):
        defualt_bgp_router = self.get_default_bgp_router()
        bgp_router_obj = self.client.bgp_router_read(
            fq_name=defualt_bgp_router.get("fq_name"))
        bgp_router_param = bgp_router_obj.get_bgp_router_parameters()
        return bgp_router_param.get_autonomous_system()

    def _filter_cfg_by_keys(self, key_names, parent_dict):
        cfg = self._config[parent_dict]  # type: ignore[index]
        if key_names is not None:
            filter_dict = {k: v for k, v in cfg.items() if k in key_names}
            LOGGER.info(
                f"Filter config[{parent_dict}] from:\n{yaml.dump(cfg)}\n "
                f"to:\n{yaml.dump(filter_dict)}")
            if filter_dict:
                return filter_dict
            raise ApiControllerError(
                f"Incorrectly group {parent_dict} in config yaml file")
        return cfg