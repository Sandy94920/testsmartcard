import json
import logging
from functools import wraps
from typing import Any, Optional

LOGGER = logging.getLogger(__name__)


class GlobalConfigError(Exception):
    pass


def wrap_missing_entry_err(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except (KeyError, IndexError) as err:
            raise GlobalConfigError(
                f'Missing entry ({err}) in configuration file') from err
    return wrapped


class GlobalConfigHandler:
    """
    Provides human-friendly way of accessing frequently-used
    global config keys
    """
    def __init__(self, config: dict):
        self._config = config

    @wrap_missing_entry_err
    def get_device_name(self) -> str:
        return self.get_dpdkapp_cfg("vdev")["mgmt"]

    @wrap_missing_entry_err
    def get_config_floating_ip_public(self, setup: int) -> str:
        cfg_ctrl = self._get_controller_config()
        cfg_routing = cfg_ctrl["floating"][setup]
        floating_ip_public = cfg_routing["floating_ip_public"]
        return floating_ip_public

    @wrap_missing_entry_err
    def get_trex_cfg(self, key: Optional[str] = None) -> dict[str, Any]:
        if key is not None:
            return self._config["trextestdirector"][key]
        return self._config["trextestdirector"]

    @wrap_missing_entry_err
    def get_dpdkapp_cfg(self, key: Optional[str] = None) -> dict[str, Any]:
        if key is not None:
            return self._config["dpdk_application"][key]
        return self._config["dpdk_application"]

    @wrap_missing_entry_err
    def get_config_floating_routing(self, setup: int) -> tuple[str, str]:
        cfg_ctrl = self._get_controller_config()
        cfg_routing = cfg_ctrl["floating"][setup]["routing"]
        ip_public_ipam = cfg_routing["ip_public_ipam"]
        ip_gateway = cfg_routing["ip_gateway"]
        return ip_public_ipam, ip_gateway

    @wrap_missing_entry_err
    def get_config_routing(self) -> tuple[str, str, str]:
        cfg_ctrl = self._get_controller_config()
        ip_public_ipam = cfg_ctrl["kernel_route_table"]["ip_public_ipam"]
        ip_gateway = cfg_ctrl["kernel_route_table"]["ip_gateway"]
        iface = cfg_ctrl["kernel_route_table"]["iface"]
        return ip_public_ipam, ip_gateway, iface

    @wrap_missing_entry_err
    def get_dpdk_bin_path(self) -> str:
        return self.get_dpdkapp_cfg("dpdk_bin_path")

    @wrap_missing_entry_err
    def get_number_of_flows_multi(self) -> int:
        return self.get_dpdkapp_cfg("n3ktt")["multi_flows"]

    @wrap_missing_entry_err
    def get_number_of_flows_performance(self) -> int:
        return self.get_dpdkapp_cfg("n3ktt")["performance_flows"]

    @wrap_missing_entry_err
    def port_ids(self) -> list[int]:
        return list(map(lambda x: x + 3,
                        json.loads(self.get_dpdkapp_cfg("vdev")["vfs"])))

    @wrap_missing_entry_err
    def _get_controller_config(self) -> dict[str, dict]:
        return self._config["controller"]