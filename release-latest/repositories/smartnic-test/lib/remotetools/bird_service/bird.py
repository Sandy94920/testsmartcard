import logging
import os
import time
from abc import ABCMeta, abstractmethod
from random import randint
from shutil import rmtree
from typing import TYPE_CHECKING, Callable, Optional

import jinja2

if TYPE_CHECKING:
    from lib.connections import Docker

LOGGER = logging.getLogger(__name__)
_ID_DIR_BIRD_CFG = f"id_path_{randint(0, 1000)}"
VM_2MX_NETWORK_PARAMS = {
    "TREX1_NH": "172.30.1.4",
    "TREX2_NH": "172.30.2.4",
    "TREX1_NH_IPv6": "2001:db8:0:1::4",
    "TREX2_NH_IPv6": "2001:db8:0:2::4",
    "MX1a": "172.30.1.1",
    "MX1b": "172.30.2.1",
    "MX2a": "172.30.1.2",
    "MX2b": "172.30.2.2",
    "AS": "64513",
    "MX_AS": "64512",
    "NO_PREFIX": 16384
}


class CustomJinjaFunctions:

    class AbstractFilter(metaclass=ABCMeta):
        @property
        @abstractmethod
        def name(self) -> str:
            pass

        @property
        @abstractmethod
        def func(self) -> Callable:
            pass

    class IntToHex(AbstractFilter):
        name: str = "hex"
        func: Callable = lambda x: f'{x:1x}'


class CfgBird:
    cfg_dir = f"{_ID_DIR_BIRD_CFG}_bird"
    cfg_bird_filename = "bird.conf"
    cfg_bird_file = os.path.join(os.getcwd(), cfg_dir, cfg_bird_filename)
    cfg_bgp_tmpl = "./lib/remotetools/bird_service/bird_bgp.j2"

    def _create_dir_path_if_not_existent(self):
        if not os.path.exists(CfgBird.cfg_bird_file):
            os.makedirs(os.path.dirname(CfgBird.cfg_bird_file))
            LOGGER.debug(
                f"Config Bird file has been created: {CfgBird.cfg_bird_file}")

    def get_cfg_temp(
            self,
            tmplt_path: str = "./lib/remotetools/bird_service/bird_config.j2",
            log_debug: bool = True,
            custom_filter: CustomJinjaFunctions.AbstractFilter = None,
            **kwargs) -> str:
        env = jinja2.Environment(loader=jinja2.FileSystemLoader('./'))
        if custom_filter is not None:
            self.add_custom_filter(env=env, filter=custom_filter)
        template = env.get_template(tmplt_path)
        bird_config = template.render(kwargs)
        if log_debug:
            LOGGER.debug(f"Bird config file:\n {bird_config}")
        return bird_config

    def create_bird_cfg_file(self,
                             neighbor: str,
                             multiplier: int = 3,
                             interval: int = 300) -> None:
        self._create_dir_path_if_not_existent()
        with open(CfgBird.cfg_bird_file, "w+") as cfg_file:
            cfg_file.write(self.get_cfg_temp(
                multiplier=multiplier,
                interval=interval,
                neighbor=neighbor))

    def create_bird_vm_2mx_cfg_file(
            self,
            custom_filter: CustomJinjaFunctions.AbstractFilter = None
            ) -> str:
        tmplt_path = "./lib/remotetools/bird_service/vm_2mx_bird_config.j2"
        self._create_dir_path_if_not_existent()
        with open(CfgBird.cfg_bird_file, "w+") as cfg_file:
            cfg = self.get_cfg_temp(tmplt_path=tmplt_path, log_debug=False,
                                    custom_filter=custom_filter,
                                    **VM_2MX_NETWORK_PARAMS)
            cfg_file.write(cfg)
        return cfg

    def create_bird_bgp_cfg_file(self,
                                 local_ip: str,
                                 contrail_ip: str,
                                 lo_ip: str,
                                 local_as: int,
                                 contrail_as: int = 64512) -> None:
        self._create_dir_path_if_not_existent()
        with open(CfgBird.cfg_bird_file, "w+") as cfg_file:
            bird_config = self.get_cfg_temp(
                tmplt_path=CfgBird.cfg_bgp_tmpl,
                local_ip=local_ip,
                contrail_ip=contrail_ip,
                lo_ip=lo_ip,
                local_as=local_as,
                contrail_as=contrail_as)
            cfg_file.write(bird_config)

    def rm_bird_cfg_file(self) -> None:
        rmtree(CfgBird.cfg_dir)

    def get_neighbor(self, ip_addr: str) -> str:
        list_ip_addr = ip_addr.split(".")
        list_ip_addr[-1] = '254'
        return '.'.join(list_ip_addr)

    @staticmethod
    def add_custom_filter(env, filter):
        env.filters[filter.name] = filter.func


class BirdDocker:
    def __init__(self, docker: 'Docker'):
        self._bird_docker = docker

    def get_bird_status(self):
        return self._bird_docker.cmd_exec("birdcl show status")

    def is_up_and_running(self):
        match_string = "daemon is up and running"
        if match_string not in self.get_bird_status().lower():
            return False
        return True

    def wait_for_setup(self, timeout: int = 10) -> None:
        time0 = time.time()
        while time.time() - time0 < timeout:
            if self.is_up_and_running():
                return
            time.sleep(1)
        raise EnvironmentError("Bird container is not up and running")

    def show_protocols(self):
        return self.cmd_exec("birdcl show protocols | grep BGP")

    def are_all_established(self):
        for line in self.show_protocols().splitlines():
            if "established" not in line.lower():
                return False
        return True

    def is_any_rejected(self):
        for line in self.show_protocols().splitlines():
            if "connection rejected" in line.lower():
                return True
        return False

    def check_for_connection_reject(self, timeout: int = 10) -> Optional[str]:
        time0 = time.time()
        while time.time() - time0 < timeout:
            if self.is_any_rejected():
                return self.show_protocols()
            time.sleep(1)
        return None

    def wait_for_protocols_established(self, timeout: int = 10) -> None:
        time0 = time.time()
        while time.time() - time0 < timeout:
            if self.are_all_established():
                return
            time.sleep(1)
        raise EnvironmentError(f"Not all protocols established!\n"
                               f"{self.show_protocols()}")

    def cmd_exec(self, cmd: str) -> str:
        return self._bird_docker.cmd_exec(cmd)
    