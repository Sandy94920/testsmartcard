import logging
from typing import TYPE_CHECKING, Any, Union
import yaml

from lib.remotetools.remote_app import RunExternalApp
from lib.utils import (
    get_trex_test_config,
    get_trex_test_scenario,
    save_results_to_csv_file,
    ReportFileData)
from lib.trex_engine.trextestdirector.trextestdirector import TrexStlScenario
from lib.trex_engine.trextestdirector.trextestdirector.rfc2544_scenario \
    import TrexScenarioError
from lib.trex_engine.trextestdirector.trextestdirector.utilities import (
    load_config)
from lib.trex_engine.trex_traffic_monitor import (
    TrexTrafficMonitor,
    TrafficRatioData)

if TYPE_CHECKING:
    from lib.global_config_handler import GlobalConfigHandler
    from lib.connections import Machine

logger = logging.getLogger(__name__)


class TrexTestRunnerError(Exception):
    pass


def run_test(
        global_config: 'GlobalConfigHandler',
        test_name: str,
        scenario_cfg: str,
        mx_scenario: str,
        scenario: str,
        get_encap_module: str,
        verify_n3k_dump: bool):
    trex_scenario = prepare_trex_scenario(
        global_config,
        test_name,
        scenario_cfg,
        mx_scenario,
        scenario,
        get_encap_module)
    try:
        trex_scenario.run()
    except TrexScenarioError as e:
        raise TrexTestRunnerError from e
    finally:
        save_results_to_csv_file(
            results=trex_scenario.statistics_csv,
            file_path=f"{ReportFileData.path}"
                      f"{trex_scenario.tests[0]['report_file_name']}"
                      f"_{mx_scenario}_{'w' if verify_n3k_dump else 'wo'}_"
                      f"offload{ReportFileData.extension}",
            headers=list(next(iter(trex_scenario.statistics_csv), {}).keys()))


def prepare_trex_scenario(
        global_config: 'GlobalConfigHandler',
        test_name: str,
        scenario_cfg: str,
        mx_scenario: str,
        scenario: str,
        get_encap_module: str) -> TrexStlScenario:
    logger.info(f"test_cfg: {test_name}")
    report_file_name = f"report_{test_name}_{get_encap_module}"
    test_cfg = update_test_cfg(
        trex_cfg=global_config.get_trex_cfg(key=get_encap_module),
        mx_scenario=mx_scenario,
        scenario_cfg=scenario_cfg,
        report_file_name=report_file_name,
        encap=get_encap_module)

    test_scenario = get_trex_test_scenario(scenario)
    trex_scenario = TrexStlScenario.load_trex_test_scenario(test_scenario)

    return trex_scenario(test_cfg)


def update_test_cfg(
        trex_cfg,
        scenario_cfg,
        mx_scenario,
        report_file_name,
        encap):
    test_config = get_trex_test_config(scenario_cfg)
    base_config = load_config(test_config)
    config = _update_servers_config(base_config, trex_cfg, mx_scenario)
    config["report_file_name"] = report_file_name
    config["static_route_scenario"] = mx_scenario
    logger.info(f"Trex test director cfg dump {yaml.dump(config)}")
    return config


def _update_servers_config(config, trex_cfg, mx_scenario):
    src_ip = trex_cfg["static_route_ips"][mx_scenario]["src_ip"]
    dst_ip = trex_cfg["static_route_ips"][mx_scenario]["dst_ip"]
    subnet_mask = trex_cfg["static_route_ips"][mx_scenario].get("subnet_mask")
    for cfg_server in trex_cfg["setup_servers"]:
        for port in cfg_server['ports']:
            if subnet_mask is not None:
                port.update({"subnet_mask": subnet_mask})
            if port["id"] == 0:
                port.update({"ip": src_ip, "default_gateway": dst_ip})
            else:
                port.update({"ip": dst_ip, "default_gateway": src_ip})

            port.update({"subnet_mask": subnet_mask})
    config["servers"] = trex_cfg["setup_servers"]
    return config


def start_trex(vm_ssh: 'Machine', config_trex: dict[str, Any],
               software_mode: Union[bool, str]) -> RunExternalApp:
    software_arg = "--software" if software_mode else ""
    cmd = (f"cd {config_trex['remote_path_trex']} && "
           f"sudo ./t-rex-64 -c 8 -i {software_arg}")
    app = RunExternalApp(
        vm_ssh=vm_ssh,
        app_name="t-rex-64")
    app.start(
        cmd=cmd,
        expected_line="-Global stats enabled \n")
    return app


def create_trex_cfg(vm_ssh: 'Machine', config_trex: dict[str, Any]) -> None:
    trex_cfg = config_trex.get("trex_cfg")
    file_name = 'trex_cfg.yaml'
    cmd = (f'echo "{yaml.dump(trex_cfg)}" | '
           f'sudo tee -a /etc/{file_name}')
    output, error = vm_ssh.get_sudo_cmd_output(cmd)
    if error:
        logger.error(error)
    else:
        logger.info(f"Created Trex config file via {output}")


def del_trex_cfg(vm_ssh: 'Machine') -> None:
    file_name = "trex_cfg.yaml"
    output, error = vm_ssh.get_sudo_cmd_output(f'rm /etc/{file_name}')
    if error:
        logger.error(error)
    else:
        logger.info("Trex config file removed")


def prepare_traffic_monitor(trex_scenario: TrexStlScenario, interval: float,
                            service_mode: bool
                            ) -> tuple[TrexTrafficMonitor, list]:
    traffic_monitor = TrexTrafficMonitor(
        client=trex_scenario.servers[0]["client"],
        interval=interval)
    traffic_monitor.register_total_pgid(
        trex_scenario.test_config["transmit"][0]["tunables"][
            "flow_traffic_pg_id"])
    capture_ids = []
    if service_mode:
        capture_ids = _register_bpf_filters(traffic_monitor,
                                            trex_scenario.test_config)
    return traffic_monitor, capture_ids


def _register_bpf_filters(traffic_monitor: TrexTrafficMonitor,
                          traffic_config: dict) -> list:
    cap_id_mx1 = traffic_monitor.register_bpf_filter(
        rx_port=1,
        bpf_filter=f"ether src "
                   f"{traffic_config.get('mac_addr_mx1')}")
    cap_id_mx2 = traffic_monitor.register_bpf_filter(
        rx_port=1,
        bpf_filter=f"ether src "
                   f"{traffic_config.get('mac_addr_mx2')}")
    return [cap_id_mx1, cap_id_mx2]


def wait_for_load_balance(traffic_monitor: TrexTrafficMonitor,
                          capture_ids: list[int], traffic_ratio: list[int],
                          timeout: int) -> None:
    expected_ratio = TrafficRatioData(
        {capture_ids[0]: traffic_ratio[0],
         capture_ids[1]: traffic_ratio[1]})
    traffic_monitor.wait_for_traffic_ratio(
        expected_traffic_ratio=expected_ratio,
        limit_time=1,
        tolerance=0.02,
        timeout=timeout,
        interval=1)