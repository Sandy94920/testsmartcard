import itertools
import logging
import os
import socket
from time import sleep

import pytest
import yaml
from retrying import retry
from typing import Generator, Any, TYPE_CHECKING, Callable

from lib.config import get_config
from lib.log_reciever import run_logger_server
from lib.remotetools.vrouter_agent import clear_flows_in_vrouter_agent
from lib.remotetools.n3k_dump_parser import get_n3k_flows
from lib.connections import (
    TestBed,
    DaemonHubs,
    VMerror)
from lib.controller import ControllerWrapper
from lib.global_config_handler import GlobalConfigHandler
from lib.remotetools.vrouter_parser.vrouter_parser import (FiveTuple,
                                                           VrouterParser)
from lib.remotetools.vrouter_tools import (set_vrouter_config_file,
                                           vrouter_instance_exists)
from lib.switch.switch import Switch
from lib.switch.switch_config_handler import SwitchConfigHandler
from lib.utils import Encapsulation

if TYPE_CHECKING:
    from lib.daemon.service_tcpdump import Tcpdump
    from lib.connections.vm import Vm
    from lib.daemon.daemon_hub import DaemonHub
    from _pytest.fixtures import FixtureRequest

LOGGER = logging.getLogger(__name__)
ENCAPSULATION = None
_SWITCH_OPERATION_FAILED = False


class ControllerConfigurationError(Exception):
    pass


class ClearFlowsError(Exception):
    pass


@pytest.fixture(scope="session")
def test_bed(request: 'FixtureRequest') -> Generator[TestBed, Any, None]:
    LOGGER.info("Configure the testbed.")
    config = get_config()
    yield TestBed(config)


@pytest.fixture(scope="session")
def ctrl_wrap(request: 'FixtureRequest') -> Generator[ControllerWrapper, Any, None]:
    LOGGER.info("ControllerWrapper initializing")
    config = get_config()
    yield ControllerWrapper(config)


@pytest.fixture()
def global_config(request: 'FixtureRequest') -> Generator[GlobalConfigHandler, Any, None]:
    LOGGER.info("Accessing Global Config")
    yield GlobalConfigHandler(get_config())


@pytest.fixture(scope="session", autouse=True)
def default_qfx_config() -> Generator:
    """Asserts default switch config at the beginning of test session"""

    def set_default_qfx_config():
        for cn in get_config()["compute"].values():
            config_handler = SwitchConfigHandler(
                cn_interfaces=cn["cn_interfaces"],
                ae_interface=cn.get("ae_interface"))
            switch = Switch(auth_data=qfx_config,
                            config_handler=config_handler)
            switch.restore_default_configuration()

    qfx_config = get_config().get("qfx")
    if qfx_config:
        LOGGER.info("QFX config given, setting default configuration")
        set_default_qfx_config()
    yield
    global _SWITCH_OPERATION_FAILED
    if qfx_config and _SWITCH_OPERATION_FAILED:
        LOGGER.critical("Switch operation has failed and QFX might be in "
                        "dirty state - attempting to restore defaults")
        set_default_qfx_config()


@pytest.fixture(scope="function", autouse=True)
def qfx_state_check() -> None:
    global _SWITCH_OPERATION_FAILED
    if _SWITCH_OPERATION_FAILED:
        msg = "QFX Switch may be in wrong state, skipping tests"
        LOGGER.error(msg)
        pytest.skip(msg)


@pytest.fixture(scope="session")
def _left_cn_switch_config() -> SwitchConfigHandler:
    config = get_config()
    cns = list(config["compute"].values())
    for cn_ in cns:
        if not cn_.get("ports"):
            cn = cn_
            break
    else:
        raise RuntimeError("All CNs have ports defined. "
                           "Cannot create configuratino for switch")
    return SwitchConfigHandler(cn_interfaces=cn["cn_interfaces"],
                               ae_interface=cn.get("ae_interface"))


@pytest.fixture(scope="function")
def left_cn_switch(_left_cn_switch_config: SwitchConfigHandler
                   ) -> Generator[Switch, None, None]:
    qfx_config = get_config().get("qfx")
    junos_switch = Switch(
        auth_data=qfx_config,
        config_handler=_left_cn_switch_config
    ) if qfx_config else None
    yield junos_switch
    try:
        if qfx_config:
            junos_switch.restore_default_configuration()
    except Exception as err:
        global _SWITCH_OPERATION_FAILED
        _SWITCH_OPERATION_FAILED = True
        LOGGER.exception(f'QFX Switch operation failed: {err}')
        raise


@pytest.fixture()
def restore_vrouter_config_file(request: 'FixtureRequest') -> Generator:
    yield
    LOGGER.info("Restore vRouter config file")
    set_vrouter_config_file(
        option="restore_old_config",
        **request.param)


@pytest.fixture(scope="function", autouse=True)
@pytest.mark.early
def encapsulation(encap: list[str], ctrl_wrap: ControllerWrapper) -> list[str]:
    """
    Fixture is responsible for setup priority encapsulation
    in the Controller: MPLS_GRE, MPLS_UDP or VxLAN.
    encap param should be passed to the fixuter with desired Encapsulation
    """
    global ENCAPSULATION
    LOGGER.info(f'Encapsulation priority: {encap}')
    if ENCAPSULATION is None:
        LOGGER.info('Setting encapsulation on the controller.')
        controller = ctrl_wrap.controller()
        controller.cfg_priorities_encapsulation(cfg_priority_encap=encap)
        ENCAPSULATION = encap
    return encap


@pytest.fixture(scope="function", autouse=True)
def lacp() -> None:
    """Required by pytest_generate_test to add (no)LACP parameter"""
    return None


@pytest.fixture(scope="function")
def setup_policy(request: 'FixtureRequest', ctrl_wrap: ControllerWrapper
                 ) -> Generator:
    """
    Fixture is responsible for setup policy in the Controller.
    :param setup: setup: number of setup from config yaml file
    :type setup: int
    :param type_policy: get configuration from yaml <policy>
        via the naming policy to use
    :type type_policy: string
    """

    def _teardown(controller):
        controller.del_policy_from_network(**request.param)
        controller.del_network_policy(**request.param)

    controller = ctrl_wrap.controller()
    try:
        controller.create_new_policy_via_json(**request.param)
        controller.add_policy_to_networks(**request.param)
        # Timeout has been added because there are races in driver n3k
        # in the mirroring area.
        if request.param['type_policy'] == 'mirror':
            sleep(30)
    except Exception as error:
        _teardown(controller=controller)
        raise error
    yield
    _teardown(controller=controller)


def _find_param_values(node, mark_name):
    for mark in node.iter_markers(name='parametrize'):
        if mark_name in mark.args[0]:
            values = list(itertools.chain.from_iterable(mark.args[1:]))
            return values if values else None
    return None


def pytest_generate_tests(metafunc):
    """
    Dynamically change fixtures and tests before the session
    """
    # Workaround for ordering fixtures
    reorder_early_fixtures(metafunc)
    # Add fixture based on cli option
    if "verify_n3k_dump" in metafunc.fixturenames:
        value_verify_n3k_dump = _find_param_values(node=metafunc.definition,
                                                   mark_name='verify_n3k_dump')
        if value_verify_n3k_dump is None:
            check_n3k_dump = metafunc.config.getoption("verify_n3k_dump")
            metafunc.parametrize(
                "verify_n3k_dump",
                [check_n3k_dump],
                ids=['verify_n3k_dump' if check_n3k_dump
                     else 'no_verify_n3k_dump'])
    # Add encap parameter value for setting up encapsulation
    env = metafunc.definition.get_closest_marker('env').args[0]
    if "encapsulation" in metafunc.fixturenames:
        values_encap = _find_param_values(node=metafunc.definition,
                                          mark_name='encap')
        if values_encap is None and env not in ['integration', 'unit_tests']:
            option_encap = metafunc.config.getoption('encap')
            metafunc.parametrize("encap",
                                 [option_encap],
                                 ids=Encapsulation.create_ids([option_encap]))
    # Set LACP parameter value
    if env not in ['integration', 'unit_tests']:
        lacp_enabled = get_config()["lacp_enabled"]
        metafunc.parametrize("lacp",
                             [lacp_enabled],
                             ids=['LACP' if lacp_enabled
                                  else 'Single_iface'])


def pytest_addoption(parser):
    """
    Add options to cmd argument parser.
    """
    parser.addoption(
        '--env',
        action='store',
        help='Path to config yaml configuration file.',
        required=True)
    parser.addoption(
        '--encap',
        required=False,
        help='Priority of encapsulation that will be used if not stated '
             'differently in a test.',
        default=Encapsulation.vxlan,
        nargs="+")
    parser.addoption(
        '--verify-n3k-dump',
        action='store_true',
        dest='verify_n3k_dump',
        help='Verify n3k dump during tests.',
        default=True)
    parser.addoption(
        '--no-verify-n3k-dump',
        action='store_false',
        help='No n3k dump verification during tests.',
        dest='verify_n3k_dump')
    parser.addoption(
        '--id',
        action='append',
        nargs='+',
        help='Filter test case(s) TC_ID. TC_ID can match beging of the'
             'test case id if ends with * in order to select test case ids '
             'with the same prefix.',
        metavar="TC_ID")
    parser.addoption(
        '--pcap-dir',
        action='store',
        default=os.path.join(os.getcwd(), 'logs', 'tcpdump'),
        help='Directory to store tcpdump packet captures in.',
        required=False)

    def _validate_encapsulation(config):
        encapsulation_priority = config.getoption('encap')
        valid_encapsulations = (Encapsulation.mpls_gre,
                                Encapsulation.mpls_udp,
                                Encapsulation.vxlan)
        if encapsulation_priority not in valid_encapsulations:
            raise pytest.UsageError(
                f'pytest: error: argument --encap: '
                f'invalid choice: {encapsulation_priority} '
                f'(choose from {valid_encapsulations})')

    def pytest_configure(config):
        """
        Configure pytest before running
        """
        os.makedirs('logs', exist_ok=True)
        os.makedirs('logs/tcpdump', exist_ok=True)
        _validate_encapsulation(config)
        get_config(path=config.getoption('env'))

    def _get_topology_from_cfg():
        return get_config().get("topology")

    def _keep_for_topology(item, config):
        topology = _get_topology_from_cfg()
        keep_item = False
        marked_topology = item.get_closest_marker("env")
        if marked_topology:
            if marked_topology.args[0] == topology:
                keep_item = True
            else:
                keep_item = False
        else:
            keep_item = True
            item.add_marker(pytest.mark.skip(
                f"No mark for {topology} topology."))
        return keep_item

    def _keep_for_id(item, config):
        valid_ids = config.getoption('--id')
        if not valid_ids:
            return True
        keep_item = False
        tc_id = item.get_closest_marker('tc_id')
        id_prefixes = tuple(itertools.chain.from_iterable(valid_ids))
        if not tc_id:
            keep_item = False
        elif not _is_id_valid(tc_id.args[0], id_prefixes):
            keep_item = False
        else:
            keep_item = True
        return keep_item

    def _keep_for_encap(item, config):
        option_encap = config.getoption('encap')
        item_encap = None
        try:
            item_encap = item.callspec.params.get('encap', None)
        except AttributeError:
            # In case there are no function parameters
            pass
        if item_encap:
            if option_encap == item_encap:
                return True
            else:
                return False
        return True

    def _is_id_valid(test_id, id_prefixes):
        for prefix in id_prefixes:
            if prefix.endswith('*') and test_id.startswith(prefix[:-1]):
                return True
            elif test_id == prefix:
                return True
        return False

    def _keep_for_multi_interface(item, config):
        lacp_enabled = get_config()["lacp_enabled"]
        marked_multi_interfaces = item.get_closest_marker("lag_multi_interfaces")
        if marked_multi_interfaces is not None and not lacp_enabled:
            return False
        return True

    @pytest.fixture(scope="session")
    def runner_ip(test_bed: TestBed) -> str:
        # get IP of pytest runner host to
        # use 22 port connection to CN1, should be always available
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect((test_bed.cn1.ip_mgmt, 22))
        return sock.getsockname()[0]

    def pytest_collection_modifyitems(session, config, items):
        """
        Don't collect items with different topoplogy than specified in config yaml
        file. Filter tc_id marked test cases when cli option specified.
        """
        keep, discard = [], []
        for item in items:
            for keeper in [_keep_for_topology, _keep_for_id, _keep_for_encap,
                           _keep_for_multi_interface]:
                if not keeper(item, config):
                    discard.append(item)
                    break
            else:
                keep.append(item)
        items[:] = keep
        config.hook.pytest_deselected(items=discard)

    def reorder_early_fixtures(metafunc):
        """
        Put fixtures with `pytest.mark.early` first during execution

        This allows patch of configurations before the application is initialized

        """
        for fixturedef in metafunc._arg2fixturedefs.values():
            fixturedef = fixturedef[0]
            for mark in getattr(fixturedef.func, 'pytestmark', []):
                if mark.name == 'early':
                    order = metafunc.fixturenames
                    order.insert(0, order.pop(order.index(fixturedef.argname)))
                    break

    def pytest_sessionstart(session):
        LOGGER.info(f'Configuration loaded:\n {yaml.dump(get_config())}')

    def pytest_csv_register_columns(columns):
        def get_tc_id(item, report):
            tc_id = item.get_closest_marker('tc_id')
            if tc_id:
                yield 'tc_id', tc_id.args[0]

        def get_env(item, report):
            env = item.get_closest_marker('env')
            if env:
                yield 'env', env.args[0]

        columns['tc_id'] = get_tc_id
        columns['env'] = get_env

    @pytest.fixture(scope="session")
    def get_free_port(port: int = 9020, max_port: int = 9999) -> int:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        while port <= max_port:
            try:
                sock.bind(('', port))
                sock.close()
                return port
            except OSError:
                port += 1
        raise IOError('no free ports')

    @pytest.fixture(scope="session")
    def log_receiver(get_free_port: int, runner_ip: str
                     ) -> Generator[int, None, None]:
        port = get_free_port
        with run_logger_server(runner_ip, port):
            yield port

    @pytest.fixture(scope="function")
    def daemon_hubs_generator(log_receiver: int, runner_ip: str) -> (
            Generator[Callable[[list['Vm']], tuple['DaemonHub', ...]], Any, None]):
        """
        Fixture returning daemon hubs started on each VM defined in testbed.
        """
        daemon_hubs = DaemonHubs(log_port=log_receiver, runner_ip=runner_ip)

        def return_daemon_hubs(*conn: list['Vm']) -> tuple['DaemonHub', ...]:
            if not conn:
                return daemon_hubs.get_hubs()
            daemon_hubs.connect(*conn)
            return daemon_hubs.get_hubs()

        yield return_daemon_hubs
        daemon_hubs.teardown()

    def _only_dns_flows(connection, verify_n3k_dump):  # workaround for DNS flows
        vrouter_flows = VrouterParser(connection)
        LOGGER.debug(
            f"List of all vRouter stale flows:\n{vrouter_flows}")
        vrouter_flows_count = vrouter_flows.get_number_of_flows()
        vrouter_dns_flows_count = vrouter_flows.get_flows(
            flow_match=FiveTuple(s_port=53),
            flow_rev=True).get_number_of_flows()
        if vrouter_dns_flows_count != vrouter_flows_count:
            LOGGER.warning(
                "vRouter flows contain some none DNS flows after clearing.")
            return False
        if verify_n3k_dump:
            n3k_flows = get_n3k_flows(
                ssh_conn=connection,
                device_name=connection.intel_pac_phy_addr_pci)
            LOGGER.debug(
                f"List of all N3K stale flows:\n{vrouter_flows_count}")
            n3k_flows_count = len(n3k_flows)
            if n3k_flows_count != vrouter_dns_flows_count:
                LOGGER.warning(
                    "N3K flows are not in sync with vRouter.")
                return False
        return True

    @pytest.fixture(scope="function")
    def clear_vrouter_flows(test_bed: TestBed, verify_n3k_dump: bool = False
                            ) -> Generator:

        @retry(wait_fixed=2000, stop_max_delay=10000)
        def clear_flows_for(cn_connections):
            for connection in cn_connections:
                if vrouter_instance_exists(connection):
                    try:
                        clear_flows_in_vrouter_agent(connection)
                    except TimeoutError:
                        if not _only_dns_flows(connection, verify_n3k_dump):
                            raise ClearFlowsError("Flows not correctly cleared.")
                else:
                    LOGGER.info(f"Clearing vRouter/N3k flows are skipped in"
                                f" compute node: {connection.ip_mgmt}")

        cn_connections = [test_bed.cn1, test_bed.cn2]
        clear_flows_for(cn_connections)
        yield
        clear_flows_for(cn_connections)

    def _finish_tcpdump_capture(vm_name: str, tcpdump: 'Tcpdump'
                                ) -> list[Exception]:
        try:
            tcpdump.finish_capture()
        except RuntimeError:
            LOGGER.debug(f'Tcpdump on {vm_name} not running (anymore).')
        except Exception as err:
            LOGGER.warning(f"Unexpected error on tcpdump termination: {err}, "
                           f"suppressed for later re-raise")
            return [err]
        return []

    def _download_pcap_file(tcpdump: 'Tcpdump', vm: 'Vm',
                            local_dir: str) -> list[Exception]:
        try:
            vm.transfer_files_from_vm(local_dir=local_dir,
                                      remote_file=tcpdump.filename)
        except RuntimeError:
            LOGGER.debug(f"Tcdpump was not run for {vm.hostname}")
        except VMerror:
            LOGGER.debug(f"No pcap file found for {vm.hostname}")
        except Exception as err:
            LOGGER.warning(f"Unexpected error on file transfer: {err}, "
                           f"suppressed for later re-raise")
            return [err]
        return []

    @pytest.fixture(scope="function")
    def tcpdumps_generator(request: 'FixtureRequest') -> (
            Generator[Callable[[dict], dict['Vm', 'Tcpdump']], Any, None]):
        tcpdumps: dict['Vm', 'Tcpdump'] = {}

        def return_tcpdumps(*daemons: dict) -> (dict['Vm', 'Tcpdump']):
            for cn_vm, daemon in daemons:
                tcpdumps[cn_vm] = daemon.get_tcpdump()
            return tcpdumps

        local_dir = request.config.getoption("--pcap-dir")
        yield return_tcpdumps
        exceptions = []
        for vm, tcpdump in tcpdumps.items():
            if tcpdump is not None:
                exceptions += _finish_tcpdump_capture(vm.hostname, tcpdump)
                exceptions += _download_pcap_file(
                    tcpdump=tcpdump,
                    vm=vm,
                    local_dir=local_dir)
        if exceptions:
            raise exceptions[0]