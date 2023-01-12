import collections.abc
import csv
from glob import glob
from ipaddress import ip_address, IPv4Address, IPv6Address
import logging
import os
from typing import Type, TypeVar, Any, Union, TYPE_CHECKING, Generator
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
import paramiko

if TYPE_CHECKING:
    from lib.connections import Compute, Vm
    from paramiko.channel import ChannelStderrFile

LOGGER = logging.getLogger(__name__)


IPvX = TypeVar('IPvX', IP, IPv6)


class ErrorUtils(Exception):
    pass


class CfgTrexTestDirector:
    """
    Enum of attributes to trextestdirector test function args
    """
    param_scenario = "test_name,scenario_cfg,scenario"


class Encapsulation:
    mpls_gre: list[str] = ["MPLSoGRE", "MPLSoUDP", "VXLAN"]
    mpls_udp: list[str] = ["MPLSoUDP", "MPLSoGRE", "VXLAN"]
    vxlan: list[str] = ["VXLAN", "MPLSoUDP", "MPLSoGRE"]

    @staticmethod
    def create_ids(encap_list: list[str]) -> list[str]:
        return ['encap(' + ','.join(encap) + ')' for encap in encap_list]


class Topology:
    """
    Enum of possibility Topology
    """
    vm_mx: str = "vm_mx"
    vm_vm: str = "vm_vm"
    integration: str = "integration"
    unit_tests: str = "unit_tests"


class PerfromanceTestScenarios:
    """
    Enum of possible values for params of performance test scenarios
    """
    latency_l3: tuple[str, str, str] = (
        "latency",
        "latency_test.yaml",
        "latency_scenario.py")
    rfc2544_l3: tuple[str, str, str] = (
        "rfc2544",
        "rfc2544_test.yaml",
        "rfc2544_scenario.py")


class ReportFileData:
    path: str = "logs/detailed_reports/"
    extension: str = ".csv"


def get_content(stream: 'ChannelStderrFile') -> str:
    """
        read whole file and return string decoded to utf8
    """
    return stream.read().decode('utf-8')


def iter_nested_keys(dictionary: dict, seeked_key: str, seeked_value: Any
                     ) -> Generator[dict, None, None]:
    """
    Itereate through nested structure of dictionaries looking for key with
    certain value.
    """
    value_from_dict = dictionary.get(seeked_key)
    if value_from_dict == seeked_value:
        yield dictionary
    for values in dictionary.values():
        if isinstance(values, dict):
            yield from iter_nested_keys(
                dictionary=values,
                seeked_key=seeked_key,
                seeked_value=seeked_value)


def update_nested_dict(dictionary: dict,
                       updated_dictionary: Union[dict, collections.abc.Mapping]
                       ) -> dict:
    """
    Update nested structure of dictionaries with other dictionary.
    """
    for key, value in updated_dictionary.items():
        if isinstance(value, collections.abc.Mapping):
            dictionary[key] = update_nested_dict(
                dictionary=dictionary.get(key, {}),
                updated_dictionary=value)
        else:
            dictionary[key] = value
    return dictionary


def get_trex_test_config(file_name: str) -> str:
    _test_cfg = "lib/trex_engine/trextestdirector/configs/"
    return os.path.join(_test_cfg, file_name)


def get_trex_test_scenario(file_name: str) -> str:
    _scenario_dir = "lib/trex_engine/trextestdirector/trextestdirector/"
    return os.path.join(_scenario_dir, file_name)


def save_results_to_csv_file(results: list,
                             file_path: str,
                             headers: str) -> None:
    if not os.path.exists(os.path.dirname(file_path)):
        os.makedirs(os.path.dirname(file_path))
    with open(file_path, 'w') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(headers)
        for row in results:
            # convert dict to list of values
            try:
                _add_decimals_to_results(row)
                row = list(row.values())
            except AttributeError:
                pass
            writer.writerow(row)


def _add_decimals_to_results(results: dict) -> dict:
    for key, value in results.items():
        if "loss" in key:
            results[key] = f"{value:5f}"
        if "latency" in key:
            results[key] = f"{value:2f}"
    return results


def get_iptables_command(ipv6_version: bool) -> str:
    return 'ip6tables' if ipv6_version else 'iptables'


def get_ip_addr_without_prefix(ip_addr: str) -> str:
    return ip_addr.split('/')[0]


def is_ipv6_address(address: str) -> bool:
    if ip_address(address).version == 6:
        return True
    return False


def get_ip_header(ip_version: Type[IPvX], ip_src: str, ip_dst: str) -> IPvX:
    if ip_version == IP:
        return ip_version(src=ip_src, dst=ip_dst, flags=2)
    elif ip_version == IPv6:
        return ip_version(src=ip_src, dst=ip_dst)


def get_ip_version(ip_header: Type[IPvX]) -> str:
    return 'ip6' if ip_header == IPv6 else 'ip'


def ipv4_from_str(s) -> int:
    return int.from_bytes(IPv4Address(s).packed,
                          byteorder='little', signed=False)


def ipv6_from_str(s) -> list[int]:
    return [int(i) for i in list(IPv6Address(s).packed)]


def mpls_label_from_int(s):
    return [i for i in int(s << 4).to_bytes(length=3, byteorder='big')]


def _remove_remote_dir_of_files(
        remote_dir: str, vm_sftp: paramiko.SFTPClient) -> None:
    try:
        for file in vm_sftp.listdir(path=remote_dir):
            LOGGER.debug(f"remove file {file}")
            vm_sftp.remove(os.path.join(remote_dir, file))
        vm_sftp.rmdir(remote_dir)
    except FileNotFoundError:
        LOGGER.debug(f"No such {remote_dir} dir")


def _transfer_file_to_vm_cn(
        local_file: str, remote_file: str,
        ssh_conn: Union['Vm', 'Compute'],
        overwrite: bool) -> None:
    with ssh_conn.open_sftp() as vm_sftp:
        LOGGER.info(f"Copy file: {local_file} to remote host: {vm_sftp}")
        _dir = os.path.dirname(remote_file)
        if _dir and overwrite:
            LOGGER.debug(f"overwrite remote dir {_dir}")
            _remove_remote_dir_of_files(remote_dir=_dir, vm_sftp=vm_sftp)
        if _dir:
            LOGGER.debug(f"create remote dir {_dir}")
            try:
                vm_sftp.mkdir(_dir)
            except IOError as error:
                LOGGER.debug(f"Directory already exist.\n{error}")
        vm_sftp.put(local_file, remote_file)


def transfer_files_from_host_folder_to_vm_cn(
        ssh_conn: Union['Vm', 'Compute'],
        folder: str = 'lib/daemon',
        filter_file: str = '*.py',
        local_file: Union[str, None] = None,
        remote_file: Union[str, None] = None,
        overwrite: bool = False) -> None:

    if local_file is None or remote_file is None:
        for file in glob(os.path.join(os.getcwd(), folder, filter_file)):
            remote_filename = os.path.join(ssh_conn.tmp_daemon_dir.name,
                                           os.path.basename(file))
            _transfer_file_to_vm_cn(local_file=file,
                                    remote_file=remote_filename,
                                    ssh_conn=ssh_conn,
                                    overwrite=overwrite)
    else:
        _transfer_file_to_vm_cn(local_file=local_file,
                                remote_file=remote_file,
                                ssh_conn=ssh_conn,
                                overwrite=overwrite)