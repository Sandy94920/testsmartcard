"""
Global configuration singleton. Supporting reading configuration form generated
yaml file and yaml jinja2 templates.
"""
import yaml
import cerberus
import jinja2
import logging
import copy
from pathlib import Path
from ipaddress import ip_address
from lib.utils import iter_nested_keys, update_nested_dict

__all__ = ['get_config']

LOGGER = logging.getLogger(__name__)
DEFAULT_PATH = Path('./config/config.yaml')
EXTRA_FILES = [
    Path('controller_tmplt.j2'),
    Path('trex_tmplt.j2'),
    Path('dpdk_app_tmplt.j2')
]
VMS_SCHEMA = {
        'type': 'dict',
        'required': True,
        'schema': {
            'group': {
                'type': 'string',
                'required': False},
            'ip_mgmt': {
                'type': 'ip_address',
                'required': True},
            'ip_data_plane': {
                'type': 'ip_address',
                'required': True},
            'mac_data_plane': {
                'type': 'string',
                'required': False},
            'iface': {
                'type': 'string',
                'required': False},
            'second_iface': {
                'type': 'string',
                'required': False},
            'port': {
                'type': 'integer',
                'default': 22,
                'required': True},
            'ssh_user': {
                'type': 'string',
                'required': True},
            'passw': {
                'type': 'string',
                'required': False,
                'default': 'None'},
            'ssh_key': {
                'type': 'string',
                'required': False},
            'python_path': {
                'type': 'string',
                'required': False,
                'default': '/usr/bin/python3'},
            'pci_addr': {
                'type': 'list',
                'required': False}}}
SCHEMA = {
    'topology': {
        'type': 'string',
        'required': False,
        'default': 'vm_vm'},
    'lacp_enabled': {
        'type': 'boolean',
        'required': False,
        'default': True},
    'docker_registry': {
        'type': 'string',
        'required': False},
    'controller': {
        'type': 'dict',
        'schema': {
            'ip_mgmt': {
                'type': 'ip_address',
                'required': True},
            'logical_router': {
                'type': 'dict',
                'required': False},
            'group': {
                'type': 'string',
                'required': False},
            'data_plane_networks_names': {
                'type': 'list',
                'required': False,
                'schema': {'type': 'string'}},
            'route_targets': {
                'type': 'dict',
                'required': False},
            'port': {
                'type': 'integer',
                'required': True,
                'default': 22},
            'ssh_user': {
                'type': 'string',
                'required': True},
            'passw': {
                'type': 'string',
                'required': False},
            'ssh_key': {
                'type': 'string',
                'required': False},
            'networks_data_plane_gateway': {
                'type': 'list',
                'required': False},
            'static_route': {
                'type': 'dict',
                'required': False},
            'physical_routers': {
                'type': 'dict',
                'required': False}}},
    'groups': {
        'type': 'dict'},
    'compute': {
        'type': 'dict',
        'nullable': True,
        'valuesrules': {
            'type': 'dict',
            'schema': {
                'ip_mgmt': {
                    'type': 'ip_address',
                    'required': True},
                'intel_pac_phy_addr_pci': {
                    'type': 'string',
                    'required': False},
                'group': {
                    'type': 'string',
                    'required': False},
                'port': {
                    'type': 'integer',
                    'required': True,
                    'default': 22},
                'ssh_user': {
                    'type': 'string',
                    'required': True},
                'passw': {
                    'type': 'string',
                    'required': False},
                'ssh_key': {
                    'type': 'string',
                    'required': False},
                'python_path': {
                    'type': 'string',
                    'required': True,
                    'default': '/usr/bin/python3'},
                'dpdk_bin_path': {
                    'type': 'string',
                    'required': False,
                    'default': '/opt/dpdk-build/bin/'},
                'pci_address_mgmt': {
                    'type': 'string',
                    'required': False,
                    'default': '0000:1d:00.0'},
                'pci_address_pf': {
                    'type': 'string',
                    'required': False,
                    'default': '0000:1d:00.2'},
                'vfs_numbers': {
                    'type': 'string',
                    'required': False,
                    'default': '[1,2]'},
                'int_vf_interfaces': {
                    'type': 'list',
                    'required': False},
                'vms': {
                    'type': 'dict',
                    'default': {},
                    'valuesrules': {
                        **VMS_SCHEMA}},
                'cn_interfaces': {
                    'type': 'dict',
                    'required': False,
                    'valuesrules': {'type': 'string'}},
                'ae_interface': {
                    'type': 'dict',
                    'required': False,
                    'valuesrules': {'type': 'string'}},
                'ports': {
                    'type': 'dict',
                    'default': {},
                    'required': False}}}},
    'qfx': {
        'type': 'dict',
        'required': False,
        'schema': {
            'host': {
                'type': 'string',
                'required': True},
            'user': {
                'type': 'string',
                'required': True},
            'passwd': {
                'type': 'string',
                'required': True},
            'port': {
                'type': 'integer',
                'default': 22,
                'required': False}}}}

__cfg = None
__path = DEFAULT_PATH


class ConfigError(ValueError):
    pass


def get_config(path: str = None) -> dict:
    global __cfg, __path
    if path:
        __path = Path(path)
    if not __cfg or path:
        with open(__path, 'r') as f:
            __cfg = yaml.full_load(f)
        _add_group_values(__cfg)
        __cfg = _normalize_and_validate(__cfg)
        # extend config
        extra_config_dir = Path(f'./config/{__cfg["topology"]}/')
        for _file in EXTRA_FILES:
            try:
                extra_config_path = extra_config_dir / _file
                _extend_with_extra_config(
                    cfg=__cfg, tmplt_path=extra_config_path)
            except jinja2.TemplateNotFound:
                LOGGER.warning(
                    f'File {extra_config_path} does not exist.'
                    f'Config skipped.')
        LOGGER.warning(f'Configuration applied:\n {yaml.dump(__cfg)}')
    return __cfg


def _normalize_and_validate(cfg):
    class Validator(cerberus.Validator):
        def _validate_type_ip_address(self, value):
            try:
                ip_address(value)
            except ValueError:
                return False
            return True
    validator = Validator(SCHEMA)
    cfg = validator.normalized(cfg)
    if not validator.validate(cfg):
        raise ConfigError(
            'Smartnic tests config validation failed:', validator.errors)
    return cfg


def _add_group_values(cfg):
    """ Find groups section dictionary and replase group with defined values"""
    groups = {}
    try:
        groups = cfg.pop('groups')
    except KeyError:
        return
    group_key = 'group'
    for group, values in groups.items():
        for tree in iter_nested_keys(dictionary=cfg, seeked_key=group_key,
                                     seeked_value=group):
            tree.update(values)
            tree.pop(group_key)


def _listify_cfg(cfg):
    """ Change compute and vms to lists """
    cfg_with_lists = copy.deepcopy(cfg)
    cfg_with_lists['compute'] = list(cfg_with_lists['compute'].values())
    for compute in cfg_with_lists['compute']:
        compute['vms'] = list(compute['vms'].values())
    return cfg_with_lists


def _extend_with_extra_config(cfg, tmplt_path):
    env = jinja2.Environment(loader=jinja2.FileSystemLoader('./'))
    tmplt = env.get_template(str(tmplt_path))
    if cfg['compute']:
        listify_cfg = _listify_cfg(cfg)
        extra_config = yaml.full_load(tmplt.render(**listify_cfg))
        update_nested_dict(cfg, extra_config)