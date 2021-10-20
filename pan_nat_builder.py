#!/usr/bin/env python3
#
#  AUTHOR: Brad Atkinson
#    DATE: 9/29/2021
# PURPOSE: To aid in the build out of NAT policies

import sys
from panos import base
from panos import panorama
from panos import policies
import config


def find_active_device():
    """Find Active Device

    Returns:
        pano_ip (str): The IP address of the active Panorama
    """
    print('Finding the active Panorama...')
    pano1_ip = config.paloalto['panorama_ip'][0]
    pano1_conn = connect_device(pano1_ip)
    pano1_results = check_ha_status(pano1_conn)
    pano1_state = process_ha_status(pano1_results)

    pano2_ip = config.paloalto['panorama_ip'][1]
    pano2_conn = connect_device(pano2_ip)
    pano2_results = check_ha_status(pano2_conn)
    pano2_state = process_ha_status(pano2_results)

    active_tuple = ('active', 'active-primary', 'primary-active')
    if pano1_state in active_tuple:
        pano_ip = pano1_ip
        pano_conn = pano1_conn
    elif pano2_state in active_tuple:
        pano_ip = pano2_ip
        pano_conn = pano2_conn
    else:
        print("-- Couldn't find the active Panorama.\n", file=sys.stderr)
        sys.exit(1)

    pano_conn = connect_device(pano_ip)
    results = get_system_info(pano_conn)
    hostname = get_hostname(results)
    print('-- Connected to the active Panorama: {}\n'.format(hostname))
    return pano_conn


def check_ha_status(pano_conn):
    """Check HA Status

    Args:
        pano_conn (PanDevice): A panos object for device

    Returns:
        results (Element): XML results from firewall
    """
    command = ('<show><high-availability><state>'
               '</state></high-availability></show>')
    results = pano_conn.op(cmd=command, cmd_xml=False)
    return results


def process_ha_status(results):
    """Process HA Status

    Args:
        results (Element): XML results from firewall

    Returns:
        ha_status (str): A string containing the HA state
    """
    ha_status = results.find('./result/local-info/state').text
    return ha_status


def connect_device(pano_ip):
    """Connect To Device

    Args:
        pano_ip (str): A string containing the Panorama IP address

    Returns:
        pano_conn (PanDevice): A panos object for device
    """
    username = config.paloalto['username']
    password = config.paloalto['password']
    pano_conn = base.PanDevice.create_from_device(
        hostname=pano_ip,
        api_username=username,
        api_password=password)
    return pano_conn


def get_system_info(pano_conn):
    """Get Show System Info

    Args:
        pano_conn (PanDevice): A panos object for device

    Returns:
        results (Element): XML results from firewall
    """
    results = pano_conn.op(cmd='show system info')
    return results


def get_hostname(results):
    """Get Hostname

    Args:
        results (Element): XML results from firewall

    Returns:
        hostname (str): A string containing the hostname
    """
    hostname = results.find('./result/system/hostname').text
    return hostname


def print_policies(pano_conn):
    devicegroup = panorama.DeviceGroup(config.device_group)
    pano_conn.add(devicegroup)
    prerulebase = policies.PreRulebase()
    devicegroup.add(prerulebase)
    list_of_rules = policies.NatRule.refreshall(prerulebase)

    print('NAT policies:')
    for rule in list_of_rules:
        print(rule)
    print("\r")


def src_static_ip():
    desired_rule_params = {
        "name": config.name,
        "description": config.description,
        "nat_type": config.nat_type,
        "fromzone": config.fromzone,
        "tozone": config.tozone,
        "to_interface": config.to_interface,
        "service": config.service,
        "source": config.source,
        "destination": config.destination,
        "source_translation_type": config.source_translation_type,
        "source_translation_static_translated_address": config.source_translation_static_translated_address,
        "source_translation_static_bi_directional": config.source_translation_static_bi_directional,
        "disabled": config.disabled
    }
    return desired_rule_params


def src_dynamic_ip():
    desired_rule_params = {
        "name": config.name,
        "description": config.description,
        "nat_type": config.nat_type,
        "fromzone": config.fromzone,
        "tozone": config.tozone,
        "to_interface": config.to_interface,
        "service": config.service,
        "source": config.source,
        "destination": config.destination,
        "source_translation_type": config.source_translation_type,
        "source_translation_translated_addresses": config.source_translation_translated_addresses,
        "disabled": config.disabled
    }
    return desired_rule_params


def dst_static_ip():
    desired_rule_params = {
        "name": config.name,
        "description": config.description,
        "nat_type": config.nat_type,
        "fromzone": config.fromzone,
        "tozone": config.tozone,
        "to_interface": config.to_interface,
        "service": config.service,
        "source": config.source,
        "destination": config.destination,
        "destination_translated_address": config.destination_translated_address,
        "destination_translated_port": config.destination_translated_port,
        "disabled": config.disabled
    }
    return desired_rule_params


def dst_dynamic_ip():
    desired_rule_params = {
        "name": config.name,
        "description": config.description,
        "nat_type": config.nat_type,
        "fromzone": config.fromzone,
        "tozone": config.tozone,
        "to_interface": config.to_interface,
        "service": config.service,
        "source": config.source,
        "destination": config.destination,
        "destination_dynamic_translated_address": config.destination_dynamic_translated_address,
        "destination_dynamic_translated_port": config.destination_dynamic_translated_port,
        "destination_dynamic_translated_distribution": config.destination_dynamic_translated_distribution,
        "disabled": config.disabled
    }
    return desired_rule_params


def main():
    """Function Calls
    """
    pano_conn = find_active_device()
    print_policies(pano_conn)

    nat = config.nat
    if nat == 'src_static_ip':
        desired_rule_params = src_static_ip()
    elif nat == 'src_dynamic_ip':
        desired_rule_params = src_dynamic_ip()
    elif nat == 'dst_static_ip':
        desired_rule_params = dst_static_ip()
    elif nat == 'dst_dynamic_ip':
        desired_rule_params = dst_dynamic_ip()

    devicegroup = panorama.DeviceGroup(config.device_group)
    pano_conn.add(devicegroup)
    prerulebase = policies.PreRulebase()
    devicegroup.add(prerulebase)
    policies.NatRule.refreshall(prerulebase)
    new_rule = policies.NatRule(**desired_rule_params)
    prerulebase.add(new_rule)
    new_rule.create()

    print_policies(pano_conn)


if __name__ == '__main__':
    main()
