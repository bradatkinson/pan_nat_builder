#!/usr/bin/env python3
#
#  AUTHOR: Brad Atkinson
#    DATE: 9/29/2021
# PURPOSE: To aid in the build out of NAT policies

from panos import base
from panos import policies
import config


def connect_device():
    """Connect To Device
    
    Returns:
        fw_conn (PanDevice): A panos object for device
    """
    fw_ip = config.paloalto['fw_ip']
    username = config.paloalto['username']
    password = config.paloalto['password']
    fw_conn = base.PanDevice.create_from_device(
        hostname=fw_ip,
        api_username=username,
        api_password=password)
    return fw_conn


def print_policies(fw_conn):
    rulebase = policies.Rulebase()
    fw_conn.add(rulebase)
    list_of_rules = policies.NatRule.refreshall(rulebase)

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
    fw_conn = connect_device()
    print_policies(fw_conn)

    nat = config.nat
    if nat == 'src_static_ip':
        desired_rule_params = src_static_ip()
    elif nat == 'src_dynamic_ip':
        desired_rule_params = src_dynamic_ip()
    elif nat == 'dst_static_ip':
        desired_rule_params = dst_static_ip()
    elif nat == 'dst_dynamic_ip':
        desired_rule_params = dst_dynamic_ip()

    rulebase = policies.Rulebase()
    fw_conn.add(rulebase)
    policies.NatRule.refreshall(rulebase)
    new_rule = policies.NatRule(**desired_rule_params)
    rulebase.add(new_rule)
    new_rule.create()

    print_policies(fw_conn)


if __name__ == '__main__':
    main()
