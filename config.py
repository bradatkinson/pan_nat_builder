#  AUTHOR: Brad Atkinson
#    DATE: 10/6/2020
# PURPOSE: Configuration file info containing username, password, and IPs

# CONNECTIVITY CONFIGURATIONS
# Update password with the new password entered during management IP
# configuration.

paloalto = {
    'username': '<USERNAME>',
    'password': '<PASSWORD>',
    'key': '<API_KEY>',
    'firewall_ip': ['<IP_ADDRESS>']
    }

# NAT CONFIGURATION
# The NAT policy options are below.  Some configuration items have multiple
# options to select from and are listed to provide assistance.

name = '<POLICY_NAME>'
description = '<POLICY_DESCRIPTION>'

# OPTIONS: ipv4, ipv6
nat_type = 'ipv4'

# OPTIONS: source zone name, any
fromzone = '<SOURCE_ZONE_OPTION>'

# OPTIONS: destination zone name, any
tozone = '<DESTINATION_ZONE_OPTION>'

# OPTIONS: destination interface, any
to_interface = '<DESTINATION_INTERFACE_OPTION>'

# OPTIONS: service port(s), any
service = '<SERVICE_OPTION>'

# OPTIONS: source IP address(es), any
source = ['<SOURCE_OPTION>']

# OPTIONS: destination IP address(es), any
destination = ['<DESTINATION_OPTION>']

# OPTIONS: True, False
disabled = True

# OPTIONS: src_static_ip, src_dynamic_ip, dst_static_ip, dst_dynamic_ip
nat = '<NAT_OPTION>'

# SOURCE STATIC IP
source_translation_type = 'static-ip'
source_translation_static_translated_address = '<IP_ADDRESS>'
source_translation_static_bi_directional = False

# SOURCE DYNAMIC IP
source_translation_type = 'dynamic-ip'
source_translation_translated_addresses = ['<IP_ADDRESS>']

# DESTINATION STATIC IP
destination_translated_address = '<IP_ADDRESS>'
destination_translated_port = 0 # Update with correct port number

# DESTINATION DYNAMIC IP
destination_dynamic_translated_address = '<IP_ADDRESS>'
destination_dynamic_translated_port = 0 # Update with correct port number

# OPTIONS: round-robin, source-ip-hash, ip-modulo, ip-hash, least-sessions
destination_dynamic_translated_distribution = '<DISTRIBUTION_OPTION>'
