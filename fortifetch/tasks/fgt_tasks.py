"""
This module contains all the fortigate api functions
which are used to retreive information from the fortigate.
"""
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from typing import Union, Dict, Optional, List
from fortigate_api import Fortigate
from shared.config import settings
import yaml
import os
from rich import print

INVENTORY_FILE = os.environ.get("FORTIFETCH_INVENTORY")
if not INVENTORY_FILE:
    raise ValueError("The FORTIFETCH_INVENTORY environment variable is not set.")


def get_fortigate_data(
    url: str,
    inventory_file: str = INVENTORY_FILE,
) -> List[Dict]:
    """
    Retrieves data from the Fortigate API for all hosts in the inventory file.

    Args:
        url: The API endpoint to retrieve data from.
        inventory_file: The path to the inventory file.

    Returns:
        A list of dictionaries containing the retrieved data for each host.
    """

    with open(inventory_file) as f:
        inventory = yaml.safe_load(f)

    device_info = []
    for host in inventory:
        try:
            fgt = Fortigate(
                host=host["host"],
                scheme=settings.FORTIFETCH_SCHEME,
                username=settings.FORTIFETCH_USERNAME,
                password=settings.FORTIFETCH_PASSWORD,
            )
            fgt.login()
            device_info.append({host["hostname"]: fgt.get(url=url)})
            fgt.logout()
        except Exception as e:
            print(
                f"[bold red]Unable to connect {host['hostname']}[/bold red] :pouting_face:"
            )
            print(e)
            continue
    return device_info


def get_fortigate_device_info() -> List[Dict]:
    """
    Returns:
        Device data in a list of dictionaries
    """
    return get_fortigate_data(
        "/api/v2/monitor/system/firmware/", inventory_file=INVENTORY_FILE
    )


def get_fortigate_interface_info() -> List[Dict]:
    """
    Returns:
        Interface data in a list of dictionaries
    """
    return get_fortigate_data(
        "/api/v2/cmdb/system/interface/", inventory_file=INVENTORY_FILE
    )


def get_fortigate_address_info() -> List[Dict]:
    """
    Returns:
        address data in a list of dictionaries
    """
    return get_fortigate_data(
        "/api/v2/cmdb/firewall/address/", inventory_file=INVENTORY_FILE
    )


def get_fortigate_address_group_info() -> List[Dict]:
    """
    Returns:
        address group data in a list of dictionaries
    """
    return get_fortigate_data(
        "/api/v2/cmdb/firewall/addrgrp/", inventory_file=INVENTORY_FILE
    )


def get_fortigate_application_info() -> List[Dict]:
    """
    Returns:
        application profile data in a list of dictionaries
    """
    return get_fortigate_data(
        "/api/v2/cmdb/application/list", inventory_file=INVENTORY_FILE
    )


def get_fortigate_av_info() -> List[Dict]:
    """
    Returns:
        antivirus profile data in a list of dictionaries
    """
    return get_fortigate_data(
        "/api/v2/cmdb/antivirus/profile", inventory_file=INVENTORY_FILE
    )


def get_fortigate_dnsfilter_info() -> List[Dict]:
    """
    Returns:
        dnsfilter profile data in a list of dictionaries
    """
    return get_fortigate_data(
        "/api/v2/cmdb/dnsfilter/profile", inventory_file=INVENTORY_FILE
    )


def get_fortigate_internetservice_info() -> List[Dict]:
    """
    Returns:
        internet service profile data in a list of dictionaries
    """
    return get_fortigate_data(
        "/api/v2/cmdb/firewall/internet-service-name", inventory_file=INVENTORY_FILE
    )


def get_fortigate_ippool_info() -> List[Dict]:
    """
    Returns:
        ippool data in a list of dictionaries
    """
    return get_fortigate_data(
        "/api/v2/cmdb/firewall/ippool/", inventory_file=INVENTORY_FILE
    )


def get_fortigate_ips_info() -> List[Dict]:
    """
    Returns:
        ips data in a list of dictionaries
    """
    return get_fortigate_data("/api/v2/cmdb/ips/sensor/", inventory_file=INVENTORY_FILE)


def get_fortigate_sslssh_info() -> List[Dict]:
    """
    Returns:
        ssl/ssh profile data in a list of dictionaries
    """
    return get_fortigate_data(
        "/api/v2/cmdb/firewall/ssl-ssh-profile/", inventory_file=INVENTORY_FILE
    )


def get_fortigate_vip_info() -> List[Dict]:
    """
    Returns:
        vip data in a list of dictionaries
    """
    return get_fortigate_data(
        "/api/v2/cmdb/firewall/vip/", inventory_file=INVENTORY_FILE
    )


def get_fortigate_webfilter_info() -> List[Dict]:
    """
    Returns:
        web filter profile data in a list of dictionaries
    """
    return get_fortigate_data(
        "/api/v2/cmdb/webfilter/profile/", inventory_file=INVENTORY_FILE
    )


def get_fortigate_fwpolicy_info() -> List[Dict]:
    """
    Returns:
        firewall policy data in a list of dictionaries
    """
    return get_fortigate_data(
        "/api/v2/cmdb/firewall/policy/", inventory_file=INVENTORY_FILE
    )


def get_fortigate_trafficshapers_info() -> List[Dict]:
    """
    Returns:
        traffic shapers data in a list of dictionaries
    """
    return get_fortigate_data(
        "/api/v2/cmdb/firewall.shaper/traffic-shaper/", inventory_file=INVENTORY_FILE
    )


def get_fortigate_trafficpolicy_info() -> List[Dict]:
    """
    Returns:
        traffic shapers policy data in a list of dictionaries
    """
    return get_fortigate_data(
        "/api/v2/cmdb/firewall/shaping-policy/", inventory_file=INVENTORY_FILE
    )


def get_fortigate_dns_info() -> List[Dict]:
    """
    Returns:
        dns data in a list of dictionaries
    """
    return get_fortigate_data("/api/v2/cmdb/system/dns/", inventory_file=INVENTORY_FILE)


def get_fortigate_static_route_info() -> List[Dict]:
    """
    Returns:
        static route data in a list of dictionaries
    """
    return get_fortigate_data(
        "/api/v2/cmdb/router/static/", inventory_file=INVENTORY_FILE
    )


def get_fortigate_policy_route_info() -> List[Dict]:
    """
    Returns:
        policy route data in a list of dictionaries
    """
    return get_fortigate_data(
        "/api/v2/cmdb/router/policy/", inventory_file=INVENTORY_FILE
    )


def get_fortigate_snmpv2_info() -> List[Dict]:
    """
    Returns:
        snmpv2 data in a list of dictionaries
    """
    return get_fortigate_data(
        "/api/v2/cmdb/system.snmp/community/", inventory_file=INVENTORY_FILE
    )


def get_fortigate_snmpv3_info() -> List[Dict]:
    """
    Returns:
        snmpv3 data in a list of dictionaries
    """
    return get_fortigate_data(
        "/api/v2/cmdb/system.snmp/user/", inventory_file=INVENTORY_FILE
    )


def get_fortigate_fortiguard_info() -> List[Dict]:
    """
    Returns:
        fortiguard data in a list of dictionaries
    """
    return get_fortigate_data(
        "/api/v2/cmdb/system/fortiguard/", inventory_file=INVENTORY_FILE
    )


def get_fortigate_admin_info() -> List[Dict]:
    """
    Returns:
        admin data in a list of dictionaries
    """
    return get_fortigate_data(
        "/api/v2/cmdb/system/admin/", inventory_file=INVENTORY_FILE
    )


def get_fortigate_admin_profile_info() -> List[Dict]:
    """
    Returns:
        admin profile data in a list of dictionaries
    """
    return get_fortigate_data(
        "/api/v2/cmdb/system/accprofile/", inventory_file=INVENTORY_FILE
    )


def get_fortigate_vpn_monitor_info() -> List[Dict]:
    """
    Returns:
        vpn monitor data in a list of dictionaries
    """
    return get_fortigate_data(
        "/api/v2/monitor/vpn/ipsec/", inventory_file=INVENTORY_FILE
    )
