"""
This module contains all the fortigate api functions
which are used to retreive information from the fortigate.
"""


# import os sys
import os
import sys

# Add the parent directory of 'app' to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# import modules

from typing import Union, Dict, Optional, List
from fortigate_api import Fortigate
from pprint import pprint
import yaml

SCHEME = os.getenv("FORTIFETCH_SCHEME")
USERNAME = os.getenv("FORTIFETCH_USERNAME")
PASSWORD = os.getenv("FORTIFETCH_PASSWORD")


def get_fortigate_data(url: str) -> List[Dict]:
    """
    Retrieves data from the Fortigate API for all hosts in the inventory file.

    Args:
        url: The API endpoint to retrieve data from.

    Returns:
        A list of dictionaries containing the retrieved data for each host.
    """
    inventory_file = os.environ.get("FORTIFETCH_INVENTORY")
    if not inventory_file:
        raise ValueError("The FORTIFETCH_INVENTORY environment variable is not set.")

    with open(inventory_file) as f:
        inventory = yaml.safe_load(f)

    device_info = []
    for host in inventory:
        device_dict = {}
        fgt = Fortigate(
            host=host["host"],
            scheme=SCHEME,
            username=USERNAME,
            password=PASSWORD,
        )
        fgt.login()
        device_dict[host["hostname"]] = fgt.get(url=url)
        device_info.append(device_dict)
        fgt.logout()
    return device_info


def get_fortigate_device_info() -> List[Dict]:
    """
    Returns:
        Device data in a list of dictionaries
    """
    return get_fortigate_data("/api/v2/monitor/system/csf")


def get_fortigate_interface_info() -> List[Dict]:
    """
    Returns:
        Interface data in a list of dictionaries
    """
    return get_fortigate_data("/api/v2/cmdb/system/interface/")


def get_fortigate_address_info() -> List[Dict]:
    """
    Returns:
        address data in a list of dictionaries
    """
    return get_fortigate_data("/api/v2/cmdb/firewall/address/")


def get_fortigate_address_group_info() -> List[Dict]:
    """
    Returns:
        address group data in a list of dictionaries
    """
    return get_fortigate_data("/api/v2/cmdb/firewall/addrgrp/")
