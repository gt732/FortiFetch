"""
This module contains functions for cleaning the data returned from the fortigate api tasks
before it is written to the database.
"""

# import os sys
import os
import sys

# Add the parent directory of 'app' to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# import modules
from typing import List, Dict, Optional
from pprint import pprint

import json

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


def get_fortigate_vpn_monitor_info() -> List[Dict]:
    """
    Returns:
        vpn monitor data in a list of dictionaries
    """
    return get_fortigate_data("/api/v2/monitor/vpn/ipsec/")


def clean_vpn_monitor_data() -> List[Dict]:
    """
    Get the vpn monitor information from the get_fortigate_vpn_monitor_info() function
    and clean the data before it is written to the database.
    """
    device_info = get_fortigate_vpn_monitor_info()
    cleaned_data = []
    for firewall in device_info:
        for device, value in firewall.items():
            for vpn in value:
                # Get the vpn phase1 data
                vpn_p1_name = vpn["name"]
                vpn_p2_data = [(p2["p2name"], p2["status"]) for p2 in vpn["proxyid"]]
                vpn_p2_name = [p2[0] for p2 in vpn_p2_data]
                vpn_p2_status = [p2[1] for p2 in vpn_p2_data]

                # Create a dictionary of the cleaned data
                cleaned_dict = {
                    "hostname": device,
                    "phase1_name": vpn_p1_name,
                    "phase2_name": vpn_p2_name,
                    "phase2_status": vpn_p2_status,
                }
                # Append the dictionary to the cleaned_data list
                cleaned_data.append(cleaned_dict)
    return cleaned_data
