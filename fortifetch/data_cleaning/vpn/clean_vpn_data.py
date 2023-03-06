"""
This module contains functions for cleaning the data returned from the fortigate api tasks
before it is written to the database.
"""

from typing import List, Dict, Optional
from tasks.fgt_tasks import *


def clean_vpn_monitor_data() -> List[Dict]:
    """
    Get the vpn monitor information from the get_fortigate_vpn_monitor_info() function
    and clean the data before it is written to the database.
    """
    device_info = get_fortigate_vpn_monitor_info()
    cleaned_data = []
    for firewall in device_info:
        for device, value in firewall.items():
            if not value:
                continue
            for vpn in value:

                vpn_p1_name = vpn["name"]
                vpn_p2_data = [(p2["p2name"], p2["status"]) for p2 in vpn["proxyid"]]
                vpn_p2_name = [p2[0] for p2 in vpn_p2_data]
                vpn_p2_status = [p2[1] for p2 in vpn_p2_data]

                cleaned_dict = {
                    "hostname": device,
                    "phase1_name": vpn_p1_name,
                    "phase2_name": vpn_p2_name,
                    "phase2_status": vpn_p2_status,
                }

                cleaned_data.append(cleaned_dict)
    return cleaned_data
