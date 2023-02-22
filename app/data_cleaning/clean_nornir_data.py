"""
This module contains functions for cleaning the data returned from the nornir tasks
before it is written to the database.
"""

# import os sys
import os
import sys

# Add the parent directory of 'app' to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# import modules
from typing import List, Dict
from shared.utilities import nr
from tasks.nornir_tasks import *
from pprint import pprint


def clean_device_data() -> List[Dict]:
    """
    Returns:
        Device data in a list of dictionaries
    """
    device_info = nr.run(task=get_fortigate_device_info)
    cleaned_data = []
    for device, multi_result in device_info.items():
        # Get the hostname, serial number, and model from the multi_result object
        hostname = multi_result[1].result["devices"]["fortigate"][0]["host_name"]
        serial_number = multi_result[1].result["devices"]["fortigate"][0]["serial"]
        model = multi_result[1].result["devices"]["fortigate"][0]["model"]
        firmware_version_major = multi_result[1].result["devices"]["fortigate"][0][
            "firmware_version_major"
        ]
        firmware_version_minor = multi_result[1].result["devices"]["fortigate"][0][
            "firmware_version_minor"
        ]
        firmware_version_patch = multi_result[1].result["devices"]["fortigate"][0][
            "firmware_version_patch"
        ]
        version = f"{firmware_version_major}.{firmware_version_minor}.{firmware_version_patch}"

        # Clean the data as necessary (e.g. remove leading/trailing whitespace)
        hostname = hostname.strip()
        serial_number = serial_number.strip()
        model = model.strip()
        version = version.strip()
        # Create a dictionary of the cleaned data
        cleaned_dict = {
            "hostname": hostname,
            "serial_number": serial_number,
            "model": model,
            "version": version,
        }

        # Append the dictionary to the cleaned_data list
        cleaned_data.append(cleaned_dict)
    return cleaned_data


def clean_interface_data() -> List[Dict]:
    """ ""
    Returns:
        interface data in a list of dictionaries
    """
    device_info = nr.run(task=get_fortigate_interface_info)
    cleaned_data = []
    for device, multi_result in device_info.items():
        # Get the hostname, serial number, and model from the multi_result object
        interface_info = multi_result[1].result
        for interface in interface_info:
            intf_name = interface["name"]
            intf_vdom = interface["vdom"]
            intf_mode = interface["mode"]
            intf_status = interface["status"]
            intf_mtu = interface["mtu"]
            intf_ip = interface["ip"]
            intf_type = interface["type"]
            intf_allowaccess = interface["allowaccess"]
            # Clean the data as necessary (e.g. remove leading/trailing whitespace)
            intf_name = intf_name.strip()
            intf_vdom = intf_vdom.strip()
            intf_mode = intf_mode.strip()
            intf_status = intf_status.strip()
            intf_ip = intf_ip.strip()
            intf_type = intf_type.strip()
            intf_allowaccess = intf_allowaccess.strip()
            # Create a dictionary of the cleaned data
            cleaned_dict = {
                "hostname": device,
                "name": intf_name,
                "vdom": intf_vdom,
                "mode": intf_mode,
                "status": intf_status,
                "mtu": intf_mtu,
                "ip": intf_ip,
                "type": intf_type,
                "allowaccess": intf_allowaccess,
            }

            # Append the dictionary to the cleaned_data list
            cleaned_data.append(cleaned_dict)
    pprint(cleaned_data)
    return cleaned_data


clean_interface_data()
