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
from tasks.fgt_tasks import *
import json


def clean_device_data() -> List[Dict]:
    """
    Get the device information from the get_fortigate_device_info() function
    and clean the data before it is written to the database.
    """
    device_info = get_fortigate_device_info()
    cleaned_data = []
    for firewall in device_info:
        for device, value in firewall.items():
            hostname = value["devices"]["fortigate"][0]["host_name"]
            serial_number = value["devices"]["fortigate"][0]["serial"]
            model = value["devices"]["fortigate"][0]["model"]
            firmware_version_major = value["devices"]["fortigate"][0][
                "firmware_version_major"
            ]
            firmware_version_minor = value["devices"]["fortigate"][0][
                "firmware_version_minor"
            ]
            firmware_version_patch = value["devices"]["fortigate"][0][
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
    """
    Get the interface information from the get_fortigate_interface_info() function
    and clean the data before it is written to the database.
    """
    device_info = get_fortigate_interface_info()
    cleaned_data = []
    for firewall in device_info:
        for device, value in firewall.items():
            for interface in value:
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
    return cleaned_data


def clean_address_data() -> List[Dict]:
    """
    Get the address information from the get_fortigate_address_info() function
    and clean the data before it is written to the database.
    """
    device_info = get_fortigate_address_info()
    cleaned_data = []
    for firewall in device_info:
        for device, value in firewall.items():
            for address in value:
                address_name = address["name"]
                address_type = address["type"]
                address_subnet = address.get("subnet")
                if address_subnet:
                    address_subnet = address["subnet"]
                address_startip = address.get("start-ip")
                if address_startip:
                    address_startip = address["start-ip"]
                address_endip = address.get("end-ip")
                if address_endip:
                    address_endip = address["end-ip"]
                address_fqdn = address.get("fqdn")
                if address_fqdn:
                    address_fqdn = address["fqdn"]
                address_country = address["country"]
                address_associated_interface = address["associated-interface"]
                # Create a dictionary of the cleaned data
                cleaned_dict = {
                    "hostname": device,
                    "name": address_name,
                    "subnet": address_subnet,
                    "address_type": address_type,
                    "start_ip": address_startip,
                    "end_ip": address_endip,
                    "fqdn": address_fqdn,
                    "country": address_country,
                    "associated_interface": address_associated_interface,
                }
                # Append the dictionary to the cleaned_data list
                cleaned_data.append(cleaned_dict)
    return cleaned_data


def clean_address_group_data() -> List[Dict]:
    """
    Get the address group information from the get_fortigate_interface_info() function
    and clean the data before it is written to the database.
    """
    device_info = get_fortigate_address_group_info()
    cleaned_data = []
    for firewall in device_info:
        for device, value in firewall.items():
            for address in value:
                address_name = address["name"]
                address_member = address["member"]
                member_str = ""
                for member in address_member:
                    member_str += f"name: {member['name']}, q_origin_key: {member['q_origin_key']}, "
                member_str = member_str[:-2]
                # Create a dictionary of the cleaned data
                cleaned_dict = {
                    "hostname": device,
                    "name": address_name,
                    "member": member_str,
                }
                # Append the dictionary to the cleaned_data list
                cleaned_data.append(cleaned_dict)
    return cleaned_data
