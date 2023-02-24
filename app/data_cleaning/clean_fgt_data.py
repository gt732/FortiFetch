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
                intf_name = interface.get("name", "")
                intf_vdom = interface.get("vdom", "")
                intf_mode = interface.get("mode", "")
                intf_status = interface.get("status", "")
                intf_mtu = interface.get("mtu", "")
                intf_ip = interface.get("ip", "")
                intf_type = interface.get("type", "")
                intf_allowaccess = interface.get("allowaccess", "")
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
                address_name = address.get("name", "")
                address_type = address.get("type", "")
                address_subnet = address.get("subnet", "")
                address_startip = address.get("start-ip", "")
                address_endip = address.get("end-ip", "")
                address_fqdn = address.get("fqdn", "")
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
                address_name = address.get("name", "")
                address_member = address.get("member", "")

                # Extract the member values as a string
                member_string = ""
                for member in address_member:
                    member_json = json.dumps(member)
                    member_values = member_json[1:-1].replace('"', "").replace(":", ",")
                    member_string += member_values + ";"
                member_string = member_string[:-1]  # Remove the last semicolon

                # Create a dictionary of the cleaned data
                cleaned_dict = {
                    "hostname": device,
                    "name": address_name,
                    "member": member_string,
                }
                # Append the dictionary to the cleaned_data list
                cleaned_data.append(cleaned_dict)
    return cleaned_data


def clean_application_data() -> List[Dict]:
    """
    Get the application profile information from the get_fortigate_application_info() function
    and clean the data before it is written to the database.
    """
    device_info = get_fortigate_application_info()
    cleaned_data = []
    for firewall in device_info:
        for device, value in firewall.items():
            for profile in value:
                profile_name = profile.get("name", "")
                profile_entries = profile.get("entries", "")
                profile_comment = profile.get("comment", "")

                # Extract the entries values as a string
                entries_string = ""
                for entry in profile_entries:
                    entry_json = json.dumps(entry)
                    entry_values = entry_json[1:-1].replace('"', "").replace(":", ",")
                    entries_string += entry_values + ";"
                entries_string = entries_string[:-1]  # Remove the last semicolon

                # Create a dictionary of the cleaned data
                cleaned_dict = {
                    "hostname": device,
                    "name": profile_name,
                    "entries": entries_string,
                    "comment": profile_comment,
                }
                # Append the dictionary to the cleaned_data list
                cleaned_data.append(cleaned_dict)
    return cleaned_data


def clean_av_data() -> List[Dict]:
    """
    Get the antivirus profile information from the get_fortigate_application_info() function
    and clean the data before it is written to the database.
    """
    device_info = get_fortigate_av_info()
    cleaned_data = []
    for firewall in device_info:
        for device, value in firewall.items():
            for profile in value:
                profile_name = profile.get("name", "")
                profile_comment = str(profile.get("comment", ""))
                profile_http = str(profile.get("http", ""))
                profile_ftp = str(profile.get("ftp", ""))
                profile_imap = str(profile.get("imap", ""))
                profile_pop3 = str(profile.get("pop3", ""))
                profile_smtp = str(profile.get("smtp", ""))
                profile_nntp = str(profile.get("nntp", ""))
                profile_mapi = str(profile.get("mapi", ""))
                profile_ssh = str(profile.get("ssh", ""))
                profile_cifs = str(profile.get("cifs", ""))
                profile_nac_quar = str(profile.get("nac-quar", ""))
                profile_content_disarm = str(profile.get("content-disarm", ""))

                # Create a dictionary of the cleaned data
                cleaned_dict = {
                    "hostname": device,
                    "name": profile_name,
                    "comment": profile_comment,
                    "http": profile_http,
                    "ftp": profile_ftp,
                    "imap": profile_imap,
                    "pop3": profile_pop3,
                    "smtp": profile_smtp,
                    "nntp": profile_nntp,
                    "mapi": profile_mapi,
                    "ssh": profile_ssh,
                    "cifs": profile_cifs,
                    "nac_quar": profile_nac_quar,
                    "content_disarm": profile_content_disarm,
                }
                # Append the dictionary to the cleaned_data list
                cleaned_data.append(cleaned_dict)
    return cleaned_data


def clean_dnsfilter_data() -> List[Dict]:
    """
    Get the dnsfilter profile information from the get_fortigate_dnsfilter_info() function
    and clean the data before it is written to the database.
    """
    device_info = get_fortigate_dnsfilter_info()
    cleaned_data = []
    for firewall in device_info:
        for device, value in firewall.items():
            for profile in value:
                profile_name = profile.get("name", "")
                profile_comment = profile.get("comment", "")
                profile_domain_filter = str(profile.get("domain-filter", ""))
                profile_ftgd_dns = str(profile.get("ftgd-dns", ""))
                profile_block_botnet = profile.get("block-botnet", "")
                profile_safe_search = profile.get("safe-search", "")
                profile_youtube_restrict = profile.get("youtube-restrict", "")

                # Create a dictionary of the cleaned data
                cleaned_dict = {
                    "hostname": device,
                    "name": profile_name,
                    "comment": profile_comment,
                    "domain_filter": profile_domain_filter,
                    "ftgd_dns": profile_ftgd_dns,
                    "block_botnet": profile_block_botnet,
                    "safe_search": profile_safe_search,
                    "youtube_restrict": profile_youtube_restrict,
                }
                # Append the dictionary to the cleaned_data list
                cleaned_data.append(cleaned_dict)
    return cleaned_data


def clean_internetservice_data() -> List[Dict]:
    """
    Get the internet service information from the get_fortigate_internetservice_info() function
    and clean the data before it is written to the database.
    """
    device_info = get_fortigate_internetservice_info()
    cleaned_data = []
    for firewall in device_info:
        for device, value in firewall.items():
            for internet_service in value:
                service_name = internet_service.get("name", "")
                service_type = internet_service.get("type", "")

                # Create a dictionary of the cleaned data
                cleaned_dict = {
                    "hostname": device,
                    "name": service_name,
                    "type": service_type,
                }
                # Append the dictionary to the cleaned_data list
                cleaned_data.append(cleaned_dict)
    return cleaned_data


def clean_ippool_data() -> List[Dict]:
    """
    Get the ippool information from the get_fortigate_ippool_info() function
    and clean the data before it is written to the database.
    """
    device_info = get_fortigate_ippool_info()
    cleaned_data = []
    for firewall in device_info:
        for device, value in firewall.items():
            for ippool in value:
                pool_name = ippool.get("name", "")
                pool_type = ippool.get("type", "")
                pool_startip = ippool.get("startip", "")
                pool_endip = ippool.get("endip", "")
                pool_startport = ippool.get("startport", "")
                pool_endport = ippool.get("endport", "")
                pool_source_startip = ippool.get("source-startip", "")
                pool_source_endip = ippool.get("source-endip", "")
                pool_arp_reply = ippool.get("arp-reply", "")
                pool_arp_intf = ippool.get("arp-intf", "")
                pool_associated_interface = ippool.get("associated-interface", "")
                pool_comments = ippool.get("comments", "")

                # Create a dictionary of the cleaned data
                cleaned_dict = {
                    "hostname": device,
                    "name": pool_name,
                    "type": pool_type,
                    "startip": pool_startip,
                    "endip": pool_endip,
                    "source_startip": pool_source_startip,
                    "source_endip": pool_source_endip,
                    "arp_reply": pool_arp_reply,
                    "arp_intf": pool_arp_intf,
                    "associated_interface": pool_associated_interface,
                    "comments": pool_comments,
                    "startport": pool_startport,
                    "endport": pool_endport,
                }
                # Append the dictionary to the cleaned_data list
                cleaned_data.append(cleaned_dict)

                cleaned_data.append(cleaned_dict)
    return cleaned_data
