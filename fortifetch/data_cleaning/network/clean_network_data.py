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
from tasks.fgt_tasks import *


def clean_interface_data() -> List[Dict]:
    """
    Get the interface information from the get_fortigate_interface_info() function
    and clean the data before it is written to the database.
    """
    device_info = get_fortigate_interface_info()
    cleaned_data = []
    for firewall in device_info:
        for device, value in firewall.items():
            if not value:
                continue
            for interface in value:
                intf_name = interface.get("name", "")
                intf_vdom = interface.get("vdom", "")
                intf_mode = interface.get("mode", "")
                intf_status = interface.get("status", "")
                intf_mtu = interface.get("mtu", "")
                intf_ip = interface.get("ip", "")
                intf_type = interface.get("type", "")
                intf_allowaccess = interface.get("allowaccess", "")
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
                cleaned_data.append(cleaned_dict)
    return cleaned_data


def clean_static_route_data() -> List[Dict]:
    """
    Get the static route information from the get_fortigate_static_route_info() function
    and clean the data before it is written to the database.
    """
    device_info = get_fortigate_static_route_info()
    cleaned_data = []
    for firewall in device_info:
        for device, value in firewall.items():
            if not value:
                continue
            for route in value:
                route_seq_num = route.get("seq-num", "")
                route_status = route.get("status", "")
                route_dst = route.get("dst", "")
                route_src = route.get("src", "")
                route_gateway = route.get("gateway", "")
                route_distance = route.get("distance", "")
                route_weight = route.get("weight", "")
                route_priority = route.get("priority", "")
                route_device = route.get("device", "")
                route_comment = route.get("comment", "")
                route_blackhole = route.get("blackhole", "")
                route_dynamic_gateway = route.get("dynamic-gateway", "")
                route_sdwan_zone = str(route.get("sdwan-zone", ""))
                route_dstaddr = str(route.get("dstaddr", ""))
                route_internet_service = str(route.get("internet-service", ""))
                route_internet_service_custom = route.get("internet-service-custom", "")
                route_tag = str(route.get("tag", ""))
                route_vrf = str(route.get("vrf", ""))
                route_bfd = route.get("bfd", "")

                cleaned_dict = {
                    "hostname": device,
                    "seq_num": route_seq_num,
                    "status": route_status,
                    "dst": route_dst,
                    "src": route_src,
                    "gateway": route_gateway,
                    "distance": route_distance,
                    "weight": route_weight,
                    "priority": route_priority,
                    "device": route_device,
                    "comment": route_comment,
                    "blackhole": route_blackhole,
                    "dynamic_gateway": route_dynamic_gateway,
                    "sdwan_zone": route_sdwan_zone,
                    "dstaddr": route_dstaddr,
                    "internet_service": route_internet_service,
                    "internet_service_custom": route_internet_service_custom,
                    "tag": route_tag,
                    "vrf": route_vrf,
                    "bfd": route_bfd,
                }

            cleaned_data.append(cleaned_dict)
    return cleaned_data


def clean_policy_route_data() -> List[Dict]:
    """
    Get the policy route information from the get_fortigate_policy_route_info() function
    and clean the data before it is written to the database.
    """
    device_info = get_fortigate_policy_route_info()
    cleaned_data = []
    for firewall in device_info:
        for device, value in firewall.items():
            if not value:
                continue
            for route in value:
                route_seq_num = route.get("seq-num", "")
                route_input_device = str(route.get("input-device", ""))
                route_input_device_negate = route.get("input-device-negate", "")
                route_src = str(route.get("src", ""))
                route_srcaddr = str(route.get("srcaddr", ""))
                route_src_negate = route.get("src-negate", "")
                route_dst = str(route.get("dst", ""))
                route_dstaddr = str(route.get("dstaddr", ""))
                route_dst_negate = route.get("dst-negate", "")
                route_action = route.get("action", "")
                route_protocol = str(route.get("protocol", ""))
                route_start_port = str(route.get("start-port", ""))
                route_end_port = str(route.get("end-port", ""))
                route_start_source_port = str(route.get("start-source-port", ""))
                route_end_source_port = str(route.get("end-source-port", ""))
                route_gateway = str(route.get("gateway", ""))
                route_output_device = str(route.get("output-device", ""))
                route_status = route.get("status", "")
                route_comments = route.get("comments", "")
                route_internet_service_id = str(route.get("internet-service-id", ""))
                route_internet_service_custom = str(
                    route.get("internet-service-custom", "")
                )

                cleaned_dict = {
                    "hostname": device,
                    "seq_num": route_seq_num,
                    "input_device": route_input_device,
                    "input_device_negate": route_input_device_negate,
                    "src": route_src,
                    "srcaddr": route_srcaddr,
                    "src_negate": route_src_negate,
                    "dst": route_dst,
                    "dstaddr": route_dstaddr,
                    "dst_negate": route_dst_negate,
                    "action": route_action,
                    "protocol": route_protocol,
                    "start_port": route_start_port,
                    "end_port": route_end_port,
                    "start_source_port": route_start_source_port,
                    "end_source_port": route_end_source_port,
                    "gateway": route_gateway,
                    "output_device": route_output_device,
                    "status": route_status,
                    "comments": route_comments,
                    "internet_service_id": route_internet_service_id,
                    "internet_service_custom": route_internet_service_custom,
                }
                cleaned_data.append(cleaned_dict)
    return cleaned_data
