"""
This module contains functions for cleaning the data returned from the fortigate api tasks
before it is written to the database.
"""

# import os sys
import os
import sys

# Add the parent directory of 'fortifetch' to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# import modules
from typing import List, Dict, Optional
from tasks.fgt_tasks import *
import json


def clean_address_data() -> List[Dict]:
    """
    Get the address information from the get_fortigate_address_info() function
    and clean the data before it is written to the database.
    """
    device_info = get_fortigate_address_info()
    cleaned_data = []
    for firewall in device_info:
        for device, value in firewall.items():
            if not value:
                continue
            for address in value:
                address_name = address.get("name", "")
                address_type = address.get("type", "")
                address_subnet = address.get("subnet", "")
                address_startip = address.get("start-ip", "")
                address_endip = address.get("end-ip", "")
                address_fqdn = address.get("fqdn", "")
                address_country = address["country"]
                address_associated_interface = address["associated-interface"]

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
            if not value:
                continue
            for address in value:
                address_name = address.get("name", "")
                address_member = address.get("member", "")

                member_string = ""
                for member in address_member:
                    member_json = json.dumps(member)
                    member_values = member_json[1:-1].replace('"', "").replace(":", ",")
                    member_string += member_values + ";"
                member_string = member_string[:-1]

                cleaned_dict = {
                    "hostname": device,
                    "name": address_name,
                    "member": member_string,
                }
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
            if not value:
                continue
            for internet_service in value:
                service_name = internet_service.get("name", "")
                service_type = internet_service.get("type", "")

                cleaned_dict = {
                    "hostname": device,
                    "name": service_name,
                    "type": service_type,
                }
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
            if not value:
                continue
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
                cleaned_data.append(cleaned_dict)
    return cleaned_data


def clean_vip_data() -> List[Dict]:
    """
    Get the vip information from the get_fortigate_vip_info() function
    and clean the data before it is written to the database.
    """
    device_info = get_fortigate_vip_info()
    cleaned_data = []
    for firewall in device_info:
        for device, value in firewall.items():
            if not value:
                continue
            for vip in value:
                vip_name = vip.get("name", "")
                vip_comment = vip.get("comment", "")
                vip_type = vip.get("type", "")
                vip_extip = vip.get("extip", "")
                vip_extaddr = str(vip.get("extaddr", ""))
                vip_nat44 = vip.get("nat44", "")
                vip_mappedip = vip.get("mappedip", "")
                vip_mappedip = vip_mappedip[0]["range"]
                vip_mapped_addr = str(vip.get("mapped-addr", ""))
                vip_extintf = vip.get("extintf", "")
                vip_arp_reply = vip.get("arp-reply", "")
                vip_portforward = vip.get("portforward", "")
                vip_status = vip.get("status", "")
                vip_protocol = vip.get("protocol", "")
                vip_extport = vip.get("extport", "")
                vip_mappedport = vip.get("mappedport", "")
                vip_src_filter = str(vip.get("src-filter", ""))
                vip_portmapping_type = vip.get("portmapping-type", "")
                vip_realservers = str(vip.get("realservers", ""))

                cleaned_dict = {
                    "hostname": device,
                    "name": vip_name,
                    "comment": vip_comment,
                    "type": vip_type,
                    "extip": vip_extip,
                    "extaddr": vip_extaddr,
                    "nat44": vip_nat44,
                    "mappedip": vip_mappedip,
                    "mapped_addr": vip_mapped_addr,
                    "extintf": vip_extintf,
                    "arp_reply": vip_arp_reply,
                    "portforward": vip_portforward,
                    "status": vip_status,
                    "protocol": vip_protocol,
                    "extport": vip_extport,
                    "mappedport": vip_mappedport,
                    "src_filter": vip_src_filter,
                    "portmapping_type": vip_portmapping_type,
                    "realservers": vip_realservers,
                }

                cleaned_data.append(cleaned_dict)
    return cleaned_data


def clean_trafficshapers_data() -> List[Dict]:
    """
    Get the traffic shapers information from the get_fortigate_trafficshapers_info() function
    and clean the data before it is written to the database.
    """
    device_info = get_fortigate_trafficshapers_info()
    cleaned_data = []
    for firewall in device_info:
        for device, value in firewall.items():
            if not value:
                continue
            for trafficshapers in value:
                trafficshapers_name = trafficshapers.get("name", "")
                trafficshapers_guaranteed_bandwidth = trafficshapers.get(
                    "guaranteed-bandwidth", ""
                )
                trafficshapers_maximum_bandwidth = trafficshapers.get(
                    "maximum-bandwidth", ""
                )
                trafficshapers_bandwidth_unit = trafficshapers.get("bandwidth-unit", "")
                trafficshapers_priority = trafficshapers.get("priority", "")
                trafficshapers_per_policy = trafficshapers.get("per-policy", "")
                trafficshapers_diffserv = trafficshapers.get("diffserv", "")
                trafficshapers_diffservcode = trafficshapers.get("diffservcode", "")
                trafficshapers_dscp_marking_method = trafficshapers.get(
                    "dscp-marking-method", ""
                )
                trafficshapers_exceed_bandwidth = trafficshapers.get(
                    "exceed-bandwidth", ""
                )
                trafficshapers_exceed_dscp = trafficshapers.get("exceed-dscp", "")
                trafficshapers_maximum_dscp = trafficshapers.get("maximum-dscp", "")
                trafficshapers_overhead = trafficshapers.get("overhead", "")
                trafficshapers_exceed_class_id = trafficshapers.get(
                    "exceed-class-id", ""
                )

                cleaned_dict = {
                    "hostname": device,
                    "name": trafficshapers_name,
                    "guaranteed_bandwidth": trafficshapers_guaranteed_bandwidth,
                    "maximum_bandwidth": trafficshapers_maximum_bandwidth,
                    "bandwidth_unit": trafficshapers_bandwidth_unit,
                    "priority": trafficshapers_priority,
                    "per_policy": trafficshapers_per_policy,
                    "diffserv": trafficshapers_diffserv,
                    "diffservcode": trafficshapers_diffservcode,
                    "dscp_marking_method": trafficshapers_dscp_marking_method,
                    "exceed_bandwidth": trafficshapers_exceed_bandwidth,
                    "exceed_dscp": trafficshapers_exceed_dscp,
                    "maximum_dscp": trafficshapers_maximum_dscp,
                    "overhead": trafficshapers_overhead,
                    "exceed_class_id": trafficshapers_exceed_class_id,
                }

                cleaned_data.append(cleaned_dict)
    return cleaned_data


def clean_trafficpolicy_data() -> List[Dict]:
    """
    Get the traffic shapers policy information from the get_fortigate_trafficpolicy_info() function
    and clean the data before it is written to the database.
    """
    device_info = get_fortigate_trafficpolicy_info()
    cleaned_data = []
    for firewall in device_info:
        for device, value in firewall.items():
            if not value:
                continue
            for trafficpolicy in value:
                policy_id = trafficpolicy.get("policyid", "")
                trafficpolicy_name = trafficpolicy.get("name", "")
                trafficpolicy_comment = trafficpolicy.get("comment", "")
                trafficpolicy_status = trafficpolicy.get("status", "")
                trafficpolicy_ip_version = trafficpolicy.get("ip-version", "")
                trafficpolicy_srcintf = str(trafficpolicy.get("srcintf", ""))
                trafficpolicy_dstintf = str(trafficpolicy.get("dstintf", ""))
                trafficpolicy_srcaddr = str(trafficpolicy.get("srcaddr", ""))
                trafficpolicy_dstaddr = str(trafficpolicy.get("dstaddr", ""))
                trafficpolicy_internet_service = str(
                    trafficpolicy.get("internet-service", "")
                )
                trafficpolicy_internet_service_name = str(
                    trafficpolicy.get("internet-service-name", "")
                )
                trafficpolicy_internet_service_group = str(
                    trafficpolicy.get("internet-service-group", "")
                )
                trafficpolicy_internet_service_custom = str(
                    trafficpolicy.get("internet-service-custom", "")
                )
                trafficpolicy_internet_service_src = str(
                    trafficpolicy.get("internet-service-src", "")
                )
                trafficpolicy_internet_service_src_name = str(
                    trafficpolicy.get("internet-service-src-name", "")
                )
                trafficpolicy_internet_service_src_group = str(
                    trafficpolicy.get("internet-service-src-group", "")
                )
                trafficpolicy_internet_service_src_custom = str(
                    trafficpolicy.get("internet-service-src-custom", "")
                )
                trafficpolicy_internet_service_src_custom_group = str(
                    trafficpolicy.get("internet-service-src-custom-group", "")
                )
                trafficpolicy_service = str(trafficpolicy.get("service", ""))
                trafficpolicy_schedule = str(trafficpolicy.get("schedule", ""))
                trafficpolicy_users = str(trafficpolicy.get("users", ""))
                trafficpolicy_groups = str(trafficpolicy.get("groups", ""))
                trafficpolicy_application = str(trafficpolicy.get("application", ""))
                trafficpolicy_app_group = str(trafficpolicy.get("app-group", ""))
                trafficpolicy_url_category = str(trafficpolicy.get("url-category", ""))
                trafficpolicy_traffic_shaper = str(
                    trafficpolicy.get("traffic-shaper", "")
                )
                trafficpolicy_traffic_shaper_reverse = str(
                    trafficpolicy.get("traffic-shaper-reverse", "")
                )
                trafficpolicy_per_ip_shaper = str(
                    trafficpolicy.get("per-ip-shaper", "")
                )
                trafficpolicy_class_id = str(trafficpolicy.get("class-id", ""))
                trafficpolicy_diffserv_forward = str(
                    trafficpolicy.get("diffserv-forward", "")
                )
                trafficpolicy_diffserv_reverse = str(
                    trafficpolicy.get("diffserv-reverse", "")
                )

                cleaned_dict = {
                    "hostname": device,
                    "policy_id": policy_id,
                    "name": trafficpolicy_name,
                    "comment": trafficpolicy_comment,
                    "status": trafficpolicy_status,
                    "ip_version": trafficpolicy_ip_version,
                    "srcintf": trafficpolicy_srcintf,
                    "dstintf": trafficpolicy_dstintf,
                    "srcaddr": trafficpolicy_srcaddr,
                    "dstaddr": trafficpolicy_dstaddr,
                    "internet_service": trafficpolicy_internet_service,
                    "internet_service_name": trafficpolicy_internet_service_name,
                    "internet_service_group": trafficpolicy_internet_service_group,
                    "internet_service_custom": trafficpolicy_internet_service_custom,
                    "internet_service_src": trafficpolicy_internet_service_src,
                    "internet_service_src_name": trafficpolicy_internet_service_src_name,
                    "internet_service_src_group": trafficpolicy_internet_service_src_group,
                    "internet_service_src_custom": trafficpolicy_internet_service_src_custom,
                    "internet_service_src_custom_group": trafficpolicy_internet_service_src_custom_group,
                    "service": trafficpolicy_service,
                    "schedule": trafficpolicy_schedule,
                    "users": trafficpolicy_users,
                    "groups": trafficpolicy_groups,
                    "application": trafficpolicy_application,
                    "app_group": trafficpolicy_app_group,
                    "url_category": trafficpolicy_url_category,
                    "traffic_shaper": trafficpolicy_traffic_shaper,
                    "traffic_shaper_reverse": trafficpolicy_traffic_shaper_reverse,
                    "per_ip_shaper": trafficpolicy_per_ip_shaper,
                    "class_id": trafficpolicy_class_id,
                    "diffserv_forward": trafficpolicy_diffserv_forward,
                    "diffserv_reverse": trafficpolicy_diffserv_reverse,
                }
                cleaned_data.append(cleaned_dict)
    return cleaned_data


def clean_fwpolicy_data() -> List[Dict]:
    """
    Get the firewall policy information from the get_fortigate_fwpolicy_info() function
    and clean the data before it is written to the database.
    """
    device_info = get_fortigate_fwpolicy_info()
    cleaned_data = []
    for firewall in device_info:
        for device, value in firewall.items():
            if not value:
                continue
            for fwpolicy in value:
                policy_id = fwpolicy.get("policyid", "")
                fwpolicy_status = fwpolicy.get("status", "")
                fwpolicy_name = fwpolicy.get("name", "")

                fwpolicy_srcintf = fwpolicy.get("srcintf", "")
                fwpolicy_srcintf = ",".join([intf["name"] for intf in fwpolicy_srcintf])

                fwpolicy_dstinft = fwpolicy.get("dstintf", "")
                fwpolicy_dstinft = ",".join([intf["name"] for intf in fwpolicy_dstinft])

                fwpolicy_action = fwpolicy.get("action", "")
                fwpolicy_nat64 = fwpolicy.get("nat64", "")
                fwpolicy_nat46 = fwpolicy.get("nat46", "")

                fwpolicy_srcaddr = fwpolicy.get("srcaddr", "")
                fwpolicy_srcaddr = ",".join([addr["name"] for addr in fwpolicy_srcaddr])

                fwpolicy_dstaddr = fwpolicy.get("dstaddr", "")
                fwpolicy_dstaddr = ",".join([addr["name"] for addr in fwpolicy_dstaddr])

                fwpolicy_srcaddr6 = str(fwpolicy.get("srcaddr6", ""))
                fwpolicy_dstaddr6 = str(fwpolicy.get("dstaddr6", ""))
                fwpolicy_internet_service = str(fwpolicy.get("internet-service", ""))

                fwpolicy_srcintf = fwpolicy.get("srcintf", "")
                fwpolicy_srcintf = ",".join([intf["name"] for intf in fwpolicy_srcintf])

                fwpolicy_dstintf = fwpolicy.get("dstintf", "")
                fwpolicy_dstintf = ",".join([intf["name"] for intf in fwpolicy_dstintf])

                fwpolicy_srcaddr = fwpolicy.get("srcaddr", "")
                fwpolicy_srcaddr = ",".join([addr["name"] for addr in fwpolicy_srcaddr])

                fwpolicy_dstaddr = fwpolicy.get("dstaddr", "")
                fwpolicy_dstaddr = ",".join([addr["name"] for addr in fwpolicy_dstaddr])

                fwpolicy_service = fwpolicy.get("service", "")
                fwpolicy_service = ",".join(
                    [service["name"] for service in fwpolicy_service]
                )

                fwpolicy_poolname = fwpolicy.get("poolname", "")
                fwpolicy_poolname = ",".join(
                    [poolname["name"] for poolname in fwpolicy_poolname]
                )

                fwpolicy_internet_service_name = fwpolicy.get(
                    "internet-service-name", ""
                )
                fwpolicy_internet_service_name = ",".join(
                    [service["name"] for service in fwpolicy_internet_service_name]
                )

                fwpolicy_internet_service_group = fwpolicy.get(
                    "internet-service-group", ""
                )
                fwpolicy_internet_service_group = ",".join(
                    [service["name"] for service in fwpolicy_internet_service_group]
                )

                fwpolicy_internet_service_dynamic = fwpolicy.get(
                    "internet-service-dynamic", ""
                )
                fwpolicy_internet_service_dynamic = ",".join(
                    [service["name"] for service in fwpolicy_internet_service_dynamic]
                )

                fwpolicy_internet_service_custom_group = fwpolicy.get(
                    "internet-service-custom-group", ""
                )
                fwpolicy_internet_service_custom_group = ",".join(
                    [
                        service["name"]
                        for service in fwpolicy_internet_service_custom_group
                    ]
                )

                fwpolicy_internet_service_src = fwpolicy.get("internet-service-src", "")

                fwpolicy_internet_service_src_name = fwpolicy.get(
                    "internet-service-src-name", ""
                )
                fwpolicy_internet_service_src_name = ",".join(
                    [service["name"] for service in fwpolicy_internet_service_src_name]
                )

                fwpolicy_internet_service_src_group = fwpolicy.get(
                    "internet-service-src-group", ""
                )
                fwpolicy_internet_service_src_group = ",".join(
                    [service["name"] for service in fwpolicy_internet_service_src_group]
                )

                fwpolicy_internet_service_src_dynamic = fwpolicy.get(
                    "internet-service-src-dynamic", ""
                )
                fwpolicy_internet_service_src_dynamic = ",".join(
                    [
                        service["name"]
                        for service in fwpolicy_internet_service_src_dynamic
                    ]
                )

                fwpolicy_internet_service_src_custom_group = fwpolicy.get(
                    "internet-service-src-custom-group", ""
                )
                fwpolicy_internet_service_src_custom_group = ",".join(
                    [
                        service["name"]
                        for service in fwpolicy_internet_service_src_custom_group
                    ]
                )

                fwpolicy_schedule = str(fwpolicy.get("schedule", ""))
                fwpolicy_schedule_timeout = fwpolicy.get("schedule-timeout", "")

                fwpolicy_service = fwpolicy.get("service", "")
                fwpolicy_service = ",".join(
                    [service["name"] for service in fwpolicy_service]
                )

                fwpolicy_service_utm_status = fwpolicy.get("service-utm-status", "")
                fwpolicy_inspection_mode = fwpolicy.get("inspection-mode", "")
                fwpolicy_http_policy_redirect = fwpolicy.get("http-policy-redirect", "")
                fwpolicy_ssh_policy_redirect = fwpolicy.get("ssh-policy-redirect", "")
                fwpolicy_profile_type = fwpolicy.get("profile-type", "")
                fwpolicy_profile_group = str(fwpolicy.get("profile-group", ""))
                fwpolicy_profile_protocol_options = str(
                    fwpolicy.get("profile-protocol-options", "")
                )
                fwpolicy_ssl_ssh_profile = str(fwpolicy.get("ssl-ssh-profile", ""))
                fwpolicy_av_profile = str(fwpolicy.get("av-profile", ""))
                fwpolicy_webfilter_profile = str(fwpolicy.get("webfilter-profile", ""))
                fwpolicy_dnsfilter_profile = str(fwpolicy.get("dnsfilter-profile", ""))
                fwpolicy_emailfilter_profile = str(
                    fwpolicy.get("emailfilter-profile", "")
                )
                fwpolicy_dlp_profile = str(fwpolicy.get("dlp-profile", ""))
                fwpolicy_file_filter = str(fwpolicy.get("file-filter", ""))
                fwpolicy_ips_sensor = str(fwpolicy.get("ips-sensor", ""))
                fwpolicy_application_list = str(fwpolicy.get("application-list", ""))
                fwpolicy_voip_profile = str(fwpolicy.get("voip-profile", ""))
                fwpolicy_sctp_profile = str(fwpolicy.get("sctp-profile", ""))
                fwpolicy_icap_profile = str(fwpolicy.get("icap-profile", ""))
                fwpolicy_cifs_profile = str(fwpolicy.get("cifs-profile", ""))
                fwpolicy_waf_profile = str(fwpolicy.get("waf-profile", ""))
                fwpolicy_ssh_filter_profile = str(
                    fwpolicy.get("ssh-filter-profile", "")
                )
                fwpolicy_logtraffic = fwpolicy.get("logtraffic", "")
                fwpolicy_logtraffic_start = fwpolicy.get("logtraffic-start", "")
                fwpolicy_capture_packet = fwpolicy.get("capture-packet", "")
                fwpolicy_traffic_shaper = str(fwpolicy.get("traffic-shaper", ""))
                fwpolicy_traffic_shaper_reverse = str(
                    fwpolicy.get("traffic-shaper-reverse", "")
                )
                fwpolicy_per_ip_shaper = str(fwpolicy.get("per-ip-shaper", ""))
                fwpolicy_nat = fwpolicy.get("nat", "")
                fwpolicy_permit_any_host = fwpolicy.get("permit-any-host", "")
                fwpolicy_permit_stun_host = fwpolicy.get("permit-stun-host", "")
                fwpolicy_fixedport = fwpolicy.get("fixedport", "")
                fwpolicy_ippool = fwpolicy.get("ippool", "")

                fwpolicy_poolname = fwpolicy.get("poolname", "")
                fwpolicy_poolname = ",".join(
                    [poolname["name"] for poolname in fwpolicy_poolname]
                )

                fwpolicy_poolname6 = str(fwpolicy.get("poolname6", ""))
                fwpolicy_inbound = fwpolicy.get("inbound", "")
                fwpolicy_outbound = fwpolicy.get("outbound", "")
                fwpolicy_natinbound = fwpolicy.get("natinbound", "")
                fwpolicy_natoutbound = fwpolicy.get("natoutbound", "")
                fwpolicy_wccp = fwpolicy.get("wccp", "")
                fwpolicy_ntlm = fwpolicy.get("ntlm", "")
                fwpolicy_ntlm_guest = fwpolicy.get("ntlm-guest", "")
                fwpolicy_ntlm_enabled_browsers = str(
                    fwpolicy.get("ntlm-enabled-browsers", "")
                )
                fwpolicy_groups = str(fwpolicy.get("groups", ""))
                fwpolicy_users = str(fwpolicy.get("users", ""))
                fwpolicy_fsso_groups = str(fwpolicy.get("fsso-groups", ""))
                fwpolicy_vpntunnel = str(fwpolicy.get("vpntunnel", ""))
                fwpolicy_natip = str(fwpolicy.get("natip", ""))
                fwpolicy_match_vip = fwpolicy.get("match-vip", "")
                fwpolicy_match_vip_only = fwpolicy.get("match-vip-only", "")
                fwpolicy_comments = str(fwpolicy.get("comments", ""))
                fwpolicy_label = str(fwpolicy.get("label", ""))
                fwpolicy_global_label = str(fwpolicy.get("global-label", ""))
                fwpolicy_auth_cert = str(fwpolicy.get("auth-cert", ""))
                fwpolicy_vlan_filter = str(fwpolicy.get("vlan-filter", ""))

                cleaned_dict = {
                    "hostname": device,
                    "policy_id": policy_id,
                    "fwpolicy_name": fwpolicy_name,
                    "fwpolicy_status": fwpolicy_status,
                    "srcintf": fwpolicy_srcintf,
                    "dstintf": fwpolicy_dstinft,
                    "action": fwpolicy_action,
                    "nat64": fwpolicy_nat64,
                    "nat46": fwpolicy_nat46,
                    "srcaddr6": fwpolicy_srcaddr6,
                    "dstaddr6": fwpolicy_dstaddr6,
                    "srcaddr": fwpolicy_srcaddr,
                    "dstaddr": fwpolicy_dstaddr,
                    "internet-service-name": fwpolicy_internet_service_name,
                    "internet-service-src-name": fwpolicy_internet_service_src_name,
                    "internet-service-dynamic": fwpolicy_internet_service_dynamic,
                    "internet-service-custom-group": fwpolicy_internet_service_custom_group,
                    "internet-service": fwpolicy_internet_service,
                    "internet-service-src": fwpolicy_internet_service_src,
                    "internet-service-group": fwpolicy_internet_service_group,
                    "internet-service-src-group": fwpolicy_internet_service_src_group,
                    "internet-service-src-dynamic": fwpolicy_internet_service_src_dynamic,
                    "internet-service-src-custom-group": fwpolicy_internet_service_src_custom_group,
                    "schedule": fwpolicy_schedule,
                    "schedule-timeout": fwpolicy_schedule_timeout,
                    "service": fwpolicy_service,
                    "service-utm-status": fwpolicy_service_utm_status,
                    "inspection-mode": fwpolicy_inspection_mode,
                    "http-policy-redirect": fwpolicy_http_policy_redirect,
                    "ssh-policy-redirect": fwpolicy_ssh_policy_redirect,
                    "profile-type": fwpolicy_profile_type,
                    "profile-group": fwpolicy_profile_group,
                    "profile-protocol-options": fwpolicy_profile_protocol_options,
                    "ssl-ssh-profile": fwpolicy_ssl_ssh_profile,
                    "av-profile": fwpolicy_av_profile,
                    "webfilter-profile": fwpolicy_webfilter_profile,
                    "dnsfilter-profile": fwpolicy_dnsfilter_profile,
                    "emailfilter-profile": fwpolicy_emailfilter_profile,
                    "dlp-profile": fwpolicy_dlp_profile,
                    "file-filter": fwpolicy_file_filter,
                    "ips-sensor": fwpolicy_ips_sensor,
                    "application-list": fwpolicy_application_list,
                    "voip-profile": fwpolicy_voip_profile,
                    "sctp-profile": fwpolicy_sctp_profile,
                    "icap-profile": fwpolicy_icap_profile,
                    "cifs-profile": fwpolicy_cifs_profile,
                    "waf-profile": fwpolicy_waf_profile,
                    "ssh-filter-profile": fwpolicy_ssh_filter_profile,
                    "logtraffic": fwpolicy_logtraffic,
                    "logtraffic-start": fwpolicy_logtraffic_start,
                    "capture-packet": fwpolicy_capture_packet,
                    "traffic-shaper": fwpolicy_traffic_shaper,
                    "traffic-shaper-reverse": fwpolicy_traffic_shaper_reverse,
                    "per-ip-shaper": fwpolicy_per_ip_shaper,
                    "nat": fwpolicy_nat,
                    "permit-any-host": fwpolicy_permit_any_host,
                    "permit-stun-host": fwpolicy_permit_stun_host,
                    "fixedport": fwpolicy_fixedport,
                    "ippool": fwpolicy_ippool,
                    "poolname": fwpolicy_poolname,
                    "poolname6": fwpolicy_poolname6,
                    "inbound": fwpolicy_inbound,
                    "outbound": fwpolicy_outbound,
                    "natinbound": fwpolicy_natinbound,
                    "natoutbound": fwpolicy_natoutbound,
                    "wccp": fwpolicy_wccp,
                    "ntlm": fwpolicy_ntlm,
                    "ntlm-guest": fwpolicy_ntlm_guest,
                    "ntlm-enabled-browsers": fwpolicy_ntlm_enabled_browsers,
                    "groups": fwpolicy_groups,
                    "users": fwpolicy_users,
                    "fsso-groups": fwpolicy_fsso_groups,
                    "vpntunnel": fwpolicy_vpntunnel,
                    "natip": fwpolicy_natip,
                    "match-vip": fwpolicy_match_vip,
                    "match-vip-only": fwpolicy_match_vip_only,
                    "comments": fwpolicy_comments,
                    "label": fwpolicy_label,
                    "global-label": fwpolicy_global_label,
                    "auth-cert": fwpolicy_auth_cert,
                    "vlan-filter": fwpolicy_vlan_filter,
                }
                cleaned_data.append(cleaned_dict)
    return cleaned_data
