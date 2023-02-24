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
    return cleaned_data


def clean_ips_data() -> List[Dict]:
    """
    Get the ips information from the get_fortigate_ips_info() function
    and clean the data before it is written to the database.
    """
    device_info = get_fortigate_ips_info()
    cleaned_data = []
    for firewall in device_info:
        for device, value in firewall.items():
            for ips in value:
                ips_name = ips.get("name", "")
                ips_comment = ips.get("comment", "")
                ips_block_malicious_url = ips.get("block-malicious-url", "")
                ips_scan_botnet_connections = ips.get("scan-botnet-connections", "")
                ips_extended_log = ips.get("extended-log", "")
                ips_entries = str(ips.get("entries", ""))

                # Create a dictionary of the cleaned data
                cleaned_dict = {
                    "hostname": device,
                    "name": ips_name,
                    "comment": ips_comment,
                    "block_malicious_url": ips_block_malicious_url,
                    "scan_botnet_connections": ips_scan_botnet_connections,
                    "extended_log": ips_extended_log,
                    "entries": ips_entries,
                }
                # Append the dictionary to the cleaned_data list
                cleaned_data.append(cleaned_dict)
    return cleaned_data


def clean_sslssh_data() -> List[Dict]:
    """
    Get the ssl/ssh profile information from the get_fortigate_sslssh_info() function
    and clean the data before it is written to the database.
    """
    device_info = get_fortigate_sslssh_info()
    cleaned_data = []
    for firewall in device_info:
        for device, value in firewall.items():
            for sslssh in value:
                sslssh_name = sslssh.get("name", "")
                sslssh_comment = sslssh.get("comment", "")
                sslssh_ssl = str(sslssh.get("ssl", ""))
                sslssh_https = str(sslssh.get("https", ""))
                sslssh_ftps = str(sslssh.get("ftps", ""))
                sslssh_imaps = str(sslssh.get("imaps", ""))
                sslssh_pop3s = str(sslssh.get("pop3s", ""))
                sslssh_smtps = str(sslssh.get("smtps", ""))
                sslssh_ssh = str(sslssh.get("ssh", ""))
                sslssh_dot = str(sslssh.get("dot", ""))
                sslssh_allowlist = sslssh.get("allowlist", "")
                sslssh_block_blocklisted_certificates = sslssh.get(
                    "block-blocklisted-certificates", ""
                )
                sslssh_exempt = str(sslssh.get("ssl-exempt", ""))
                sslssh_exemption_ip_rating = sslssh.get("ssl-exemption-ip-rating", "")
                sslssh_ssl_server = str(sslssh.get("ssl-server", ""))
                sshssh_caname = sslssh.get("caname", "")
                sslssh_mapi_over_https = sslssh.get("mapi-over-https", "")
                sslssh_rpc_over_https = sslssh.get("rpc-over-https", "")
                sslssh_untrusted_caname = sslssh.get("untrusted-caname", "")

                # Create a dictionary of the cleaned data
                cleaned_dict = {
                    "hostname": device,
                    "name": sslssh_name,
                    "comment": sslssh_comment,
                    "ssl": sslssh_ssl,
                    "https": sslssh_https,
                    "ftps": sslssh_ftps,
                    "imaps": sslssh_imaps,
                    "pop3s": sslssh_pop3s,
                    "smtps": sslssh_smtps,
                    "ssh": sslssh_ssh,
                    "dot": sslssh_dot,
                    "allowlist": sslssh_allowlist,
                    "block_blocklisted_certificates": sslssh_block_blocklisted_certificates,
                    "ssl_exempt": sslssh_exempt,
                    "ssl_exemption_ip_rating": sslssh_exemption_ip_rating,
                    "ssl_server": sslssh_ssl_server,
                    "caname": sshssh_caname,
                    "mapi_over_https": sslssh_mapi_over_https,
                    "rpc_over_https": sslssh_rpc_over_https,
                    "untrusted_caname": sslssh_untrusted_caname,
                }

                # Append the dictionary to the cleaned_data list
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
                # Create a dictionary of the cleaned data
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


def clean_webfilter_data() -> List[Dict]:
    """
    Get the web filter information from the get_fortigate_webfilter_info() function
    and clean the data before it is written to the database.
    """
    device_info = get_fortigate_webfilter_info()
    cleaned_data = []
    for firewall in device_info:
        for device, value in firewall.items():
            for webfilter in value:
                webfilter_name = webfilter.get("name", "")
                webfilter_comment = webfilter.get("comment", "")
                webfilter_options = webfilter.get("options", "")
                webfilter_https_replacemsg = webfilter.get("https-replacemsg", "")
                webfilter_override = str(webfilter.get("override", ""))
                webfilter_web = str(webfilter.get("web", ""))
                webfilter_ftgd_wf = str(webfilter.get("ftgd-wf", ""))

                # Create a dictionary of the cleaned data
                cleaned_dict = {
                    "hostname": device,
                    "name": webfilter_name,
                    "comment": webfilter_comment,
                    "options": webfilter_options,
                    "https_replacemsg": webfilter_https_replacemsg,
                    "override": webfilter_override,
                    "web": webfilter_web,
                    "ftgd_wf": webfilter_ftgd_wf,
                }

                # Append the dictionary to the cleaned_data list
                cleaned_data.append(cleaned_dict)
    return cleaned_data


def clean_dns_data() -> List[Dict]:
    """
    Get the dns information from the get_fortigate_dns_info() function
    and clean the data before it is written to the database.
    """
    device_info = get_fortigate_dns_info()
    cleaned_data = []
    for firewall in device_info:
        for device, value in firewall.items():
            dns_primary = value.get("primary", "")
            dns_secondary = value.get("secondary", "")
            dns_protocol = value.get("protocol", "")
            dns_ssl_certificate = value.get("ssl-certificate", "")
            dns_server_hostname = str(value.get("server-hostname", ""))
            dns_domain = str(value.get("domain", ""))
            dns_ip6_primary = value.get("ip6-primary", "")
            dns_ip6_secondary = value.get("ip6-secondary", "")
            dns_timeout = value.get("timeout", "")
            dns_retry = value.get("retry", "")
            dns_cache_limit = value.get("dns-cache-limit", "")
            dns_cache_ttl = value.get("dns-cache-ttl", "")
            dns_source_ip = value.get("source-ip", "")
            dns_interface_select_method = value.get("interface-select-method", "")
            dns_interface = value.get("interface", "")
            dns_server_select_method = value.get("server-select-method", "")
            dns_alt_primary = value.get("alt-primary", "")
            dns_alt_secondary = value.get("alt-secondary", "")
            dns_log_fqdn = value.get("log", "")

            # Create a dictionary of the cleaned data
            cleaned_dict = {
                "hostname": device,
                "dns_primary": dns_primary,
                "dns_secondary": dns_secondary,
                "protocol": dns_protocol,
                "ssl_certificate": dns_ssl_certificate,
                "server_hostname": dns_server_hostname,
                "domain": dns_domain,
                "ip6_primary": dns_ip6_primary,
                "ip6_secondary": dns_ip6_secondary,
                "timeout": dns_timeout,
                "retry": dns_retry,
                "cache_limit": dns_cache_limit,
                "cache_ttl": dns_cache_ttl,
                "source_ip": dns_source_ip,
                "interface_select_method": dns_interface_select_method,
                "interface": dns_interface,
                "server_select_method": dns_server_select_method,
                "alt_primary": dns_alt_primary,
                "alt_secondary": dns_alt_secondary,
                "log_fqdn": dns_log_fqdn,
            }

            # Append the dictionary to the cleaned_data list
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

                # Create a dictionary of the cleaned data
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

            # Append the dictionary to the cleaned_data list
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

                # Create a dictionary of the cleaned data
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

                # Append the dictionary to the cleaned_data list
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

                # Create a dictionary of the cleaned data
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
                # Append the dictionary to the cleaned_data list
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
            for fwpolicy in value:
                policy_id = fwpolicy.get("policyid", "")
                fwpolicy_status = fwpolicy.get("status", "")
                fwpolicy_name = fwpolicy.get("name", "")
                fwpolicy_srcintf = str(fwpolicy.get("srcintf", ""))
                fwpolicy_dstinft = str(fwpolicy.get("dstintf", ""))
                fwpolicy_action = fwpolicy.get("action", "")
                fwpolicy_nat64 = fwpolicy.get("nat64", "")
                fwpolicy_nat46 = fwpolicy.get("nat46", "")
                fwpolicy_srcaddr = str(fwpolicy.get("srcaddr", ""))
                fwpolicy_dstaddr = str(fwpolicy.get("dstaddr", ""))
                fwpolicy_srcaddr6 = str(fwpolicy.get("srcaddr6", ""))
                fwpolicy_dstaddr6 = str(fwpolicy.get("dstaddr6", ""))
                fwpolicy_internet_service = str(fwpolicy.get("internet-service", ""))
                fwpolicy_internet_service_name = str(
                    fwpolicy.get("internet-service-name", "")
                )
                fwpolicy_internet_service_group = str(
                    fwpolicy.get("internet-service-group", "")
                )
                fwpolicy_internet_service_dynamic = str(
                    fwpolicy.get("internet-service-dynamic", "")
                )
                fwpolicy_internet_service_custom_group = str(
                    fwpolicy.get("internet-service-custom-group", "")
                )
                fwpolicy_internet_service_src = str(
                    fwpolicy.get("internet-service-src", "")
                )
                fwpolicy_internet_service_src_name = str(
                    fwpolicy.get("internet-service-src-name", "")
                )
                fwpolicy_internet_service_src_group = str(
                    fwpolicy.get("internet-service-src-group", "")
                )
                fwpolicy_internet_service_src_dynamic = str(
                    fwpolicy.get("internet-service-src-dynamic", "")
                )
                fwpolicy_internet_service_src_custom_group = str(
                    fwpolicy.get("internet-service-src-custom-group", "")
                )
                fwpolicy_schedule = str(fwpolicy.get("schedule", ""))
                fwpolicy_schedule_timeout = fwpolicy.get("schedule-timeout", "")
                fwpolicy_service = str(fwpolicy.get("service", ""))
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
                fwpolicy_poolname = str(fwpolicy.get("poolname", ""))
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

                # Create a dictionary of the cleaned data
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
                # Append the dictionary to the cleaned_data list
                cleaned_data.append(cleaned_dict)
    return cleaned_data
