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


def clean_fortiguard_data() -> List[Dict]:
    """
    Get the fortiguard information from the get_fortigate_fortiguard_info() function
    and clean the data before it is written to the database.
    """
    device_info = get_fortigate_fortiguard_info()
    cleaned_data = []
    for firewall in device_info:
        for device, value in firewall.items():
            forti_fortiguard_anycast = value.get("fortiguard-anycast", "")
            forti_fortiguard_anycast_source = value.get("fortiguard-anycast-source", "")
            forti_protocol = value.get("protocol", "")
            forti_port = value.get("port", "")
            forti_forti_service_account_id = value.get("service-account-id", "")
            forti_forti_load_balace_servers = str(value.get("load-balance-servers", ""))
            forti_forti_auto_join_forticloud = value.get("auto-join-forticloud", "")
            forti_forti_update_server_location = value.get("update-server-location", "")
            forti_sandbox_region = value.get("sandbox-region", "")
            forti_sandbox_inline_scan = value.get("sandbox-inline-scan", "")
            forti_update_ffdb = value.get("update-ffdb", "")
            forti_update_uwdb = value.get("update-uwdb", "")
            forti_update_extdb = value.get("update-extdb", "")
            forti_update_build_proxy = value.get("update-build-proxy", "")
            forti_persistent_connection = value.get("persistent-connection", "")
            forti_vdom = value.get("vdom", "")
            forti_auto_firmware_upgrade = value.get("auto-firmware-upgrade", "")
            forti_auto_firmware_upgrade_day = value.get("auto-firmware-upgrade-day", "")
            forti_auto_firmware_upgrade_start_hour = value.get(
                "auto-firmware-upgrade-start-hour", ""
            )
            forti_auto_firmware_upgrade_end_hour = value.get(
                "auto-firmware-upgrade-end-hour", ""
            )
            forti_antispam_force_off = value.get("antispam-force-off", "")
            forti_antispam_cache = value.get("antispam-cache", "")
            forti_antispam_cache_ttl = value.get("antispam-cache-ttl", "")
            forti_antispam_cache_mpercent = value.get("antispam-cache-mpercent", "")
            forti_antispam_license = value.get("antispam-license", "")
            forti_antispam_expiration = value.get("antispam-expiration", "")
            forti_antispam_timeout = value.get("antispam-timeout", "")
            forti_outbreak_prevention_force_off = value.get(
                "outbreak-prevention-force-off", ""
            )
            forti_outbreak_prevention_cache = value.get("outbreak-prevention-cache", "")
            forti_outbreak_prevention_cache_ttl = value.get(
                "outbreak-prevention-cache-ttl", ""
            )
            forti_outbreak_prevention_cache_mpercent = value.get(
                "outbreak-prevention-cache-mpercent", ""
            )
            forti_outbreak_prevention_license = value.get(
                "outbreak-prevention-license", ""
            )
            forti_outbreak_prevention_expiration = value.get(
                "outbreak-prevention-expiration", ""
            )
            forti_outbreak_prevention_timeout = value.get(
                "outbreak-prevention-timeout", ""
            )
            forti_webfilter_force_off = value.get("webfilter-force-off", "")
            forti_webfilter_cache = value.get("webfilter-cache", "")
            forti_webfilter_cache_ttl = value.get("webfilter-cache-ttl", "")
            forti_webfilter_license = value.get("webfilter-license", "")
            forti_webfilter_expiration = value.get("webfilter-expiration", "")
            forti_webfilter_timeout = value.get("webfilter-timeout", "")
            forti_sdns_server_ip = value.get("sdns-server-ip", "")
            forti_sdns_server_port = value.get("sdns-server-port", "")
            forti_anycast_sdns_server_ip = value.get("anycast-sdns-server-ip", "")
            forti_anycast_sdns_server_port = value.get("anycast-sdns-server-port", "")
            forti_sdns_options = value.get("sdns-options", "")
            forti_source_ip = value.get("source-ip", "")
            forti_source_ip6 = value.get("source-ip6", "")
            forti_proxy_server_ip = value.get("proxy-server-ip", "")
            forti_proxy_server_port = value.get("proxy-server-port", "")
            forti_proxy_username = value.get("proxy-username", "")
            forti_proxy_password = value.get("proxy-password", "")
            forti_ddns_server_ip = value.get("ddns-server-ip", "")
            forti_ddns_server_ip6 = value.get("ddns-server-ip6", "")
            forti_ddns_server_port = value.get("ddns-server-port", "")
            forti_interface_select_method = value.get("interface-select-method", "")
            forti_interface = value.get("interface", "")

            # Create a dictionary of the cleaned data
            cleaned_dict = {
                "hostname": device,
                "fortiguard_anycast": forti_fortiguard_anycast,
                "fortiguard_anycast_source": forti_fortiguard_anycast_source,
                "protocol": forti_protocol,
                "port": forti_port,
                "forti_forti_service_account_id": forti_forti_service_account_id,
                "forti_forti_load_balace_servers": forti_forti_load_balace_servers,
                "forti_forti_auto_join_forticloud": forti_forti_auto_join_forticloud,
                "forti_forti_update_server_location": forti_forti_update_server_location,
                "forti_sandbox_region": forti_sandbox_region,
                "forti_sandbox_inline_scan": forti_sandbox_inline_scan,
                "forti_update_ffdb": forti_update_ffdb,
                "forti_update_uwdb": forti_update_uwdb,
                "forti_update_extdb": forti_update_extdb,
                "forti_update_build_proxy": forti_update_build_proxy,
                "forti_persistent_connection": forti_persistent_connection,
                "forti_vdom": forti_vdom,
                "forti_auto_firmware_upgrade": forti_auto_firmware_upgrade,
                "forti_auto_firmware_upgrade_day": forti_auto_firmware_upgrade_day,
                "forti_auto_firmware_upgrade_start_hour": forti_auto_firmware_upgrade_start_hour,
                "forti_auto_firmware_upgrade_end_hour": forti_auto_firmware_upgrade_end_hour,
                "forti_antispam_force_off": forti_antispam_force_off,
                "forti_antispam_cache": forti_antispam_cache,
                "forti_antispam_cache_ttl": forti_antispam_cache_ttl,
                "forti_antispam_cache_mpercent": forti_antispam_cache_mpercent,
                "forti_antispam_license": forti_antispam_license,
                "forti_antispam_expiration": forti_antispam_expiration,
                "forti_antispam_timeout": forti_antispam_timeout,
                "forti_outbreak_prevention_force_off": forti_outbreak_prevention_force_off,
                "forti_outbreak_prevention_cache": forti_outbreak_prevention_cache,
                "forti_outbreak_prevention_cache_ttl": forti_outbreak_prevention_cache_ttl,
                "forti_outbreak_prevention_cache_mpercent": forti_outbreak_prevention_cache_mpercent,
                "forti_outbreak_prevention_license": forti_outbreak_prevention_license,
                "forti_outbreak_prevention_expiration": forti_outbreak_prevention_expiration,
                "forti_outbreak_prevention_timeout": forti_outbreak_prevention_timeout,
                "forti_webfilter_force_off": forti_webfilter_force_off,
                "forti_webfilter_cache": forti_webfilter_cache,
                "forti_webfilter_cache_ttl": forti_webfilter_cache_ttl,
                "forti_webfilter_license": forti_webfilter_license,
                "forti_webfilter_expiration": forti_webfilter_expiration,
                "forti_webfilter_timeout": forti_webfilter_timeout,
                "forti_sdns_server_ip": forti_sdns_server_ip,
                "forti_sdns_server_port": forti_sdns_server_port,
                "forti_anycast_sdns_server_ip": forti_anycast_sdns_server_ip,
                "forti_anycast_sdns_server_port": forti_anycast_sdns_server_port,
                "forti_sdns_options": forti_sdns_options,
                "forti_source_ip": forti_source_ip,
                "forti_source_ip6": forti_source_ip6,
                "forti_proxy_server_ip": forti_proxy_server_ip,
                "forti_proxy_server_port": forti_proxy_server_port,
                "forti_proxy_username": forti_proxy_username,
                "forti_proxy_password": forti_proxy_password,
                "forti_ddns_server_ip": forti_ddns_server_ip,
                "forti_ddns_server_ip6": forti_ddns_server_ip6,
                "forti_ddns_server_port": forti_ddns_server_port,
                "forti_interface_select_method": forti_interface_select_method,
                "forti_interface": forti_interface,
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


def clean_snmpv2_data() -> List[Dict]:
    """
    Get the snmpv2 information from the get_fortigate_snmpv2_info() function
    and clean the data before it is written to the database.
    """
    device_info = get_fortigate_snmpv2_info()
    cleaned_data = []
    for firewall in device_info:
        for device, value in firewall.items():
            for snmp in value:
                snmpv2_id = snmp.get("id", "")
                snmpv2_name = snmp.get("name", "")
                snmpv2_status = snmp.get("status", "")
                snmpv2_host = str(snmp.get("host", ""))
                snmpv2_host6 = str(snmp.get("host6", ""))
                snmpv2_query_v1_status = snmp.get("query-v1-status", "")
                snmpv2_query_v1_port = snmp.get("query-v1-port", "")
                snmpv2_query_v2c_status = snmp.get("query-v2c-status", "")
                snmpv2_query_v2c_port = snmp.get("query-v2c-port", "")
                snmpv2_query_trap_v1_status = snmp.get("query-trap-v1-status", "")
                snmpv2_query_trap_v1_rport = snmp.get("query-trap-v1-rport", "")
                snmpv2_query_trap_v2c_status = snmp.get("query-trap-v2c-status", "")
                snmpv2_query_trap_v2c_lport = snmp.get("query-trap-v2c-lport", "")
                snmpv2_query_trap_v2c_rport = snmp.get("query-trap-v2c-rport", "")
                snmpv2_events = str(snmp.get("events", ""))
                snmpv2_vdoms = str(snmp.get("vdoms", ""))

                # Create a dictionary of the cleaned data
                cleaned_dict = {
                    "hostname": device,
                    "id": snmpv2_id,
                    "name": snmpv2_name,
                    "status": snmpv2_status,
                    "host": snmpv2_host,
                    "host6": snmpv2_host6,
                    "query_v1_status": snmpv2_query_v1_status,
                    "query_v1_port": snmpv2_query_v1_port,
                    "query_v2c_status": snmpv2_query_v2c_status,
                    "query_v2c_port": snmpv2_query_v2c_port,
                    "query_trap_v1_status": snmpv2_query_trap_v1_status,
                    "query_trap_v1_rport": snmpv2_query_trap_v1_rport,
                    "query_trap_v2c_status": snmpv2_query_trap_v2c_status,
                    "query_trap_v2c_lport": snmpv2_query_trap_v2c_lport,
                    "query_trap_v2c_rport": snmpv2_query_trap_v2c_rport,
                    "events": snmpv2_events,
                    "vdoms": snmpv2_vdoms,
                }

                # Append the dictionary to the cleaned_data list
                cleaned_data.append(cleaned_dict)
    return cleaned_data


def clean_snmpv3_data() -> List[Dict]:
    """
    Get the snmpv3 information from the get_fortigate_snmpv3_info() function
    and clean the data before it is written to the database.
    """
    device_info = get_fortigate_snmpv3_info()
    cleaned_data = []
    for firewall in device_info:
        for device, value in firewall.items():
            for snmp in value:
                snmpv3_name = snmp.get("name", "")
                snmpv3_status = snmp.get("status", "")
                snmpv3_trap_status = snmp.get("trap-status", "")
                snmpv3_trap_lport = snmp.get("trap-lport", "")
                snmpv3_trap_rport = snmp.get("trap-rport", "")
                snmpv3_queries = str(snmp.get("queries", ""))
                snmpv3_query_port = snmp.get("query-port", "")
                snmpv3_notify_hosts = str(snmp.get("notify-hosts", ""))
                snmpv3_notify_hosts6 = str(snmp.get("notify-hosts6", ""))
                snmpv3_source_ip = snmp.get("source-ip", "")
                snmpv3_source_ipv6 = snmp.get("source-ipv6", "")
                snmpv3_events = str(snmp.get("events", ""))
                snmpv3_vdoms = str(snmp.get("vdoms", ""))
                snmpv3_security_level = snmp.get("security-level", "")
                snmpv3_auth_proto = snmp.get("auth-proto", "")
                snmpv3_priv_proto = snmp.get("priv-proto", "")
                snmpv3_priv_pwd = snmp.get("priv-pwd", "")

                # Create a dictionary of the cleaned data
                cleaned_dict = {
                    "hostname": device,
                    "name": snmpv3_name,
                    "status": snmpv3_status,
                    "trap_status": snmpv3_trap_status,
                    "trap_lport": snmpv3_trap_lport,
                    "trap_rport": snmpv3_trap_rport,
                    "queries": snmpv3_queries,
                    "query_port": snmpv3_query_port,
                    "notify_hosts": snmpv3_notify_hosts,
                    "notify_hosts6": snmpv3_notify_hosts6,
                    "source_ip": snmpv3_source_ip,
                    "source_ipv6": snmpv3_source_ipv6,
                    "events": snmpv3_events,
                    "vdoms": snmpv3_vdoms,
                    "security_level": snmpv3_security_level,
                    "auth_proto": snmpv3_auth_proto,
                    "priv_proto": snmpv3_priv_proto,
                    "priv_pwd": snmpv3_priv_pwd,
                }
                # Append the dictionary to the cleaned_data list
                cleaned_data.append(cleaned_dict)
    return cleaned_data
