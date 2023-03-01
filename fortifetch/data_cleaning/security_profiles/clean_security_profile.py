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
import json


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
