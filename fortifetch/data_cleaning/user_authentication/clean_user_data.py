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


def clean_admin_data() -> List[Dict]:
    """
    Get the admin information from the get_fortigate_admin_info() function
    and clean the data before it is written to the database.
    """
    device_info = get_fortigate_admin_info()
    cleaned_data = []
    for firewall in device_info:
        for device, value in firewall.items():
            if not value:
                continue
            for admin in value:
                admin_name = admin.get("name", "")
                admin_wildcard = admin.get("wildcard", "")
                admin_remote_auth = admin.get("remote-auth", "")
                admin_remote_group = admin.get("remote-group", "")
                admin_trusthost1 = admin.get("trusthost1", "")
                admin_trusthost2 = admin.get("trusthost2", "")
                admin_trusthost3 = admin.get("trusthost3", "")
                admin_trusthost4 = admin.get("trusthost4", "")
                admin_trusthost5 = admin.get("trusthost5", "")
                admin_trusthost6 = admin.get("trusthost6", "")
                admin_trusthost7 = admin.get("trusthost7", "")
                admin_trusthost8 = admin.get("trusthost8", "")
                admin_trusthost9 = admin.get("trusthost9", "")
                admin_trusthost10 = admin.get("trusthost10", "")
                admin_ip6_trusthost1 = admin.get("ip6-trusthost1", "")
                admin_ip6_trusthost2 = admin.get("ip6-trusthost2", "")
                admin_ip6_trusthost3 = admin.get("ip6-trusthost3", "")
                admin_ip6_trusthost4 = admin.get("ip6-trusthost4", "")
                admin_ip6_trusthost5 = admin.get("ip6-trusthost5", "")
                admin_ip6_trusthost6 = admin.get("ip6-trusthost6", "")
                admin_ip6_trusthost7 = admin.get("ip6-trusthost7", "")
                admin_ip6_trusthost8 = admin.get("ip6-trusthost8", "")
                admin_ip6_trusthost9 = admin.get("ip6-trusthost9", "")
                admin_ip6_trusthost10 = admin.get("ip6-trusthost10", "")
                admin_accprofile = admin.get("accprofile", "")
                admin_allow_remove_admin_session = admin.get(
                    "allow-remove-admin-session", ""
                )
                admin_comments = admin.get("comments", "")
                admin_vdoms = str(admin.get("vdoms", ""))
                admin_force_password_change = admin.get("force-password-change", "")
                admin_two_factor = admin.get("two-factor", "")
                admin_two_factor_authentication = admin.get(
                    "two-factor-authentication", ""
                )
                admin_two_factor_notification = admin.get("two-factor-notification", "")

                cleaned_dict = {
                    "hostname": device,
                    "name": admin_name,
                    "wildcard": admin_wildcard,
                    "remote-auth": admin_remote_auth,
                    "remote-group": admin_remote_group,
                    "trusthost1": admin_trusthost1,
                    "trusthost2": admin_trusthost2,
                    "trusthost3": admin_trusthost3,
                    "trusthost4": admin_trusthost4,
                    "trusthost5": admin_trusthost5,
                    "trusthost6": admin_trusthost6,
                    "trusthost7": admin_trusthost7,
                    "trusthost8": admin_trusthost8,
                    "trusthost9": admin_trusthost9,
                    "trusthost10": admin_trusthost10,
                    "ip6-trusthost1": admin_ip6_trusthost1,
                    "ip6-trusthost2": admin_ip6_trusthost2,
                    "ip6-trusthost3": admin_ip6_trusthost3,
                    "ip6-trusthost4": admin_ip6_trusthost4,
                    "ip6-trusthost5": admin_ip6_trusthost5,
                    "ip6-trusthost6": admin_ip6_trusthost6,
                    "ip6-trusthost7": admin_ip6_trusthost7,
                    "ip6-trusthost8": admin_ip6_trusthost8,
                    "ip6-trusthost9": admin_ip6_trusthost9,
                    "ip6-trusthost10": admin_ip6_trusthost10,
                    "accprofile": admin_accprofile,
                    "allow-remove-admin-session": admin_allow_remove_admin_session,
                    "comments": admin_comments,
                    "vdoms": admin_vdoms,
                    "force-password-change": admin_force_password_change,
                    "two-factor": admin_two_factor,
                    "two-factor-authentication": admin_two_factor_authentication,
                    "two-factor-notification": admin_two_factor_notification,
                }

                cleaned_data.append(cleaned_dict)
    return cleaned_data


def clean_admin_profile_data() -> List[Dict]:
    """
    Get the admin profile information from the get_fortigate_admin_profile_info() function
    and clean the data before it is written to the database.
    """
    device_info = get_fortigate_admin_profile_info()
    cleaned_data = []
    for firewall in device_info:
        for device, value in firewall.items():
            if not value:
                continue
            for admin in value:
                admin_name = admin.get("name", "")
                admin_scope = admin.get("scope", "")
                admin_comments = admin.get("comments", "")
                admin_ftviewgrp = admin.get("ftviewgrp", "")
                admin_authgrp = admin.get("authgrp", "")
                admin_sysgrp = admin.get("sysgrp", "")
                admin_netgrp = admin.get("netgrp", "")
                admin_loggrp = admin.get("loggrp", "")
                admin_fwgrp = admin.get("fwgrp", "")
                admin_vpngrp = admin.get("vpngrp", "")
                admin_utmgrp = admin.get("utmgrp", "")
                admin_wanoptgrp = admin.get("wanoptgrp", "")
                admin_wifi = admin.get("wifi", "")
                admin_netgrp_permission = str(admin.get("netgrp-permission", ""))
                admin_sysgrp_permission = str(admin.get("sysgrp-permission", ""))
                admin_fwgrp_permission = str(admin.get("fwgrp-permission", ""))
                admin_loggrp_permission = str(admin.get("loggrp-permission", ""))
                admin_utmgrpu_permission = str(admin.get("utmgrp-permission", ""))
                admin_admintimeout_override = admin.get("admintimeout-override", "")
                admin_admintimeout = admin.get("admintimeout", "")
                admin_systemdiagnostics = admin.get("systemdiagnostics", "")
                admin_system_execute_ssh = admin.get("system_execute_ssh", "")
                admin_system_execute_telnet = admin.get("system_execute_telnet", "")

                cleaned_dict = {
                    "hostname": device,
                    "name": admin_name,
                    "scope": admin_scope,
                    "comments": admin_comments,
                    "ftviewgrp": admin_ftviewgrp,
                    "authgrp": admin_authgrp,
                    "sysgrp": admin_sysgrp,
                    "netgrp": admin_netgrp,
                    "loggrp": admin_loggrp,
                    "fwgrp": admin_fwgrp,
                    "vpngrp": admin_vpngrp,
                    "utmgrp": admin_utmgrp,
                    "wanoptgrp": admin_wanoptgrp,
                    "wifi": admin_wifi,
                    "netgrp_permission": admin_netgrp_permission,
                    "sysgrp_permission": admin_sysgrp_permission,
                    "fwgrp_permission": admin_fwgrp_permission,
                    "loggrp_permission": admin_loggrp_permission,
                    "utmgrp_permission": admin_utmgrpu_permission,
                    "admintimeout_override": admin_admintimeout_override,
                    "admintimeout": admin_admintimeout,
                    "systemdiagnostics": admin_systemdiagnostics,
                    "system_execute_ssh": admin_system_execute_ssh,
                    "system_execute_telnet": admin_system_execute_telnet,
                }

                cleaned_data.append(cleaned_dict)
    return cleaned_data
