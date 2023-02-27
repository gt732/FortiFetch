"""
This module contains all the backend functions to write
firewall data to each table in the database.
"""

# import modules
import os
import sys
import sqlite3

# Add the parent directory of 'app' to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# import modules
from data_cleaning.network.clean_network_data import *
from data_cleaning.policy_object.clean_policy_address import *
from data_cleaning.security_profiles.clean_security_profile import *
from data_cleaning.system.clean_device_data import *
from data_cleaning.user_authentication.clean_user_data import *


# Define constants
DATABASE_NAME = "FortiFetch.db"
DB_DIRECTORY = os.path.join(os.path.dirname(__file__), "../../db")
SCHEMA_FILE = os.path.join(DB_DIRECTORY, "schema.sql")
DB_PATH = os.path.join(DB_DIRECTORY, DATABASE_NAME)


def write_device_info():
    """
    Get the device information from the clean_device_data() function and
    Write device information to the `device` table in the database
    """
    print("Updating devices in database")
    device_info = clean_device_data()
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM device")
        for device in device_info:
            hostname = device["hostname"]
            serial_number = device["serial_number"]
            version = device["version"]
            model = device["model"]

            # Insert device information into the database
            insert_query = """
            INSERT INTO device (hostname, serial_number, version, model)
            VALUES (?, ?, ?, ?)
            """
            cursor.execute(insert_query, (hostname, serial_number, version, model))

            conn.commit()
    print("Device information updated successfully")
    print("*" * 80)


def write_adminprofile_info():
    """
    Get the admin profile information from the clean_admin_profile_data() function and
    Write admin profile information to the `adminprofile` table in the database
    """
    print("Updating admin profile in database")
    admin_profile_info = clean_admin_profile_data()
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM adminprofile")
        for admin_profile in admin_profile_info:
            hostname = admin_profile["hostname"]
            name = admin_profile["name"]
            scope = admin_profile["scope"]
            comments = admin_profile["comments"]
            ftviewgrp = admin_profile["ftviewgrp"]
            authgrp = admin_profile["authgrp"]
            sysgrp = admin_profile["sysgrp"]
            netgrp = admin_profile["netgrp"]
            loggrp = admin_profile["loggrp"]
            fwgrp = admin_profile["fwgrp"]
            vpngrp = admin_profile["vpngrp"]
            utmgrp = admin_profile["utmgrp"]
            wanoptgrp = admin_profile["wanoptgrp"]
            wifi = admin_profile["wifi"]
            netgrp_permission = admin_profile["netgrp_permission"]
            sysgrp_permission = admin_profile["sysgrp_permission"]
            fwgrp_permission = admin_profile["fwgrp_permission"]
            loggrp_permission = admin_profile["loggrp_permission"]
            utmgrp_permission = admin_profile["utmgrp_permission"]
            admintimeout_override = admin_profile["admintimeout_override"]
            admintimeout = admin_profile["admintimeout"]
            systemdiagnostics = admin_profile["systemdiagnostics"]
            system_execute_ssh = admin_profile["system_execute_ssh"]
            system_execute_telnet = admin_profile["system_execute_telnet"]

            cursor.execute("SELECT device_id FROM device WHERE hostname=?", (hostname,))
            device_id = cursor.fetchone()[0]
            insert_query = """
            INSERT INTO adminprofile (
                device_id,
                name,
                scope,
                comments,
                ftviewgrp,
                authgrp,
                sysgrp,
                netgrp,
                loggrp,
                fwgrp,
                vpngrp,
                utmgrp,
                wanoptgrp,
                wifi,
                netgrp_permission,
                sysgrp_permission,
                fwgrp_permission,
                loggrp_permission,
                utmgrp_permission,
                admintimeout_override,
                admintimeout,
                systemdiagnostics,
                system_execute_ssh,
                system_execute_telnet
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            cursor.execute(
                insert_query,
                (
                    device_id,
                    name,
                    scope,
                    comments,
                    ftviewgrp,
                    authgrp,
                    sysgrp,
                    netgrp,
                    loggrp,
                    fwgrp,
                    vpngrp,
                    utmgrp,
                    wanoptgrp,
                    wifi,
                    netgrp_permission,
                    sysgrp_permission,
                    fwgrp_permission,
                    loggrp_permission,
                    utmgrp_permission,
                    admintimeout_override,
                    admintimeout,
                    systemdiagnostics,
                    system_execute_ssh,
                    system_execute_telnet,
                ),
            )
            conn.commit()
    print("Admin profile information updated successfully")
    print("*" * 80)


def write_admin_info():
    """
    Get the admin information from the clean_admin_data() function and
    Write admin information to the `admin` table in the database
    """
    print("Updating admin in database")
    admin_info = clean_admin_data()
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM admin")
        for admin in admin_info:
            device = admin["hostname"]
            admin_name = admin["name"]
            admin_wildcard = admin["wildcard"]
            admin_remote_auth = admin["remote-auth"]
            admin_remote_group = admin["remote-group"]
            admin_trusthost1 = admin["trusthost1"]
            admin_trusthost2 = admin["trusthost2"]
            admin_trusthost3 = admin["trusthost3"]
            admin_trusthost4 = admin["trusthost4"]
            admin_trusthost5 = admin["trusthost5"]
            admin_trusthost6 = admin["trusthost6"]
            admin_trusthost7 = admin["trusthost7"]
            admin_trusthost8 = admin["trusthost8"]
            admin_trusthost9 = admin["trusthost9"]
            admin_trusthost10 = admin["trusthost10"]
            admin_ip6_trusthost1 = admin["ip6-trusthost1"]
            admin_ip6_trusthost2 = admin["ip6-trusthost2"]
            admin_ip6_trusthost3 = admin["ip6-trusthost3"]
            admin_ip6_trusthost4 = admin["ip6-trusthost4"]
            admin_ip6_trusthost5 = admin["ip6-trusthost5"]
            admin_ip6_trusthost6 = admin["ip6-trusthost6"]
            admin_ip6_trusthost7 = admin["ip6-trusthost7"]
            admin_ip6_trusthost8 = admin["ip6-trusthost8"]
            admin_ip6_trusthost9 = admin["ip6-trusthost9"]
            admin_ip6_trusthost10 = admin["ip6-trusthost10"]
            admin_accprofile = admin["accprofile"]
            admin_allow_remove_admin_session = admin["allow-remove-admin-session"]
            admin_comments = admin["comments"]
            admin_vdoms = admin["vdoms"]
            admin_force_password_change = admin["force-password-change"]
            admin_two_factor = admin["two-factor"]
            admin_two_factor_authentication = admin["two-factor-authentication"]
            admin_two_factor_notification = admin["two-factor-notification"]

            # Get device ID
            cursor.execute("SELECT device_id FROM device WHERE hostname=?", (device,))
            device_id = cursor.fetchone()[0]

            # Insert admin information into the database
            cursor.execute(
                """
            INSERT INTO admin (
            device_id,name,wildcard,remote_auth,remote_group,trusthost1,trusthost2,trusthost3,trusthost4,trusthost5,trusthost6,
            trusthost7,trusthost8,trusthost9,trusthost10,ip6_trusthost1,ip6_trusthost2,ip6_trusthost3,ip6_trusthost4,ip6_trusthost5,ip6_trusthost6,ip6_trusthost7,
            ip6_trusthost8,ip6_trusthost9,ip6_trusthost10,accprofile,allow_remove_admin_session,comments,vdoms,force_password_change,two_factor,two_factor_authentication,two_factor_notification
            ) 
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?
            )
            """,
                (
                    device_id,
                    admin_name,
                    admin_wildcard,
                    admin_remote_auth,
                    admin_remote_group,
                    admin_trusthost1,
                    admin_trusthost2,
                    admin_trusthost3,
                    admin_trusthost4,
                    admin_trusthost5,
                    admin_trusthost6,
                    admin_trusthost7,
                    admin_trusthost8,
                    admin_trusthost9,
                    admin_trusthost10,
                    admin_ip6_trusthost1,
                    admin_ip6_trusthost2,
                    admin_ip6_trusthost3,
                    admin_ip6_trusthost4,
                    admin_ip6_trusthost5,
                    admin_ip6_trusthost6,
                    admin_ip6_trusthost7,
                    admin_ip6_trusthost8,
                    admin_ip6_trusthost9,
                    admin_ip6_trusthost10,
                    admin_accprofile,
                    admin_allow_remove_admin_session,
                    admin_comments,
                    admin_vdoms,
                    admin_force_password_change,
                    admin_two_factor,
                    admin_two_factor_authentication,
                    admin_two_factor_notification,
                ),
            )
            conn.commit()
    print("Admin information updated successfully")
    print("*" * 80)


def write_fortiguard_info():
    """
    Get the fortiguard information from the clean_fortiguard_data() function and
    Write fortiguard information to the `fortiguard` table in the database
    """
    print("Updating device fortiguard in database")
    fortiguard_info = clean_fortiguard_data()
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM fortiguard")
        for device in fortiguard_info:
            hostname = device["hostname"]
            forti_fortiguard_anycast = device["fortiguard_anycast"]
            forti_fortiguard_anycast_source = device["fortiguard_anycast_source"]
            forti_protocol = device["protocol"]
            forti_port = device["port"]
            forti_forti_service_account_id = device["forti_forti_service_account_id"]
            forti_forti_load_balace_servers = device["forti_forti_load_balace_servers"]
            forti_forti_auto_join_forticloud = device[
                "forti_forti_auto_join_forticloud"
            ]
            forti_forti_update_server_location = device[
                "forti_forti_update_server_location"
            ]
            forti_sandbox_inline_scan = device["forti_sandbox_inline_scan"]
            forti_update_ffdb = device["forti_update_ffdb"]
            forti_update_uwdb = device["forti_update_uwdb"]
            forti_update_extdb = device["forti_update_extdb"]
            forti_update_build_proxy = device["forti_update_build_proxy"]
            forti_persistent_connection = device["forti_persistent_connection"]
            forti_vdom = device["forti_vdom"]
            forti_auto_firmware_upgrade = device["forti_auto_firmware_upgrade"]
            forti_auto_firmware_upgrade_day = device["forti_auto_firmware_upgrade_day"]
            forti_auto_firmware_upgrade_start_hour = device[
                "forti_auto_firmware_upgrade_start_hour"
            ]
            forti_auto_firmware_upgrade_end_hour = device[
                "forti_auto_firmware_upgrade_end_hour"
            ]
            forti_antispam_force_off = device["forti_antispam_force_off"]
            forti_antispam_cache = device["forti_antispam_cache"]
            forti_antispam_cache_ttl = device["forti_antispam_cache_ttl"]
            forti_antispam_cache_mpercent = device["forti_antispam_cache_mpercent"]
            forti_antispam_license = device["forti_antispam_license"]
            forti_antispam_expiration = device["forti_antispam_expiration"]
            forti_antispam_timeout = device["forti_antispam_timeout"]
            forti_outbreak_prevention_force_off = device[
                "forti_outbreak_prevention_force_off"
            ]
            forti_outbreak_prevention_cache = device["forti_outbreak_prevention_cache"]
            forti_outbreak_prevention_cache_ttl = device[
                "forti_outbreak_prevention_cache_ttl"
            ]
            forti_outbreak_prevention_cache_mpercent = device[
                "forti_outbreak_prevention_cache_mpercent"
            ]
            forti_outbreak_prevention_license = device[
                "forti_outbreak_prevention_license"
            ]
            forti_outbreak_prevention_expiration = device[
                "forti_outbreak_prevention_expiration"
            ]
            forti_outbreak_prevention_timeout = device[
                "forti_outbreak_prevention_timeout"
            ]
            forti_webfilter_force_off = device["forti_webfilter_force_off"]
            forti_webfilter_cache = device["forti_webfilter_cache"]
            forti_webfilter_cache_ttl = device["forti_webfilter_cache_ttl"]
            forti_webfilter_license = device["forti_webfilter_license"]
            forti_webfilter_expiration = device["forti_webfilter_expiration"]
            forti_webfilter_timeout = device["forti_webfilter_timeout"]
            forti_sdns_server_ip = device["forti_sdns_server_ip"]
            forti_sdns_server_port = device["forti_sdns_server_port"]
            forti_anycast_sdns_server_ip = device["forti_anycast_sdns_server_ip"]
            forti_anycast_sdns_server_port = device["forti_anycast_sdns_server_port"]
            forti_sdns_options = device["forti_sdns_options"]
            forti_source_ip = device["forti_source_ip"]
            forti_source_ip6 = device["forti_source_ip6"]
            forti_proxy_server_ip = device["forti_proxy_server_ip"]
            forti_proxy_server_port = device["forti_proxy_server_port"]
            forti_proxy_username = device["forti_proxy_username"]
            forti_proxy_password = device["forti_proxy_password"]
            forti_ddns_server_ip = device["forti_ddns_server_ip"]
            forti_ddns_server_ip6 = device["forti_ddns_server_ip6"]
            forti_ddns_server_port = device["forti_ddns_server_port"]
            forti_interface_select_method = device["forti_interface_select_method"]
            forti_interface = device["forti_interface"]
            cursor.execute("SELECT device_id FROM device WHERE hostname=?", (hostname,))
            device_id = cursor.fetchone()[0]
            cursor.execute(
                """
                INSERT INTO fortiguard (
                device_id, fortiguard_anycast, fortiguard_anycast_source, protocol, port, load_balace_servers,
                auto_join_forticloud, update_server_location,
                sandbox_region, sandbox_inline_scan, update_ffdb,
                update_uwdb, update_extdb, update_build_proxy,
                persistent_connection, vdom, auto_firmware_upgrade,
                auto_firmware_upgrade_day, auto_firmware_upgrade_start_hour,
                auto_firmware_upgrade_end_hour, antispam_force_off,
                antispam_cache, antispam_cache_ttl,
                antispam_cache_mpercent, antispam_license,
                antispam_expiration, antispam_timeout,
                outbreak_prevention_force_off, outbreak_prevention_cache,
                outbreak_prevention_cache_ttl, outbreak_prevention_cache_mpercent,
                outbreak_prevention_license, outbreak_prevention_expiration,
                outbreak_prevention_timeout, webfilter_force_off,
                webfilter_cache, webfilter_cache_ttl, webfilter_license,
                webfilter_expiration, webfilter_timeout, sdns_server_ip,
                sdns_server_port, anycast_sdns_server_ip, anycast_sdns_server_port,
                sdns_options, source_ip, source_ip6, proxy_server_ip,
                proxy_server_port, proxy_username, proxy_password,
                ddns_server_ip, ddns_server_ip6, ddns_server_port,
                interface_select_method, interface
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    device_id,
                    forti_fortiguard_anycast,
                    forti_fortiguard_anycast_source,
                    forti_protocol,
                    forti_port,
                    forti_forti_service_account_id,
                    forti_forti_load_balace_servers,
                    forti_forti_auto_join_forticloud,
                    forti_forti_update_server_location,
                    forti_sandbox_inline_scan,
                    forti_update_ffdb,
                    forti_update_uwdb,
                    forti_update_extdb,
                    forti_update_build_proxy,
                    forti_persistent_connection,
                    forti_vdom,
                    forti_auto_firmware_upgrade,
                    forti_auto_firmware_upgrade_day,
                    forti_auto_firmware_upgrade_start_hour,
                    forti_auto_firmware_upgrade_end_hour,
                    forti_antispam_force_off,
                    forti_antispam_cache,
                    forti_antispam_cache_ttl,
                    forti_antispam_cache_mpercent,
                    forti_antispam_license,
                    forti_antispam_expiration,
                    forti_antispam_timeout,
                    forti_outbreak_prevention_force_off,
                    forti_outbreak_prevention_cache,
                    forti_outbreak_prevention_cache_ttl,
                    forti_outbreak_prevention_cache_mpercent,
                    forti_outbreak_prevention_license,
                    forti_outbreak_prevention_expiration,
                    forti_outbreak_prevention_timeout,
                    forti_webfilter_force_off,
                    forti_webfilter_cache,
                    forti_webfilter_cache_ttl,
                    forti_webfilter_license,
                    forti_webfilter_expiration,
                    forti_webfilter_timeout,
                    forti_sdns_server_ip,
                    forti_sdns_server_port,
                    forti_anycast_sdns_server_ip,
                    forti_anycast_sdns_server_port,
                    forti_sdns_options,
                    forti_source_ip,
                    forti_source_ip6,
                    forti_proxy_server_ip,
                    forti_proxy_server_port,
                    forti_proxy_username,
                    forti_proxy_password,
                    forti_ddns_server_ip,
                    forti_ddns_server_ip6,
                    forti_ddns_server_port,
                    forti_interface_select_method,
                    forti_interface,
                ),
            )
            conn.commit()
    print(f"Interface information updated successfully")
    print("*" * 80)


def write_interface_info():
    """
    Get the interface information from the clean_interface_data() function and
    write interface information to the `interface` table in the database
    """
    print("Updating interfaces in database")
    interface_info = clean_interface_data()
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM interface")
        for interface in interface_info:
            allowaccess = interface["allowaccess"]
            hostname = interface["hostname"]
            ip = interface["ip"]
            interface_name = interface["name"]
            mode = interface["mode"]
            mtu = interface["mtu"]
            status = interface["status"]
            type = interface["type"]
            vdom = interface["vdom"]
            cursor.execute("SELECT device_id FROM device WHERE hostname=?", (hostname,))
            device_id = cursor.fetchone()[0]
            cursor.execute(
                "INSERT INTO interface (device_id, name, type, ip, mtu, mode, status, allowaccess, vdom) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    device_id,
                    interface_name,
                    type,
                    ip,
                    mtu,
                    mode,
                    status,
                    allowaccess,
                    vdom,
                ),
            )

            conn.commit()
    print(f"Interface information updated successfully")
    print("*" * 80)


def write_address_info():
    """
    Get the address information from the clean_address_data() function and
    Write address information to the `address` table in the database
    """
    print("Updating addresses in database")
    address_info = clean_address_data()
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM address")
        for address in address_info:
            associated_interface = address["associated_interface"]
            country = address["country"]
            end_ip = address["end_ip"]
            fqdn = address["fqdn"]
            hostname = address["hostname"]
            name = address["name"]
            start_ip = address["start_ip"]
            subnet = address["subnet"]
            address_type = address["address_type"]
            cursor.execute("SELECT device_id FROM device WHERE hostname=?", (hostname,))
            device_id = cursor.fetchone()[0]
            cursor.execute(
                "INSERT INTO address (device_id, name, associated_interface, country, end_ip, fqdn, start_ip, subnet, address_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    device_id,
                    name,
                    associated_interface,
                    country,
                    end_ip,
                    fqdn,
                    start_ip,
                    subnet,
                    address_type,
                ),
            )
            conn.commit()

    print(f"Address information updated successfully")
    print("*" * 80)


def write_address_group_info():
    """
    Get the address group information from the clean_address_group_data() function and
    write address group information to the `addressgroup` table in the database
    """
    print("Updating address group in database")
    address_info = clean_address_group_data()
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM addressgroup")
        for address in address_info:
            hostname = address["hostname"]
            name = address["name"]
            member = address["member"]
            cursor.execute("SELECT device_id FROM device WHERE hostname=?", (hostname,))
            device_id = cursor.fetchone()[0]
            cursor.execute(
                "INSERT INTO addressgroup (device_id, name, member) VALUES (?, ?, ?)",
                (device_id, name, member),
            )

            conn.commit()

    print(f"Address group information updated successfully")
    print("*" * 80)


def write_application_info():
    """
    Get the application profile information from the clean_application_data() function and
    write application profile information to the `appprofile` table in the database
    """
    print("Updating application profile in database")
    application_info = clean_application_data()
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM appprofile")
        for application in application_info:
            hostname = application["hostname"]
            name = application["name"]
            entries = application["entries"]
            comment = application["comment"]
            cursor.execute("SELECT device_id FROM device WHERE hostname=?", (hostname,))
            device_id = cursor.fetchone()[0]
            cursor.execute(
                "INSERT INTO appprofile (device_id, name, comment, entries) VALUES (?, ?, ?, ?)",
                (device_id, name, comment, entries),
            )

        conn.commit()

    print("Application profile information updated successfully")
    print("*" * 80)


def write_av_info():
    """
    Get the antivirus profile information from the clean_av_data() function and
    write antivirus profile information to the `avprofile` table in the database.
    """
    print("Updating antivirus profile in database")
    av_info = clean_av_data()

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()

        # Clear the avprofile table
        cursor.execute("DELETE FROM avprofile")

        for av in av_info:
            hostname = av["hostname"]
            name = av["name"]
            comment = av["comment"]
            http = av["http"]
            ftp = av["ftp"]
            imap = av["imap"]
            pop3 = av["pop3"]
            smtp = av["smtp"]
            nntp = av["nntp"]
            mapi = av["mapi"]
            ssh = av["ssh"]
            cifs = av["cifs"]
            profile_nac_quar = av["nac_quar"]
            profile_content_disarm = av["content_disarm"]

            cursor.execute("SELECT device_id FROM device WHERE hostname=?", (hostname,))
            device_id = cursor.fetchone()[0]

            cursor.execute(
                """
                INSERT INTO avprofile 
                (device_id, name, comment, http, ftp, imap, pop3, smtp, nntp, mapi, ssh, cifs, nac_quar, content_disarm) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    device_id,
                    name,
                    comment,
                    http,
                    ftp,
                    imap,
                    pop3,
                    smtp,
                    nntp,
                    mapi,
                    ssh,
                    cifs,
                    profile_nac_quar,
                    profile_content_disarm,
                ),
            )

            conn.commit()

    print("Antivirus profile information updated successfully")
    print("*" * 80)


def write_dns_info():
    """
    Get the DNS information from the clean_dns_data() function and
    write DNS information to the `dns` table in the database.
    """
    print("Updating DNS data in database")
    cleaned_data = clean_dns_data()

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()

        # Delete all existing entries from the dns table
        cursor.execute("DELETE FROM dns")

        # Insert cleaned DNS data into dns table
        for dns in cleaned_data:
            hostname = dns["hostname"]
            dns_primary = dns["dns_primary"]
            dns_secondary = dns["dns_secondary"]
            protocol = dns["protocol"]
            ssl_certificate = dns["ssl_certificate"]
            server_hostname = dns["server_hostname"]
            domain = dns["domain"]
            ip6_primary = dns["ip6_primary"]
            ip6_secondary = dns["ip6_secondary"]
            timeout = dns["timeout"]
            retry = dns["retry"]
            cache_limit = dns["cache_limit"]
            cache_ttl = dns["cache_ttl"]
            source_ip = dns["source_ip"]
            interface_select_method = dns["interface_select_method"]
            interface = dns["interface"]
            server_select_method = dns["server_select_method"]
            alt_primary = dns["alt_primary"]
            alt_secondary = dns["alt_secondary"]
            log_fqdn = dns["log_fqdn"]

            cursor.execute("SELECT device_id FROM device WHERE hostname=?", (hostname,))
            device_id = cursor.fetchone()[0]

            cursor.execute(
                """
                INSERT INTO dns (
                    device_id, primary_dns, secondary_dns, protocol, ssl_certificate, server_hostname, domain, ip6_primary, ip6_secondary, 
                    dns_timeout, retry, cache_limit, cache_ttl, source_ip, interface_select_method, interface, server_select_method, 
                    alt_primary, alt_secondary, log_fqdn
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    device_id,
                    dns_primary,
                    dns_secondary,
                    protocol,
                    ssl_certificate,
                    server_hostname,
                    domain,
                    ip6_primary,
                    ip6_secondary,
                    timeout,
                    retry,
                    cache_limit,
                    cache_ttl,
                    source_ip,
                    interface_select_method,
                    interface,
                    server_select_method,
                    alt_primary,
                    alt_secondary,
                    log_fqdn,
                ),
            )

            conn.commit()

    print("DNS data updated successfully")
    print("*" * 80)


def write_static_route_info():
    """
    Get the static route information from the clean_static_route_data() function and
    write static route information to the `staticroute` table in the database.
    """
    print("Updating static route data in database")
    cleaned_data = clean_static_route_data()

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()

        # Delete all existing entries from the staticroute table
        cursor.execute("DELETE FROM staticroute")

        # Insert cleaned static route data into staticroute table
        for route in cleaned_data:
            hostname = route["hostname"]
            seq_num = route["seq_num"]
            status = route["status"]
            dst = route["dst"]
            src = route["src"]
            gateway = route["gateway"]
            distance = route["distance"]
            weight = route["weight"]
            priority = route["priority"]
            device = route["device"]
            comment = route["comment"]
            blackhole = route["blackhole"]
            dynamic_gateway = route["dynamic_gateway"]
            sdwan_zone = route["sdwan_zone"]
            dstaddr = route["dstaddr"]
            internet_service = route["internet_service"]
            internet_service_custom = route["internet_service_custom"]
            tag = route["tag"]
            vrf = route["vrf"]
            bfd = route["bfd"]

            cursor.execute("SELECT device_id FROM device WHERE hostname=?", (hostname,))
            device_id = cursor.fetchone()[0]

            cursor.execute(
                """
                INSERT INTO staticroute (
                    device_id, seq_num, status, dst, src, gateway, distance, weight, priority, device, comment, blackhole, dynamic_gateway, 
                    sdwan_zone, dstaddr, internet_service, internet_service_custom, tag, vrf, bfd
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    device_id,
                    seq_num,
                    status,
                    dst,
                    src,
                    gateway,
                    distance,
                    weight,
                    priority,
                    device,
                    comment,
                    blackhole,
                    dynamic_gateway,
                    sdwan_zone,
                    dstaddr,
                    internet_service,
                    internet_service_custom,
                    tag,
                    vrf,
                    bfd,
                ),
            )

            conn.commit()

    print("Static route data updated successfully")
    print("*" * 80)


def write_policy_route_info():
    """
    Get the policy route information from the clean_policy_route_data() function and
    write policy route information to the `policyroute` table in the database.
    """
    print("Updating policy route data in database")
    cleaned_data = clean_policy_route_data()

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()

        # Delete all existing entries from the policyroute table
        cursor.execute("DELETE FROM policyroute")

        # Insert cleaned policy route data into policyroute table
        for route in cleaned_data:
            hostname = route["hostname"]
            seq_num = route["seq_num"]
            input_device = route["input_device"]
            input_device_negate = route["input_device_negate"]
            src = route["src"]
            srcaddr = route["srcaddr"]
            src_negate = route["src_negate"]
            dst = route["dst"]
            dstaddr = route["dstaddr"]
            dst_negate = route["dst_negate"]
            action = route["action"]
            protocol = route["protocol"]
            start_port = route["start_port"]
            end_port = route["end_port"]
            start_source_port = route["start_source_port"]
            end_source_port = route["end_source_port"]
            gateway = route["gateway"]
            output_device = route["output_device"]
            status = route["status"]
            comments = route["comments"]
            internet_service_id = route["internet_service_id"]
            internet_service_custom = route["internet_service_custom"]

            cursor.execute("SELECT device_id FROM device WHERE hostname=?", (hostname,))
            device_id = cursor.fetchone()[0]

            cursor.execute(
                """
                INSERT INTO policyroute (
                    device_id, seq_num, input_device, input_device_negate, src, srcaddr, src_negate, dst, dstaddr, dst_negate, action, protocol, 
                    start_port, end_port, start_source_port, end_source_port, gateway, output_device, status, comments, internet_service_id, 
                    internet_service_custom
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    device_id,
                    seq_num,
                    input_device,
                    input_device_negate,
                    src,
                    srcaddr,
                    src_negate,
                    dst,
                    dstaddr,
                    dst_negate,
                    action,
                    protocol,
                    start_port,
                    end_port,
                    start_source_port,
                    end_source_port,
                    gateway,
                    output_device,
                    status,
                    comments,
                    internet_service_id,
                    internet_service_custom,
                ),
            )

            conn.commit()

    print("Policy route data updated successfully")
    print("*" * 80)


def write_snmpv2_info():
    """
    Get the snmpv2 information from the clean_snmpv2_data() function and
    write snmpv2 information to the `snmpv2` table in the database.
    """
    print("SNMPv2 data in database")
    cleaned_data = clean_snmpv2_data()

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()

        # Delete all existing entries from the policyroute table
        cursor.execute("DELETE FROM snmpv2")

        # Insert cleaned policy route data into policyroute table
        for snmp in cleaned_data:
            hostname = snmp["hostname"]
            id = snmp["id"]
            name = snmp["name"]
            status = snmp["status"]
            host = snmp["host"]
            host6 = snmp["host6"]
            query_v1_status = snmp["query_v1_status"]
            query_v1_port = snmp["query_v1_port"]
            query_v2c_status = snmp["query_v2c_status"]
            query_v2c_port = snmp["query_v2c_port"]
            query_trap_v1_status = snmp["query_trap_v1_status"]
            query_trap_v1_rport = snmp["query_trap_v1_rport"]
            query_trap_v2c_status = snmp["query_trap_v2c_status"]
            query_trap_v2c_lport = snmp["query_trap_v2c_lport"]
            query_trap_v2c_rport = snmp["query_trap_v2c_rport"]
            events = snmp["events"]
            vdoms = snmp["vdoms"]

            cursor.execute("SELECT device_id FROM device WHERE hostname=?", (hostname,))
            device_id = cursor.fetchone()[0]

            cursor.execute(
                """
                INSERT INTO snmpv2 (
                    device_id, id, name, status, host, host6, query_v1_status, query_v1_port, query_v2c_status, query_v2c_port, query_trap_v1_status, 
                    query_trap_v1_rport, query_trap_v2c_status, query_trap_v2c_lport, query_trap_v2c_rport, events, vdoms
                )
                VALUES (?, ?, ?, ? ,? ,? ,? ,? ,? ,? ,? ,? ,? ,? ,? ,? ,?)
                """,
                (
                    device_id,
                    id,
                    name,
                    status,
                    host,
                    host6,
                    query_v1_status,
                    query_v1_port,
                    query_v2c_status,
                    query_v2c_port,
                    query_trap_v1_status,
                    query_trap_v1_rport,
                    query_trap_v2c_status,
                    query_trap_v2c_lport,
                    query_trap_v2c_rport,
                    events,
                    vdoms,
                ),
            )
            conn.commit()

    print("SNMPv2 data updated successfully")
    print("*" * 80)


def write_snmpv3_info():
    """
    Get the snmpv3 information from the clean_snmpv3_data() function and
    write snmpv3 information to the `snmpv3` table in the database.
    """
    print("SNMPv3 data in database")
    cleaned_data = clean_snmpv3_data()

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()

        # Delete all existing entries from the policyroute table
        cursor.execute("DELETE FROM snmpv3")

        # Insert cleaned policy route data into policyroute table
        for snmp in cleaned_data:
            hostname = snmp["hostname"]
            name = snmp["name"]
            status = snmp["status"]
            trap_status = snmp["trap_status"]
            trap_lport = snmp["trap_lport"]
            trap_rport = snmp["trap_rport"]
            queries = snmp["queries"]
            query_port = snmp["query_port"]
            notify_hosts = snmp["notify_hosts"]
            notify_hosts6 = snmp["notify_hosts6"]
            source_ip = snmp["source_ip"]
            source_ipv6 = snmp["source_ipv6"]
            events = snmp["events"]
            vdoms = snmp["vdoms"]
            security_level = snmp["security_level"]
            auth_proto = snmp["auth_proto"]
            priv_proto = snmp["priv_proto"]
            priv_pwd = snmp["priv_pwd"]

            cursor.execute("SELECT device_id FROM device WHERE hostname=?", (hostname,))
            device_id = cursor.fetchone()[0]

            cursor.execute(
                """
                INSERT INTO snmpv3 (
                    device_id, name, status, trap_status, trap_lport, trap_rport, queries, query_port, notify_hosts, notify_hosts6, source_ip, 
                    source_ipv6, events, vdoms, security_level, auth_proto, priv_proto, priv_pwd
                )
                VALUES (?, ?, ?, ? ,? ,? ,? ,? ,? ,? ,? ,? ,? ,? ,? ,? ,? ,?)
                """,
                (
                    device_id,
                    name,
                    status,
                    trap_status,
                    trap_lport,
                    trap_rport,
                    queries,
                    query_port,
                    notify_hosts,
                    notify_hosts6,
                    source_ip,
                    source_ipv6,
                    events,
                    vdoms,
                    security_level,
                    auth_proto,
                    priv_proto,
                    priv_pwd,
                ),
            )
            conn.commit()

    print("SNMPv3 data updated successfully")
    print("*" * 80)


def write_dnsfilter_info():
    """
    Get the dnsfilter profile information from the clean_dnsfilter_data() function and
    write dnsfilter profile information to the `dnsprofile` table in the database.
    """
    print("Updating dnsprofile profile in database")
    cleaned_data = clean_dnsfilter_data()

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()

        cursor.execute("DELETE FROM dnsprofile")
        for profile in cleaned_data:
            hostname = profile["hostname"]
            name = profile["name"]
            comment = profile["comment"]
            domain_filter = profile["domain_filter"]
            ftgd_dns = profile["ftgd_dns"]
            block_botnet = profile["block_botnet"]
            safe_search = profile["safe_search"]
            youtube_restrict = profile["youtube_restrict"]

            cursor.execute("SELECT device_id FROM device WHERE hostname=?", (hostname,))
            device_id = cursor.fetchone()[0]

            cursor.execute(
                """
                INSERT INTO dnsprofile 
                (device_id, name, comment, domain_filter, ftgd_dns, block_botnet, safe_search, youtube_restrict) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    device_id,
                    name,
                    comment,
                    domain_filter,
                    ftgd_dns,
                    block_botnet,
                    safe_search,
                    youtube_restrict,
                ),
            )

            conn.commit()

    print("Dnsprofile profile information updated successfully")
    print("*" * 80)


def write_internetservice_info():
    """
    Get the internet service information from the clean_internetservice_data() function and
    write internet service information to the `internetservice` table in the database.
    """
    print("Updating internet service data in database")
    cleaned_data = clean_internetservice_data()

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()

        # Clear internetservice table
        cursor.execute("DELETE FROM internetservice")
        conn.commit()

        for service in cleaned_data:
            hostname = service["hostname"]
            service_name = service["name"]
            service_type = service["type"]

            cursor.execute("SELECT device_id FROM device WHERE hostname=?", (hostname,))
            device_id = cursor.fetchone()[0]

            cursor.execute(
                """
                INSERT INTO internetservice (device_id, name, type)
                VALUES (?, ?, ?)
            """,
                (device_id, service_name, service_type),
            )

            conn.commit()

    print("Internet service data updated successfully")
    print("*" * 80)


def write_ippool_info():
    """
    Get the ippool information from the clean_ippool_data() function and
    write ippool information to the `ippool` table in the database.
    """
    print("Updating ippool data in database")
    cleaned_data = clean_ippool_data()

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()

        # Clear ippool table
        cursor.execute("DELETE FROM ippool")
        conn.commit()

        for pool in cleaned_data:
            hostname = pool["hostname"]
            pool_name = pool["name"]
            pool_type = pool["type"]
            pool_startip = pool["startip"]
            pool_endip = pool["endip"]
            pool_startport = pool["startport"]
            pool_endport = pool["endport"]
            pool_source_startip = pool["source_startip"]
            pool_source_endip = pool["source_endip"]
            pool_arp_reply = pool["arp_reply"]
            pool_arp_intf = pool["arp_intf"]
            pool_associated_interface = pool["associated_interface"]
            pool_comments = pool["comments"]

            cursor.execute("SELECT device_id FROM device WHERE hostname=?", (hostname,))
            device_id = cursor.fetchone()[0]

            cursor.execute(
                """
                INSERT INTO ippool (
                    device_id, name, type, start_ip, end_ip, startport, endport, source_start_ip, source_end_ip,
                    arp_reply, arp_intf, associated_interface, comments
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    device_id,
                    pool_name,
                    pool_type,
                    pool_startip,
                    pool_endip,
                    pool_startport,
                    pool_endport,
                    pool_source_startip,
                    pool_source_endip,
                    pool_arp_reply,
                    pool_arp_intf,
                    pool_associated_interface,
                    pool_comments,
                ),
            )

            conn.commit()

    print("Ippool data updated successfully")
    print("*" * 80)


def write_ips_info():
    """
    Get the ips profile information from the clean_ips_data() function and
    write ips profile information to the `ipsprofile` table in the database.
    """
    print("Updating IPS profile data in database")
    cleaned_data = clean_ips_data()

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM ipsprofile")
        for profile in cleaned_data:
            hostname = profile["hostname"]
            ips_name = profile["name"]
            ips_comment = profile["comment"]
            ips_block_malicious_url = profile["block_malicious_url"]
            ips_scan_botnet_connections = profile["scan_botnet_connections"]
            ips_extended_log = profile["extended_log"]
            ips_entries = profile["entries"]

            cursor.execute("SELECT device_id FROM device WHERE hostname=?", (hostname,))
            device_id = cursor.fetchone()[0]

            cursor.execute(
                "DELETE FROM ipsprofile WHERE device_id=? AND name=?",
                (device_id, ips_name),
            )

            cursor.execute(
                """
                INSERT INTO ipsprofile (device_id, name, comment, block_malicious_url, scan_botnet_connections, extended_log, entries)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    device_id,
                    ips_name,
                    ips_comment,
                    ips_block_malicious_url,
                    ips_scan_botnet_connections,
                    ips_extended_log,
                    ips_entries,
                ),
            )

            conn.commit()

    print("IPS profile data updated successfully")
    print("*" * 80)


def write_sslssh_info():
    """
    Get the ssl/ssh profile information from the clean_sslssh_data() function and
    write ssl/ssh profile information to the `sslsshprofile` table in the database.
    """
    print("Updating SSL/SSH profile data in database")
    cleaned_data = clean_sslssh_data()

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()

        # Delete all existing entries from sslsshprofile table
        cursor.execute("DELETE FROM sslsshprofile")

        for profile in cleaned_data:
            hostname = profile["hostname"]
            name = profile["name"]
            comment = profile["comment"]
            ssl = profile["ssl"]
            https = profile["https"]
            ftps = profile["ftps"]
            imaps = profile["imaps"]
            pop3s = profile["pop3s"]
            smtps = profile["smtps"]
            ssh = profile["ssh"]
            dot = profile["dot"]
            allowlist = profile["allowlist"]
            block_blocklisted_certificates = profile["block_blocklisted_certificates"]
            ssl_exempt = profile["ssl_exempt"]
            ssl_exemption_ip_rating = profile["ssl_exemption_ip_rating"]
            ssl_server = profile["ssl_server"]
            caname = profile["caname"]
            mapi_over_https = profile["mapi_over_https"]
            rpc_over_https = profile["rpc_over_https"]
            untrusted_caname = profile["untrusted_caname"]

            cursor.execute("SELECT device_id FROM device WHERE hostname=?", (hostname,))
            result = cursor.fetchone()
            if result:
                device_id = result[0]
            else:
                print(f"Device with hostname {hostname} not found.")
                continue

            cursor.execute(
                """
                INSERT INTO sslsshprofile (
                    device_id, name, comment, ssl, https, ftps, imaps, pop3s, smtps, ssh,
                    dot, allowlist, block_blocklisted_certificates, ssl_exempt,
                    ssl_exemption_ip_rating, ssl_server, caname, mapi_over_https,
                    rpc_over_https, untrusted_caname
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    device_id,
                    name,
                    comment,
                    ssl,
                    https,
                    ftps,
                    imaps,
                    pop3s,
                    smtps,
                    ssh,
                    dot,
                    allowlist,
                    block_blocklisted_certificates,
                    ssl_exempt,
                    ssl_exemption_ip_rating,
                    ssl_server,
                    caname,
                    mapi_over_https,
                    rpc_over_https,
                    untrusted_caname,
                ),
            )

            conn.commit()

    print("SSL/SSH profile data updated successfully")
    print("*" * 80)


def write_vip_info():
    """
    Get the vip profile information from the clean_vip_data() function and
    write vip profile information to the `vip` table in the database.
    """
    print("Updating VIP profile data in database")
    cleaned_data = clean_vip_data()

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()

        cursor.execute("DELETE FROM vip")

        for vip in cleaned_data:
            hostname = vip["hostname"]
            name = vip["name"]
            comment = vip["comment"]
            vip_type = vip["type"]
            extip = vip["extip"]
            extaddr = vip["extaddr"]
            nat44 = vip["nat44"]
            mappedip = vip["mappedip"]
            mapped_addr = vip["mapped_addr"]
            extintf = vip["extintf"]
            arp_reply = vip["arp_reply"]
            portforward = vip["portforward"]
            status = vip["status"]
            protocol = vip["protocol"]
            extport = vip["extport"]
            mappedport = vip["mappedport"]
            src_filter = vip["src_filter"]
            portmapping_type = vip["portmapping_type"]
            realservers = vip["realservers"]

            cursor.execute("SELECT device_id FROM device WHERE hostname=?", (hostname,))
            result = cursor.fetchone()
            if result:
                device_id = result[0]
            else:
                print(f"Device with hostname {hostname} not found.")
                continue

            cursor.execute(
                """
                INSERT INTO vip (
                    name, comment, type, ext_ip, ext_addr, nat44, mapped_ip, mapped_addr, ext_intf,
                    arp_reply, portforward, status, protocol, ext_port, mapped_port, src_filter,
                    portmapping_type, realservers, device_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    name,
                    comment,
                    vip_type,
                    extip,
                    extaddr,
                    nat44,
                    mappedip,
                    mapped_addr,
                    extintf,
                    arp_reply,
                    portforward,
                    status,
                    protocol,
                    extport,
                    mappedport,
                    src_filter,
                    portmapping_type,
                    realservers,
                    device_id,
                ),
            )

            conn.commit()

    print("VIP profile data updated successfully")
    print("*" * 80)


def write_webfilter_info():
    """
    Get the web filter profile information from the clean_webfilter_data() function and
    write web filter profile information to the `webprofile` table in the database.
    """
    print("Updating web filter profile data in database")
    cleaned_data = clean_webfilter_data()

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()

        cursor.execute("DELETE FROM webprofile")

        for profile in cleaned_data:
            hostname = profile["hostname"]
            webfilter_name = profile["name"]
            webfilter_comment = profile["comment"]
            webfilter_options = profile["options"]
            webfilter_https_replacemsg = profile["https_replacemsg"]
            webfilter_override = profile["override"]
            webfilter_web = profile["web"]
            webfilter_ftgd_wf = profile["ftgd_wf"]

            cursor.execute("SELECT device_id FROM device WHERE hostname=?", (hostname,))
            device_id = cursor.fetchone()[0]

            cursor.execute(
                "DELETE FROM webprofile WHERE device_id=? AND name=?",
                (device_id, webfilter_name),
            )

            cursor.execute(
                """
                INSERT INTO webprofile (
                    device_id, name, comment, options, https_replacemsg, override, web, ftgd_wf
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    device_id,
                    webfilter_name,
                    webfilter_comment,
                    webfilter_options,
                    webfilter_https_replacemsg,
                    webfilter_override,
                    webfilter_web,
                    webfilter_ftgd_wf,
                ),
            )

            conn.commit()

    print("Web filter profile data updated successfully")
    print("*" * 80)


def write_trafficshapers_info():
    """
    Get the traffic shapers information from the get_fortigate_trafficshapers_info() function and
    write traffic shapers information to the `trafficshapers` table in the database.
    """
    print("Updating traffic shapers data in database")
    cleaned_data = clean_trafficshapers_data()

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()

        # Delete all existing entries from trafficshapers table
        cursor.execute("DELETE FROM trafficshapers")

        # Insert cleaned traffic shapers data into trafficshapers table
        for trafficshaper in cleaned_data:
            hostname = trafficshaper["hostname"]
            name = trafficshaper["name"]
            guaranteed_bandwidth = trafficshaper["guaranteed_bandwidth"]
            maximum_bandwidth = trafficshaper["maximum_bandwidth"]
            bandwidth_unit = trafficshaper["bandwidth_unit"]
            priority = trafficshaper["priority"]
            per_policy = trafficshaper["per_policy"]
            diffserv = trafficshaper["diffserv"]
            diffservcode = trafficshaper["diffservcode"]
            dscp_marking_method = trafficshaper["dscp_marking_method"]
            exceed_bandwidth = trafficshaper["exceed_bandwidth"]
            exceed_dscp = trafficshaper["exceed_dscp"]
            maximum_dscp = trafficshaper["maximum_dscp"]
            overhead = trafficshaper["overhead"]
            exceed_class_id = trafficshaper["exceed_class_id"]

            cursor.execute("SELECT device_id FROM device WHERE hostname=?", (hostname,))
            device_id = cursor.fetchone()[0]

            cursor.execute(
                """INSERT INTO trafficshapers (device_id, name, guaranteed_bandwidth, maximum_bandwidth, bandwidth_unit, priority, per_policy, diffserv, 
                   diffservcode, dscp_marking_method, exceed_bandwidth, exceed_dscp, maximum_dscp, overhead, exceed_class_id) 
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    device_id,
                    name,
                    guaranteed_bandwidth,
                    maximum_bandwidth,
                    bandwidth_unit,
                    priority,
                    per_policy,
                    diffserv,
                    diffservcode,
                    dscp_marking_method,
                    exceed_bandwidth,
                    exceed_dscp,
                    maximum_dscp,
                    overhead,
                    exceed_class_id,
                ),
            )

            conn.commit()

    print("Traffic shapers data updated successfully")
    print("*" * 80)


def write_trafficpolicy_info():
    """
    Get the traffic shaper policy information from the clean_trafficpolicy_data() function and
    write traffic shaper policy information to the `trafficpolicy` table in the database.
    """
    print("Updating traffic shaper policy data in database")
    cleaned_data = clean_trafficpolicy_data()

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()

        # Delete all existing entries from trafficpolicy table
        cursor.execute("DELETE FROM trafficpolicy")

        # Insert cleaned traffic policy data into trafficpolicy table
        for policy in cleaned_data:
            hostname = policy["hostname"]
            policy_id = policy["policy_id"]
            trafficpolicy_name = policy["name"]
            trafficpolicy_comment = policy["comment"]
            trafficpolicy_status = policy["status"]
            trafficpolicy_ip_version = policy["ip_version"]
            trafficpolicy_srcintf = policy["srcintf"]
            trafficpolicy_dstintf = policy["dstintf"]
            trafficpolicy_srcaddr = policy["srcaddr"]
            trafficpolicy_dstaddr = policy["dstaddr"]
            trafficpolicy_internet_service = policy["internet_service"]
            trafficpolicy_internet_service_name = policy["internet_service_name"]
            trafficpolicy_internet_service_group = policy["internet_service_group"]
            trafficpolicy_internet_service_custom = policy["internet_service_custom"]
            trafficpolicy_internet_service_src = policy["internet_service_src"]
            trafficpolicy_internet_service_src_name = policy[
                "internet_service_src_name"
            ]
            trafficpolicy_internet_service_src_group = policy[
                "internet_service_src_group"
            ]
            trafficpolicy_internet_service_src_custom = policy[
                "internet_service_src_custom"
            ]
            trafficpolicy_internet_service_src_custom_group = policy[
                "internet_service_src_custom_group"
            ]
            trafficpolicy_service = policy["service"]
            trafficpolicy_schedule = policy["schedule"]
            trafficpolicy_users = policy["users"]
            trafficpolicy_groups = policy["groups"]
            trafficpolicy_application = policy["application"]
            trafficpolicy_app_group = policy["app_group"]
            trafficpolicy_url_category = policy["url_category"]
            trafficpolicy_traffic_shaper = policy["traffic_shaper"]
            trafficpolicy_traffic_shaper_reverse = policy["traffic_shaper_reverse"]
            trafficpolicy_per_ip_shaper = policy["per_ip_shaper"]
            trafficpolicy_class_id = policy["class_id"]
            trafficpolicy_diffserv_forward = policy["diffserv_forward"]
            trafficpolicy_diffserv_reverse = policy["diffserv_reverse"]

            cursor.execute("SELECT device_id FROM device WHERE hostname=?", (hostname,))
            device_id = cursor.fetchone()[0]

            cursor.execute(
                """
                INSERT INTO trafficpolicy (
                    device_id, policy_id, name, comment, status, ip_version, srcintf, dstintf, srcaddr, dstaddr, internet_service,
                    internet_service_name, internet_service_group, internet_service_custom, internet_service_src, internet_service_src_name,
                    internet_service_src_group, internet_service_src_custom, internet_service_src_custom_group, service, schedule, users,
                    groups, application, app_group, url_category, traffic_shaper, traffic_shaper_reverse, per_ip_shaper, class_id, diffserv_forward, diffserv_reverse
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    device_id,
                    policy_id,
                    trafficpolicy_name,
                    trafficpolicy_comment,
                    trafficpolicy_status,
                    trafficpolicy_ip_version,
                    trafficpolicy_srcintf,
                    trafficpolicy_dstintf,
                    trafficpolicy_srcaddr,
                    trafficpolicy_dstaddr,
                    trafficpolicy_internet_service,
                    trafficpolicy_internet_service_name,
                    trafficpolicy_internet_service_group,
                    trafficpolicy_internet_service_custom,
                    trafficpolicy_internet_service_src,
                    trafficpolicy_internet_service_src_name,
                    trafficpolicy_internet_service_src_group,
                    trafficpolicy_internet_service_src_custom,
                    trafficpolicy_internet_service_src_custom_group,
                    trafficpolicy_service,
                    trafficpolicy_schedule,
                    trafficpolicy_users,
                    trafficpolicy_groups,
                    trafficpolicy_application,
                    trafficpolicy_app_group,
                    trafficpolicy_url_category,
                    trafficpolicy_traffic_shaper,
                    trafficpolicy_traffic_shaper_reverse,
                    trafficpolicy_per_ip_shaper,
                    trafficpolicy_class_id,
                    trafficpolicy_diffserv_forward,
                    trafficpolicy_diffserv_reverse,
                ),
            )

            conn.commit()

    print("Traffic shaper policy data updated successfully")
    print("*" * 80)


def write_fwpolicy_info():
    """
    Get the firewall policy information from the clean_fwpolicy_data() function and
    write firewall policy information to the `firewallpolicy` table in the database.
    """
    print("Updating firewallpolicy data in database")
    cleaned_data = clean_fwpolicy_data()

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()

        # Delete all existing entries from firewallpolicy table
        cursor.execute("DELETE FROM firewallpolicy")
        conn.commit()

        # Insert cleaned data into firewallpolicy table
        for policy in cleaned_data:
            policy_id = policy["policy_id"]
            fwpolicy_name = policy["fwpolicy_name"]
            fwpolicy_status = policy["fwpolicy_status"]
            fwpolicy_srcintf = policy["srcintf"]
            fwpolicy_dstintf = policy["dstintf"]
            fwpolicy_action = policy["action"]
            fwpolicy_nat64 = policy["nat64"]
            fwpolicy_nat46 = policy["nat46"]
            fwpolicy_srcaddr6 = policy["srcaddr6"]
            fwpolicy_dstaddr6 = policy["dstaddr6"]
            fwpolicy_srcaddr = policy["srcaddr"]
            fwpolicy_dstaddr = policy["dstaddr"]
            fwpolicy_internet_service_name = policy["internet-service-name"]
            fwpolicy_internet_service_src_name = policy["internet-service-src-name"]
            fwpolicy_internet_service_dynamic = policy["internet-service-dynamic"]
            fwpolicy_internet_service_custom_group = policy[
                "internet-service-custom-group"
            ]
            fwpolicy_internet_service = policy["internet-service"]
            fwpolicy_internet_service_src = policy["internet-service-src"]
            fwpolicy_internet_service_group = policy["internet-service-group"]
            fwpolicy_internet_service_src_group = policy["internet-service-src-group"]
            fwpolicy_internet_service_src_dynamic = policy[
                "internet-service-src-dynamic"
            ]
            fwpolicy_internet_service_src_custom_group = policy[
                "internet-service-src-custom-group"
            ]
            fwpolicy_schedule = policy["schedule"]
            fwpolicy_schedule_timeout = policy["schedule-timeout"]
            fwpolicy_service = policy["service"]
            fwpolicy_service_utm_status = policy["service-utm-status"]
            fwpolicy_inspection_mode = policy["inspection-mode"]
            fwpolicy_http_policy_redirect = policy["http-policy-redirect"]
            fwpolicy_ssh_policy_redirect = policy["ssh-policy-redirect"]
            fwpolicy_profile_type = policy["profile-type"]
            fwpolicy_profile_group = policy["profile-group"]
            fwpolicy_profile_protocol_options = policy["profile-protocol-options"]
            fwpolicy_ssl_ssh_profile = policy["ssl-ssh-profile"]
            fwpolicy_av_profile = policy["av-profile"]
            fwpolicy_webfilter_profile = policy["webfilter-profile"]
            fwpolicy_dnsfilter_profile = policy["dnsfilter-profile"]
            fwpolicy_emailfilter_profile = policy["emailfilter-profile"]
            fwpolicy_dlp_profile = policy["dlp-profile"]
            fwpolicy_file_filter = policy["file-filter"]
            fwpolicy_ips_sensor = policy["ips-sensor"]
            fwpolicy_application_list = policy["application-list"]
            fwpolicy_voip_profile = policy["voip-profile"]
            fwpolicy_sctp_profile = policy["sctp-profile"]
            fwpolicy_icap_profile = policy["icap-profile"]
            fwpolicy_cifs_profile = policy["cifs-profile"]
            fwpolicy_waf_profile = policy["waf-profile"]
            fwpolicy_ssh_filter_profile = policy["ssh-filter-profile"]
            fwpolicy_logtraffic = policy["logtraffic"]
            fwpolicy_logtraffic_start = policy["logtraffic-start"]
            fwpolicy_capture_packet = policy["capture-packet"]
            fwpolicy_traffic_shaper = policy["traffic-shaper"]
            fwpolicy_traffic_shaper_reverse = policy["traffic-shaper-reverse"]
            fwpolicy_per_ip_shaper = policy["per-ip-shaper"]
            fwpolicy_nat = policy["nat"]
            fwpolicy_permit_any_host = policy["permit-any-host"]
            fwpolicy_permit_stun_host = policy["permit-stun-host"]
            fwpolicy_fixedport = policy["fixedport"]
            fwpolicy_ippool = policy["ippool"]
            fwpolicy_poolname = policy["poolname"]
            fwpolicy_poolname6 = policy["poolname6"]
            fwpolicy_inbound = policy["inbound"]
            fwpolicy_outbound = policy["outbound"]
            fwpolicy_natinbound = policy["natinbound"]
            fwpolicy_natoutbound = policy["natoutbound"]
            fwpolicy_wccp = policy["wccp"]
            fwpolicy_ntlm = policy["ntlm"]
            fwpolicy_ntlm_guest = policy["ntlm-guest"]
            fwpolicy_ntlm_enabled_browsers = policy["ntlm-enabled-browsers"]
            fwpolicy_groups = policy["groups"]
            fwpolicy_users = policy["users"]
            fwpolicy_fsso_groups = policy["fsso-groups"]
            fwpolicy_vpntunnel = policy["vpntunnel"]
            fwpolicy_natip = policy["natip"]
            fwpolicy_match_vip = policy["match-vip"]
            fwpolicy_match_vip_only = policy["match-vip-only"]
            fwpolicy_comments = policy["comments"]
            fwpolicy_label = policy["label"]
            fwpolicy_global_label = policy["global-label"]
            fwpolicy_auth_cert = policy["auth-cert"]
            fwpolicy_vlan_filter = policy["vlan-filter"]

            cursor.execute(
                "SELECT device_id FROM device WHERE hostname=?", (policy["hostname"],)
            )
            device_id = cursor.fetchone()[0]

            cursor.execute(
                """
                INSERT INTO firewallpolicy (
                    device_id, policy_id, fwpolicy_name, fwpolicy_status, srcintf, dstintf, action, nat64, nat46,
                    srcaddr6, dstaddr6, srcaddr, dstaddr, internet_service_name, internet_service_src_name, 
                    internet_service_dynamic, internet_service_custom_group, internet_service, internet_service_src, 
                    internet_service_group, internet_service_src_group, internet_service_src_dynamic, 
                    internet_service_src_custom_group, schedule, schedule_timeout, service, service_utm_status, 
                    inspection_mode, http_policy_redirect, ssh_policy_redirect, profile_type, profile_group, 
                    profile_protocol_options, ssl_ssh_profile, av_profile, webfilter_profile, dnsfilter_profile, 
                    emailfilter_profile, dlp_profile, file_filter, ips_sensor, application_list, voip_profile, 
                    sctp_profile, icap_profile, cifs_profile, waf_profile, ssh_filter_profile, logtraffic, 
                    logtraffic_start, capture_packet, traffic_shaper, traffic_shaper_reverse, per_ip_shaper, nat, 
                    permit_any_host, permit_stun_host, fixedport, ippool, poolname, poolname6, inbound, outbound, 
                    natinbound, natoutbound, wccp, ntlm, ntlm_guest, ntlm_enabled_browsers, groups, users, 
                    fsso_groups, vpntunnel, natip, match_vip,
                    match_vip_only, comments, label, global_label, auth_cert, vlan_filter
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 
                    ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                (
                    device_id,
                    policy_id,
                    fwpolicy_name,
                    fwpolicy_status,
                    fwpolicy_srcintf,
                    fwpolicy_dstintf,
                    fwpolicy_action,
                    fwpolicy_nat64,
                    fwpolicy_nat46,
                    fwpolicy_srcaddr6,
                    fwpolicy_dstaddr6,
                    fwpolicy_srcaddr,
                    fwpolicy_dstaddr,
                    fwpolicy_internet_service_name,
                    fwpolicy_internet_service_src_name,
                    fwpolicy_internet_service_dynamic,
                    fwpolicy_internet_service_custom_group,
                    fwpolicy_internet_service,
                    fwpolicy_internet_service_src,
                    fwpolicy_internet_service_group,
                    fwpolicy_internet_service_src_group,
                    fwpolicy_internet_service_src_dynamic,
                    fwpolicy_internet_service_src_custom_group,
                    fwpolicy_schedule,
                    fwpolicy_schedule_timeout,
                    fwpolicy_service,
                    fwpolicy_service_utm_status,
                    fwpolicy_inspection_mode,
                    fwpolicy_http_policy_redirect,
                    fwpolicy_ssh_policy_redirect,
                    fwpolicy_profile_type,
                    fwpolicy_profile_group,
                    fwpolicy_profile_protocol_options,
                    fwpolicy_ssl_ssh_profile,
                    fwpolicy_av_profile,
                    fwpolicy_webfilter_profile,
                    fwpolicy_dnsfilter_profile,
                    fwpolicy_emailfilter_profile,
                    fwpolicy_dlp_profile,
                    fwpolicy_file_filter,
                    fwpolicy_ips_sensor,
                    fwpolicy_application_list,
                    fwpolicy_voip_profile,
                    fwpolicy_sctp_profile,
                    fwpolicy_icap_profile,
                    fwpolicy_cifs_profile,
                    fwpolicy_waf_profile,
                    fwpolicy_ssh_filter_profile,
                    fwpolicy_logtraffic,
                    fwpolicy_logtraffic_start,
                    fwpolicy_capture_packet,
                    fwpolicy_traffic_shaper,
                    fwpolicy_traffic_shaper_reverse,
                    fwpolicy_per_ip_shaper,
                    fwpolicy_nat,
                    fwpolicy_permit_any_host,
                    fwpolicy_permit_stun_host,
                    fwpolicy_fixedport,
                    fwpolicy_ippool,
                    fwpolicy_poolname,
                    fwpolicy_poolname6,
                    fwpolicy_inbound,
                    fwpolicy_outbound,
                    fwpolicy_natinbound,
                    fwpolicy_natoutbound,
                    fwpolicy_wccp,
                    fwpolicy_ntlm,
                    fwpolicy_ntlm_guest,
                    fwpolicy_ntlm_enabled_browsers,
                    fwpolicy_groups,
                    fwpolicy_users,
                    fwpolicy_fsso_groups,
                    fwpolicy_vpntunnel,
                    fwpolicy_natip,
                    fwpolicy_match_vip,
                    fwpolicy_match_vip_only,
                    fwpolicy_comments,
                    fwpolicy_label,
                    fwpolicy_global_label,
                    fwpolicy_auth_cert,
                    fwpolicy_vlan_filter,
                ),
            )

            conn.commit()
    print("Firewallpolicy data updated successfully")
    print("*" * 80)
