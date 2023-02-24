"""
This module contains all the "backend" functions
which are used to perform backend tasks such as:
- Retrieve data from databases
- Store data in databases
- Delete data from databases
- Transform backend data for frontend usage
"""

# import modules
import os
import sys
import sqlite3

# Add the parent directory of 'app' to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# import modules
from data_cleaning.clean_fgt_data import *

# Define constants
DATABASE_NAME = "FortiFetch.db"
DB_DIRECTORY = os.path.join(os.path.dirname(__file__), "../../db")
SCHEMA_FILE = os.path.join(DB_DIRECTORY, "schema.sql")
DB_PATH = os.path.join(DB_DIRECTORY, DATABASE_NAME)


def create_database():
    """
    Create the database and tables if they do not already exist. The database and
    table schemas are defined in `schema.sql`. This function should be called once
    when the application is first run.
    """
    with sqlite3.connect(DB_PATH) as conn:
        try:
            with open(SCHEMA_FILE) as f:
                schema_sql = f.read()
                conn.executescript(schema_sql)
            print("Database created at", DB_PATH)
        except sqlite3.OperationalError as e:
            if str(e) == f"table device already exists":
                print("Database already exists")
            else:
                print(f"An error occurred while executing SQL script: {e}")


def clear_database():
    """
    Clear all the values in the database but keep the tables.
    """
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("DELETE FROM device;")
        c.execute("DELETE FROM interface;")
        c.execute("DELETE FROM firewallpolicy;")
        c.execute("DELETE FROM webprofile;")
        c.execute("DELETE FROM dnsprofile;")
        c.execute("DELETE FROM appprofile;")
        c.execute("DELETE FROM ipsprofile;")
        c.execute("DELETE FROM sslsshprofile;")
        c.execute("DELETE FROM avprofile;")
        c.execute("DELETE FROM address;")
        c.execute("DELETE FROM addressgroup;")
        c.execute("DELETE FROM address_group_member;")
        c.execute("DELETE FROM internetservice;")
        c.execute("DELETE FROM ippool;")
        c.execute("DELETE FROM vip;")

        conn.commit()


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

            # Get the device_id for the current hostname
            cursor.execute("SELECT device_id FROM device WHERE hostname=?", (hostname,))
            result = cursor.fetchone()
            if result:
                device_id = result[0]
            else:
                print(f"Device with hostname {hostname} not found.")
                continue

            # Insert the SSL/SSH profile information for the current device and profile name
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
