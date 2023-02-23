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


def write_device_info():
    """
    Get the device information from the clean_device_data() function and
    Write device information to the `device` table in the database
    """
    print("Updating devices in database")
    device_info = clean_device_data()
    with sqlite3.connect(DB_PATH) as conn:
        for device in device_info:
            hostname = device["hostname"]
            serial_number = device["serial_number"]
            version = device["version"]
            model = device["model"]

            # Check if the device already exists in the database
            select_query = "SELECT COUNT(*) FROM device WHERE hostname = ? AND serial_number = ? AND version = ? AND model = ?"
            cursor = conn.execute(
                select_query, (hostname, serial_number, version, model)
            )
            row_count = cursor.fetchone()[0]

            if row_count == 0:
                # Insert device information into the database
                insert_query = """
                INSERT INTO device (hostname, serial_number, version, model)
                VALUES (?, ?, ?, ?)
                """
                conn.execute(insert_query, (hostname, serial_number, version, model))

                conn.commit()
            else:
                # Update device information in the database
                update_query = """
                UPDATE device
                SET version = ?
                WHERE hostname = ? AND serial_number = ? AND model = ?
                """
                conn.execute(update_query, (version, hostname, serial_number, model))

                conn.commit()
    print("Device information updated successfully")
    print("*" * 80)


def write_interface_info():
    """
    Get the interface information from the clean_interface_data() function and
    Write interface information to the `interface` table in the database
    """
    print("Updating interfaces in database")
    interface_info = clean_interface_data()
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
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
                "INSERT OR IGNORE INTO interface (device_id, name) VALUES (?, ?)",
                (device_id, interface_name),
            )
            cursor.execute(
                "UPDATE interface SET type=?, ip=?, mtu=?, mode=?, status=?, allowaccess=?, vdom=? WHERE device_id=? AND name=?",
                (
                    type,
                    ip,
                    mtu,
                    mode,
                    status,
                    allowaccess,
                    vdom,
                    device_id,
                    interface_name,
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
                "INSERT OR IGNORE INTO address (device_id, name) VALUES (?, ?)",
                (device_id, name),
            )
            cursor.execute(
                "UPDATE address SET associated_interface=?, country=?, end_ip=?, fqdn=?, start_ip=?, subnet=?, address_type=? WHERE device_id=? AND name=?",
                (
                    associated_interface,
                    country,
                    end_ip,
                    fqdn,
                    start_ip,
                    subnet,
                    address_type,
                    device_id,
                    name,
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
        for address in address_info:
            hostname = address["hostname"]
            name = address["name"]
            member = address["member"]
            cursor.execute("SELECT device_id FROM device WHERE hostname=?", (hostname,))
            device_id = cursor.fetchone()[0]
            cursor.execute(
                "INSERT OR IGNORE INTO addressgroup (device_id, name) VALUES (?, ?)",
                (device_id, name),
            )
            cursor.execute(
                "UPDATE addressgroup SET member=? WHERE device_id=? AND name=?",
                (member, device_id, name),
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
        for application in application_info:
            hostname = application["hostname"]
            name = application["name"]
            entries = application["entries"]
            comment = application["comment"]
            cursor.execute("SELECT device_id FROM device WHERE hostname=?", (hostname,))
            device_id = cursor.fetchone()[0]
            cursor.execute(
                "INSERT OR IGNORE INTO appprofile (device_id, name) VALUES (?, ?)",
                (device_id, name),
            )
            cursor.execute(
                "UPDATE appprofile SET entries=?, comment=? WHERE device_id=? AND name=?",
                (entries, comment, device_id, name),
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
                INSERT OR IGNORE INTO avprofile 
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

            cursor.execute(
                """
                UPDATE avprofile 
                SET comment=?, http=?, ftp=?, imap=?, pop3=?, smtp=?, nntp=?, mapi=?, ssh=?, cifs=?, nac_quar=?, content_disarm=? 
                WHERE device_id=? AND name=?
            """,
                (
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
                    device_id,
                    name,
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
                INSERT OR IGNORE INTO dnsprofile 
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

            cursor.execute(
                """
                UPDATE dnsprofile 
                SET comment=?, domain_filter=?, ftgd_dns=?, block_botnet=?, safe_search=?, youtube_restrict=? 
                WHERE device_id=? AND name=?
            """,
                (
                    comment,
                    domain_filter,
                    ftgd_dns,
                    block_botnet,
                    safe_search,
                    youtube_restrict,
                    device_id,
                    name,
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

        for service in cleaned_data:
            hostname = service["hostname"]
            service_name = service["name"]
            service_type = service["type"]

            cursor.execute("SELECT device_id FROM device WHERE hostname=?", (hostname,))
            device_id = cursor.fetchone()[0]

            cursor.execute(
                """
                INSERT OR IGNORE INTO internetservice (device_id, name, type)
                VALUES (?, ?, ?)
            """,
                (device_id, service_name, service_type),
            )

            cursor.execute(
                """
                UPDATE internetservice
                SET type=?
                WHERE device_id=? AND name=?
            """,
                (service_type, device_id, service_name),
            )

            conn.commit()

    print("Internet service data updated successfully")
    print("*" * 80)
