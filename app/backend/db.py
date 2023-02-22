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
from data_cleaning.clean_nornir_data import *

# Define constants
DATABASE_NAME = "FortiFetch.db"
DB_DIRECTORY = os.path.join(os.path.dirname(__file__), "../../db")
SCHEMA_FILE = os.path.join(DB_DIRECTORY, "schema.sql")
DB_PATH = os.path.join(DB_DIRECTORY, DATABASE_NAME)
DB_CONN = sqlite3.connect(DB_PATH)

CLEANED_DATA = {
    "DEVICE_INFO": clean_device_data(),
}


def create_database():
    """
    Create the database and tables if they do not already exist. The database and
    table schemas are defined in `schema.sql`. This function should be called once
    when the application is first run.
    """
    if os.path.exists(DB_PATH):
        print("Database already exists")
        return

    with open(SCHEMA_FILE) as f:
        schema_sql = f.read()
        DB_CONN.executescript(schema_sql)

    DB_CONN.close()
    print("Database created at", DB_PATH)


def write_device_info():
    """
    Write device information to the `device` table in the database, but only if the
    device does not already exist in the table.
    """
    # Loop through devices in CLEANED_DATA["DEVICE_INFO"]
    for device in CLEANED_DATA["DEVICE_INFO"]:
        hostname = device["hostname"]
        serial_number = device["serial_number"]
        version = device["version"]
        model = device["model"]

        # Check if the device already exists in the database
        select_query = "SELECT COUNT(*) FROM device WHERE hostname = ? AND serial_number = ? AND version = ? AND model = ?"
        cursor = DB_CONN.execute(
            select_query, (hostname, serial_number, version, model)
        )
        row_count = cursor.fetchone()[0]

        if row_count == 0:
            # Insert device information into the database
            insert_query = """
            INSERT INTO device (hostname, serial_number, version, model)
            VALUES (?, ?, ?, ?)
            """
            DB_CONN.execute(insert_query, (hostname, serial_number, version, model))

            DB_CONN.commit()
            print(f"Device information for {hostname} written to database")
        else:
            # Update device information in the database
            update_query = """
            UPDATE device
            SET version = ?
            WHERE hostname = ? AND serial_number = ? AND model = ?
            """
            DB_CONN.execute(update_query, (version, hostname, serial_number, model))

            DB_CONN.commit()
            print(f"Device information for {hostname} updated in database")

    DB_CONN.close()
