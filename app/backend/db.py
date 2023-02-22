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
import sqlite3

DATABASE_NAME = "FortiFetch.db"
DB_DIRECTORY = os.path.join(os.path.dirname(__file__), "../../db")
SCHEMA_FILE = os.path.join(DB_DIRECTORY, "schema.sql")
DB_PATH = os.path.join(DB_DIRECTORY, DATABASE_NAME)
DB_CONN = sqlite3.connect(DB_PATH)


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


def write_device_info(hostname, serial_number, model):
    """
    Write device information to the `device` table in the database, but only if the
    device does not already exist in the table.

    Args:
        hostname (str): The hostname of the device
        serial_number (str): The serial number of the device
        model (str): The model of the device
    """
    # Check if the device already exists in the database
    select_query = "SELECT COUNT(*) FROM device WHERE hostname = ? AND serial_number = ? AND model = ?"
    cursor = DB_CONN.execute(select_query, (hostname, serial_number, model))
    row_count = cursor.fetchone()[0]

    if row_count == 0:
        # Insert device information into the database
        insert_query = """
        INSERT INTO device (hostname, serial_number, model)
        VALUES (?, ?, ?)
        """
        DB_CONN.execute(insert_query, (hostname, serial_number, model))

        DB_CONN.commit()
        print("Device information written to database")
    else:
        print("Device information already exists in database")

    DB_CONN.close()
