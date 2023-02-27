"""
This module contains all the general backend functions to interact with the database.
"""
# import modules
import os
import sys
import sqlite3

# Add the parent directory of 'app' to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

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
