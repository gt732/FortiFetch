"""
This module contains all the general backend functions to create and interact with the database.
"""
# import modules
import os
import sys
import sqlite3
from typing import Union, Dict, Optional, List

# Add the parent directory of 'fortifetch' to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Define constants
DATABASE_NAME = "FortiFetch.db"
DB_DIRECTORY = os.path.join(os.path.dirname(__file__), "../db")
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


def delete_database():
    """
    Delete the FortiFetch database from the file system.
    """
    try:
        os.remove(DB_PATH)
        print("Database deleted at", DB_PATH)
    except FileNotFoundError:
        print("Database does not exist")


def execute_sql(sql: str, params: Optional[tuple] = None) -> List[Dict]:
    """
    Execute an SQL query and return the results.

    Args:
        sql: The SQL query to execute.
        params: The parameters to pass to the SQL query.

    Returns:
        A list of dictionaries containing the results of the query.
    """
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        if params:
            cursor.execute(sql, params)
        else:
            cursor.execute(sql)
        return [dict(row) for row in cursor.fetchall()]
