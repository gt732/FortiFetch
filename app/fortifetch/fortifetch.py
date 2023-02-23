"""
This module contains the main class `FortiFetch` which orchastrates the
logic of the application.

"""

# import os sys
import os
import sys
import time

# Add the parent directory of 'app' to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# imports
from typing import List, Dict, Optional
from data_cleaning.clean_fgt_data import *
from backend import db


class FortiFetch:
    def __init__(self, **kwargs):
        pass

    @staticmethod
    def update_all_devices():

        db.write_device_info()

        db.write_interface_info()

        db.write_address_info()

        db.write_address_group_info()

    @staticmethod
    def create_sql_database():
        db.create_database()
