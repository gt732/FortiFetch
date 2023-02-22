"""
This module contains the main class `FortiFetch` which orchastrates the
logic of the application.

"""

# import os sys
import os
import sys

# Add the parent directory of 'app' to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# imports
from typing import List, Dict, Optional
from data_cleaning.clean_nornir_data import *
from tasks.nornir_tasks import *
from backend import db


class FortiFetch:
    def __init__(self, **kwargs):
        pass

    @staticmethod
    def update_all_devices():
        db.write_device_info()

    @staticmethod
    def create_sql_database():
        db.create_database()
