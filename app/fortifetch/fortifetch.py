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

        db.write_application_info()

        db.write_av_info()

        db.write_dnsfilter_info()

        # Uncomment the following line to enable the internetservice info, this will take a long time since there is 1000+ entries
        # db.write_internetservice_info()

        db.write_ippool_info()

        db.write_ips_info()

        db.write_sslssh_info()

        db.write_vip_info()

        db.write_webfilter_info()

        db.write_fwpolicy_info()

        db.write_trafficshapers_info()

        db.write_trafficpolicy_info()

        db.write_dns_info()

        db.write_static_route_info()

        db.write_policy_route_info()

    @staticmethod
    def create_sql_database():
        db.create_database()

    @staticmethod
    def clear_sql_database():
        db.clear_database()
