"""
This module contains all the nornir tasks functions
which are used to retreive information from the fortigate
and write it to the database
"""

# import modules
import os
from nornir import InitNornir
from nornir_pyfgt.plugins.tasks import pyfgt_get_url
from typing import Union, Dict, Optional
from nornir_utils.plugins.functions import print_result
from backend import db

# init nornir
NORNIR_CONFIG = os.getenv("NORNIR_CONFIG_PATH")
nr = InitNornir(config_file=NORNIR_CONFIG)


def get_fortigate_device_info(task):
    """
    Get the fortigate device information

    Returns:
        device_info: A dictionary containing the device information

    """
    results = task.run(task=pyfgt_get_url, url="/api/v2/monitor/system/csf")
    task.host["facts"] = results.result
    hostname = task.host["facts"]["devices"]["fortigate"][0]["host_name"]
    serial_number = task.host["facts"]["devices"]["fortigate"][0]["serial"]
    model = task.host["facts"]["devices"]["fortigate"][0]["model"]
    print(hostname)
    print(serial_number)
    print(model)


results = nr.run(task=get_fortigate_device_info)
