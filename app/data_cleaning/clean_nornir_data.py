"""
This module contains functions for cleaning the data returned from the nornir tasks
before it is written to the database.
"""

# import os sys
import os
import sys

# Add the parent directory of 'app' to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# import modules
from typing import List, Dict
from shared.utilities import nr
from tasks.nornir_tasks import *


def clean_device_data(device_info=nr.run(task=get_fortigate_device_info)) -> List[Dict]:
    """_summary_

    Args:
        device_info (_type_, optional): _description_. Defaults to nr.run(task=get_fortigate_device_info).

    Returns:
        Device data in a list of dictionaries
    """
    cleaned_data = []
    for device, multi_result in device_info.items():
        # Get the hostname, serial number, and model from the multi_result object
        hostname = multi_result[1].result["devices"]["fortigate"][0]["host_name"]
        serial_number = multi_result[1].result["devices"]["fortigate"][0]["serial"]
        model = multi_result[1].result["devices"]["fortigate"][0]["model"]
        firmware_version_major = multi_result[1].result["devices"]["fortigate"][0][
            "firmware_version_major"
        ]
        firmware_version_minor = multi_result[1].result["devices"]["fortigate"][0][
            "firmware_version_minor"
        ]
        firmware_version_patch = multi_result[1].result["devices"]["fortigate"][0][
            "firmware_version_patch"
        ]
        version = f"{firmware_version_major}.{firmware_version_minor}.{firmware_version_patch}"

        # Clean the data as necessary (e.g. remove leading/trailing whitespace)
        hostname = hostname.strip()
        serial_number = serial_number.strip()
        model = model.strip()
        version = version.strip()
        # Create a dictionary of the cleaned data
        cleaned_dict = {
            "hostname": hostname,
            "serial_number": serial_number,
            "model": model,
            "version": version,
        }

        # Append the dictionary to the cleaned_data list
        cleaned_data.append(cleaned_dict)
    return cleaned_data
