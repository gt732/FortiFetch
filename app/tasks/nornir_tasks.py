"""
This module contains all the nornir tasks functions
which are used to retreive information from the fortigate.
"""


# import os sys
import os
import sys

# Add the parent directory of 'app' to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# import modules
from nornir.core.task import Result
from nornir_pyfgt.plugins.tasks import pyfgt_get_url
from typing import Union, Dict, Optional
from nornir_utils.plugins.functions import print_result
from shared.utilities import nr


def get_fortigate_device_info(task) -> Result:
    """
    Get the fortigate device information

    Returns:
        Result: The result of the task

    """
    task.run(task=pyfgt_get_url, url="/api/v2/monitor/system/csf")

    return Result(
        name="get_fortigate_device_info", host=task.host, result=task.host.result
    )
