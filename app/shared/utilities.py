"""
This module contains shared utilies over multiple
parts of the codebase, to prevention repetition
"""

import os
from nornir import InitNornir


def initialize_nornir():
    """
    Initializes Nornir and returns the Nornir object
    """
    NORNIR_CONFIG = os.getenv("NORNIR_CONFIG_PATH")
    nr = InitNornir(config_file=NORNIR_CONFIG)
    return nr


nr = initialize_nornir()
