import sys
import os

# Get path of the current dir under which the file is executed.
dirname = os.path.dirname(__file__)
# Append sys path so that local relative imports can work.
sys.path.append(os.path.join(dirname, ".."))


from typing import Dict, List
from fortigate_api import Fortigate
from fortifetch.tasks.fgt_tasks import get_fortigate_data
import pytest
import yaml


def test_get_fortigate_data(mock_fortigate):
    inventory_file = "test_inventory.yaml"
    inventory = [
        {"host": "host1", "hostname": "hostname1"},
        {"host": "host2", "hostname": "hostname2"},
    ]
    with open(inventory_file, "w") as f:
        yaml.dump(inventory, f)

    data = get_fortigate_data("some-url", inventory_file=inventory_file)

    assert len(data) == 2
    assert data[0] == {"hostname1": {"some": "data"}}
    assert data[1] == {"hostname2": {"some": "data"}}
