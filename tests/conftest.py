# tests/conftest.py
import pytest
from fortigate_api import Fortigate


class FakeFortigate:
    def __init__(self, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def login(self):
        pass

    def logout(self):
        pass

    def get(self, url):
        # Return some fake data
        return {"some": "data"}


@pytest.fixture()
def mock_fortigate(monkeypatch):
    """Mock Fortigate."""
    monkeypatch.setattr(
        Fortigate, "__new__", lambda cls, *args, **kwargs: FakeFortigate()
    )
