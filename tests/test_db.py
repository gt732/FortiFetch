from sqlalchemy.orm import Session
from fortifetch.db.db import get_db


def test_get_db():
    db = get_db()
    assert isinstance(db, Session)
    db.close()
