import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from shared.config import settings
from db.models import Base
from sqlalchemy.orm import Session


SQLALCHEMY_DATABASE_URL = f"postgresql://{settings.FORTIFETCH_DB_USERNAME}:{settings.FORTIFETCH_DB_PASSWORD}@{settings.FORTIFETCH_DB_HOSTNAME}:{settings.FORTIFETCH_DB_PORT}/{settings.FORTIFETCH_DB_NAME}"

engine = create_engine(SQLALCHEMY_DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


Base.metadata.create_all(bind=engine)


def get_db() -> Session:
    db = SessionLocal()
    try:
        return db
    finally:
        db.close()
