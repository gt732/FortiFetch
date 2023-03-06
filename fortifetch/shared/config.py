from pydantic import BaseSettings

# import os


# os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Settings(BaseSettings):
    FORTIFETCH_DB_HOSTNAME: str
    FORTIFETCH_DB_PORT: str
    FORTIFETCH_DB_PASSWORD: str
    FORTIFETCH_DB_NAME: str
    FORTIFETCH_DB_USERNAME: str


settings = Settings()
