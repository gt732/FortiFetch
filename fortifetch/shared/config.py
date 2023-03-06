from pydantic import BaseSettings


class Settings(BaseSettings):
    FORTIFETCH_DB_HOSTNAME: str
    FORTIFETCH_DB_PORT: str
    FORTIFETCH_DB_PASSWORD: str
    FORTIFETCH_DB_NAME: str
    FORTIFETCH_DB_USERNAME: str
    FORTIFETCH_SCHEME: str
    FORTIFETCH_USERNAME: str
    FORTIFETCH_PASSWORD: str


settings = Settings()
