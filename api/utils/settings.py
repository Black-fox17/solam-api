from pydantic_settings import BaseSettings
from decouple import config
from pathlib import Path


# Use this to build paths inside the project
BASE_DIR = Path(__file__).resolve().parent

class Settings(BaseSettings):
    """Class to hold application's config values."""

    SECRET_KEY: str = config("SECRET_KEY")
    ALGORITHM: str = config("ALGORITHM")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = config("ACCESS_TOKEN_EXPIRE_MINUTES")
    JWT_REFRESH_EXPIRY: int = config("JWT_REFRESH_EXPIRY")

    DB_HOST: str = config("DB_HOST", default="localhost")
    DB_PORT: int = config("DB_PORT", default=5432)
    DB_USER: str = config("DB_USER", default="postgres")
    DB_PASSWORD: str = config("DB_PASSWORD", default="postgres")
    DB_NAME: str = config("DB_NAME", default="postgres")
    DB_TYPE: str = config("DB_TYPE", default="postgresql")
    COOKIE_DOMAIN: str = config("COOKIE_DOMAIN", default="")

settings = Settings()
