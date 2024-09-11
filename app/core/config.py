from passlib.context import CryptContext

from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    allow_credentials: bool = True
    allowed_methods: list[str] = ["*"]
    allowed_origins: list[str] = ["*"]
    app_name: str = "Address Verification System API"
    app_version: str = "0.0.1"
    database_url: str = "sqlite:///./test.db"
    debug: bool = True
    from_email: str
    from_name: str
    otp_expiry_minutes: int = 5
    paypal_client_id: str
    paypal_secret: str
    secret_key: str
    session_expire_days: int = 7
    session_same_site: str = "lax"
    session_secret_key: str
    session_secure: bool = False
    smtp_host: str
    smtp_login: str
    smtp_password: str
    smtp_port: int

    class Config:
        env_file = ".env"


@lru_cache
def get_settings():
    return Settings()


password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
