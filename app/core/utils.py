from decimal import Decimal
import secrets

from .config import password_context


def hash_password(password: str) -> str:
    return password_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return password_context.verify(plain_password, hashed_password)


async def generate_otp() -> str:
    """
    Generates a random OTP (One-Time Password) consisting of 6 alphanumeric characters.

    Returns:
        str: The generated OTP.
    """
    return "".join(
        secrets.choice("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(6)
    )
