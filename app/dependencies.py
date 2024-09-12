from uuid import UUID
import aiosmtplib
from typing import Annotated

from fastapi import Form, HTTPException, Request, status, Depends

from pydantic import EmailStr
from sqlalchemy.ext.asyncio import AsyncSession

from .core.config import get_settings
from .crud.developers import authenticate_developer, Developer, get_developer_by_id
from .db.config import get_async_session


async def get_async_smtp():
    """
    Manage the SMTP connection by creating a new connection for each request.

    Raises:
        HTTPException: If there is an error connecting to the SMTP server, starting TLS, authenticating, or if any other SMTP exception occurs.

    Returns:
        async_smtp: An SMTP connection object.

    Example usage:
        ```
        async with get_async_smtp() as smtp:
            # Use the smtp connection for sending emails
        ```
    """
    async_smtp = aiosmtplib.SMTP(
        hostname=get_settings().smtp_host,
        port=get_settings().smtp_port,
        use_tls=False,
        start_tls=False,
    )
    try:
        await async_smtp.connect()
        await async_smtp.starttls()
        await async_smtp.login(get_settings().smtp_login, get_settings().smtp_password)
        yield async_smtp
    except aiosmtplib.SMTPConnectError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Could not connect to SMTP server", "error": str(e)},
        )
    except aiosmtplib.SMTPHeloError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Could not start TLS", "error": str(e)},
        )
    except aiosmtplib.SMTPAuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Could not authenticate", "error": str(e)},
        )
    except aiosmtplib.SMTPException as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "An error occurred", "error": str(e)},
        )
    finally:
        try:
            await async_smtp.quit()
        except Exception as e:
            # Handle or log the exception if quitting fails
            print(f"Failed to quit SMTP connection cleanly: {e}")


async def authenticate(
    email: Annotated[EmailStr, Form(title="Email")],
    password: Annotated[str, Form(title="Password")],
    async_session: Annotated[AsyncSession, Depends(get_async_session)],
) -> Developer | None:
    return await authenticate_developer(async_session, email, password)


async def get_developer(
    async_session: Annotated[AsyncSession, Depends(get_async_session)],
    request: Request,
) -> Developer | None:
    developer_id = request.session.get("developer_id")
    if not developer_id:
        return None
    return await get_developer_by_id(async_session, UUID(developer_id))
