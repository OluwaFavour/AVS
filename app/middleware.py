from typing import Callable
from fastapi import FastAPI, Request, status, HTTPException
from fastapi.responses import JSONResponse

from starlette.middleware.base import BaseHTTPMiddleware

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from .db.config import get_async_session
from .db.models import Client


class ClientVerificationMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: FastAPI):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Callable):
        # Only process HTTP requests
        if (
            request.scope["type"] == "http"
            and request.scope["path"].split("/api/v1/end_users")[0] == ""
        ):
            client_id = request.headers.get("Client-Id")
            client_secret = request.headers.get("Authorization")

            if not client_secret:
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"detail": "Missing client secret."},
                )

            async with get_async_session() as session:
                client = await self.get_client(session, client_id)

                if not client:
                    return JSONResponse(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        content={"detail": "Invalid client secret."},
                    )

                if not await client.verify_secret(client_secret):
                    return JSONResponse(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        content={"detail": "Invalid client secret."},
                    )

                # Attach client and developer to request.state for use in views
                request.state.client = client
                request.state.developer = client.developer

        response = await call_next(request)
        return response

    async def get_client(self, session: AsyncSession, client_id: str) -> Client | None:
        result = await session.execute(select(Client).filter(Client.id == client_id))
        return result.scalar_one_or_none()
