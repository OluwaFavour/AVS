from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Path, Request, status, HTTPException, Body

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Client, Developer

from ..crud.developers import (
    create_client,
    create_developer,
    get_client_by_id,
    get_developer_by_id,
)
from ..db.config import get_async_session
from ..dependencies import authenticate_developer, get_developer

from ..schemas.developers import (
    Client as ClientSchema,
    ClientCreateResponse,
    DeveloperCreate as DeveloperCreateSchema,
    Developer as DeveloperSchema,
    SignUpResponse,
)


router = APIRouter(
    prefix="/developers",
    tags=["developers"],
)


@router.post("/", response_model=SignUpResponse, status_code=status.HTTP_201_CREATED)
async def create_developer_route(
    developer_data: Annotated[DeveloperCreateSchema, Body(title="Developer")],
    async_session: Annotated[AsyncSession, Depends(get_async_session)],
) -> SignUpResponse:
    try:
        developer = await create_developer(async_session, **developer_data.model_dump())
        client, secret = await create_client(
            async_session, developer.id, developer.name
        )
        return SignUpResponse(
            developer=developer, client_id=client.id, client_secret=secret
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        )


@router.post("/login", status_code=status.HTTP_200_OK, response_model=DeveloperSchema)
async def login_route(
    developer: Annotated[Developer | None, Depends(authenticate_developer)],
    request: Request,
):
    if not developer:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )
    request.session["developer_id"] = str(developer.id)
    return developer


@router.post("/change-password", status_code=status.HTTP_200_OK)
async def change_password_route(
    developer: Annotated[Developer | None, Depends(get_developer)],
    password: Annotated[str, Body(title="New Password")],
    async_session: Annotated[AsyncSession, Depends(get_async_session)],
) -> None:
    if not developer:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="You are not authorized"
        )
    developer.update_password(password)
    await async_session.commit()
    await async_session.refresh(developer)
    return None


@router.get("/", response_model=DeveloperSchema, status_code=status.HTTP_200_OK)
async def get_developer_route(
    developer: Annotated[Developer | None, Depends(get_developer)],
    async_session: Annotated[AsyncSession, Depends(get_async_session)],
) -> DeveloperSchema:
    if not developer:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="You are not authorized"
        )
    developer = await get_developer_by_id(async_session, developer.id)
    if not developer:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Developer not found"
        )
    return developer


@router.post(
    "/client", response_model=ClientCreateResponse, status_code=status.HTTP_201_CREATED
)
async def create_client_route(
    developer: Annotated[Developer | None, Depends(get_developer)],
    name: Annotated[str, Body(title="Client Name")],
    async_session: Annotated[AsyncSession, Depends(get_async_session)],
) -> ClientCreateResponse:
    if not developer:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="You are not authorized"
        )
    client, secret = await create_client(async_session, developer.id, name)
    return ClientCreateResponse(client=client, client_secret=secret)


@router.get(
    "/client/{client_id}", response_model=ClientSchema, status_code=status.HTTP_200_OK
)
async def get_client_route(
    developer: Annotated[Developer | None, Depends(get_developer)],
    async_session: Annotated[AsyncSession, Depends(get_async_session)],
    client_id: Annotated[UUID, Path(title="Client ID")],
) -> ClientSchema:
    if not developer:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="You are not authorized"
        )
    client = await get_client_by_id(async_session, developer.id, client_id)
    return client


@router.post(
    "/client/{client_id}/secret",
    response_model=ClientCreateResponse,
    status_code=status.HTTP_200_OK,
)
async def regenerate_client_secret_route(
    developer: Annotated[Developer | None, Depends(get_developer)],
    client_id: Annotated[UUID, Path(title="Client ID")],
    async_session: Annotated[AsyncSession, Depends(get_async_session)],
) -> ClientCreateResponse:
    if not developer:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="You are not authorized"
        )
    client = await get_client_by_id(async_session, developer.id, client_id)
    if not client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Client not found"
        )
    secret = client.update_secret()
    await async_session.commit()
    await async_session.refresh(client)
    return ClientCreateResponse(client=client, client_secret=secret)
