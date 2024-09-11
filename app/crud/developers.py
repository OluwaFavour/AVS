from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from ..db.models import Client, Developer


async def create_developer(
    session: AsyncSession, name: str, email: str, password: str
) -> Developer:
    new_developer = await Developer.create(name=name, email=email, password=password)
    session.add(new_developer)
    await session.commit()
    return new_developer


async def get_developer_by_email(session: AsyncSession, email: str) -> Developer | None:
    result = await session.execute(select(Developer).filter(Developer.email == email))
    return result.scalar_one_or_none()


async def authenticate_developer(
    session: AsyncSession, email: str, password: str
) -> Developer | None:
    developer = await get_developer_by_email(session, email)
    if not developer:
        return None
    if not developer.verify_password(password):
        return None
    return developer


async def get_developer_by_id(
    session: AsyncSession, developer_id: UUID
) -> Developer | None:
    result = await session.execute(
        select(Developer).filter(Developer.id == developer_id)
    )
    return result.scalar_one_or_none()


async def create_client(
    session: AsyncSession, developer_id: UUID, name: str
) -> tuple[Client, str]:
    new_client, secret = await Client.create(developer_id=developer_id, name=name)
    session.add(new_client)
    await session.commit()
    await session.refresh(new_client)
    return new_client, secret


async def get_client_by_id(
    session: AsyncSession, developer_id, client_id: UUID
) -> Client | None:
    result = await session.execute(
        select(Client).filter(
            Client.id == client_id, Client.developer_id == developer_id
        )
    )
    return result.scalar_one_or_none()


async def get_client_scopes_by_id(session: AsyncSession, client_id: UUID) -> list[str]:
    client = await get_client_by_id(session, client_id)
    if not client:
        return []
    return client.scopes


async def get_client_redirect_uris_by_id(
    session: AsyncSession, client_id: UUID
) -> list[str]:
    client = await get_client_by_id(session, client_id)
    if not client:
        return []
    return client.redirect_uris


async def get_clients_by_developer_id(
    session: AsyncSession, developer_id: UUID
) -> list[Client]:
    result = await session.execute(
        select(Client).filter(Client.developer_id == developer_id)
    )
    return result.scalars().all()
