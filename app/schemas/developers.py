from datetime import datetime
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class DeveloperBase(BaseModel):
    name: str
    email: EmailStr


class DeveloperCreate(DeveloperBase):
    password: str


class Developer(DeveloperBase):
    model_config: ConfigDict = ConfigDict(from_attributes=True)
    id: UUID
    created_at: datetime
    updated_at: datetime


class SignUpResponse(BaseModel):
    model_config: ConfigDict = ConfigDict(from_attributes=True)
    developer: Developer
    client_id: UUID
    client_secret: Annotated[
        str,
        Field(
            title="Client Secret",
            description="The secret for the client. It is important to keep this secret as it can only be seen once or regenerated.",
        ),
    ]


class ClientBase(BaseModel):
    name: str


class Client(ClientBase):
    model_config: ConfigDict = ConfigDict(from_attributes=True)
    id: UUID
    developer_id: UUID
    first_four: str
    last_four: str
    redirect_uris: list[str] | None = None
    scopes: list[str] | None = None
    created_at: datetime
    updated_at: datetime


class ClientCreateResponse(BaseModel):
    model_config: ConfigDict = ConfigDict(from_attributes=True)
    client: Client
    client_secret: Annotated[
        str,
        Field(
            title="Client Secret",
            description="The secret for the client. It is important to keep this secret as it can only be seen once or regenerated.",
        ),
    ]
