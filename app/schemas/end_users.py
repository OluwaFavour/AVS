from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, HttpUrl, Field


class UserBase(BaseModel):
    email: EmailStr


class User(UserBase):
    model_config: ConfigDict = ConfigDict(from_attributes=True)
    id: UUID
    created_at: datetime
    updated_at: datetime

    security_questions: list["UserSecurityQuestion"]


class SecurityQuestionBase(BaseModel):
    question: str


class SecurityQuestionCreate(SecurityQuestionBase):
    pass


class SecurityQuestion(SecurityQuestionBase):
    model_config: ConfigDict = ConfigDict(from_attributes=True)
    id: UUID
    created_at: datetime


class UserSecurityQuestionBase(BaseModel):
    user_id: UUID
    security_question_id: UUID


class UserSecurityQuestion(UserSecurityQuestionBase):
    model_config: ConfigDict = ConfigDict(from_attributes=True)
    id: UUID
    created_at: datetime

    security_question: SecurityQuestion


class UserSecurityAnswerBase(BaseModel):
    user_security_question_id: UUID


class UserSecurityAnswerCreate(UserSecurityAnswerBase):
    answer: str


class UserSecurityAnswer(UserSecurityAnswerBase):
    model_config: ConfigDict = ConfigDict(from_attributes=True)
    id: UUID
    user_id: UUID
    created_at: datetime

    user_security_question: UserSecurityQuestion


class BillingAddressBase(BaseModel):
    address_line_1: Annotated[str, Field(max_length=300)]
    postal_code: Annotated[str, Field(max_length=10)]
    country_code: Annotated[str, Field(max_length=2, pattern=r"^([A-Z]{2}|C2)$")]


class BillingAddressCreate(BillingAddressBase):
    address_line_2: Annotated[str | None, Field(max_length=300)]
    city: Annotated[str, Field(max_length=120)]
    state: Annotated[str, Field(max_length=300)]


class CardBase(BaseModel):
    name: Annotated[str, Field(max_length=300)]
    number: Annotated[str, Field(max_length=19, min_length=13)]
    cvv: Annotated[str, Field(max_length=4, min_length=3)]
    expiry: Annotated[str, Field(pattern=r"^[0-9]{4}-(0[1-9]|1[0-2])$")]


class CardCreate(CardBase):
    return_url: HttpUrl
    cancel_url: HttpUrl


class SuspicionResponse(BaseModel):
    is_suspicious: bool
    suspicious_price: Decimal | None = None


class SuspicionInput(BaseModel):

    class PaymentMethod(str, Enum):
        bank_transfer = "bank_transfer"
        cash_on_delivery = "cash_on_delivery"
        debit_card = "debit_card"
        mobile_money = "mobile_money"
        paypal = "paypal"

    class DeviceType(str, Enum):
        desktop = "desktop"
        mobile = "mobile"
        tablet = "tablet"

    total_amount: float
    order_frequency: Annotated[
        int, Field(gt=0, description="Number of orders in the last 24 hours")
    ]
    history_of_addresses: Annotated[
        list[str], Field(description="List of addresses used in the past by the user")
    ]
    payment_method: Annotated[PaymentMethod, Field(description="Payment method used")]
    device_type: Annotated[DeviceType, Field(description="Device type used")]
