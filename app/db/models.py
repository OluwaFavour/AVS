from datetime import datetime, timedelta, timezone
import secrets
from uuid import uuid4, UUID

from email_validator import validate_email, EmailNotValidError

from fastapi import HTTPException
from sqlalchemy import ForeignKey, func, UniqueConstraint, String
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import mapped_column, relationship, Mapped, validates

from ..core.config import get_settings
from ..core.paypal import PayPalClient
from ..core.utils import hash_password, verify_password
from .config import Base
from .enums import EventType, LogLevel


class Developer(Base):
    __tablename__ = "developers"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(nullable=False)
    email: Mapped[str] = mapped_column(unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        default=func.now(), onupdate=func.now(), nullable=False
    )

    clients: Mapped[list["Client"]] = relationship(
        "Client", back_populates="developer", lazy="selectin"
    )

    @validates("email")
    def validate_email(self, key, email):
        try:
            validate_email(email)
        except EmailNotValidError as e:
            raise ValueError(str(e))
        return email

    @staticmethod
    async def create(name: str, email: str, password: str) -> "Developer":
        return Developer(name=name, email=email, password_hash=hash_password(password))

    async def verify_password(self, password: str) -> bool:
        return verify_password(password, self.password_hash)

    async def update_password(self, password: str) -> None:
        self.password_hash = hash_password(password)


class Client(Base):

    __tablename__ = "clients"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    developer_id: Mapped[UUID] = mapped_column(
        ForeignKey("developers.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(nullable=False)
    first_four: Mapped[str] = mapped_column(nullable=False)
    last_four: Mapped[str] = mapped_column(nullable=False)
    hashed_secret: Mapped[str] = mapped_column(nullable=False)
    redirect_uris: Mapped[list[str] | None] = mapped_column(
        ARRAY(String), nullable=True
    )
    scopes: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True)
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        default=func.now(), onupdate=func.now(), nullable=False
    )

    developer: Mapped[Developer] = relationship("Developer", back_populates="clients")
    security_questions: Mapped[list["SecurityQuestion"]] = relationship(
        "SecurityQuestion", back_populates="client", lazy="selectin"
    )

    @staticmethod
    async def create(
        developer_id: UUID,
        name: str,
        redirect_uris: list[str] | None = None,
        scopes: list[str] | None = None,
    ) -> tuple["Client", str]:
        secret = secrets.token_urlsafe(32)
        hashed_secret = hash_password(secret)
        input = {
            "developer_id": developer_id,
            "name": name,
            "hashed_secret": hashed_secret,
        }
        if redirect_uris:
            input["redirect_uris"] = redirect_uris
        if scopes:
            input["scopes"] = scopes
        return (
            Client(**input, first_four=secret[:4], last_four=secret[-4:]),
            secret,
        )

    async def update_secret(self) -> str:
        secret = secrets.token_urlsafe(32)
        self.hashed_secret = hash_password(secret)
        self.first_four = secret[:4]
        self.last_four = secret[-4:]
        return secret

    async def verify_secret(self, secret: str) -> bool:
        return verify_password(secret, self.hashed_secret)

    async def get_secret_plain(self) -> str:
        return self.first_four + "*" * 24 + self.last_four


class Log(Base):
    __tablename__ = "logs"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    developer_id: Mapped[UUID] = mapped_column(
        ForeignKey("developers.id", ondelete="CASCADE"), nullable=False, index=True
    )
    message: Mapped[str] = mapped_column(nullable=False)
    level: Mapped[LogLevel] = mapped_column(nullable=False, index=True)
    event_type: Mapped[EventType] = mapped_column(
        nullable=False, index=True
    )  # e.g., AUTHENTICATION, TRANSACTION
    ip_address: Mapped[str] = mapped_column(nullable=True)
    user_agent: Mapped[str] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=func.now(), nullable=False)

    developer: Mapped[Developer] = relationship("Developer")


class User(Base):
    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    client_id: Mapped[UUID] = mapped_column(
        ForeignKey("clients.id", ondelete="CASCADE"), nullable=False, index=True
    )
    email: Mapped[str] = mapped_column(unique=True, index=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        default=func.now(), onupdate=func.now(), nullable=False
    )

    security_questions: Mapped[list["UserSecurityQuestion"]] = relationship(
        "UserSecurityQuestion", back_populates="user", lazy="selectin"
    )
    security_answers: Mapped[list["UserSecurityAnswer"]] = relationship(
        "UserSecurityAnswer", back_populates="user", lazy="selectin"
    )
    client: Mapped[Client] = relationship("Client")
    otps: Mapped["OTP"] = relationship("OTP", back_populates="user")
    transactions: Mapped[list["Transaction"]] = relationship(
        "Transaction", back_populates="user"
    )

    @validates("email")
    def validate_email(self, key, email):
        try:
            validate_email(email)
        except EmailNotValidError as e:
            raise ValueError(str(e))
        return email

    @staticmethod
    async def create(email: str) -> "User":
        return User(email=email)


class OTP(Base):
    __tablename__ = "otps"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    otp_hash: Mapped[str] = mapped_column(nullable=False)
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=func.now(), nullable=False)

    user: Mapped[User] = relationship("User", back_populates="otps")

    @staticmethod
    async def create(user_id: UUID, otp: str) -> "OTP":
        otp_hash = hash_password(otp)
        return OTP(user_id=user_id, otp_hash=otp_hash)

    async def verify_otp(self, otp: str) -> bool:
        if not self.is_active:
            return False
        is_correct = verify_password(otp, self.otp_hash)

        expiry_minutes = get_settings().otp_expiry_minutes
        is_expired = (
            timedelta(minutes=expiry_minutes)
            < datetime.now(timezone.utc) - self.created_at
        )

        if is_correct and not is_expired:
            self.is_active = False
            return True

    async def update_otp(self, otp: str) -> None:
        self.otp_hash = hash_password(otp)
        self.created_at = datetime.now(timezone.utc)
        self.is_active = True


class SecurityQuestion(Base):
    __tablename__ = "security_questions"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    client_id: Mapped[UUID] = mapped_column(
        ForeignKey("clients.id", ondelete="CASCADE"), nullable=False, index=True
    )
    question: Mapped[str] = mapped_column(unique=True, index=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=func.now(), nullable=False)

    client: Mapped[Client] = relationship("Client", back_populates="security_questions")

    @staticmethod
    async def create(client_id: UUID, question: str) -> "SecurityQuestion":
        return SecurityQuestion(client_id=client_id, question=question)


class UserSecurityQuestion(Base):
    __tablename__ = "user_security_questions"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    security_question_id: Mapped[UUID] = mapped_column(
        ForeignKey("security_questions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(default=func.now(), nullable=False)

    user: Mapped[User] = relationship("User", back_populates="security_questions")
    security_question: Mapped["SecurityQuestion"] = relationship("SecurityQuestion")
    user_security_answers: Mapped[list["UserSecurityAnswer"]] = relationship(
        "UserSecurityAnswer", back_populates="user_security_question", lazy="selectin"
    )

    __table_args__ = (
        UniqueConstraint(
            "user_id", "security_question_id", name="uq_user_security_question"
        ),
    )

    @staticmethod
    async def create(
        user_id: UUID, security_question_id: UUID
    ) -> "UserSecurityQuestion":
        return UserSecurityQuestion(
            user_id=user_id, security_question_id=security_question_id
        )


class UserSecurityAnswer(Base):
    __tablename__ = "user_security_answers"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_security_question_id: Mapped[UUID] = mapped_column(
        ForeignKey("user_security_questions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    answer_hash: Mapped[str] = mapped_column(nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=func.now(), nullable=False)

    user: Mapped[User] = relationship("User", back_populates="security_answers")
    user_security_question: Mapped[UserSecurityQuestion] = relationship(
        "UserSecurityQuestion"
    )

    __table_args__ = (
        UniqueConstraint(
            "user_id", "user_security_question_id", name="uq_user_security_answer"
        ),
    )

    @staticmethod
    async def create(
        user_id: UUID, user_security_question_id: UUID, answer: str
    ) -> "UserSecurityAnswer":
        return UserSecurityAnswer(
            user_id=user_id,
            user_security_question_id=user_security_question_id,
            answer_hash=hash_password(answer),
        )

    async def verify_answer(self, answer: str) -> bool:
        return verify_password(answer, self.answer_hash)

    async def update_answer(self, answer: str) -> None:
        self.answer_hash = hash_password(answer)


class Transaction(Base):
    __tablename__ = "transactions"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    paypal_order_id: Mapped[str] = mapped_column(nullable=True)
    amount: Mapped[float] = mapped_column(nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=func.now(), nullable=False)

    user: Mapped[User] = relationship("User", back_populates="transactions")

    @staticmethod
    async def create(user_id: UUID, amount: float) -> tuple["Transaction", str]:
        client = PayPalClient()
        id, approval_url = await client.create_order(amount=amount)
        return (
            Transaction(
                user_id=user_id,
                amount=amount,
                paypal_order_id=id,
            ),
            approval_url,
        )
