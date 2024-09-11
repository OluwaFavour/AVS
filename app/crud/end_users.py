from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from ..db.models import (
    OTP,
    SecurityQuestion,
    Transaction,
    User,
    UserSecurityAnswer,
    UserSecurityQuestion,
)


async def create_end_user(async_session: AsyncSession, email: str) -> User:
    """
    Create a new end user.

    Args:
        async_session (AsyncSession): An async session object.
        email (str): The email address of the end user.

    Returns:
        User: The newly created end user.
    """
    user = await User.create(email=email)
    async_session.add(user)
    await async_session.commit()
    await async_session.refresh(user)
    return user


async def get_end_user_by_email(async_session: AsyncSession, email: str) -> User | None:
    """
    Get an end user by email.

    Args:
        async_session (AsyncSession): An async session object.
        email (str): The email address of the end user.

    Returns:
        User | None: The end user if found, otherwise None.
    """
    query = select(User).filter(User.email == email)
    result = await async_session.execute(query)
    return result.scalar_one_or_none()


async def get_end_user_by_id(async_session: AsyncSession, id: UUID) -> User | None:
    """
    Get an end user by id.

    Args:
        async_session (AsyncSession): An async session object.
        id (UUID): The id of the end user.

    Returns:
        User | None: The end user if found, otherwise None.
    """
    query = select(User).filter(User.id == id)
    result = await async_session.execute(query)
    return result.scalar_one_or_none()


async def get_end_user_security_answer(
    async_session: AsyncSession, user_id: UUID, security_question_id: UUID
) -> UserSecurityAnswer | None:
    """
    Get a user security answer.

    Args:
        async_session (AsyncSession): An async session object.
        user_id (UUID): The id of the end user.
        security_question_id (UUID): The id of the security question.

    Returns:
        UserSecurityAnswer | None: The user security answer if found, otherwise None.
    """
    query = select(UserSecurityAnswer).filter(
        UserSecurityAnswer.user_id == user_id,
        UserSecurityAnswer.security_question_id == security_question_id,
    )
    result = await async_session.execute(query)
    return result.scalar_one_or_none()


async def get_existing_security_answers(
    async_session: AsyncSession, user_id: UUID, question_ids: list[UUID]
) -> list[UserSecurityAnswer]:
    """
    Get existing security answers for a user and security questions.

    Args:
        async_session (AsyncSession): An async session object.
        user_id (UUID): The id of the end user.
        question_ids (list[UUID]): The ids of the security questions.

    Returns:
        list[UserSecurityAnswer]: The existing security answers.
    """
    query = select(UserSecurityAnswer).filter(
        UserSecurityAnswer.user_id == user_id,
        UserSecurityAnswer.security_question_id.in_(question_ids),
    )
    result = await async_session.execute(query)
    return result.scalars().all()


async def get_security_question_by_id(
    async_session: AsyncSession, id: UUID
) -> SecurityQuestion | None:
    """
    Get a security question by id.

    Args:
        async_session (AsyncSession): An async session object.
        id (UUID): The id of the security question.

    Returns:
        SecurityQuestion | None: The security question if found, otherwise None.
    """
    query = select(SecurityQuestion).filter(SecurityQuestion.id == id)
    result = await async_session.execute(query)
    return result.scalar_one_or_none()


async def get_security_questions_by_ids(
    async_session: AsyncSession, ids: list[UUID]
) -> list[SecurityQuestion]:
    """
    Get security questions by ids.

    Args:
        async_session (AsyncSession): An async session object.
        ids (list[UUID]): The ids of the security questions.

    Returns:
        list[SecurityQuestion]: The security questions.
    """
    query = select(SecurityQuestion).filter(SecurityQuestion.id.in_(ids))
    result = await async_session.execute(query)
    return result.scalars().all()


async def get_user_security_question(
    async_session: AsyncSession, user_id: UUID, security_question_id: UUID
) -> UserSecurityQuestion | None:
    """
    Get a user security question.

    Args:
        async_session (AsyncSession): An async session object.
        user_id (UUID): The id of the end user.
        security_question_id (UUID): The id of the security question.

    Returns:
        UserSecurityQuestion | None: The user security question if found, otherwise None.
    """
    query = select(UserSecurityQuestion).filter(
        UserSecurityQuestion.user_id == user_id,
        UserSecurityQuestion.security_question_id == security_question_id,
    )
    result = await async_session.execute(query)
    return result.scalar_one_or_none()


async def create_user_security_question(
    async_session: AsyncSession, user_id: UUID, security_question_id: UUID
) -> UserSecurityQuestion:
    """
    Create a new user security question.

    Args:
        async_session (AsyncSession): An async session object.
        user_id (UUID): The id of the end user.
        security_question_id (UUID): The id of the security question.

    Returns:
        UserSecurityQuestion: The newly created user security question.
    """
    user_security_question = await UserSecurityQuestion.create(
        user_id=user_id, security_question_id=security_question_id
    )
    async_session.add(user_security_question)
    await async_session.commit()
    await async_session.refresh(user_security_question)
    return user_security_question


async def get_user_security_questions(
    async_session: AsyncSession, user_id: UUID
) -> list[UserSecurityQuestion]:
    """
    Get user security questions.

    Args:
        async_session (AsyncSession): An async session object.
        user_id (UUID): The id of the end user.

    Returns:
        list[UserSecurityQuestion]: The user security questions.
    """
    query = select(UserSecurityQuestion).filter(UserSecurityQuestion.user_id == user_id)
    result = await async_session.execute(query)
    return result.scalars().all()


async def create_user_security_answer(
    async_session: AsyncSession,
    user_id: UUID,
    user_security_question_id: UUID,
    answer: str,
) -> UserSecurityAnswer:
    """
    Create a new user security answer.

    Args:
        async_session (AsyncSession): An async session object.
        user_id (UUID): The id of the end user.
        user_security_question_id (UUID): The id of the user security question.
        answer (str): The answer to the security question.

    Returns:
        UserSecurityAnswer: The newly created user security answer.
    """
    user_security_answer = await UserSecurityAnswer.create(
        user_id=user_id,
        user_security_question_id=user_security_question_id,
        answer=answer,
    )
    async_session.add(user_security_answer)
    await async_session.commit()
    await async_session.refresh(user_security_answer)
    return user_security_answer


async def create_otp(async_session: AsyncSession, user_id: UUID, otp: str) -> str:
    """
    Create a new OTP for the user or update the existing one.

    Args:
        async_session (AsyncSession): An async session object.
        user_id (UUID): The id of the end user.
        otp (str): The OTP to be hashed and stored.

    Returns:
        str: The generated OTP.
    """
    try:
        # Fetch existing OTP for the user
        existing_otp = await get_otp(async_session, user_id)

        if existing_otp:
            # Update existing OTP
            existing_otp.update_otp(otp)
            await async_session.commit()
            await async_session.refresh(existing_otp)
        else:
            # Create new OTP
            otp_instance = OTP.create(user_id=user_id, otp=otp)
            await async_session.commit()
            await async_session.refresh(otp_instance)

        # Return the OTP
        return otp

    except Exception as e:
        # Rollback in case of error
        await async_session.rollback()
        raise e


async def get_otp(async_session: AsyncSession, user_id: UUID) -> OTP | None:
    """
    Get the OTP for the user.

    Args:
        async_session (AsyncSession): An async session object.
        user_id (UUID): The id of the end user.

    Returns:
        OTP | None: The OTP if found, otherwise None.
    """
    query = select(OTP).filter(OTP.user_id == user_id)
    result = await async_session.execute(query)
    return result.scalar_one_or_none()


async def verify_otp(async_session: AsyncSession, otp: OTP) -> bool:
    """
    Verify the OTP for the user.

    Args:
        async_session (AsyncSession): An async session object.
        otp (OTP): The OTP instance to be verified.

    Returns:
        bool: True if the OTP is valid, otherwise False.
    """
    is_verified = otp.verify_otp()
    await async_session.commit()
    await async_session.refresh(otp)
    return is_verified


async def create_transaction(
    async_session: AsyncSession, user_id: UUID, amount: float
) -> tuple[Transaction, str]:
    """
    Create a new transaction for the user.

    Args:
        async_session (AsyncSession): An async session object.
        user_id (UUID): The id of the end user.
        amount (float): The amount of the transaction.

    Returns:
        tuple[Transaction, str]: The newly created transaction and the approval URL
    """
    # Create a new transaction
    transaction, approval_url = Transaction.create(user_id=user_id, amount=amount)
    async_session.add(transaction)
    await async_session.commit()
    await async_session.refresh(transaction)
    return transaction, approval_url
