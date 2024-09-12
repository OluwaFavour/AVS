from decimal import Decimal
from typing import Annotated
from uuid import UUID

from aiosmtplib import SMTP
from fastapi import Depends, APIRouter, Request, status, Path, Body, HTTPException

from fastapi.responses import JSONResponse
import httpx
from pydantic import EmailStr

from sqlalchemy.ext.asyncio import AsyncSession

from ..core.check_suspicion import check_suspicious_activity_in_price
from ..core.endpoint import process_new_data, predict
from ..core.messages import send_email
from ..core.paypal import AVS_CODE_MAP, PayPalClient
from ..core.utils import generate_otp
from ..dependencies import get_async_smtp

from ..db.config import get_async_session
from ..db.models import (
    Client,
    UserSecurityAnswer,
    SecurityQuestion,
    UserSecurityQuestion,
)
from ..crud.end_users import (
    create_end_user,
    create_otp,
    create_transaction,
    create_user_security_answer,
    create_user_security_question,
    get_end_user_by_email,
    get_end_user_by_id,
    get_end_user_security_answer,
    get_existing_security_answers,
    get_otp,
    get_security_question_by_id,
    get_security_questions_by_ids,
    get_user_security_question,
    get_user_security_questions,
    verify_otp,
)
from ..schemas.end_users import (
    BillingAddressCreate as BillingAddressCreateSchema,
    CardCreate as CardCreateSchema,
    User as UserSchema,
    SecurityQuestionCreate as SecurityQuestionCreateSchema,
    SecurityQuestion as SecurityQuestionSchema,
    UserSecurityQuestion as UserSecurityQuestionSchema,
    UserSecurityAnswerCreate as UserSecurityAnswerCreateSchema,
    UserSecurityAnswer as UserSecurityAnswerSchema,
    SuspicionResponse,
    SuspicionInput,
)


router = APIRouter(
    prefix="/api/v1/end_users",
    tags=["end_users"],
    responses={
        status.HTTP_401_UNAUTHORIZED: {
            "description": "Missing secret",
            "content": {
                "application/json": {"example": {"detail": "Missing client secret."}},
            },
        }
    },
)


@router.post("/create", status_code=status.HTTP_201_CREATED, response_model=UserSchema)
async def create_end_user_route(
    email: Annotated[
        EmailStr, Body(title="Email", description="The email address of the end user.")
    ],
    async_session: Annotated[AsyncSession, Depends(get_async_session)],
) -> UserSchema:
    """
    Create a new end user/customer. This customer will be used during the verification process.
    """
    user = await create_end_user(async_session, email)
    return user


@router.get("/get_by_email", response_model=UserSchema, status_code=status.HTTP_200_OK)
async def get_end_user_by_email_route(
    email: Annotated[
        EmailStr, Body(title="Email", description="The email address of the end user.")
    ],
    async_session: Annotated[AsyncSession, Depends(get_async_session)],
) -> UserSchema:
    """
    Get an end user by email.
    """
    user = await get_end_user_by_email(async_session, email)
    return user


@router.get("/{id}/", response_model=UserSchema, status_code=status.HTTP_200_OK)
async def get_end_user_by_id_route(
    id: Annotated[UUID, Path(title="ID", description="The id of the end user.")],
    async_session: Annotated[AsyncSession, Depends(get_async_session)],
) -> UserSchema:
    """
    Get an end user by id.
    """
    user = await get_end_user_by_id(async_session, id)
    return user


@router.post("/add_security_question", status_code=status.HTTP_201_CREATED)
async def add_security_question_route(
    security_question: Annotated[
        SecurityQuestionCreateSchema,
        Body(
            title="Security Question",
        ),
    ],
    async_session: Annotated[AsyncSession, Depends(get_async_session)],
    request: Request,
) -> SecurityQuestionSchema:
    """
    Add a security question to the client account.
    """
    client: Client = request.state.client

    question = SecurityQuestion.create(
        client_id=client.id, question=security_question.question
    )
    await async_session.commit()

    return question


@router.get(
    "/get_security_questions",
    response_model=list[SecurityQuestionSchema],
    status_code=status.HTTP_200_OK,
)
async def get_security_questions_route(
    request: Request,
) -> list[SecurityQuestionSchema]:
    """
    Get the security questions for the client account.
    """
    client: Client = request.state.client

    questions = client.security_questions
    return questions


@router.get(
    "/check_suspicious_acitivity_in_transaction",
    status_code=status.HTTP_200_OK,
)
async def check_suspicious_acitivity_in_transaction_route(
    input_data: Annotated[SuspicionInput, Body(title="Suspicion Input")],
):
    """
    Check for suspicious activity in the transaction prices.
    """
    processed_data = process_new_data(**input_data.model_dump())
    prediction = predict(processed_data)
    return JSONResponse(status_code=status.HTTP_200_OK, content=prediction)


# @router.get(
#     "/check_suspicious_acitivity_in_transaction",
#     status_code=status.HTTP_200_OK,
#     response_model=SuspicionResponse,
# )
# async def check_suspicious_acitivity_in_transaction_route(
#     old_transaction_prices: Annotated[
#         list[Decimal],
#         Body(
#             title="Old Transaction Prices",
#             description="The old transaction prices.",
#         ),
#     ],
#     new_transaction_prices: Annotated[
#         list[Decimal],
#         Body(
#             title="New Transaction Prices",
#             description="The new transaction prices.",
#         ),
#     ],
# ) -> SuspicionResponse:
#     """
#     Check for suspicious activity in the transaction prices.
#     """
#     suspicion, suspicious_price = check_suspicious_activity_in_price(
#         old_transaction_prices, new_transaction_prices
#     )
#     return SuspicionResponse(is_suspicious=suspicion, suspicious_price=suspicious_price)


@router.delete("/{id}/delete_security_question", status_code=status.HTTP_204_NO_CONTENT)
async def delete_security_question_route(
    id: Annotated[
        UUID, Path(title="ID", description="The id of the security question.")
    ],
    async_session: Annotated[AsyncSession, Depends(get_async_session)],
) -> None:
    """
    Delete a security question.
    """
    if (question := await get_security_question_by_id(async_session, id)) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "Security question not found."},
        )
    await async_session.delete(question)
    await async_session.commit()


@router.post(
    "/{user_id}/add_user_security_question",
    status_code=status.HTTP_201_CREATED,
    response_model=UserSecurityQuestionSchema,
)
async def add_user_security_question_route(
    user_id: Annotated[UUID, Path(title="ID", description="The id of the end user.")],
    security_question_id: Annotated[
        UUID,
        Body(
            title="Security Question ID",
            description="The id of the security question.",
        ),
    ],
    async_session: Annotated[AsyncSession, Depends(get_async_session)],
) -> UserSecurityQuestionSchema:
    """
    Add a security question to an end user.
    """
    user = await get_end_user_by_id(async_session, user_id)
    question = await get_security_question_by_id(async_session, security_question_id)

    if question is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "Security question not found."},
        )

    user_security_question = await get_user_security_question(
        async_session, user.id, question.id
    )

    if user_security_question:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "Security question already exists for the user."},
        )

    user_security_question = await create_user_security_question(
        async_session, user.id, question.id
    )

    return user_security_question


@router.get(
    "/{user_id}/get_user_security_questions",
    response_model=list[UserSecurityQuestionSchema],
    status_code=status.HTTP_200_OK,
)
async def get_user_security_questions_route(
    user_id: Annotated[
        UUID, Path(title="User ID", description="The id of the end user.")
    ],
    async_session: Annotated[AsyncSession, Depends(get_async_session)],
) -> list[UserSecurityQuestionSchema]:
    """
    Get the security questions for an end user.
    """
    user = await get_end_user_by_id(async_session, user_id)
    return user.security_questions


@router.post(
    "/{user_id}/add_user_security_answer",
    status_code=status.HTTP_201_CREATED,
    response_model=UserSecurityAnswerSchema,
)
async def add_user_security_answer_route(
    user_id: Annotated[
        UUID, Path(title="User ID", description="The id of the end user.")
    ],
    user_security_answer: Annotated[
        UserSecurityAnswerCreateSchema,
        Body(
            title="User Security Answer",
            description="The security answer for the end user.",
        ),
    ],
    async_session: Annotated[AsyncSession, Depends(get_async_session)],
) -> list[UserSecurityAnswerSchema]:
    """
    Add the security answers for an end user.
    """
    user = await get_end_user_by_id(async_session, user_id)

    user_security_question = await get_user_security_question(
        async_session, user.id, user_security_answer.user_security_question_id
    )
    if user_security_question is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "Security question not found for the user."},
        )

    # Check if the user already has an answer for the security question
    existing_answer = await get_end_user_security_answer(
        async_session, user.id, user_security_question.security_question_id
    )
    if existing_answer:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "Security answer already exists for the user. Update the answer instead."
            },
        )

    db_user_security_answer = await create_user_security_answer(
        async_session,
        user.id,
        user_security_question.security_question_id,
        user_security_answer.answer,
    )
    return db_user_security_answer


@router.put(
    "/{user_id}/update_user_security_answer",
    status_code=status.HTTP_200_OK,
    response_model=UserSecurityAnswerSchema,
)
async def update_user_security_answer_route(
    user_id: Annotated[
        UUID, Path(title="User ID", description="The id of the end user.")
    ],
    user_security_answer: Annotated[
        UserSecurityAnswerCreateSchema,
        Body(
            title="User Security Answer",
            description="The security answer for the end user.",
        ),
    ],
    async_session: Annotated[AsyncSession, Depends(get_async_session)],
) -> UserSecurityAnswerSchema:
    """
    Update the security answer for an end user.
    """
    user = await get_end_user_by_id(async_session, user_id)

    user_security_question = await get_user_security_question(
        async_session, user.id, user_security_answer.user_security_question_id
    )
    if user_security_question is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "Security question not found for the user."},
        )

    db_user_security_answer = await get_end_user_security_answer(
        async_session, user.id, user_security_question.security_question_id
    )
    if db_user_security_answer is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "Security answer not found for the user."},
        )

    db_user_security_answer.update_answer(user_security_answer.answer)
    await async_session.commit()

    return db_user_security_answer


@router.post("/{user_id}/verify_user_security_answer", status_code=status.HTTP_200_OK)
async def verify_user_security_answer_route(
    user_id: Annotated[
        UUID, Path(title="User ID", description="The id of the end user.")
    ],
    user_security_answer: Annotated[
        UserSecurityAnswerCreateSchema,
        Body(
            title="User Security Answer",
            description="The security answer for the end user.",
        ),
    ],
    async_session: Annotated[AsyncSession, Depends(get_async_session)],
) -> None:
    """
    Verify the security answer for an end user.
    """
    user = await get_end_user_by_id(async_session, user_id)

    user_security_question = await get_user_security_question(
        async_session, user.id, user_security_answer.user_security_question_id
    )
    if user_security_question is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "Security question not found for the user."},
        )

    db_user_security_answer = await get_end_user_security_answer(
        async_session, user.id, user_security_question.security_question_id
    )
    if db_user_security_answer is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "Security answer not found for the user."},
        )

    if not db_user_security_answer.verify_answer(user_security_answer.answer):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "Security answer does not match."},
        )


@router.post(
    "/{user_id}/send_transaction_verification_email",
    status_code=status.HTTP_200_OK,
    responses={
        200: {
            "description": "Transaction Verification email sent.",
            "content": {
                "application/json": {
                    "example": {"message": "Transaction Verification email sent."}
                }
            },
        },
        500: {
            "description": "Failed to save OTP to the database.",
            "content": {
                "application/json": {
                    "example": {
                        "error": "Failed to save OTP to the database.",
                        "exception": "Exception message",
                    }
                }
            },
        },
    },
)
async def send_transaction_verification_email_route(
    user_id: Annotated[
        UUID, Path(title="User ID", description="The id of the end user.")
    ],
    async_session: Annotated[AsyncSession, Depends(get_async_session)],
    async_smtp: Annotated[SMTP, Depends(get_async_smtp)],
) -> None:
    """
    Send a verification email to the end user.
    """
    user = await get_end_user_by_id(async_session, user_id)

    otp = generate_otp()

    # Send verification email
    message = f"Hello {user.email},\n\n"
    message += "Please use this OTP to verify your email address:\n\n"
    message += f"{otp}\n\n"
    message += "\n\n"
    message += (
        "Please reply to this email with your answers to the security questions.\n\n"
    )
    message += "Thank you."

    await send_email(
        smtp=async_smtp,
        subject="Verification Required",
        recipient=user.email,
        plain_text=message,
    )

    # TODO: Save the OTP to the database
    try:
        await create_otp(async_session, user.id, otp)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "Failed to save OTP to the database.",
                "exception": str(e),
            },
        )

    return JSONResponse(content={"message": "Verification email sent."})


@router.post(
    "/{user_id}/verify_transaction",
    status_code=status.HTTP_200_OK,
    responses={
        200: {
            "description": "Transaction verified.",
            "content": {
                "application/json": {"example": {"message": "Transaction verified."}}
            },
        },
        400: {
            "description": "Invalid OTP.",
            "content": {
                "application/json": {
                    "example": {
                        "error": "Invalid OTP.",
                    }
                }
            },
        },
    },
)
async def verify_transaction_route(
    user_id: Annotated[
        UUID, Path(title="User ID", description="The id of the end user.")
    ],
    otp: Annotated[str, Body(title="OTP", description="The OTP to verify.")],
    async_session: Annotated[AsyncSession, Depends(get_async_session)],
) -> None:
    """
    Verify the OTP for the end user.
    """
    user = await get_end_user_by_id(async_session, user_id)

    existing_otp = await get_otp(async_session, user.id)
    if existing_otp is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "Invalid OTP."},
        )

    if not await verify_otp(async_session, otp):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "Invalid OTP."},
        )

    return JSONResponse(content={"message": "Transaction verified."})


@router.post(
    "/{user_id}/initiate_transaction",
    status_code=status.HTTP_200_OK,
    responses={
        200: {
            "description": "Transaction initiated.",
            "content": {
                "application/json": {
                    "example": {
                        "approval_url": "https://www.paypal.com/checkout",
                        "order_id": "1234567890",
                    }
                }
            },
        },
        400: {
            "description": "An error occurred.",
            "content": {
                "application/json": {
                    "example": {
                        "error": "An error occurred.",
                    }
                }
            },
        },
    },
)
async def initiate_transaction_route(
    user_id: Annotated[
        UUID, Path(title="User ID", description="The id of the end user.")
    ],
    amount: Annotated[
        float, Body(title="Amount", description="The amount of the transaction.")
    ],
    async_session: Annotated[AsyncSession, Depends(get_async_session)],
):
    """
    Initiate a transaction for the end user.
    """
    user = await get_end_user_by_id(async_session, user_id)

    try:
        transaction, approval_url = await create_transaction(
            async_session, user.id, amount
        )

        return JSONResponse(
            content={
                "approval_url": approval_url,
                "order_id": transaction.paypal_order_id,
            }
        )

    except httpx.HTTPStatusError as e:
        raise HTTPException(
            status_code=e.response.status_code,
            detail={"error": e.response.json()},
        )
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": str(e)},
        )


@router.post(
    "/{user_id}/capture_transaction",
    status_code=status.HTTP_200_OK,
    responses={
        200: {
            "description": "Transaction captured.",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "message": "Billing address verification successful.",
                    }
                }
            },
        },
        400: {
            "description": "Billing address verification failed.",
            "content": {
                "application/json": {
                    "example": {
                        "error": "Billing address verification failed.",
                    }
                }
            },
        },
        503: {
            "description": "AVS service unavailable.",
            "content": {
                "application/json": {
                    "example": {
                        "error": "AVS service unavailable.",
                    }
                }
            },
        },
        500: {
            "description": "An error occurred.",
            "content": {
                "application/json": {
                    "example": {
                        "error": "An error occurred.",
                    }
                }
            },
        },
    },
)
async def capture_transaction_route(
    user_id: Annotated[
        UUID, Path(title="User ID", description="The id of the end user.")
    ],
    order_id: Annotated[str, Body(title="Order ID", description="The order ID.")],
    card: Annotated[
        CardCreateSchema, Body(title="Card", description="The card details.")
    ],
    billing_address: Annotated[
        BillingAddressCreateSchema,
        Body(
            title="Billing Address",
            description="The billing address details.",
        ),
    ],
    async_session: Annotated[AsyncSession, Depends(get_async_session)],
):
    """
    Capture the transaction for the end user.
    """
    paypal_client = PayPalClient()
    billing_address_data = await paypal_client.build_billing_address(
        **billing_address.model_dump()
    )

    try:
        card_data = await paypal_client.build_card(
            **card.model_dump(), billing_address=billing_address_data
        )
        paypal_id, processor_response = await paypal_client.capture_order(
            order_id, card_data
        )

        avs_code = processor_response["avs_code"]
        avs_message = AVS_CODE_MAP.get(avs_code, "Unknown AVS code")
        if avs_code in ["Y", "D", "X", "M"]:  # These codes indicate a successful match.
            return {
                "status": "success",
                "message": "Billing address verification successful.",
            }
        elif avs_code in ["A", "Z", "W"]:  # Partial matches
            return {
                "status": "warning",
                "message": f"Partial match: {avs_message}. Consider verifying the billing address.",
            }
        elif avs_code in ["N", "C", "G"]:  # No match
            raise HTTPException(
                status_code=400,
                detail=f"Billing address verification failed: {avs_message}. Please double-check your address.",
            )
        elif avs_code in ["S", "U", "R"]:  # Service unavailable or retry
            raise HTTPException(
                status_code=503,
                detail=f"AVS service unavailable: {avs_message}. Please try again later.",
            )
        else:
            # Handle any other AVS codes that may need additional logic
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={"status": "info", "message": f"AVS response: {avs_message}."},
            )
    except httpx.HTTPStatusError as e:
        raise HTTPException(
            status_code=e.response.status_code,
            detail={"error": e.response.json()},
        )
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": str(e)},
        )


@router.post(
    "/{user_id}/authorize_transaction",
    status_code=status.HTTP_200_OK,
)
async def authorize_transaction_route(
    user_id: Annotated[
        UUID, Path(title="User ID", description="The id of the end user.")
    ],
    order_id: Annotated[str, Body(title="Order ID", description="The order ID.")],
    async_session: Annotated[AsyncSession, Depends(get_async_session)],
):
    """
    Authorize the transaction for the end user.
    """
    paypal_client = PayPalClient()

    try:
        paypal_id, processor_response = await paypal_client.authorize_order(order_id)

        return {
            "status": "success",
            "message": "Transaction authorized successfully.",
        }
    except httpx.HTTPStatusError as e:
        raise HTTPException(
            status_code=e.response.status_code,
            detail={"error": e.response.json()},
        )
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": str(e)},
        )
