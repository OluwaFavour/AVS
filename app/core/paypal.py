from typing import Any
import httpx
from enum import Enum
from app.core.config import get_settings

from fastapi import HTTPException


class PayPalClient:
    def __init__(self):
        self.client_id = get_settings().paypal_client_id
        self.secret = get_settings().paypal_secret
        self.base_url = "https://api-m.sandbox.paypal.com"

    class PaypalCardVerificationMethod(Enum):
        SCA_ALWAYS = "SCA_ALWAYS"
        SCA_WHEN_REQUIRED = "SCA_WHEN_REQUIRED"
        THREE_D_SECURE = "3D_SECURE"
        AVS_CVV = "AVS_CVV"

    async def get_access_token(self) -> str:
        """
        Get the access token for the PayPal API.

        Returns:
            str: The access token.

        Raises:
            HTTPException: If there is an error getting the access token.
        """
        url = f"{self.base_url}/v1/oauth2/token"
        auth = (self.client_id, self.secret)
        data = {"grant_type": "client_credentials"}
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                data=data,
                headers=headers,
                auth=auth,
            )
            response.raise_for_status()
            return response.json()["access_token"]

    async def create_order(self, amount: float) -> tuple[str, str]:
        """
        Create a new order in PayPal.

        Args:
            amount (float): The amount of the order.

        Returns:
            str: The order ID.
            str: The approval URL.

        Raises:
            HTTPException: If there is an error creating the order.
        """
        url = f"{self.base_url}/v2/checkout/orders"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {await self.get_access_token()}",
        }
        data = {
            "intent": "CAPTURE",
            "purchase_units": [
                {"amount": {"currency_code": "USD", "value": str(amount)}}
            ],
        }
        async with httpx.AsyncClient() as client:
            response = await client.post(url, json=data, headers=headers)
            response.raise_for_status()
            response_data = response.json()
            id: str = response_data["id"]
            approval_url: str | None = next(
                (
                    link["href"]
                    for link in response_data["links"]
                    if link["rel"] == "approve"
                ),
                None,
            )
            if not approval_url:
                raise HTTPException(
                    status_code=500, detail="Approval URL not found in response"
                )
            return id, approval_url

    async def build_billing_address(
        self,
        address_line_1: str,
        city: str,
        state: str,
        postal_code: str,
        country_code: str,
        address_line_2: str | None = None,
    ) -> dict[str, str]:
        """
        Build the billing address details for a payment in PayPal.

        Args:
            address_line_1 (str): The first line of the address.
            city (str): The city.
            state (str): The state.
            postal_code (str): The postal code.
            country_code (str): The country code.
            address_line_2 (str | None, optional): The second line of the address. Defaults to None.
        """
        billing_address = {
            "address_line_1": address_line_1,
            "admin_area_2": city,
            "admin_area_1": state,
            "postal_code": postal_code,
            "country_code": country_code,
        }
        if address_line_2:
            billing_address["address_line_2"] = address_line_2
        return billing_address

    async def build_card(
        self,
        name: str,
        number: str,
        expiry: str,
        cvv: str,
        billing_address: dict[str, str],
        return_url: str,
        cancel_url: str,
    ) -> dict[str, Any]:
        """
        Build the card details for a payment in PayPal.

        Args:
            name (str): The name on the card.
            number (str): The card number.
            expiry (str): The card expiry date in YYYY-MM format.
            cvv (str): The card CVV number.
            billing_address (dict[str, str]): The billing address details.
            return_url (str): The URL to return to after payment.
            cancel_url (str): The URL to return to if payment is cancelled.

        Returns:
            dict[str, Any]: The card details.
        """
        return {
            "name": name,
            "number": number,
            "expiry": expiry,
            "security_code": cvv,
            "billing_address": billing_address,
            "attributes": {
                "verification": {
                    "method": self.PaypalCardVerificationMethod.AVS_CVV.value
                }
            },
            "experience_context": {
                "return_url": return_url,
                "cancel_url": cancel_url,
            },
        }

    async def capture_order(
        self, order_id: str, card: dict[str, Any]
    ) -> tuple[str, dict[str, str]]:
        """
        Capture the payment for an order in PayPal.

        Args:
            order_id (str): The ID of the order.
            card (dict[str, Any]): The card details.

        Returns:
            str: The PayPal-generated ID for the purchase unit.
            dict[str, str]: The processor response.

        Raises:
            HTTPException: If there is an error capturing the payment.
        """
        url = f"{self.base_url}/v2/checkout/orders/{order_id}/capture"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {await self.get_access_token()}",
            "Prefer": "return=representation",
        }
        data = {"payment_source": {"card": card}}
        async with httpx.AsyncClient() as client:
            response = await client.post(url, json=data, headers=headers)
            response.raise_for_status()
            id: str = response.json()["purchase_units"][0]["payments"]["captures"][0][
                "id"
            ]
            processor_response: dict[str, str] = response.json()["purchase_units"][0][
                "payments"
            ]["authorizations"][0]["processor_response"]
            return id, processor_response

    async def authorize_order(self, order_id: str) -> tuple[str, dict[str, str]]:
        """
        Authorize the payment for an order in PayPal.

        Args:
            order_id (str): The ID of the order.

        Returns:
            str: The PayPal-generated ID for the purchase unit.
            dict[str, str]: The processor response.

        Raises:
            HTTPException: If there is an error authorizing the payment.
        """
        url = f"{self.base_url}/v2/checkout/orders/{order_id}/authorize"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {await self.get_access_token()}",
        }
        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers)
            response.raise_for_status()
            id: str = response.json()["purchase_units"][0]["payments"]["captures"][0][
                "id"
            ]
            processor_response: dict[str, str] = response.json()["purchase_units"][0][
                "payments"
            ]["authorizations"][0]["processor_response"]
            return id, processor_response


AVS_CODE_MAP = {
    "0": "All address information matches (Maestro).",
    "1": "None of the address information matches (Maestro).",
    "2": "Part of the address information matches (Maestro).",
    "3": "No AVS information was provided by the merchant (Maestro).",
    "4": "Address was not checked or no response from acquirer (Maestro).",
    "A": "Address matches but the ZIP code does not (Visa/Mastercard/Discover).",
    "B": "Address matches (Visa/Mastercard/Discover, International A).",
    "C": "No values match (Visa/Mastercard/Discover, International N).",
    "D": "Address and postal code match (Visa/Mastercard/Discover, International X).",
    "E": "Not allowed for internet/phone transactions (Visa/Mastercard/Discover).",
    "F": "Address and postal code match (UK Visa/Mastercard/Discover).",
    "G": "Global AVS unavailable; no match (Visa/Mastercard/Discover).",
    "I": "International AVS unavailable (Visa/Mastercard/Discover).",
    "M": "Address and postal code match (Visa/Mastercard/Discover/Amex).",
    "N": "Nothing matches (Visa/Mastercard/Discover/Amex).",
    "P": "Postal code matches only (Visa/Mastercard/Discover).",
    "R": "Re-try request (Visa/Mastercard/Discover/Amex).",
    "S": "Service not supported (Visa/Mastercard/Discover/Amex).",
    "U": "Service unavailable (Visa/Mastercard/Discover/Amex/Maestro).",
    "W": "ZIP code matches, address does not (Visa/Mastercard/Discover).",
    "X": "Exact match of address and nine-digit ZIP (Visa/Mastercard/Discover).",
    "Y": "Address and five-digit ZIP code match (Visa/Mastercard/Discover).",
    "Z": "ZIP code matches but no address (Visa/Mastercard/Discover/Amex).",
    "Null": "No AVS response obtained (Maestro).",
}
