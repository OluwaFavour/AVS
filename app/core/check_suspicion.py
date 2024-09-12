import asyncio
from decimal import Decimal
from statistics import mean, median, stdev


async def check_suspicious_activity_in_price(
    new_transaction_prices: list[Decimal],
    old_transaction_prices: list[Decimal],
    tolerance_factor: Decimal = Decimal("1.2"),
) -> tuple[bool, Decimal | None]:
    """
    Checks for any suspicious activity in the transaction prices using statistical methods,
    allowing for breathing space by using a dynamic tolerance factor.

    Parameters:
    - new_transaction_prices (list[Decimal]): The list of new transaction prices.
    - old_transaction_prices (list[Decimal]): The list of old transaction prices.
    - tolerance_factor (Decimal): A factor to allow deviation from the old price range (default: 1.2).

    Returns:
        bool: True if any suspicious activity is detected, False otherwise.
        Decimal: The suspicious price
    """
    if len(old_transaction_prices) < 2:
        # Not enough data to perform statistical analysis
        return False

    # Sort both lists
    new_transaction_prices.sort()
    old_transaction_prices.sort()

    # Calculate basic statistics for old prices
    mean_old = mean(old_transaction_prices)
    median_old = median(old_transaction_prices)
    stddev_old = stdev(old_transaction_prices)

    # Get max and min prices from old transactions
    max_old_price = max(old_transaction_prices)
    min_old_price = min(old_transaction_prices)

    # Set a threshold for standard deviation (e.g., 2 stddev)
    threshold_stddev = Decimal(5)

    # Define the allowed maximum price based on tolerance_factor
    allowed_max_price = max_old_price * tolerance_factor

    # Flag to detect any suspicious activity
    suspicious_activity = False
    suspicious_price = None

    # Check each new transaction price for suspicious behavior
    for price in new_transaction_prices:
        # Calculate the deviation from the mean
        deviation_from_mean = abs(price - mean_old)

        # Mark prices that do not exceed the allowed max price as non-suspicious
        # if price <= allowed_max_price:
        #     continue

        # Check if the price exceeds the allowed max price
        if price > allowed_max_price:
            suspicious_activity = True
            suspicious_price = price
            break

        # If price deviates significantly from mean or median, flag it
        if (
            deviation_from_mean > threshold_stddev * stddev_old
            or abs(price - median_old) > threshold_stddev * stddev_old
        ):
            suspicious_activity = True
            suspicious_price = price
            break

    return suspicious_activity, suspicious_price


if __name__ == "__main__":
    # Sample old transaction prices (in Decimal format) with larger values
    old_transaction_prices = [
        Decimal("1500.00"),
        Decimal("1550.00"),
        Decimal("1525.00"),
        Decimal("1540.50"),
        Decimal("1510.00"),
        Decimal("1530.00"),
        Decimal("1495.00"),
        Decimal("1505.50"),
        Decimal("1560.00"),
        Decimal("1570.00"),
        Decimal("1520.00"),
        Decimal("1535.00"),
    ]

    # Sample new transaction prices with larger decimals
    new_transaction_prices = [
        Decimal("1580.00"),  # slightly higher but within tolerance
        Decimal("5000.00"),  # similar to old prices
        Decimal("1500.00"),  # same as old price
        Decimal("1600.00"),  # outside tolerance
        Decimal("1595.00"),  # much higher, suspicious
    ]

    # Check for suspicious activity with a 20% tolerance factor
    suspicious_activity_detected = asyncio.run(
        check_suspicious_activity_in_price(
            new_transaction_prices,
            old_transaction_prices,
            tolerance_factor=Decimal("1.2"),
        )
    )
    print(f"Suspicious activity detected: {suspicious_activity_detected}")
