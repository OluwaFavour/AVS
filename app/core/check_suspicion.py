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
