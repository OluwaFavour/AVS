def calculate_deviations(base_price, current_price, address):
    import joblib

    """Calculate deviations for price, state, and address number."""

    # Calculate price deviation
    price_deviation = abs(current_price - base_price) / base_price

    return {
        "price": [base_price],
        "price_deviation": [price_deviation],
        "address": [address],
    }


def predict(base_price, current_price, address):

    import joblib
    import pandas as pd

    new_data = pd.DataFrame(calculate_deviations(base_price, current_price, address))

    # Process the new data
    one_encode = joblib.load("model/one_encoder.pkl")
    new_shipping_address = one_encode.transform(new_data[["address"]])
    new_shipping_address_df = pd.DataFrame(
        new_shipping_address, columns=one_encode.get_feature_names_out(["address"])
    )

    new_shipping_address_df

    # Drop the original shipping_address column
    new_data = new_data.drop(columns=["address"])

    # Combine the new dataframe with the encoded columns
    new_data = pd.concat([new_data, new_shipping_address_df], axis=1)

    model = joblib.load("model/modeled_model.pkl")
    prediction = model.predict(new_data.values)

    return prediction


print(predict(453, 23, "Lagos"))
