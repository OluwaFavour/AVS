import numpy as np
from sklearn.preprocessing import LabelEncoder
from statistics import mode

# Initialize the LabelEncoder globally (or it can be passed as an argument)
le = LabelEncoder()


# Fit the LabelEncoder on all known addresses from previous data
def fit_label_encoder(all_addresses):
    le.fit(all_addresses)


# Helper function to calculate the mean of a transaction history
def calculate_mean_transaction_history(trans_history):
    return np.mean(trans_history)


# Helper function to calculate the mode of history of addresses
def calculate_mode_history_addresses(addr_history):
    return mode(addr_history)


# Function to process new data
def process_new_data(new_data):
    """
    new_data: A dictionary that must contain these keys:
        ['Transaction Amount', 'Transaction History', 'Current Address', 'History of Addresses']
        where 'Transaction History' and 'History of Addresses' are lists.

    Returns: A dictionary with processed and encoded data, including:
        'Transaction Amount', 'Mean Transaction History', 'Current Address Encoded',
        'History of Addresses Encoded', 'Mode of Addresses Encoded'
    """

    fit_label_encoder(all_known_addresses)

    # Process the 'Transaction History' to calculate 'Mean Transaction History'
    trans_history = new_data["transaction_history"]
    mean_trans_hist = calculate_mean_transaction_history(trans_history)

    # Process 'History of Addresses' to calculate 'Mode of Addresses'
    addr_history = new_data["history_of_addresses"]
    mode_addr = calculate_mode_history_addresses(addr_history)

    # Encode 'Current Address' and 'History of Addresses'
    current_address_encoded = le.transform([new_data["current_address"]])[0]
    history_addresses_encoded = le.transform(addr_history)
    mode_address_encoded = le.transform([mode_addr])[0]

    # Prepare the result as a dictionary
    processed_data = {
        "Transaction Amount": new_data["transaction_amount"],
        "Mean Transaction History": mean_trans_hist,
        "Current Address Encoded": current_address_encoded,
        # 'History of Addresses Encoded': history_addresses_encoded,
        "Mode of Addresses Encoded": mode_address_encoded,
    }

    values = []
    for i in processed_data.values():
        values.append(int(i))

    return np.array(values).reshape(1, -1)


def predict(data):
    import joblib

    model = joblib.load("modeled_model.pkl")
    prediction = model.predict(data)
    return {"prediction": prediction[0]}


if __name__ == "__main__":
    # ----------------------------------------------Testing data--------------------------------------------------------------------
    # Fit the LabelEncoder with all known addresses first
    all_known_addresses = [
        "123 Main St, Springfield",
        "456 Elm St, Rivertown",
        "789 Oak St, Hillview",
        "359 High St, Sunnydale",
        "987 Maple St, Greenville",
    ]

    # print(fit_label_encoder)
    # Example new data
    new_data = {
        "Transaction Amount": 3000,
        "Transaction History": [1000, 2000, 2500, 4000],
        "Current Address": "123 Main St, Springfield",
        "History of Addresses": [
            "123 Main St, Springfield",
            "456 Elm St, Rivertown",
            "789 Oak St, Hillview",
        ],
    }

    # Process the new data
    processed = process_new_data(new_data)

    # ----------------------------------------------Predicting data--------------------------------------------------------------------
    print(predict(processed))
