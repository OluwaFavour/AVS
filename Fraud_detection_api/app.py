import pickle
import numpy as np
import pandas as pd
import logging
from sklearn.preprocessing import StandardScaler
from tensorflow.keras.models import load_model

# Configure logging
logging.basicConfig(level=logging.INFO)

# Load the model
model = load_model("Fraud_detection_api/model/cnn_lstm_fraud_detection.h5")

# Load the label encoders
with open("Fraud_detection_api/model/laabel_encoders.pkl", "rb") as f:
    label_encoders = pickle.load(f)

# Load the scaler
with open("Fraud_detection_api/model/nuumerical_scaler.pkl", "rb") as f:
    scaler = pickle.load(f)


def preprocess_data(input_data):
    # Convert input data to DataFrame
    input_df = pd.DataFrame(input_data)

    # Debug: Check the structure of the DataFrame
    print(f"Filtered data: {input_df.head()}")
    print(f"Columns in input DataFrame: {input_df.columns.tolist()}")

    # Check if all necessary features are present
    features = [
        "total_amount",
        "order_frequency",
        "unusual_time",
        "location_mismatch",
        "payment_method",
        "device_type",
    ]

    for feature in features:
        if feature not in input_df.columns:
            raise ValueError(f"Missing feature: {feature}")

    # Select features for preprocessing
    X = input_df[features].copy()  # Use .copy() to avoid SettingWithCopyWarning

    # Debug: Check selected features
    print(f"Selected features for preprocessing: {X.columns.tolist()}")

    # Apply Label Encoding to categorical features
    for feature in ["payment_method", "device_type"]:
        if feature in X.columns:
            print(f"Processing {feature} with values: {X[feature].unique()}")
            X[feature] = label_encoders[feature].transform(X[feature])
        else:
            raise ValueError(f"Feature {feature} not found in input data")

    # Standardize numerical features
    numerical_features = [
        "total_amount",
        "order_frequency",
        "unusual_time",
        "location_mismatch",
    ]
    X[numerical_features] = scaler.transform(
        X[numerical_features]
    )  # Use the loaded scaler

    # Reshape X for LSTM input
    X = X.values.reshape((X.shape[0], 1, X.shape[1]))

    return X


def predict(data):
    # Preprocess the input data
    try:
        X_preprocessed = preprocess_data(data)
    except ValueError as e:
        raise ValueError(f"Error during preprocessing: {e}")

    # Make predictions
    predictions = model.predict(X_preprocessed)

    # Convert predictions to binary
    prediction_classes = np.argmax(predictions, axis=1)

    # Return the predictions as a JSON response
    return int(prediction_classes[0])
