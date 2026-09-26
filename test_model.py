import joblib
import pandas as pd

from feature_extractor import extract_url_features


MODEL_PATH = "phishing_model.pkl"

# Load model
saved = joblib.load(MODEL_PATH)

model = saved["model"]
expected_features = saved["features"]

print("Model loaded successfully.")
print("Expected features:", len(expected_features))


# Test URL
url = "https://example.com"

# Extract features
features = extract_url_features(url)

print("\nURL:", url)
print("Extracted features:", len(features))


# Convert to DataFrame using exact feature names
X = pd.DataFrame(
    [features],
    columns=expected_features
)

# Prediction
prediction = model.predict(X)[0]

# Probability
probabilities = model.predict_proba(X)[0]

confidence = max(probabilities)

print("\n==============================")
print("MODEL PREDICTION")
print("==============================")

print("Prediction value:", prediction)
print("Confidence:", round(confidence, 4))

if prediction == 1:
    print("Result: PHISHING")
else:
    print("Result: LEGITIMATE")