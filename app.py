from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd

from feature_extractor import (
    extract_url_features,
    apply_page_features
)
from page_analyzer import analyze_page
from explanation_service import generate_explanation, generate_ai_summary

app = Flask(__name__)
CORS(app)

# ---------------------------------------
# Load trained ML model
# ---------------------------------------
MODEL_PATH = "phishing_model.pkl"

saved_model = joblib.load(MODEL_PATH)

model = saved_model["model"]
expected_features = saved_model["features"]


# ---------------------------------------
# Home route
# ---------------------------------------
@app.route("/")
def home():
    return jsonify({
        "message": "PhishGuard API is running",
        "model_loaded": True,
        "features": len(expected_features)
    })


# ---------------------------------------
# Prediction route
# ---------------------------------------
@app.route("/predict", methods=["POST"])
def predict():

    try:

        data = request.get_json()

        if not data or "url" not in data:
            return jsonify({
                "error": "URL is required"
            }), 400

        url = data["url"].strip()

        if not url:
            return jsonify({
                "error": "URL cannot be empty"
            }), 400


        # ---------------------------------------
        # 1. Extract URL-based features
        # ---------------------------------------
        url_features = extract_url_features(url)


        # ---------------------------------------
        # 2. Analyze webpage
        # ---------------------------------------
        page_features = analyze_page(url)

        page_analysis_failed = page_features.get("analysis_failed", 0)
        page_features.pop("analysis_failed", None)


        # ---------------------------------------
        # 3. Combine URL + webpage features
        # ---------------------------------------
        features = apply_page_features(
            url_features,
            page_features
        )


        # ---------------------------------------
        # 4. Check feature count
        # ---------------------------------------
        if len(features) != len(expected_features):

            return jsonify({
                "error": "Feature count mismatch",
                "expected": len(expected_features),
                "received": len(features)
            }), 500


        # ---------------------------------------
        # 5. Create DataFrame
        # ---------------------------------------
        X = pd.DataFrame(
            [features],
            columns=expected_features
        )


        # ---------------------------------------
        # 6. ML prediction
        # ---------------------------------------
        prediction = model.predict(X)[0]

        probabilities = model.predict_proba(X)[0]

        confidence = float(max(probabilities))


        # ---------------------------------------
        # 7. Convert prediction to result
        # ---------------------------------------
        if int(prediction) == 1:
            result = "phishing"
        else:
            result = "legitimate"


        # ---------------------------------------
        # 8. Additional safety check if
        #    webpage analysis failed
        # ---------------------------------------
        if page_analysis_failed:

            suspicious_score = 0

            url_lower = url.lower()

            if "@" in url:
                suspicious_score += 2

            if len(url) > 75:
                suspicious_score += 1

            if url.count("-") >= 2:
                suspicious_score += 1

            suspicious_words = [
                "login", "verify", "secure", "account",
                "update", "confirm", "password",
                "signin", "security", "urgent"
            ]

            found_words = [
                word for word in suspicious_words
                if word in url_lower
            ]

            if len(found_words) >= 2:
                suspicious_score += 2
            elif len(found_words) == 1:
                suspicious_score += 1

            if url_features[14] == 1:
                suspicious_score += 1

            if url_features[16] == 1:
                suspicious_score += 2

            if suspicious_score >= 4:
                result = "phishing"


        # ---------------------------------------
        # 9. Generate explanation and AI summary
        # ---------------------------------------
        feature_dict = dict(zip(expected_features, features))

        explanation = generate_explanation(
            url,
            result,
            confidence,
            feature_dict
        )

        ai_summary = generate_ai_summary(
            url,
            result,
            confidence,
            explanation
        )


        # ---------------------------------------
        # 10. Send response
        # ---------------------------------------
        return jsonify({

            "url": url,

            "prediction": result,

            "confidence": round(confidence, 4),

            "features_used": len(features),

            "message": (
                "Website classified as phishing"
                if result == "phishing"
                else "Website classified as legitimate"
            ),

            "explanation": explanation,

            "ai_summary": ai_summary

        })


    except Exception as e:

        print("Prediction error:", e)

        return jsonify({
            "error": str(e)
        }), 500


# ---------------------------------------
# Run Flask server
# ---------------------------------------
if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )