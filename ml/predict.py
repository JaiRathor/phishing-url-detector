import sys
import os
import json
import joblib
from feature_extractor import extract_url_features

# Load pipeline model relative to script location
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, 'saved_models', 'phishing_model.pkl')

model_pipeline = joblib.load(MODEL_PATH)

def predict_url(url_input: str):
    # Ensure url_input is a string if a list is accidentally passed
    if isinstance(url_input, list):
        url_input = url_input[0] if url_input else ""

    # Extract 18 candidate features
    features_18 = [extract_url_features(url_input)]
    
    # Pipeline automatically selects features and predicts
    prediction = model_pipeline.predict(features_18)[0]
    probabilities = model_pipeline.predict_proba(features_18)[0]
    risk_score = round(float(probabilities[1]) * 100, 2)
    
    return {
        "url": url_input,
        "isPhishing": int(prediction),
        "predictionLabel": "Phishing" if prediction == 1 else "Legitimate",
        "phishingRiskScore": risk_score
    }

if __name__ == '__main__':
    # Select index 1 to grab the single URL string argument
    target = sys.argv[1] if len(sys.argv) > 1 else ""
    if target:
        print(json.dumps(predict_url(target)))
    else:
        print(json.dumps({"error": "No URL provided"}))
