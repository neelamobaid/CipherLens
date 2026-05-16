import pickle
import numpy as np
import pandas as pd
from feature_extractor import extract_features

# Load the saved model
with open("model/phishing_model.pkl", "rb") as f:
    model = pickle.load(f)

# Load feature names
with open("model/feature_names.pkl", "rb") as f:
    feature_names = pickle.load(f)

def predict_url(url):
    features = extract_features(url)
    features_df = pd.DataFrame([features], columns=feature_names)
    prediction = model.predict(features_df)[0]
    probability = model.predict_proba(features_df)[0]

    result = {
        "url": url,
        "prediction": "PHISHING" if prediction == "phishing" else "LEGITIMATE",
        "confidence": round(max(probability) * 100, 2),
        "features": features,
        "feature_names": feature_names
    }
    return result

if __name__ == "__main__":
    test_urls = [
        "http://google.com",
        "http://192.168.1.1/login/verify.php",
        "http://paypal-secure-login.com/update"
    ]

    for url in test_urls:
        print("\nAnalyzing:", url)
        result = predict_url(url)
        print(f"Prediction : {result['prediction']}")
        print(f"Confidence : {result['confidence']}%")