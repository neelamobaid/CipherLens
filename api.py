from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import pickle
import pandas as pd
from virustotal import check_url_virustotal

app = FastAPI(title="CipherLens API")

# Allow Chrome extension to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load model and feature names
with open("model/phishing_model.pkl", "rb") as f:
    model = pickle.load(f)

with open("model/feature_names.pkl", "rb") as f:
    feature_names = pickle.load(f)

class URLRequest(BaseModel):
    url: str
    dom_features: dict = {}

@app.get("/")
def root():
    return {"status": "CipherLens is running"}

@app.post("/analyze")
def analyze_url(request: URLRequest):
    from feature_extractor import extract_features
    
    # Extract URL-based features
    features = extract_features(request.url)
    features_df = pd.DataFrame([features], columns=feature_names)
    
    # Override with DOM features if provided by extension
    for feature, value in request.dom_features.items():
        if feature in feature_names:
            features_df[feature] = value
    
    prediction = model.predict(features_df)[0]
    probability = model.predict_proba(features_df)[0]
    
    vt_result = check_url_virustotal(request.url)
    
    ml_phishing = prediction == "phishing"
    vt_phishing = vt_result and vt_result["vt_verdict"] == "PHISHING"
    
    return {
        "url": request.url,
        "ml_prediction": "PHISHING" if ml_phishing else "LEGITIMATE",
        "ml_confidence": round(max(probability) * 100, 2),
        "vt_result": vt_result,
        "final_verdict": "PHISHING" if (ml_phishing or vt_phishing) else "LEGITIMATE"
    }