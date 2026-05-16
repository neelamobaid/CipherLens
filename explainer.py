import shap
import pickle
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

# Load model
with open("model/phishing_model.pkl", "rb") as f:
    model = pickle.load(f)

# Load feature names
with open("model/feature_names.pkl", "rb") as f:
    feature_names = pickle.load(f)

# Initialize SHAP explainer
explainer = shap.TreeExplainer(model)

def explain_url(features, prediction):
    features_df = pd.DataFrame([features], columns=feature_names)
    shap_values = explainer.shap_values(features_df)

    if prediction == "PHISHING":
        values = shap_values[0, :, 1]
    else:
        values = shap_values[0, :, 0]

    impact_df = pd.DataFrame({
        "Feature": feature_names,
        "Value": features,
        "Impact": values
    })

    impact_df = impact_df.reindex(
        impact_df["Impact"].abs().sort_values(ascending=True).index
    )

    # Only show top 20 most impactful features for clarity
    impact_df = impact_df.tail(20)

    fig, ax = plt.subplots(figsize=(8, 7))
    colors = ["#e74c3c" if x < 0 else "#2ecc71" for x in impact_df["Impact"]]
    ax.barh(impact_df["Feature"], impact_df["Impact"], color=colors)
    ax.axvline(x=0, color="black", linewidth=0.8)
    ax.set_xlabel("SHAP Value (Impact on Prediction)")
    ax.set_title("Feature Impact on Prediction\n(Green = Legitimate | Red = Phishing)")
    plt.tight_layout()

    return fig

if __name__ == "__main__":
    from feature_extractor import extract_features
    features = extract_features("http://google.com")
    fig = explain_url(features, "LEGITIMATE")
    fig.savefig("test_shap.png")
    print("SHAP chart saved as test_shap.png")