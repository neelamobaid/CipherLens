import streamlit as st
import pickle
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import shap

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="CipherLens",
    layout="wide"
)

# ── Dark crimson/purple theme ─────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');

:root {
    --bg:        #0a0008;
    --bg2:       #110010;
    --bg3:       #1a0018;
    --border:    #4a0040;
    --purple:    #9b30a0;
    --crimson:   #dc143c;
    --dim:       #7a6080;
    --text:      #e8d0f0;
    --mono:      'Share Tech Mono', monospace;
    --sans:      'Rajdhani', sans-serif;
}

html, body, [class*="css"] {
    background-color: var(--bg) !important;
    color: var(--text) !important;
    font-family: var(--sans) !important;
}

/* Hide default streamlit elements */
#MainMenu, footer, header { visibility: hidden; }
.block-container { padding: 2rem 3rem; }

/* Hero */
.hero {
    border: 1px solid var(--border);
    background: linear-gradient(135deg, #110010 0%, #1a0018 50%, #0d000d 100%);
    padding: 3rem;
    margin-bottom: 2rem;
    position: relative;
    overflow: hidden;
}
.hero::before {
    content: '';
    position: absolute;
    top: -50%;
    right: -20%;
    width: 600px;
    height: 600px;
    background: radial-gradient(circle, rgba(155,48,160,0.08) 0%, transparent 70%);
    pointer-events: none;
}
.hero-title {
    font-family: var(--mono);
    font-size: 3.5rem;
    color: var(--purple);
    letter-spacing: 6px;
    margin: 0;
    text-shadow: 0 0 40px rgba(155,48,160,0.4);
}
.hero-sub {
    font-size: 1.1rem;
    color: var(--dim);
    letter-spacing: 3px;
    text-transform: uppercase;
    margin-top: 0.5rem;
    font-family: var(--mono);
}
.hero-desc {
    font-size: 1.15rem;
    color: var(--text);
    margin-top: 1.5rem;
    max-width: 700px;
    line-height: 1.7;
}
.tag {
    display: inline-block;
    border: 1px solid var(--border);
    color: var(--purple);
    font-family: var(--mono);
    font-size: 0.75rem;
    padding: 4px 12px;
    margin: 4px 4px 0 0;
    letter-spacing: 1px;
}

/* Metric cards */
.metric-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 1rem;
    margin-bottom: 2rem;
}
.metric-card {
    border: 1px solid var(--border);
    background: var(--bg2);
    padding: 1.5rem;
    text-align: center;
    position: relative;
}
.metric-card::after {
    content: '';
    position: absolute;
    bottom: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, var(--crimson), var(--purple));
}
.metric-value {
    font-family: var(--mono);
    font-size: 2.2rem;
    color: var(--purple);
    display: block;
}
.metric-label {
    font-size: 0.8rem;
    color: var(--dim);
    letter-spacing: 2px;
    text-transform: uppercase;
    margin-top: 4px;
}

/* Section headers */
.section-header {
    font-family: var(--mono);
    color: var(--crimson);
    font-size: 0.85rem;
    letter-spacing: 4px;
    text-transform: uppercase;
    border-bottom: 1px solid var(--border);
    padding-bottom: 0.5rem;
    margin: 2rem 0 1rem;
}

/* Data panels */
.panel {
    border: 1px solid var(--border);
    background: var(--bg2);
    padding: 1.5rem;
    margin-bottom: 1rem;
}

/* Architecture steps */
.arch-step {
    border-left: 2px solid var(--purple);
    padding: 0.8rem 1.2rem;
    margin-bottom: 0.8rem;
    background: var(--bg2);
    font-family: var(--mono);
    font-size: 0.9rem;
    color: var(--text);
}
.arch-step span {
    color: var(--crimson);
    margin-right: 8px;
}

/* Override streamlit dataframe */
.stDataFrame { border: 1px solid var(--border) !important; }

/* Matplotlib charts transparent */
.stpyplot > div { background: transparent !important; }
</style>
""", unsafe_allow_html=True)

# ── Load model artifacts ──────────────────────────────────────────────────────
@st.cache_resource
def load_artifacts():
    with open("model/phishing_model.pkl", "rb") as f:
        model = pickle.load(f)
    with open("model/feature_names.pkl", "rb") as f:
        feature_names = pickle.load(f)
    data = pd.read_csv("dataset_phishing.csv")
    return model, feature_names, data

model, feature_names, data = load_artifacts()

# ── Hero ──────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="hero">
    <div class="hero-title">CIPHERLENS</div>
    <div class="hero-sub">AI-Powered Phishing Detection System</div>
    <div class="hero-desc">
        CipherLens is a real-time phishing detection platform combining machine learning,
        live DOM analysis, and threat intelligence to protect users from malicious URLs.
        The system runs as a Chrome extension — analyzing every page you visit before it loads.
    </div>
    <br>
    <span class="tag">Random Forest</span>
    <span class="tag">SHAP Explainability</span>
    <span class="tag">VirusTotal API</span>
    <span class="tag">Chrome Extension</span>
    <span class="tag">FastAPI Backend</span>
    <span class="tag">94.95% Accuracy</span>
</div>
""", unsafe_allow_html=True)

# ── Key metrics ───────────────────────────────────────────────────────────────
st.markdown("""
<div class="metric-grid">
    <div class="metric-card">
        <span class="metric-value">94.95%</span>
        <div class="metric-label">Model Accuracy</div>
    </div>
    <div class="metric-card">
        <span class="metric-value">11,430</span>
        <div class="metric-label">Training Samples</div>
    </div>
    <div class="metric-card">
        <span class="metric-value">83</span>
        <div class="metric-label">Features Extracted</div>
    </div>
    <div class="metric-card">
        <span class="metric-value">60+</span>
        <div class="metric-label">VT Engines Checked</div>
    </div>
</div>
""", unsafe_allow_html=True)

# ── Model performance ─────────────────────────────────────────────────────────
st.markdown('<div class="section-header">Model Performance</div>', unsafe_allow_html=True)

col1, col2 = st.columns(2)

with col1:
    st.markdown('<div class="panel">', unsafe_allow_html=True)
    
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, confusion_matrix

    X = data.drop(columns=['url', 'status', 'google_index', 'page_rank',
                            'web_traffic', 'statistical_report'], errors='ignore')
    Y = data['status']
    X_train, X_test, Y_train, Y_test = train_test_split(
        X, Y, test_size=0.3, random_state=2)

    Y_pred = model.predict(X_test)
    report = classification_report(Y_test, Y_pred, output_dict=True)

    metrics_df = pd.DataFrame({
        'Class': ['Legitimate', 'Phishing'],
        'Precision': [
            round(report['legitimate']['precision'], 3),
            round(report['phishing']['precision'], 3)
        ],
        'Recall': [
            round(report['legitimate']['recall'], 3),
            round(report['phishing']['recall'], 3)
        ],
        'F1-Score': [
            round(report['legitimate']['f1-score'], 3),
            round(report['phishing']['f1-score'], 3)
        ]
    })
    st.dataframe(metrics_df, use_container_width=True, hide_index=True)
    st.markdown('</div>', unsafe_allow_html=True)

with col2:
    cm = confusion_matrix(Y_test, Y_pred)
    fig, ax = plt.subplots(figsize=(4, 3))
    fig.patch.set_facecolor('#110010')
    ax.set_facecolor('#110010')
    im = ax.imshow(cm, cmap='RdPu')
    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(['Legitimate', 'Phishing'], color='#e8d0f0', fontsize=9)
    ax.set_yticklabels(['Legitimate', 'Phishing'], color='#e8d0f0', fontsize=9)
    ax.set_xlabel('Predicted', color='#7a6080', fontsize=9)
    ax.set_ylabel('Actual', color='#7a6080', fontsize=9)
    ax.set_title('Confusion Matrix', color='#9b30a0', fontsize=10,
                 fontfamily='monospace')
    for i in range(2):
        for j in range(2):
            ax.text(j, i, str(cm[i, j]), ha='center', va='center',
                   color='white', fontsize=14, fontweight='bold')
    plt.tight_layout()
    st.pyplot(fig)
    plt.close()

# ── Feature importance ────────────────────────────────────────────────────────
st.markdown('<div class="section-header">Top Feature Importance</div>',
            unsafe_allow_html=True)

importances = model.feature_importances_
indices = np.argsort(importances)[::-1][:20]
top_features = [feature_names[i] for i in indices]
top_importances = [importances[i] * 100 for i in indices]

fig, ax = plt.subplots(figsize=(10, 5))
fig.patch.set_facecolor('#110010')
ax.set_facecolor('#110010')
colors = ['#dc143c' if i == 0 else '#9b30a0' if i < 5 else '#4a0040'
          for i in range(len(top_features))]
bars = ax.barh(top_features[::-1], top_importances[::-1], color=colors[::-1])
ax.set_xlabel('Importance (%)', color='#7a6080', fontsize=9)
ax.set_title('Top 20 Features by Importance', color='#9b30a0',
             fontsize=11, fontfamily='monospace')
ax.tick_params(colors='#e8d0f0', labelsize=8)
ax.spines[:].set_color('#4a0040')
plt.tight_layout()
st.pyplot(fig)
plt.close()

# ── SHAP examples ─────────────────────────────────────────────────────────────
st.markdown('<div class="section-header">SHAP Explainability — Real Examples</div>',
            unsafe_allow_html=True)

st.markdown("""
<div class="panel">
These explanations use real samples from the training dataset where ground truth is known.
Green bars push the prediction toward <b style="color:#9b30a0">Legitimate</b>.
Red bars push toward <b style="color:#dc143c">Phishing</b>.
</div>
""", unsafe_allow_html=True)

@st.cache_resource
def get_shap_explainer():
    return shap.TreeExplainer(model)

explainer = get_shap_explainer()

phishing_sample = X_test[Y_test == 'phishing'].iloc[[0]]
legit_sample    = X_test[Y_test == 'legitimate'].iloc[[0]]

col3, col4 = st.columns(2)

for col, sample, label, color in [
    (col3, phishing_sample, 'PHISHING EXAMPLE', '#dc143c'),
    (col4, legit_sample,    'LEGITIMATE EXAMPLE', '#9b30a0')
]:
    with col:
        st.markdown(f'<div style="font-family:monospace;color:{color};'
                   f'font-size:0.8rem;letter-spacing:2px;margin-bottom:8px">'
                   f'{label}</div>', unsafe_allow_html=True)
        shap_vals = explainer.shap_values(sample)
        if label == 'PHISHING EXAMPLE':
            vals = shap_vals[0, :, 1]
        else:
            vals = shap_vals[0, :, 0]

        impact = pd.DataFrame({
            'Feature': feature_names,
            'Impact': vals
        }).reindex(
            pd.Series(vals).abs().sort_values(ascending=True).index
        ).tail(15)

        fig, ax = plt.subplots(figsize=(5, 5))
        fig.patch.set_facecolor('#110010')
        ax.set_facecolor('#110010')
        colors_bar = ['#dc143c' if x < 0 else '#9b30a0'
                      for x in impact['Impact']]
        ax.barh(impact['Feature'], impact['Impact'], color=colors_bar)
        ax.axvline(x=0, color='#4a0040', linewidth=1)
        ax.tick_params(colors='#e8d0f0', labelsize=7)
        ax.spines[:].set_color('#4a0040')
        ax.set_title('Feature Impact', color=color,
                     fontsize=9, fontfamily='monospace')
        plt.tight_layout()
        st.pyplot(fig)
        plt.close()

# ── Architecture ──────────────────────────────────────────────────────────────
st.markdown('<div class="section-header">How It Works</div>',
            unsafe_allow_html=True)

st.markdown("""
<div class="arch-step"><span>01</span> User navigates to any URL in Chrome</div>
<div class="arch-step"><span>02</span> Chrome extension intercepts and reads fully rendered DOM</div>
<div class="arch-step"><span>03</span> 83 features extracted: URL structure + page content + domain intelligence</div>
<div class="arch-step"><span>04</span> FastAPI backend receives features and runs Random Forest inference</div>
<div class="arch-step"><span>05</span> VirusTotal API cross-checks URL against 60+ security engines</div>
<div class="arch-step"><span>06</span> Combined verdict returned to extension popup in real time</div>
""", unsafe_allow_html=True)

# ── Dataset stats ─────────────────────────────────────────────────────────────
st.markdown('<div class="section-header">Dataset Overview</div>',
            unsafe_allow_html=True)

col5, col6 = st.columns(2)

with col5:
    fig, ax = plt.subplots(figsize=(4, 3))
    fig.patch.set_facecolor('#110010')
    ax.set_facecolor('#110010')
    counts = data['status'].value_counts()
    ax.pie(counts.values,
           labels=['Legitimate', 'Phishing'],
           colors=['#9b30a0', '#dc143c'],
           autopct='%1.1f%%',
           textprops={'color': '#e8d0f0', 'fontsize': 10})
    ax.set_title('Class Distribution', color='#9b30a0',
                 fontsize=10, fontfamily='monospace')
    plt.tight_layout()
    st.pyplot(fig)
    plt.close()

with col6:
    st.markdown("""
    <div class="panel">
        <div style="font-family:monospace;color:#dc143c;font-size:0.8rem;
                    letter-spacing:2px;margin-bottom:1rem">DATASET FACTS</div>
        <table style="width:100%;font-size:0.9rem;color:#e8d0f0">
            <tr><td style="color:#7a6080;padding:4px 0">Total samples</td>
                <td style="font-family:monospace;color:#9b30a0">11,430</td></tr>
            <tr><td style="color:#7a6080;padding:4px 0">Legitimate URLs</td>
                <td style="font-family:monospace;color:#9b30a0">5,715</td></tr>
            <tr><td style="color:#7a6080;padding:4px 0">Phishing URLs</td>
                <td style="font-family:monospace;color:#dc143c">5,715</td></tr>
            <tr><td style="color:#7a6080;padding:4px 0">Features engineered</td>
                <td style="font-family:monospace;color:#9b30a0">87 → 83 used</td></tr>
            <tr><td style="color:#7a6080;padding:4px 0">Train / Test split</td>
                <td style="font-family:monospace;color:#9b30a0">70% / 30%</td></tr>
            <tr><td style="color:#7a6080;padding:4px 0">Source</td>
                <td style="font-family:monospace;color:#9b30a0">Kaggle 2023</td></tr>
        </table>
    </div>
    """, unsafe_allow_html=True)

# ── Footer ────────────────────────────────────────────────────────────────────
st.markdown("""
<div style="border-top:1px solid #4a0040;margin-top:3rem;padding-top:1rem;
            text-align:center;font-family:monospace;font-size:0.75rem;
            color:#4a0040;letter-spacing:2px">
    CIPHERLENS — AI COURSE PROJECT —
    <a href="https://github.com/neelamobaid/CipherLens"
       style="color:#9b30a0;text-decoration:none">GITHUB</a>
</div>
""", unsafe_allow_html=True)