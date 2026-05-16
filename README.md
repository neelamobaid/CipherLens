# CipherLens 
### AI-Powered Real-Time Phishing Detection System
**Live Dashboard:** [cipherlens.streamlit.app](https://your-actual-url.streamlit.app)

CipherLens is an end-to-end phishing detection platform that combines machine learning, 
live DOM analysis, and threat intelligence APIs to identify malicious URLs in real time. 
It consists of a Chrome extension for live browser protection, a FastAPI backend for 
ML inference, and a Streamlit dashboard for analysis and explainability.

---

## Architecture

**User visits a URL**  
↓ Chrome Extension extracts URL + DOM features (links, forms, scripts, favicons)  
↓ FastAPI Backend receives features → runs ML model + VirusTotal API  
↓ Extension displays verdict instantly  
↓ Streamlit Dashboard shows detailed analysis + SHAP explainability chart
---

## Key Features

- **Chrome Extension** — Real-time phishing detection as you browse, with instant verdict popup
- **ML-Based Detection** — Random Forest classifier trained on 11,430 modern phishing/legitimate URLs with 94.95% accuracy
- **Live DOM Feature Extraction** — Extension reads fully loaded page content for accurate feature computation
- **VirusTotal Integration** — Cross-checks every URL against 60+ security engines
- **SHAP Explainability** — Visual breakdown of exactly which features drove each prediction
- **FastAPI Backend** — REST API serving ML predictions, designed for extension and dashboard integration
- **Streamlit Dashboard** — Web interface for detailed URL analysis with feature breakdown

---

## Tech Stack

| Component | Technology |
|---|---|
| ML Model | Random Forest (scikit-learn) |
| Explainability | SHAP |
| Backend API | FastAPI + Uvicorn |
| Dashboard | Streamlit |
| Browser Extension | Chrome Manifest V3 |
| Threat Intelligence | VirusTotal API v3 |
| Feature Extraction | Python (requests, BeautifulSoup, python-whois) |
| Dataset | Web Page Phishing Detection Dataset (11,430 samples) |

---

## Project Structure

    CipherLens/
    ├── chrome_extension/       # Chrome extension (Manifest V3)
    │   ├── manifest.json
    │   ├── popup.html          # Extension UI
    │   ├── popup.js            # Handles API calls and UI updates
    │   └── content.js          # DOM feature extraction
    ├── model/
    │   ├── phishing_model.pkl  # Trained Random Forest model
    │   └── feature_names.pkl   # Feature names for inference
    ├── api.py                  # FastAPI backend
    ├── app.py                  # Streamlit dashboard
    ├── feature_extractor.py    # URL feature extraction
    ├── explainer.py            # SHAP explainability
    ├── predict.py              # ML inference engine
    ├── virustotal.py           # VirusTotal API integration
    ├── dataset_phishing.csv    # Training dataset
    ├── .env.example            # Environment variable template
    └── requirements.txt        # Python dependencies
---

## Setup Instructions

### 1. Clone the repository
```bash
git clone https://github.com/neelamobaid/CipherLens.git
cd CipherLens
```

### 2. Create virtual environment
```bash
python -m venv venv
venv\Scripts\activate  # Windows
source venv/bin/activate  # Mac/Linux
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Set up environment variables
```bash
cp .env.example .env
# Add your VirusTotal API key to .env
```

### 5. Start the FastAPI backend
```bash
uvicorn api:app --reload --port 8000
```

### 6. Start the Streamlit dashboard (optional)
```bash
streamlit run app.py
```

### 7. Load the Chrome extension
- Open Chrome → `chrome://extensions/`
- Enable Developer Mode
- Click Load Unpacked → select the `chrome_extension/` folder

---

## How It Works

### Feature Engineering
CipherLens extracts 83 features from each URL split across three categories:

- **URL Structure** (43 features) — length, special characters, subdomains, TLD analysis, digit ratios, phishing keyword hints, known brand impersonation detection
- **Page Content** (30 features) — hyperlink ratios, form analysis, iframe detection, favicon source, script sources, popup detection, right-click disabling
- **Domain Intelligence** (10 features) — WHOIS registration length, domain age, DNS record existence

### Why DOM-Based Extraction?
Most phishing detectors scrape pages using HTTP requests, which fail on JavaScript-heavy sites and get blocked by bot detection. CipherLens uses a Chrome extension to read the fully rendered DOM directly — the same data the browser sees — making feature extraction accurate and reliable.

### Model Performance
| Metric | Score |
|---|---|
| Accuracy | 94.95% |
| Precision (Phishing) | 0.95 |
| Recall (Phishing) | 0.95 |
| F1-Score | 0.95 |

Trained on a balanced dataset of 11,430 URLs (5,715 legitimate, 5,715 phishing).

---

## Known Limitations

- VirusTotal free tier is rate-limited to 4 requests/minute
- Unusual TLDs (.college, .xyz) on legitimate sites may produce false positives
- WHOIS lookups can fail or timeout for some domains
- Backend must be running locally for the Chrome extension to work (not yet cloud-deployed)

---

## Future Improvements

- Cloud deployment so the extension works without a local backend
- Retraining pipeline with continuously updated phishing feeds from PhishTank
- NLP-based social engineering detection in email content
- Firefox extension support

---

## Dataset

This project uses the 
[Web Page Phishing Detection Dataset](https://www.kaggle.com/datasets/shashwatwork/web-page-phishing-detection-dataset) 
from Kaggle — 11,430 URLs with 87 engineered features, balanced equally between 
phishing and legitimate samples.

---

## Author

**Neelam Obaid**  
Cybersecurity Enthusiast | AI Course Project  
[GitHub](https://github.com/neelamobaid)
