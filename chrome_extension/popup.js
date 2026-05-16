const API_URL = "http://127.0.0.1:8000/analyze";

document.addEventListener('DOMContentLoaded', () => {
    // Get current tab URL
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const url = tabs[0].url;
        document.getElementById('currentUrl').textContent = url;

        document.getElementById('scanBtn').addEventListener('click', () => {
            analyzeURL(tabs[0], url);
        });
    });
});

function analyzeURL(tab, url) {
    const btn = document.getElementById('scanBtn');
    const loading = document.getElementById('loading');
    const result = document.getElementById('result');
    const error = document.getElementById('error');

    // Reset UI
    btn.disabled = true;
    loading.style.display = 'block';
    result.style.display = 'none';
    error.style.display = 'none';

    // Ask content script to extract DOM features
    chrome.tabs.sendMessage(tab.id, { action: "extractFeatures" }, (domResponse) => {
        const dom_features = domResponse ? domResponse.features : {};

        // Send to backend API
        fetch(API_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url, dom_features })
        })
        .then(res => res.json())
        .then(data => {
            showResult(data);
        })
        .catch(err => {
            error.textContent = "Cannot connect to CipherLens backend. Make sure the API is running on port 8000.";
            error.style.display = 'block';
        })
        .finally(() => {
            btn.disabled = false;
            loading.style.display = 'none';
        });
    });
}

function showResult(data) {
    const result = document.getElementById('result');
    const verdictBox = document.getElementById('verdictBox');
    const mlConfidence = document.getElementById('mlConfidence');
    const mlVerdict = document.getElementById('mlVerdict');
    const vtFill = document.getElementById('vtFill');
    const vtNumbers = document.getElementById('vtNumbers');

    // Verdict
    const isPhishing = data.final_verdict === "PHISHING";
    verdictBox.textContent = isPhishing ? "⚠ PHISHING DETECTED" : "✓ LEGITIMATE";
    verdictBox.className = `verdict ${isPhishing ? 'phishing' : 'legitimate'}`;

    // ML stats
    mlConfidence.textContent = `${data.ml_confidence}%`;
    mlConfidence.className = `value ${isPhishing ? 'danger' : 'safe'}`;
    mlVerdict.textContent = data.ml_prediction;
    mlVerdict.className = `value ${isPhishing ? 'danger' : 'safe'}`;

    // VirusTotal bar
    if (data.vt_result && data.vt_result.total_engines > 0) {
        const malicious = data.vt_result.malicious_engines;
        const total = data.vt_result.total_engines;
        const pct = Math.round((malicious / total) * 100);
        vtFill.style.width = `${pct}%`;
        vtFill.className = `vt-fill ${malicious > 0 ? 'danger' : ''}`;
        vtNumbers.textContent = `${malicious} malicious / ${total} engines`;
    } else {
        vtNumbers.textContent = "No VirusTotal data available";
    }

    result.style.display = 'block';
}