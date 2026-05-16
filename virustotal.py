import os
import requests
import base64
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def check_url_virustotal(url):
    try:
        # Encode URL to base64 as required by VirusTotal API v3
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        headers = {"x-apikey": API_KEY}
        
        # First submit the URL for analysis
        submit_response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=10
        )
        
        # Then fetch the report
        report_response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=10
        )
        
        if report_response.status_code == 200:
            data = report_response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            total = malicious + suspicious + harmless
            
            return {
                "malicious_engines": malicious,
                "suspicious_engines": suspicious,
                "harmless_engines": harmless,
                "total_engines": total,
                "vt_verdict": "PHISHING" if malicious > 0 else "CLEAN"
            }
        else:
            return None
            
    except Exception as e:
        return None
if __name__ == "__main__":
    result = check_url_virustotal("http://google.com")
    print(result)