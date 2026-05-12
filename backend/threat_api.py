import requests
import base64

import os

VT_API_KEY = os.getenv("VT_API_KEY")

def url_to_id(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def check_virustotal(url):
    try:
        url_id = url_to_id(url)

        headers = {
            "x-apikey": VT_API_KEY
        }

        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers
        )

        if response.status_code != 200:
            return {
                "vt_error": f"VirusTotal API error: {response.status_code}"
            }

        data = response.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        return {
            "vt_malicious": malicious,
            "vt_suspicious": suspicious,
            "vt_stats": stats
        }

    except Exception as e:
        return {
            "vt_error": str(e)
        }
