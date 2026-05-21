import os
import re
import base64
import requests
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
print("VT KEY LOADED:", VT_API_KEY[:6] + "..." if VT_API_KEY else "NO KEY")


def check_virustotal(url):
    if not VT_API_KEY:
        return {
            "status": "skipped",
            "message": "VirusTotal check skipped. API key not configured."
        }

    headers = {
        "x-apikey": VT_API_KEY.strip()
    }

    try:
        submit_response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=10
        )

        if submit_response.status_code != 200:
            return {
                "status": "unavailable",
                "message": f"VirusTotal submit failed: {submit_response.status_code}"
            }

        analysis_id = submit_response.json()["data"]["id"]

        analysis_response = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=10
        )

        if analysis_response.status_code != 200:
            return {
                "status": "unavailable",
                "message": f"VirusTotal analysis failed: {analysis_response.status_code}"
            }

        stats = analysis_response.json()["data"]["attributes"]["stats"]

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        return {
            "status": "success",
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "message": f"VirusTotal: {malicious} malicious, {suspicious} suspicious detections."
        }

    except Exception as e:
        return {
            "status": "unavailable",
            "message": f"VirusTotal check unavailable: {str(e)}"
        }


def generate_attack_summary(level, flags):
    if level == "HIGH RISK":
        return "This input shows strong signs of phishing, scam, or malicious behavior."

    if level == "SUSPICIOUS":
        return "This input has warning signs and should be handled carefully."

    return "No major threat indicators were found from local analysis."


def analyze_single_url(url):
    flags = []
    score = 0

    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    full_url = url.lower()

    suspicious_words = [
        "login", "verify", "update", "secure", "account", "banking",
        "password", "wallet", "gift", "free", "bonus", "claim",
        "urgent", "alert", "support", "confirm"
    ]

    brand_words = [
        "paypal", "google", "microsoft", "facebook", "instagram",
        "amazon", "apple", "netflix", "whatsapp", "telegram"
    ]

    shorteners = [
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd",
        "cutt.ly", "shorturl.at", "rebrand.ly"
    ]

    if not url.startswith("https://"):
        flags.append("URL does not use HTTPS.")
        score += 15

    if any(word in full_url for word in suspicious_words):
        flags.append("Suspicious phishing-related keywords detected.")
        score += 20

    if any(brand in full_url for brand in brand_words):
        flags.append("Popular brand name detected, possible impersonation.")
        score += 15

    if any(shortener in domain for shortener in shorteners):
        flags.append("URL shortener detected.")
        score += 20

    if re.search(r"\d+\.\d+\.\d+\.\d+", domain):
        flags.append("IP address used instead of domain name.")
        score += 25

    if domain.count("-") >= 2:
        flags.append("Domain contains multiple hyphens.")
        score += 10

    if domain.count(".") >= 3:
        flags.append("Too many subdomains detected.")
        score += 10

    if "@" in url:
        flags.append("URL contains '@', which can hide the real destination.")
        score += 20

    if len(url) > 90:
        flags.append("URL is unusually long.")
        score += 10

    if not flags:
        flags.append("No obvious local URL red flags detected.")

    vt_result = check_virustotal(url)

    if vt_result.get("status") == "success":
        if vt_result.get("malicious", 0) > 0:
            score += 35
            flags.append("VirusTotal detected malicious reports.")

        if vt_result.get("suspicious", 0) > 0:
            score += 20
            flags.append("VirusTotal detected suspicious reports.")

    score = min(score, 100)

    if score >= 70:
        level = "HIGH RISK"
    elif score >= 35:
        level = "SUSPICIOUS"
    else:
        level = "SAFE"

    attack_summary_text = generate_attack_summary(level, flags)

    explanation = vt_result.get("message", "Local analysis completed.")

    recommendation = (
        "Avoid opening this link. Do not enter passwords, OTPs, or personal information."
        if level == "HIGH RISK"
        else "Be careful. Verify the sender/source before trusting this link."
        if level == "SUSPICIOUS"
        else "No major red flags found, but still verify the source."
    )

    return {
        "input": url,
        "type": "url",

        # frontend expected names
        "level": level,
        "score": score,
        "explanation": explanation,
        "red_flags": flags,
        "recommendation": recommendation,
        "attack_summary": {
            "attack_type": "Phishing / Malicious URL" if level != "SAFE" else "None detected",
            "attacker_goal": "Steal login details, personal data, or redirect the user" if level != "SAFE" else "None detected",
            "user_risk": attack_summary_text,
            "confidence": "High" if score >= 70 else "Medium" if score >= 35 else "Low"
        },

        # extra backend names, safe to keep
        "risk_level": level,
        "flags": flags,
        "description": explanation,
        "virustotal": vt_result
    }


def analyze_input(user_input):
    return analyze_single_url(user_input)