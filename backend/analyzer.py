import os
import re
import base64
import requests
from urllib.parse import urlparse
from dotenv import load_dotenv
from domain_info import get_domain_intelligence

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
print("VT KEY LOADED:", VT_API_KEY[:6] + "..." if VT_API_KEY else "NO KEY")


def check_virustotal(url):
    if not VT_API_KEY or VT_API_KEY == "your_virustotal_api_key_here":
        return {
            "status": "skipped",
            "message": "VirusTotal check skipped. API key not configured."
        }

    headers = {
        "x-apikey": VT_API_KEY.strip()
    }

    try:
        # Generate safe b64 URL identifier (VirusTotal v3 standard)
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        # Try fetching analysis details directly (avoids costly double requests)
        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=10
        )

        if response.status_code == 200:
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
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
        
        # If not analyzed previously (404), submit the URL for scanning
        submit_response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=10
        )

        if submit_response.status_code == 200:
            analysis_id = submit_response.json()["data"]["id"]
            return {
                "status": "submitted",
                "analysis_id": analysis_id,
                "message": "URL submitted to VirusTotal for active scanning."
            }

        return {
            "status": "unavailable",
            "message": f"VirusTotal query failed: {response.status_code}"
        }

    except Exception as e:
        return {
            "status": "unavailable",
            "message": f"VirusTotal lookup error: {str(e)}"
        }


def generate_attack_summary(level, flags):
    if level == "HIGH RISK":
        return "This input shows strong signs of phishing, active scam lures, or malicious URL redirections."
    if level == "SUSPICIOUS":
        return "This input contains warning signs and potential threats. Exercise extreme caution."
    return "No significant indicators of phishing or malicious activity detected."


def analyze_single_url(url):
    flags = []
    score = 0

    # Ensure URL prefix exists for parsing
    working_url = url
    if not url.startswith(("http://", "https://")):
        working_url = "http://" + url

    parsed = urlparse(working_url)
    domain = parsed.netloc.lower() or parsed.path.lower()
    full_url = url.lower()

    suspicious_words = [
        "login", "verify", "update", "secure", "account", "banking",
        "password", "wallet", "gift", "free", "bonus", "claim",
        "urgent", "alert", "support", "confirm", "signin", "recovery"
    ]

    brand_words = [
        "paypal", "google", "microsoft", "facebook", "instagram",
        "amazon", "apple", "netflix", "whatsapp", "telegram", "chase", "bankofamerica"
    ]

    shorteners = [
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd",
        "cutt.ly", "shorturl.at", "rebrand.ly"
    ]

    # 1. Local URL Lexical Checks
    if not url.startswith("https://"):
        flags.append("Security: URL does not use secure HTTPS encryption.")
        score += 15

    if any(word in full_url for word in suspicious_words):
        flags.append("Lexical: Phishing keyword (e.g. login, verify, account) detected in URL path.")
        score += 20

    if any(brand in domain for brand in brand_words) and not any(domain.endswith(f"{brand}.com") or domain == brand for brand in brand_words):
        flags.append("Spoofing: Popular brand impersonation keyword detected in subdomains/domain.")
        score += 25

    if any(shortener in domain for shortener in shorteners):
        flags.append("Evasion: URL shortener masking the true destination page.")
        score += 20

    if re.search(r"\d+\.\d+\.\d+\.\d+", domain):
        flags.append("Infrastructure: Raw IP address utilized as domain name.")
        score += 25

    if domain.count("-") >= 2:
        flags.append("Domain: Excessive hyphens in domain name (common in typo-squatting).")
        score += 10

    if domain.count(".") >= 3:
        flags.append("Domain: Too many subdomains detected (phishing subdomain abuse).")
        score += 10

    if "@" in url:
        flags.append("Evasion: URL contains '@' character, typically used to hide real landing host.")
        score += 25

    if len(url) > 90:
        flags.append("Domain: URL length is unusually long (potential evasion).")
        score += 10

    # 2. Domain WHOIS Intelligence Integration
    clean_domain = domain.split(":")[0]  # Strip port if any
    clean_domain = re.sub(r"^www\.", "", clean_domain)
    
    domain_intel = get_domain_intelligence(clean_domain)
    
    if domain_intel.get("error") is None:
        age_label = domain_intel.get("domain_age_label", "Unknown")
        age_days = domain_intel.get("domain_age_days")
        
        if age_label == "Very New":
            flags.append(f"Domain Age: This domain was created very recently ({age_days} days ago). Extreme phishing risk!")
            score += 35
        elif age_label == "New":
            flags.append(f"Domain Age: This domain is relatively new ({age_days} days ago).")
            score += 15
    else:
        # If WHOIS fails (e.g. invalid TLD or lookup failure), it might be a suspicious custom domain
        domain_intel = {
            "domain": clean_domain,
            "registrar": "Unknown/Private",
            "country": "Unknown",
            "created_date": "Unknown",
            "expiry_date": "Unknown",
            "domain_age_days": None,
            "domain_age_label": "Unknown"
        }

    # 3. VirusTotal Integration Checks
    vt_result = check_virustotal(url)
    if vt_result.get("status") == "success":
        malicious = vt_result.get("malicious", 0)
        suspicious = vt_result.get("suspicious", 0)
        
        if malicious > 0:
            score += 35
            flags.append(f"VirusTotal: Flagged as malicious by {malicious} security vendors.")
        elif suspicious > 0:
            score += 20
            flags.append(f"VirusTotal: Flagged as suspicious by {suspicious} security vendors.")

    score = min(score, 100)

    # Risk Categorization
    if score >= 70:
        level = "HIGH RISK"
    elif score >= 35:
        level = "SUSPICIOUS"
    else:
        level = "LOW RISK"

    attack_summary_text = generate_attack_summary(level, flags)
    explanation = vt_result.get("message", "Local lexical and WHOIS evaluation completed.")

    recommendation = (
        "Do NOT open this link. Do not submit credentials, OTPs, bank numbers, or personal info under any circumstance."
        if level == "HIGH RISK"
        else "Be careful. Independently verify the domain and sender before engaging."
        if level == "SUSPICIOUS"
        else "No major threat parameters hit, but always inspect the source."
    )

    return {
        "input": url,
        "type": "url",
        "level": level,
        "score": score,
        "explanation": explanation,
        "red_flags": flags,
        "recommendation": recommendation,
        "attack_summary": {
            "attack_type": "Phishing / Typo-squatting URL" if level != "LOW RISK" else "None detected",
            "attacker_goal": "Steal credentials, redirect user, or execute malicious scripts" if level != "LOW RISK" else "None",
            "user_risk": attack_summary_text,
            "confidence": "High" if score >= 70 else "Medium" if score >= 35 else "Low"
        },
        "domain_intelligence": domain_intel,
        "virustotal": vt_result
    }


def analyze_text_lexically(text):
    flags = []
    score = 0
    text_lower = text.lower()

    urgency_words = [
        "urgent", "immediately", "action required", "suspended", "blocked", 
        "deactivated", "unauthorized", "restrict", "compromised", "limited", "alert",
        "expires", "final notice", "security breach"
    ]
    financial_words = [
        "lottery", "prize", "cash", "bonus", "winner", "millions", "gift card", 
        "crypto", "refund", "won", "free money", "claim your", "inheritance"
    ]
    credential_words = [
        "verify", "update details", "security check", "pin code", "otp", "login now",
        "confirm password", "bank details", "identity confirmation", "reset link"
    ]
    generic_greetings = [
        "dear customer", "dear user", "dear sir", "dear madam", "valued customer",
        "dear client", "attention user"
    ]

    urgency_hits = [w for w in urgency_words if w in text_lower]
    financial_hits = [w for w in financial_words if w in text_lower]
    credential_hits = [w for w in credential_words if w in text_lower]
    greeting_hits = [w for w in generic_greetings if w in text_lower]

    if urgency_hits:
        flags.append(f"Lexical: Extreme urgency or coercive text detected ({', '.join(urgency_hits)}).")
        score += 25
    if financial_hits:
        flags.append(f"Lexical: Financial bait or prize lure detected ({', '.join(financial_hits)}).")
        score += 25
    if credential_hits:
        flags.append(f"Lexical: Solicitations for credentials, verification, or OTP details ({', '.join(credential_hits)}).")
        score += 30
    if greeting_hits:
        flags.append("Lexical: Impersonal greeting typical of bulk phishing campaigns.")
        score += 15

    # SCAN check for text indicators
    if len(re.findall(r'[A-Z]{4,}', text)) > 3:
        flags.append("Lexical: Abnormally high use of uppercase words (unprofessional urgency).")
        score += 10

    if text_lower.count("!!") >= 2 or text_lower.count("??") >= 2:
        flags.append("Lexical: Excessive punctuation (!!!) indicative of aggressive scamming.")
        score += 10

    return score, flags


def analyze_input(user_input):
    user_input = user_input.strip()
    
    # Check if the entire input is simply a single clean URL
    url_regex = re.compile(
        r'^(?:https?://)?' 
        r'(?:www\.)?' 
        r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' 
        r'(?::\d+)?' 
        r'(?:/[^\s]*)?$', 
        re.IGNORECASE
    )
    
    if url_regex.match(user_input):
        # Path A: Single URL Analysis
        return analyze_single_url(user_input)

    # Path B: Text Analysis
    # 1. Extract nested URLs
    nested_url_regex = re.compile(
        r'https?://[^\s]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?::\d+)?/[^\s]*', 
        re.IGNORECASE
    )
    extracted_urls = nested_url_regex.findall(user_input)

    # 2. Analyze the body text lexically
    text_score, text_flags = analyze_text_lexically(user_input)

    # 3. Analyze nested URLs if present
    url_scans = []
    max_url_score = 0
    highest_risk_url = None

    for url in extracted_urls:
        # Standardize URL strings
        clean_url = url.strip(".,()[]{}'\"")
        if not clean_url.startswith(("http://", "https://")):
            # Only treat it as URL if it starts with standard or is clean domain
            if "." in clean_url and not clean_url.endswith("."):
                clean_url = "http://" + clean_url
            else:
                continue

        url_analysis = analyze_single_url(clean_url)
        url_scans.append(url_analysis)
        
        if url_analysis["score"] > max_url_score:
            max_url_score = url_analysis["score"]
            highest_risk_url = url_analysis

    # 4. Integrate scores
    final_flags = list(text_flags)
    final_score = text_score

    domain_intel = None
    virustotal = None

    if highest_risk_url:
        domain_intel = highest_risk_url.get("domain_intelligence")
        virustotal = highest_risk_url.get("virustotal")
        
        # Append URL specific flags
        for f in highest_risk_url["red_flags"]:
            if "No obvious local URL red flags" not in f:
                final_flags.append(f"Nested URL ({highest_risk_url['input']}): {f}")

        # Combine scores smartly (Segment gateway model)
        if highest_risk_url["score"] >= 70 and text_score >= 30:
            # Dangerous URL + Phishing language = High Certainty Phishing
            final_score = max(highest_risk_url["score"], text_score) + 15
        else:
            final_score = max(highest_risk_url["score"], text_score)
    else:
        # No URL nested
        if not final_flags:
            final_flags.append("No obvious lexical phishing patterns detected.")

    final_score = min(final_score, 100)

    # Risk Categorization
    if final_score >= 70:
        level = "HIGH RISK"
    elif final_score >= 35:
        level = "SUSPICIOUS"
    else:
        level = "LOW RISK"

    attack_summary_text = generate_attack_summary(level, final_flags)
    
    explanation = (
        f"Analyzed text content. Found {len(extracted_urls)} embedded URLs. "
        + (highest_risk_url.get("explanation", "") if highest_risk_url else "No suspicious URLs embedded.")
    )

    recommendation = (
        "Do NOT reply, interact, or click any links in this message. Delete this text and flag it as spam."
        if level == "HIGH RISK"
        else "Be cautious. The message exhibits indicators of social engineering or unverified links."
        if level == "SUSPICIOUS"
        else "No major indicators of phishing detected, but still treat unsolicited messages with care."
    )

    return {
        "input": user_input[:500] + ("..." if len(user_input) > 500 else ""),
        "type": "text",
        "level": level,
        "score": final_score,
        "explanation": explanation,
        "red_flags": final_flags,
        "recommendation": recommendation,
        "attack_summary": {
            "attack_type": "Social Engineering Phishing Text" if level != "LOW RISK" else "None detected",
            "attacker_goal": "Bait user into clicking links, revealing credentials, or transmitting money" if level != "LOW RISK" else "None",
            "user_risk": attack_summary_text,
            "confidence": "High" if final_score >= 70 else "Medium" if final_score >= 35 else "Low"
        },
        "domain_intelligence": domain_intel,
        "virustotal": virustotal,
        "url_scans_count": len(extracted_urls)
    }