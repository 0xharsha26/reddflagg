import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "urgent", "immediately", "verify", "suspended", "locked",
    "password", "reset", "confirm", "account", "login",
    "click here", "limited time", "security alert",
    "unusual activity", "payment failed", "invoice attached",
    "winner", "prize", "claim", "bank", "otp"
]

BRAND_KEYWORDS = [
    "microsoft", "google", "apple", "paypal", "amazon",
    "netflix", "instagram", "facebook", "whatsapp",
    "bank", "hdfc", "sbi", "icici"
]

SAFE_DOMAINS = [
    "google.com", "microsoft.com", "apple.com", "paypal.com",
    "amazon.com", "instagram.com", "facebook.com", "whatsapp.com",
    "netflix.com", "hdfcbank.com", "sbi.co.in", "icicibank.com"
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".click", ".link", ".tk", ".ml", ".ga", ".cf",
    ".work", ".support", ".rest", ".zip", ".mov"
]


def extract_urls(text):
    return re.findall(r'https?://[^\s]+|www\.[^\s]+', text)


def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


def get_domain(url):
    parsed = urlparse(normalize_url(url))
    return parsed.netloc.lower().replace("www.", "")


def is_safe_brand_domain(domain):
    return any(domain == safe or domain.endswith("." + safe) for safe in SAFE_DOMAINS)


def analyze_single_url(url):
    domain = get_domain(url)
    score = 0
    flags = []

    if not domain:
        return {
            "url": url,
            "domain": "Invalid URL",
            "score": 100,
            "level": "HIGH RISK",
            "red_flags": ["Invalid or malformed URL"],
            "recommendation": "Do not open this link."
        }

    if domain.startswith("xn--"):
        score += 30
        flags.append("Punycode domain detected, possible lookalike attack")

    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 25
        flags.append(f"Suspicious domain extension detected: {domain}")

    if "-" in domain:
        score += 15
        flags.append(f"Hyphenated domain detected: {domain}")

    if len(domain) > 35:
        score += 15
        flags.append(f"Unusually long domain detected: {domain}")

    digit_count = sum(char.isdigit() for char in domain)
    if digit_count >= 3:
        score += 15
        flags.append("Multiple numbers detected in domain")

    brand_hits = [brand for brand in BRAND_KEYWORDS if brand in domain]

    if brand_hits and not is_safe_brand_domain(domain):
        score += 35
        flags.append(f"Possible brand impersonation: {', '.join(brand_hits)}")

    suspicious_words = ["login", "verify", "secure", "account", "update", "support", "billing"]
    found_words = [word for word in suspicious_words if word in domain]

    if found_words:
        score += len(found_words) * 8
        flags.append(f"Sensitive action words in domain: {', '.join(found_words)}")

    score = min(score, 100)

    if score >= 70:
        level = "HIGH RISK"
        recommendation = "Do not open this link. Visit the official website manually instead."
    elif score >= 35:
        level = "SUSPICIOUS"
        recommendation = "Be careful. Verify the domain before opening."
    else:
        level = "LOW RISK"
        recommendation = "No strong suspicious URL patterns detected."

    return {
        "url": url,
        "domain": domain,
        "score": score,
        "level": level,
        "red_flags": flags if flags else ["No strong URL red flags detected"],
        "recommendation": recommendation
    }


def analyze_urls(urls):
    findings = []

    for url in urls:
        result = analyze_single_url(url)
        for flag in result["red_flags"]:
            if "No strong" not in flag:
                findings.append(flag)

    return findings


def analyze_text(text):
    text_lower = text.lower()
    score = 0
    red_flags = []

    keyword_hits = []

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in text_lower:
            keyword_hits.append(keyword)

    if keyword_hits:
        score += len(keyword_hits) * 8
        red_flags.append(f"Suspicious wording detected: {', '.join(keyword_hits[:8])}")

    if "click here" in text_lower:
        score += 15
        red_flags.append("Uses 'click here' style call-to-action")

    if "urgent" in text_lower or "immediately" in text_lower:
        score += 15
        red_flags.append("Creates urgency or panic")

    if "password" in text_lower or "otp" in text_lower:
        score += 20
        red_flags.append("Mentions sensitive credentials or OTP")

    urls = extract_urls(text)
    url_findings = analyze_urls(urls)

    if urls:
        score += 10
        red_flags.append(f"Contains {len(urls)} link(s)")

    if url_findings:
        score += len(url_findings) * 12
        red_flags.extend(url_findings)

    if re.search(r'\bfree\b|\bprize\b|\bwinner\b|\bclaim\b', text_lower):
        score += 15
        red_flags.append("Uses reward/prize style bait language")

    score = min(score, 100)

    if score >= 70:
        level = "HIGH RISK"
        recommendation = "Do not click links or download attachments. Verify directly through the official website or app."
    elif score >= 40:
        level = "SUSPICIOUS"
        recommendation = "Be careful. Check the sender, links, and request before taking action."
    else:
        level = "LOW RISK"
        recommendation = "No major phishing indicators detected, but still verify unknown messages."

    return {
        "mode": "TEXT_ANALYSIS",
        "score": score,
        "level": level,
        "red_flags": red_flags if red_flags else ["No strong red flags detected"],
        "explanation": generate_explanation(level),
        "recommendation": recommendation,
        "urls_found": urls
    }


def analyze_input(text):
    urls = extract_urls(text.strip())

    if len(urls) == 1 and text.strip() == urls[0]:
        result = analyze_single_url(urls[0])
        result["mode"] = "URL_ANALYSIS"
        result["explanation"] = generate_url_explanation(result["level"], result["domain"])
        return result

    return analyze_text(text)


def generate_explanation(level):
    if level == "HIGH RISK":
        return "This message shows multiple phishing indicators such as urgency, suspicious wording, credential-related language, or risky links."
    elif level == "SUSPICIOUS":
        return "This message contains some warning signs. It may not be confirmed phishing, but it should be treated carefully."
    else:
        return "This message does not show strong phishing patterns based on the current analysis."


def generate_url_explanation(level, domain):
    if level == "HIGH RISK":
        return f"The domain {domain} shows multiple suspicious URL patterns commonly used in phishing or impersonation attempts."
    elif level == "SUSPICIOUS":
        return f"The domain {domain} contains some warning signs and should be verified before opening."
    else:
        return f"The domain {domain} does not show strong suspicious URL patterns in this basic analysis."
