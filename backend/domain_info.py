import whois
from datetime import datetime


def clean_date(value):
    if isinstance(value, list):
        value = value[0] if value else None

    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d")

    if value:
        return str(value)

    return "Unknown"


def calculate_domain_age(created_date):
    if isinstance(created_date, list):
        created_date = created_date[0] if created_date else None

    if not isinstance(created_date, datetime):
        return {
            "days": None,
            "label": "Unknown"
        }

    age_days = (datetime.now() - created_date).days

    if age_days <= 30:
        label = "Very New"
    elif age_days <= 180:
        label = "New"
    elif age_days <= 365:
        label = "Less than 1 year"
    else:
        label = "Established"

    return {
        "days": age_days,
        "label": label
    }


def get_domain_intelligence(domain):
    try:
        data = whois.whois(domain)

        created_date = data.creation_date
        expiry_date = data.expiration_date
        registrar = data.registrar
        country = data.country

        age = calculate_domain_age(created_date)

        return {
            "domain": domain,
            "registrar": registrar or "Unknown",
            "country": country or "Unknown",
            "created_date": clean_date(created_date),
            "expiry_date": clean_date(expiry_date),
            "domain_age_days": age["days"],
            "domain_age_label": age["label"],
            "error": None
        }

    except Exception as e:
        return {
            "domain": domain,
            "registrar": "Unknown",
            "country": "Unknown",
            "created_date": "Unknown",
            "expiry_date": "Unknown",
            "domain_age_days": None,
            "domain_age_label": "Unknown",
            "error": str(e)
        }