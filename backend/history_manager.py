import json
import os
from datetime import datetime

HISTORY_FILE = "history.json"


def load_history():
    """Loads all scans from the history file."""
    if not os.path.exists(HISTORY_FILE):
        return []

    try:
        with open(HISTORY_FILE, "r") as file:
            return json.load(file)
    except:
        return []


def save_to_history(scan_input, result):
    """Saves a new scan entry to the history file, capping at 50 entries."""
    history = load_history()

    # Truncate input message in history to keep visualization clean
    cleaned_input = scan_input
    if len(scan_input) > 200:
        cleaned_input = scan_input[:200] + "..."

    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "input": cleaned_input,
        "mode": result.get("mode", "TEXT_ANALYSIS"),
        "score": result.get("score", 0),
        "level": result.get("level", "LOW RISK"),
        "explanation": result.get("explanation", ""),
        "red_flags": result.get("red_flags", []),
        "recommendation": result.get("recommendation", "")
    }

    history.insert(0, entry)
    history = history[:50]  # Cap history

    try:
        with open(HISTORY_FILE, "w") as file:
            json.dump(history, file, indent=2)
    except Exception as e:
        print(f"Failed to write history file: {e}")

    return entry


def clear_history_file():
    """Clears all scan history entries."""
    try:
        with open(HISTORY_FILE, "w") as file:
            json.dump([], file, indent=2)
        return []
    except Exception as e:
        print(f"Failed to clear history file: {e}")
        return []


def generate_stats():
    """Aggregates and generates threat statistics based on scan history."""
    history = load_history()
    total_scans = len(history)

    high_risk = sum(1 for item in history if item.get("level") == "HIGH RISK")
    suspicious = sum(1 for item in history if item.get("level") == "SUSPICIOUS")
    low_risk = sum(1 for item in history if item.get("level") == "LOW RISK")

    latest_scan = history[0] if history else None

    return {
        "total_scans": total_scans,
        "high_risk": high_risk,
        "suspicious": suspicious,
        "low_risk": low_risk,
        "latest_scan": latest_scan
    }
