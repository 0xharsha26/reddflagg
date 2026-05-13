import json
import os
from datetime import datetime

HISTORY_FILE = "history.json"


def load_history():
    if not os.path.exists(HISTORY_FILE):
        return []

    try:
        with open(HISTORY_FILE, "r") as file:
            return json.load(file)
    except:
        return []


def save_scan(scan_type, input_value, result):
    history = load_history()

    entry = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scan_type": scan_type,
        "input": input_value[:300],
        "mode": result.get("mode"),
        "level": result.get("level"),
        "score": result.get("score"),
        "red_flags": result.get("red_flags", []),
        "recommendation": result.get("recommendation")
    }

    history.insert(0, entry)

    history = history[:50]

    with open(HISTORY_FILE, "w") as file:
        json.dump(history, file, indent=2)

    return entry
