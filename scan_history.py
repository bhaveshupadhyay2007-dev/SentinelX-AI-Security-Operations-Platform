import json
import os
from datetime import datetime


HISTORY_FILE = "data/scan_history.json"


def save_scan(ioc, detection, risk, explanation):
    """
    Save a completed IOC analysis to scan history.
    """

    os.makedirs("data", exist_ok=True)

    scan_record = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ioc": ioc,
        "classification": detection.get("classification", "UNKNOWN"),
        "risk_score": risk.get("risk_score", 0),
        "severity": risk.get("severity", "LOW"),
        "decision": risk.get("decision", "ALLOW"),
        "indicators": explanation.get("indicators", []),
        "summary": explanation.get("summary", "")
    }

    history = []

    if os.path.exists(HISTORY_FILE):

        try:

            with open(HISTORY_FILE, "r", encoding="utf-8") as file:
                history = json.load(file)

        except (json.JSONDecodeError, OSError):

            history = []


    history.append(scan_record)


    with open(HISTORY_FILE, "w", encoding="utf-8") as file:

        json.dump(
            history,
            file,
            indent=4
        )


def get_scan_history():
    """
    Return all stored scan records.
    """

    if not os.path.exists(HISTORY_FILE):
        return []


    try:

        with open(HISTORY_FILE, "r", encoding="utf-8") as file:
            return json.load(file)

    except (json.JSONDecodeError, OSError):

        return []
