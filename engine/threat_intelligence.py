import json
import os

THREAT_FILE = "data/threats.json"


def load_threats():
    """
    Load locally stored threat-intelligence records.
    """

    if not os.path.exists(THREAT_FILE):
        return []

    try:
        with open(THREAT_FILE, "r", encoding="utf-8-sig") as file:
            return json.load(file)

    except (json.JSONDecodeError, OSError):
        return []


def lookup_ioc(ioc):
    """
    Check whether an IOC exists in the local
    SentinelX threat-intelligence database.
    """

    ioc = ioc.strip().lower()

    threats = load_threats()

    for threat in threats:

        stored_ioc = threat.get("ioc", "").strip().lower()

        if stored_ioc == ioc:
            return {
                "found": True,
                "ioc": threat.get("ioc"),
                "type": threat.get("type", "UNKNOWN"),
                "threat": threat.get("threat", "UNKNOWN"),
                "severity": threat.get("severity", "UNKNOWN"),
                "source": threat.get(
                    "source",
                    "SentinelX Local Threat Intelligence"
                ),
                "description": threat.get("description", "")
            }

    return {
        "found": False,
        "ioc": ioc
    }

