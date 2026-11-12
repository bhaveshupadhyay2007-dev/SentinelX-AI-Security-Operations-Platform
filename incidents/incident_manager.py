import json
import os
import uuid
from datetime import datetime


INCIDENT_FILE = "data/incidents.json"


def _load_incidents():

    if not os.path.exists(INCIDENT_FILE):
        return []

    try:

        with open(INCIDENT_FILE, "r", encoding="utf-8") as file:
            return json.load(file)

    except (json.JSONDecodeError, OSError):

        return []


def _save_incidents(incidents):

    os.makedirs("data", exist_ok=True)

    with open(INCIDENT_FILE, "w", encoding="utf-8") as file:

        json.dump(
            incidents,
            file,
            indent=4
        )


def create_incident(ioc, detection, risk, explanation):

    incidents = _load_incidents()

    incident = {

        "incident_id":
            "INC-" + uuid.uuid4().hex[:8].upper(),

        "created_at":
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),

        "ioc":
            ioc,

        "classification":
            detection.get("classification", "UNKNOWN"),

        "risk_score":
            risk.get("risk_score", 0),

        "severity":
            risk.get("severity", "LOW"),

        "decision":
            risk.get("decision", "ALLOW"),

        "status":
            "OPEN",

        "indicators":
            explanation.get("indicators", []),

        "summary":
            explanation.get("summary", "")

    }

    incidents.append(incident)

    _save_incidents(incidents)

    return incident


def get_incidents():

    return _load_incidents()


def update_incident_status(incident_id, new_status):

    incidents = _load_incidents()

    allowed_statuses = [
        "OPEN",
        "INVESTIGATING",
        "RESOLVED"
    ]

    if new_status not in allowed_statuses:
        return None


    for incident in incidents:

        if incident["incident_id"] == incident_id:

            incident["status"] = new_status

            incident["updated_at"] = datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            _save_incidents(incidents)

            return incident


    return None
