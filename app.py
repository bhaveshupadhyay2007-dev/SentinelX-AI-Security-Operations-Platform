from flask import Flask, render_template, request, jsonify

from engine.detector import analyze_ioc
from engine.risk_engine import calculate_risk
from engine.explainability import generate_explanation
from engine.threat_intelligence import lookup_ioc

from scan_history import save_scan, get_scan_history

from incidents.incident_manager import (
    create_incident,
    get_incidents,
    update_incident_status
)


app = Flask(__name__)


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/scanner")
def scanner_page():
    return render_template("scanner.html")


@app.route("/history")
def history_page():
    return render_template("history.html")


@app.route("/api/analyze", methods=["POST"])
def analyze():

    data = request.get_json() or {}

    ioc = data.get("ioc", "").strip()

    if not ioc:
        return jsonify({
            "error": "IOC is required"
        }), 400

    # Detection Engine
    detection = analyze_ioc(ioc)

    # Risk Engine
    risk = calculate_risk(detection)

    # Explainability Engine
    explanation = generate_explanation(
        detection,
        risk
    )

    # Threat Intelligence Lookup
    threat_intelligence = lookup_ioc(ioc)

    # Save scan history
    save_scan(
        ioc,
        detection,
        risk,
        explanation
    )

    incident = None

    if risk["risk_score"] >= 50:

        incident = create_incident(
            ioc,
            detection,
            risk,
            explanation
        )

    return jsonify({

        "ioc": ioc,

        "classification":
            detection["classification"],

        "risk_score":
            risk["risk_score"],

        "severity":
            risk["severity"],

        "decision":
            risk["decision"],

        "indicators":
            explanation["indicators"],

        "summary":
            explanation["summary"],

        "threat_intelligence":
            threat_intelligence,

        "incident":
            incident

    })


@app.route("/api/history", methods=["GET"])
def history():

    return jsonify(
        get_scan_history()
    )


@app.route("/api/analytics", methods=["GET"])
def analytics():

    history = get_scan_history()
    incidents = get_incidents()

    total_scans = len(history)

    threats_detected = sum(
        1
        for scan in history
        if scan.get("classification") in [
            "SUSPICIOUS",
            "MALICIOUS"
        ]
    )

    alerts = sum(
        1
        for scan in history
        if scan.get("decision") == "ALERT"
    )

    blocked = sum(
        1
        for scan in history
        if scan.get("decision") == "BLOCK"
    )

    allowed = sum(
        1
        for scan in history
        if scan.get("decision") == "ALLOW"
    )

    severity_counts = {
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0
    }

    for scan in history:

        severity = scan.get(
            "severity",
            "LOW"
        )

        if severity in severity_counts:
            severity_counts[severity] += 1

    open_incidents = sum(
        1
        for incident in incidents
        if incident.get("status") == "OPEN"
    )

    investigating_incidents = sum(
        1
        for incident in incidents
        if incident.get("status") == "INVESTIGATING"
    )

    resolved_incidents = sum(
        1
        for incident in incidents
        if incident.get("status") == "RESOLVED"
    )

    average_risk = 0

    if total_scans > 0:

        average_risk = round(
            sum(
                scan.get("risk_score", 0)
                for scan in history
            ) / total_scans,
            2
        )

    return jsonify({

        "total_scans":
            total_scans,

        "threats_detected":
            threats_detected,

        "alerts":
            alerts,

        "blocked":
            blocked,

        "allowed":
            allowed,

        "average_risk":
            average_risk,

        "severity_counts":
            severity_counts,

        "incident_counts": {

            "open":
                open_incidents,

            "investigating":
                investigating_incidents,

            "resolved":
                resolved_incidents

        }

    })


@app.route("/incidents")
def incidents_page():
    return render_template("incidents.html")


@app.route("/api/incidents", methods=["GET"])
def incidents():

    return jsonify(
        get_incidents()
    )


@app.route(
    "/api/incidents/<incident_id>/status",
    methods=["POST"]
)
def change_incident_status(incident_id):

    data = request.get_json() or {}

    new_status = data.get(
        "status",
        ""
    ).upper()

    incident = update_incident_status(
        incident_id,
        new_status
    )

    if incident is None:

        return jsonify({
            "error":
                "Incident not found or invalid status"
        }), 400

    return jsonify(incident)


if __name__ == "__main__":

    app.run(
        debug=True
    )