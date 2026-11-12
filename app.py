from flask import Flask, jsonify, render_template, request

from engine.detector import analyze_ioc
from engine.risk_engine import calculate_risk
from engine.explainability import generate_explanation
from engine.threat_intelligence import lookup_ioc
from engine.trusted_domains import is_trusted_domain

from ml.predictor import predict_url

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

    # =========================================
    # 1. RULE-BASED DETECTION
    # =========================================

    detection = analyze_ioc(ioc)

    # =========================================
    # 2. MACHINE LEARNING PREDICTION
    # =========================================

    try:

        ml_result = predict_url(ioc)

    except Exception as error:

        ml_result = {
            "prediction": -1,
            "classification": "UNAVAILABLE",
            "confidence": 0,
            "error": str(error)
        }

    # =========================================
    # 3. TRUSTED DOMAIN CONTEXT
    # =========================================

    trusted_domain = is_trusted_domain(ioc)

    # =========================================
    # 4. RULE ENGINE RISK
    # =========================================

    risk = calculate_risk(detection)

    rule_score = risk["risk_score"]

    # =========================================
    # 5. ML RISK SCORE
    # =========================================

    ml_score = 0

    if ml_result["prediction"] == 1:

        ml_score = ml_result["confidence"]

    elif ml_result["prediction"] == 0:

        ml_score = 100 - ml_result["confidence"]

    # =========================================
    # 6. HYBRID RISK
    # =========================================

    hybrid_score = round(
        (rule_score * 0.60) +
        (ml_score * 0.40)
    )

    # =========================================
    # 7. TRUSTED DOMAIN MITIGATION
    # =========================================

    trusted_domain_adjustment = False

    if trusted_domain:

        if detection["classification"] == "BENIGN":

            hybrid_score = min(
                hybrid_score,
                10
            )

            trusted_domain_adjustment = True

    hybrid_score = min(
        max(hybrid_score, 0),
        100
    )

    # =========================================
    # 8. FINAL SEVERITY
    # =========================================

    if hybrid_score >= 80:

        final_severity = "CRITICAL"

    elif hybrid_score >= 60:

        final_severity = "HIGH"

    elif hybrid_score >= 30:

        final_severity = "MEDIUM"

    else:

        final_severity = "LOW"

    # =========================================
    # 9. FINAL DECISION
    # =========================================

    if hybrid_score >= 80:

        final_decision = "BLOCK"

    elif hybrid_score >= 30:

        final_decision = "ALERT"

    else:

        final_decision = "ALLOW"

    # =========================================
    # 10. FINAL CLASSIFICATION
    # =========================================

    if final_decision == "BLOCK":

        final_classification = "MALICIOUS"

    elif final_decision == "ALERT":

        final_classification = "SUSPICIOUS"

    else:

        final_classification = "BENIGN"

    # =========================================
    # 11. UPDATE RISK RESULT
    # =========================================

    risk["risk_score"] = hybrid_score
    risk["severity"] = final_severity
    risk["decision"] = final_decision

    # =========================================
    # 12. EXPLAINABILITY
    # =========================================

    explanation = generate_explanation(
        detection,
        risk
    )

    if trusted_domain:

        explanation["indicators"].append(
            "Trusted domain context detected."
        )

        if trusted_domain_adjustment:

            explanation["indicators"].append(
                "ML false-positive risk reduced using trusted-domain context."
            )

    # =========================================
    # 13. THREAT INTELLIGENCE
    # =========================================

    threat_intelligence = lookup_ioc(ioc)

    # =========================================
    # 14. SAVE SCAN HISTORY
    # =========================================

    save_scan(
        ioc,
        {
            **detection,
            "classification": final_classification
        },
        risk,
        explanation
    )

    # =========================================
    # 15. CREATE INCIDENT
    # =========================================

    incident = None

    if hybrid_score >= 30:

        incident = create_incident(
            ioc,
            {
                **detection,
                "classification": final_classification
            },
            risk,
            explanation
        )

    # =========================================
    # 16. FINAL API RESPONSE
    # =========================================

    return jsonify({

        "ioc":
            ioc,

        "classification":
            final_classification,

        "risk_score":
            hybrid_score,

        "severity":
            final_severity,

        "decision":
            final_decision,

        "indicators":
            explanation["indicators"],

        "summary":
            explanation["summary"],

        "ml_analysis": {

            "prediction":
                ml_result["prediction"],

            "classification":
                ml_result["classification"],

            "confidence":
                ml_result["confidence"]

        },

        "rule_engine_score":
            rule_score,

        "ml_score":
            round(ml_score, 2),

        "trusted_domain":
            trusted_domain,

        "trusted_domain_adjustment":
            trusted_domain_adjustment,

        "threat_intelligence":
            threat_intelligence,

        "incident":
            incident

    })


# =============================================
# SCAN HISTORY API
# =============================================

@app.route("/api/history", methods=["GET"])
def history():

    return jsonify(
        get_scan_history()
    )


# =============================================
# ANALYTICS API
# =============================================

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


# =============================================
# INCIDENT MANAGEMENT PAGE
# =============================================

@app.route("/incidents")
def incidents_page():

    return render_template(
        "incidents.html"
    )


# =============================================
# INCIDENTS API
# =============================================

@app.route("/api/incidents", methods=["GET"])
def incidents():

    return jsonify(
        get_incidents()
    )


# =============================================
# UPDATE INCIDENT STATUS
# =============================================

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


# =============================================
# APPLICATION START
# =============================================

if __name__ == "__main__":

    app.run(
        debug=True
    )