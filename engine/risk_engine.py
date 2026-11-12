def calculate_risk(analysis_result):
    """
    Convert detection results into a normalized
    0-100 security risk assessment.
    """

    classification = analysis_result.get("classification", "UNKNOWN")
    base_score = analysis_result.get("risk_score", 0)
    indicators = analysis_result.get("indicators", [])

    # Start with detector score
    risk_score = base_score

    # Add a small confidence adjustment based on
    # the number of independent indicators.
    indicator_count = len(indicators)

    if indicator_count >= 4:
        risk_score += 10

    elif indicator_count >= 2:
        risk_score += 5

    # Classification-based weighting
    if classification == "MALICIOUS":
        risk_score += 10

    elif classification == "SUSPICIOUS":
        risk_score += 5

    # Keep score within 0-100
    risk_score = min(max(risk_score, 0), 100)

    # Determine severity
    if risk_score >= 80:
        severity = "CRITICAL"

    elif risk_score >= 60:
        severity = "HIGH"

    elif risk_score >= 30:
        severity = "MEDIUM"

    else:
        severity = "LOW"

    # Overall security decision
    if risk_score >= 80:
        decision = "BLOCK"

    elif risk_score >= 50:
        decision = "ALERT"

    else:
        decision = "ALLOW"

    return {
        "risk_score": risk_score,
        "severity": severity,
        "decision": decision
    }
