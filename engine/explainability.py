def generate_explanation(analysis_result, risk_result):
    """
    Generate a human-readable security explanation
    for a detected IOC.
    """

    classification = analysis_result.get("classification", "UNKNOWN")
    indicators = analysis_result.get("indicators", [])
    risk_score = risk_result.get("risk_score", 0)
    severity = risk_result.get("severity", "LOW")
    decision = risk_result.get("decision", "ALLOW")

    explanation = []

    if classification == "MALICIOUS":
        explanation.append(
            "The IOC shows strong characteristics associated with malicious activity."
        )

    elif classification == "SUSPICIOUS":
        explanation.append(
            "The IOC contains multiple characteristics commonly associated with suspicious activity."
        )

    elif classification == "BENIGN":
        explanation.append(
            "No major suspicious characteristics were detected."
        )

    else:
        explanation.append(
            "The IOC could not be confidently classified."
        )

    if indicators:
        explanation.append(
            f"Security analysis identified {len(indicators)} indicator(s) that influenced the assessment."
        )

    explanation.append(
        f"Final risk score: {risk_score}/100."
    )

    explanation.append(
        f"Severity level: {severity}."
    )

    explanation.append(
        f"Recommended action: {decision}."
    )

    return {
        "summary": " ".join(explanation),
        "indicators": indicators,
        "risk_score": risk_score,
        "severity": severity,
        "decision": decision
    }
