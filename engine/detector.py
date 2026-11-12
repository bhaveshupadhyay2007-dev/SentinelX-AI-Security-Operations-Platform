import re
from urllib.parse import urlparse


def analyze_ioc(ioc):
    """
    Analyze a URL/domain/IP-like IOC and return
    a basic security assessment.
    """

    ioc = ioc.strip()

    if not ioc:
        return {
            "classification": "UNKNOWN",
            "risk_score": 0,
            "severity": "LOW",
            "indicators": ["No IOC provided"]
        }

    indicators = []
    risk_score = 0

    # ---------------------------------
    # 1. URL structure
    # ---------------------------------

    test_url = ioc

    if not test_url.startswith(("http://", "https://")):
        test_url = "http://" + test_url

    parsed = urlparse(test_url)
    hostname = parsed.hostname or ""

    # ---------------------------------
    # 2. Suspicious keywords
    # ---------------------------------

    suspicious_keywords = [
        "login",
        "verify",
        "verification",
        "password",
        "account",
        "secure",
        "update",
        "confirm",
        "payment",
        "signin",
        "bank",
        "wallet",
        "credential"
    ]

    keyword_matches = [
        word for word in suspicious_keywords
        if word in ioc.lower()
    ]

    if keyword_matches:
        risk_score += min(len(keyword_matches) * 8, 30)

        indicators.append(
            "Suspicious keywords: " + ", ".join(keyword_matches)
        )

    # ---------------------------------
    # 3. HTTP instead of HTTPS
    # ---------------------------------

    if test_url.startswith("http://"):
        risk_score += 10
        indicators.append("Connection does not use HTTPS")

    # ---------------------------------
    # 4. IP address as hostname
    # ---------------------------------

    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    if re.match(ip_pattern, hostname):
        risk_score += 20
        indicators.append("IP address used instead of domain name")

    # ---------------------------------
    # 5. URL length
    # ---------------------------------

    if len(ioc) > 100:
        risk_score += 15
        indicators.append("Unusually long URL")

    elif len(ioc) > 75:
        risk_score += 8
        indicators.append("Long URL")

    # ---------------------------------
    # 6. Suspicious separators
    # ---------------------------------

    if "@" in ioc:
        risk_score += 20
        indicators.append("URL contains @ symbol")

    # ---------------------------------
    # 7. Excessive subdomains
    # ---------------------------------

    if hostname.count(".") >= 3:
        risk_score += 10
        indicators.append("Multiple subdomains detected")

    # ---------------------------------
    # 8. Suspicious TLDs
    # ---------------------------------

    suspicious_tlds = [
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".top",
        ".xyz",
        ".click",
        ".work"
    ]

    if any(hostname.lower().endswith(tld) for tld in suspicious_tlds):
        risk_score += 20
        indicators.append("Suspicious top-level domain")

    # ---------------------------------
    # Keep score between 0 and 100
    # ---------------------------------

    risk_score = min(risk_score, 100)

    # ---------------------------------
    # Classification
    # ---------------------------------

    if risk_score >= 75:
        classification = "MALICIOUS"
        severity = "CRITICAL"

    elif risk_score >= 50:
        classification = "SUSPICIOUS"
        severity = "HIGH"

    elif risk_score >= 25:
        classification = "SUSPICIOUS"
        severity = "MEDIUM"

    else:
        classification = "BENIGN"
        severity = "LOW"

    if not indicators:
        indicators.append("No major suspicious indicators detected")

    return {
        "classification": classification,
        "risk_score": risk_score,
        "severity": severity,
        "indicators": indicators,
        "ioc": ioc
    }