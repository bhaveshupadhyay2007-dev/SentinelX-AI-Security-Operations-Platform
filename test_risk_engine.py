from engine.detector import analyze_ioc
from engine.risk_engine import calculate_risk


test_urls = [
    "https://google.com",
    "http://paypal-confirm-payment.cf/login",
    "http://verify-user-account.top/password"
]


for url in test_urls:

    detection = analyze_ioc(url)
    risk = calculate_risk(detection)

    print("=" * 60)
    print("IOC:", url)
    print("Classification:", detection["classification"])
    print("Risk Score:", risk["risk_score"])
    print("Severity:", risk["severity"])
    print("Decision:", risk["decision"])
    print("Indicators:")

    for indicator in detection["indicators"]:
        print(" -", indicator)

print("=" * 60)
