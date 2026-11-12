from engine.detector import analyze_ioc


test_urls = [
    "https://google.com",
    "http://paypal-confirm-payment.cf/login",
    "http://verify-user-account.top/password",
    "https://example.com"
]


for url in test_urls:

    result = analyze_ioc(url)

    print("=" * 60)
    print("IOC:", result["ioc"])
    print("Classification:", result["classification"])
    print("Risk Score:", result["risk_score"])
    print("Severity:", result["severity"])
    print("Indicators:")

    for indicator in result["indicators"]:
        print(" -", indicator)

print("=" * 60)