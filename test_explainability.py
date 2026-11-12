from engine.detector import analyze_ioc
from engine.risk_engine import calculate_risk
from engine.explainability import generate_explanation


ioc = "http://verify-user-account.top/password"

detection = analyze_ioc(ioc)
risk = calculate_risk(detection)
explanation = generate_explanation(detection, risk)


print("=" * 60)
print("SENTINELX SECURITY ANALYSIS")
print("=" * 60)

print("IOC:", ioc)
print("Classification:", detection["classification"])
print("Risk Score:", risk["risk_score"])
print("Severity:", risk["severity"])
print("Decision:", risk["decision"])

print("\nWHY WAS IT FLAGGED?")

for indicator in explanation["indicators"]:
    print(" -", indicator)

print("\nSUMMARY:")
print(explanation["summary"])

print("=" * 60)
