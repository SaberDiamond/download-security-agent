RISK_WEIGHTS = {
    "PDF is encrypted": 1,
    "External URL(s) detected": 1,
    "JavaScript detected": 2,
    "Embedded file(s) detected": 2,
    "PDF action detected": 2,
}

# Function to calculate risk score and level based on findings
def calculate_risk(findings: list[str]) -> dict:
    score = 0

    for finding in findings:
        score += RISK_WEIGHTS.get(finding, 0)

    if score <= 1:
        level = "LOW"
    elif score <= 3:
        level = "MEDIUM"
    elif score <= 5:
        level = "HIGH"
    else:
        level = "CRITICAL"

    return {
        "score": score,
        "level": level,
        "findings": findings,
    }