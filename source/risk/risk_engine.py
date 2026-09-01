RISK_WEIGHTS = {
    # Basic PDF characteristics
    "PDF is encrypted": 1,
    "External URL(s) detected": 1,
    "JavaScript detected": 2,
    "Embedded file(s) detected": 1,
    "PDF action detected": 2,

    # Detailed JavaScript indicators
    "Suspicious JavaScript": 3,

    # Embedded file types
    "Embedded script": 3,
    "Embedded executable": 5,

    # URL indicators
    "Suspicious URL": 3,
}


def calculate_risk(analysis: dict) -> dict:
    """
    Calculate a risk score from the complete PDF analysis.

    The risk engine does not perform analysis itself.
    It evaluates findings produced by the analyzers.
    """

    score = 0
    findings = []

    # --------------------------------------------------
    # Basic PDF findings
    # --------------------------------------------------

    for finding in analysis.get("findings", []):
        weight = RISK_WEIGHTS.get(finding, 0)

        score += weight

        if finding not in findings:
            findings.append(finding)

    # --------------------------------------------------
    # JavaScript analysis
    # --------------------------------------------------

    javascript_analysis = analysis.get(
        "javascript_analysis",
        []
    )

    for script in javascript_analysis:
        if not script.get("suspicious"):
            continue

        score += RISK_WEIGHTS["Suspicious JavaScript"]

        if "Suspicious JavaScript detected" not in findings:
            findings.append(
                "Suspicious JavaScript detected"
            )

        for indicator in script.get("findings", []):
            indicator_finding = (
                f"JavaScript indicator: {indicator}"
            )

            if indicator_finding not in findings:
                findings.append(indicator_finding)

    # --------------------------------------------------
    # Embedded file analysis
    # --------------------------------------------------

    embedded_files = analysis.get(
        "embedded_file_analysis",
        []
    )

    for embedded_file in embedded_files:
        classification = embedded_file.get(
            "classification"
        )

        filename = embedded_file.get(
            "filename",
            "unknown"
        )

        if classification == "script":
            score += RISK_WEIGHTS["Embedded script"]

            finding = (
                f"Embedded script detected: {filename}"
            )

            if finding not in findings:
                findings.append(finding)

        elif classification == "executable":
            score += RISK_WEIGHTS["Embedded executable"]

            finding = (
                f"Embedded executable detected: {filename}"
            )

            if finding not in findings:
                findings.append(finding)

    # --------------------------------------------------
    # URL assessment
    # --------------------------------------------------

    url_assessments = analysis.get(
        "url_assessment",
        []
    )

    for assessment in url_assessments:
        verdict = assessment.get("assessment")
        url = assessment.get("url")

        # Only assessments indicating an actual concern
        # contribute to the risk score.
        if verdict in (
            "suspicious",
            "concerning",
        ):
            score += RISK_WEIGHTS["Suspicious URL"]

            finding = (
                f"Suspicious URL detected: {url}"
            )

            if finding not in findings:
                findings.append(finding)

    # --------------------------------------------------
    # Determine risk level
    # --------------------------------------------------

    if score <= 1:
        level = "LOW"

    elif score <= 4:
        level = "MEDIUM"

    elif score <= 7:
        level = "HIGH"

    else:
        level = "CRITICAL"

    return {
        "score": score,
        "level": level,
        "findings": findings,
    }