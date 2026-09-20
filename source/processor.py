from pathlib import Path

from source.analyzers.pdf_analyzer import analyze_pdf
from source.identification.file_identifier import identify_file
from source.risk.risk_engine import calculate_risk


SUPPORTED_TYPES = {
    ".pdf",
}

AVAILABLE_ACTIONS = [
    "allow",
    "move_to_trash",
]


def process_file(file_path: str) -> dict:
    """
    Analyze a downloaded file and return one complete structured result.

    The returned object is the contract used by the terminal interface
    and the GUI. File identification, analysis, and risk assessment are
    all represented in the same result.

    No user action is performed automatically.
    """

    path = Path(file_path)

    result = {
        "file": {
            "name": path.name,
            "path": str(path),
            "extension": path.suffix.lower(),
            "mime_type": "unknown",
            "actual_type": None,
            "size": None,
            "sha256": None,
            "type": None,
        },
        "status": None,
        "error": None,
        "analysis": None,
        "risk": None,
        "available_actions": [],
        "action": None,
    }

    # --------------------------------------------------
    # Step 1: Identify the file
    # --------------------------------------------------

    try:
        file_info = identify_file(file_path)

    except Exception as error:
        result["status"] = "identification_failed"
        result["error"] = str(error)
        return result

    result["file"].update(
        {
            "name": file_info["filename"],
            "extension": file_info["extension"],
            "mime_type": file_info["mime_type"],
            "actual_type": file_info["actual_type"],
            "size": file_info["size"],
            "sha256": file_info["sha256"],
        }
    )

    # --------------------------------------------------
    # Step 2: Verify the actual file type
    # --------------------------------------------------

    if not file_info["type_verified"]:
        result["file"]["type"] = file_info["actual_type"]
        result["status"] = "type_mismatch"
        result["error"] = (
            "File extension does not match the detected file type."
        )
        result["available_actions"] = AVAILABLE_ACTIONS.copy()
        return result

    # --------------------------------------------------
    # Step 3: Check whether the file type is supported
    # --------------------------------------------------

    if file_info["extension"] not in SUPPORTED_TYPES:
        result["file"]["type"] = file_info["actual_type"]
        result["status"] = "unsupported"
        result["available_actions"] = AVAILABLE_ACTIONS.copy()
        return result

    result["file"]["type"] = file_info["actual_type"]

    # --------------------------------------------------
    # Step 4: Analyze the file
    # --------------------------------------------------

    try:
        analysis = analyze_pdf(file_path)

    except Exception as error:
        result["status"] = "analysis_failed"
        result["error"] = str(error)
        result["available_actions"] = AVAILABLE_ACTIONS.copy()
        return result

    result["analysis"] = analysis

    # --------------------------------------------------
    # Step 5: Calculate risk
    # --------------------------------------------------

    try:
        risk = calculate_risk(analysis)

    except Exception as error:
        result["status"] = "risk_assessment_failed"
        result["error"] = str(error)
        result["risk"] = {
            "score": None,
            "level": "UNKNOWN",
            "findings": [],
        }
        result["available_actions"] = AVAILABLE_ACTIONS.copy()
        return result

    # --------------------------------------------------
    # Step 6: Store final result
    # --------------------------------------------------

    result["status"] = "analyzed"
    result["risk"] = risk
    result["available_actions"] = AVAILABLE_ACTIONS.copy()

    return result


def print_result(result: dict) -> None:
    """
    Display a structured processing result in the terminal.

    This function is intentionally separate from process_file() so the
    GUI can consume the same structured result without depending on
    terminal output.
    """

    print()
    print("================================")
    print("Download Security Agent")
    print("================================")

    file_info = result["file"]

    print(f"File: {file_info['name']}")
    print(f"Path: {file_info['path']}")
    print(f"Extension: {file_info['extension']}")
    print(f"MIME Type: {file_info['mime_type']}")

    if file_info["actual_type"]:
        print(f"Actual Type: {file_info['actual_type']}")

    if file_info["size"] is not None:
        print(f"Size: {file_info['size']} bytes")

    if file_info["sha256"]:
        print(f"SHA-256: {file_info['sha256']}")

    if file_info["type"]:
        print(f"Type: {file_info['type']}")

    # --------------------------------------------------
    # Error states
    # --------------------------------------------------

    if result["status"] == "identification_failed":
        print("Status: File identification failed")
        print(f"Error: {result['error']}")
        print("================================")
        return

    if result["status"] == "type_mismatch":
        print("Status: File type mismatch")
        print(f"Error: {result['error']}")
        print("================================")
        return

    if result["status"] == "unsupported":
        print("Status: Unsupported file type")
        print("================================")
        return

    if result["status"] == "analysis_failed":
        print("Status: Analysis failed")
        print(f"Error: {result['error']}")
        print("================================")
        return

    if result["status"] == "risk_assessment_failed":
        print("Status: Risk assessment failed")
        print(f"Error: {result['error']}")
        print("================================")
        return

    print("Status: Analysis complete")

    analysis = result["analysis"]
    risk = result["risk"]

    # --------------------------------------------------
    # Basic PDF analysis
    # --------------------------------------------------

    print()
    print("Analysis Results")
    print("----------------")
    print(f"Pages: {analysis['pages']}")
    print(f"Encrypted: {analysis['encrypted']}")
    print(f"JavaScript: {analysis['javascript_detected']}")
    print(f"URLs: {len(analysis['urls'])}")
    print(f"Embedded Files: {analysis['embedded_files_detected']}")
    print(f"Actions: {analysis['actions_detected']}")

    # --------------------------------------------------
    # JavaScript analysis
    # --------------------------------------------------

    if analysis["javascript_analysis"]:
        print()
        print("JavaScript Analysis")
        print("--------------------")

        for script in analysis["javascript_analysis"]:
            print()
            print(f"Name: {script.get('name')}")
            print(f"Suspicious: {script.get('suspicious')}")
            print(f"Findings: {script.get('findings')}")

    # --------------------------------------------------
    # URL analysis
    # --------------------------------------------------

    if analysis["url_analysis"]:
        print()
        print("URL Analysis")
        print("------------")

        for url_result in analysis["url_analysis"]:
            print()
            print(f"URL: {url_result.get('url')}")
            print(f"Domain: {url_result.get('domain')}")
            print(f"IP Addresses: {url_result.get('ip_addresses')}")

            whois = url_result.get("whois", {})

            if whois:
                print("WHOIS")
                print(f"  Registrar: {whois.get('registrar')}")
                print(f"  Creation Date: {whois.get('creation_date')}")
                print(f"  Expiration Date: {whois.get('expiration_date')}")
                print(f"  Domain Age: {whois.get('domain_age_days')} days")

            dnsbl = url_result.get("dnsbl", [])

            if dnsbl:
                print("DNSBL")

                for dnsbl_result in dnsbl:
                    print(f"  IP: {dnsbl_result.get('ip')}")
                    print(f"  Status: {dnsbl_result.get('status')}")

    # --------------------------------------------------
    # URL assessment
    # --------------------------------------------------

    if analysis["url_assessment"]:
        print()
        print("URL Assessment")
        print("--------------")

        for assessment in analysis["url_assessment"]:
            print()
            print(f"URL: {assessment.get('url')}")
            print(f"Verdict: {assessment.get('verdict')}")
            print(f"Assessment: {assessment.get('assessment')}")

            findings = assessment.get("findings", [])

            if findings:
                print("Findings:")

                for finding in findings:
                    print(f"  - {finding}")

    # --------------------------------------------------
    # Embedded files
    # --------------------------------------------------

    if analysis["embedded_file_analysis"]:
        print()
        print("Embedded File Analysis")
        print("----------------------")

        for embedded_file in analysis["embedded_file_analysis"]:
            print()
            print(f"Filename: {embedded_file.get('filename')}")
            print(f"Extension: {embedded_file.get('extension')}")
            print(f"MIME Type: {embedded_file.get('mime_type')}")
            print(f"Size: {embedded_file.get('size')} bytes")
            print(f"SHA256: {embedded_file.get('sha256')}")
            print(f"Classification: {embedded_file.get('classification')}")

    # --------------------------------------------------
    # Risk assessment
    # --------------------------------------------------

    print()
    print("Risk Assessment")
    print("----------------")
    print(f"Score: {risk['score']}")
    print(f"Level: {risk['level']}")

    if risk["findings"]:
        print()
        print("Findings")

        for finding in risk["findings"]:
            print(f"- {finding}")

    # --------------------------------------------------
    # Available actions
    # --------------------------------------------------

    print()
    print("Available Actions")
    print("-----------------")

    for action in result["available_actions"]:
        print(f"- {action}")

    print("================================")