from pathlib import Path

from source.analyzers.pdf_analyzer import analyze_pdf
from source.risk.risk_engine import calculate_risk


SUPPORTED_TYPES = {
    ".pdf",
}


def process_file(file_path: str) -> None:
    path = Path(file_path)

    print()
    print("================================")
    print("Download Security Agent")
    print("================================")

    print(f"File: {path.name}")

    if path.suffix.lower() not in SUPPORTED_TYPES:
        print("Status: Unsupported file type")
        return

    print("Type: PDF")
    print("Analyzing...")

    analysis = analyze_pdf(file_path)

    risk = calculate_risk(analysis["findings"])

    print()
    print("Analysis Results")
    print("----------------")

    print(f"Pages: {analysis['pages']}")
    print(f"JavaScript: {analysis['javascript_detected']}")
    print(f"URLs: {analysis['urls']}")
    print(f"Embedded Files: {analysis['embedded_files_detected']}")
    print(f"Actions: {analysis['actions_detected']}")

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

    print("================================")