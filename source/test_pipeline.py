from source.analyzers.pdf_analyzer import analyze_pdf
from source.risk.risk_engine import calculate_risk

def analyze_file(file_path: str) -> dict:
    analysis = analyze_pdf(file_path)

    risk = calculate_risk(analysis["findings"])

    return {
        "file": file_path,
        "analysis": analysis,
        "risk": risk,
    }


if __name__ == "__main__":
    result = analyze_file("samples/test_js.pdf")

    print("File Analysis")
    print("-------------------------")
    print(f"File: {result['file']}")
    print(f"Pages: {result['analysis']['pages']}")
    print(f"JavaScript: {result['analysis']['javascript_detected']}")
    print(f"URLs: {result['analysis']['urls']}")
    print(
        f"Embedded Files: "
        f"{result['analysis']['embedded_files_detected']}"
    )
    print(
        f"Actions: "
        f"{result['analysis']['actions_detected']}"
    )

    print()
    print("Risk Assessment")
    print("-------------------------")
    print(f"Score: {result['risk']['score']}")
    print(f"Level: {result['risk']['level']}")

    print()
    print("Findings")

    for finding in result["risk"]["findings"]:
        print(f"- {finding}")