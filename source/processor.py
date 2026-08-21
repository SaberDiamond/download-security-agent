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

    print("URL Analysis:")

    for url_result in analysis["url_analysis"]:
        print()
        print(f"  URL: {url_result.get('url')}")
        print(f"  Domain: {url_result.get('domain')}")
        print(f"  IP Addresses: {url_result.get('ip_addresses')}")

        whois = url_result.get("whois", {})

        print("  WHOIS:")
        print(f"    Registrar: {whois.get('registrar')}")
        print(f"    Creation Date: {whois.get('creation_date')}")
        print(f"    Expiration Date: {whois.get('expiration_date')}")
        print(f"    Domain Age: {whois.get('domain_age_days')} days")

        dnsbl = url_result.get("dnsbl", [])

        print("  DNSBL:")

        for result in dnsbl:
            print(f"    IP: {result.get('ip')}")
            print(f"    Status: {result.get('status')}")
    
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