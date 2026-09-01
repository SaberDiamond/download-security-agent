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
    risk = calculate_risk(analysis)

    print()
    print("Analysis Results")
    print("----------------")

    print(f"Pages: {analysis['pages']}")
    print(f"Encrypted: {analysis['encrypted']}")
    print(f"JavaScript: {analysis['javascript_detected']}")
    print(f"URLs: {len(analysis['urls'])}")
    print(f"Embedded Files: {analysis['embedded_files_detected']}")
    print(f"Actions: {analysis['actions_detected']}")

    if analysis["javascript_analysis"]:
        print()
        print("JavaScript Analysis")

        for script in analysis["javascript_analysis"]:
            print()
            print(f"  Name: {script.get('name')}")
            print(f"  Suspicious: {script.get('suspicious')}")
            print(f"  Findings: {script.get('findings')}")

    if analysis["url_analysis"]:
        print()
        print("URL Analysis")

        for url_result in analysis["url_analysis"]:
            print()
            print(f"  URL: {url_result.get('url')}")
            print(f"  Domain: {url_result.get('domain')}")
            print(f"  IP Addresses: {url_result.get('ip_addresses')}")

            whois = url_result.get("whois", {})

            if whois:
                print("  WHOIS:")
                print(f"    Registrar: {whois.get('registrar')}")
                print(f"    Creation Date: {whois.get('creation_date')}")
                print(f"    Expiration Date: {whois.get('expiration_date')}")
                print(f"    Domain Age: {whois.get('domain_age_days')} days")

            dnsbl = url_result.get("dnsbl", [])

            if dnsbl:
                print("  DNSBL:")

                for result in dnsbl:
                    print(f"    IP: {result.get('ip')}")
                    print(f"    Status: {result.get('status')}")

    if analysis["embedded_file_analysis"]:
        print()
        print("Embedded File Analysis")

        for embedded_file in analysis["embedded_file_analysis"]:
            print()
            print(f"  Filename: {embedded_file.get('filename')}")
            print(f"  Extension: {embedded_file.get('extension')}")
            print(f"  MIME Type: {embedded_file.get('mime_type')}")
            print(f"  Size: {embedded_file.get('size')} bytes")
            print(f"  SHA256: {embedded_file.get('sha256')}")
            print(f"  Classification: {embedded_file.get('classification')}")

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