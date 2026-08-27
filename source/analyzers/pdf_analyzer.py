import re
from pathlib import Path

from pypdf import PdfReader

from source.analyzers.url_analyzer import analyze_urls
from source.assessment.url_assessment import assess_urls
from source.analyzers.javascript_analyzer import analyze_embedded_javascript
from source.analyzers.embedded_file_analyzer import extract_embedded_files


# Function to extract URLs from PDF text
def extract_urls(reader: PdfReader) -> list[str]:

    urls = set()

    url_pattern = re.compile(r"https?://[^\s<>\"']+")

    for page in reader.pages:

        # Check URLs contained in visible PDF text
        text = page.extract_text() or ""

        matches = url_pattern.findall(text)

        for url in matches:
            urls.add(url.rstrip(".,;:!?"))

        # Check clickable link annotations
        annotations = page.get("/Annots")

        if not annotations:
            continue

        for annotation_ref in annotations:

            annotation = annotation_ref.get_object()

            action = annotation.get("/A")

            if not action:
                continue

            action = action.get_object()

            uri = action.get("/URI")

            if uri:
                urls.add(str(uri))

    return sorted(urls)


# Function to detect embedded files in PDF
def detect_embedded_files(reader: PdfReader) -> bool:

    root = reader.root_object

    names = root.get("/Names")

    if not names:
        return False

    names = names.get_object()

    embedded_files = names.get("/EmbeddedFiles")

    return embedded_files is not None


# Function to detect OpenAction or AA in PDF
def detect_pdf_actions(reader: PdfReader) -> bool:

    root = reader.root_object

    if root.get("/OpenAction"):
        return True

    if root.get("/AA"):
        return True

    return False


# Function to analyze PDF
def analyze_pdf(file_path: str) -> dict:

    path = Path(file_path)

    reader = PdfReader(path)

    findings = []

    # Basic PDF information
    if reader.is_encrypted:
        findings.append("PDF is encrypted")

    # JavaScript detection
    javascript_detected = False

    root = reader.root_object

    names = root.get("/Names")

    if names:

        names = names.get_object()

        if names.get("/JavaScript"):
            javascript_detected = True

    if javascript_detected:
        findings.append("JavaScript detected")

    # Embedded JavaScript analysis
    javascript_analysis = analyze_embedded_javascript(file_path)

    # URL detection
    urls = extract_urls(reader)

    # Analyze extracted URLs
    url_analysis = analyze_urls(urls)

    # Assess analyzed URLs
    url_assessment = assess_urls(url_analysis)

    if urls:
        findings.append("External URL(s) detected")

    # Embedded file detection
    embedded_files_detected = detect_embedded_files(reader)

    # Embedded file analysis
    embedded_file_analysis = []

    if embedded_files_detected:

        embedded_file_analysis = extract_embedded_files(
            file_path,
            "samples/extracted"
        )

        findings.append("Embedded file(s) detected")

    # PDF action detection
    actions_detected = detect_pdf_actions(reader)

    if actions_detected:
        findings.append("PDF action detected")

    # Return analysis results
    return {
        "pages": len(reader.pages),
        "encrypted": reader.is_encrypted,

        "javascript_detected": javascript_detected,
        "javascript_analysis": javascript_analysis,

        "urls": urls,
        "url_analysis": url_analysis,
        "url_assessment": url_assessment,

        "embedded_files_detected": embedded_files_detected,
        "embedded_file_analysis": embedded_file_analysis,

        "actions_detected": actions_detected,

        "findings": findings,
    }