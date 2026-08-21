import re
from pathlib import Path

from pypdf import PdfReader

from source.analyzers.url_analyzer import analyze_urls


def extract_urls(reader: PdfReader) -> list[str]:
    """
    Extract URLs from visible PDF text and clickable
    PDF link annotations.
    """

    urls = set()

    url_pattern = re.compile(r"https?://[^\s<>\"]+")

    for page in reader.pages:

        # Check URLs contained in visible text.
        text = page.extract_text() or ""

        matches = url_pattern.findall(text)

        for url in matches:
            urls.add(url.rstrip(".,;:!?"))

        # Check clickable link annotations.
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


def detect_embedded_files(reader: PdfReader) -> bool:
    """
    Detect embedded files inside the PDF.
    """

    root = reader.root_object

    names = root.get("/Names")

    if not names:
        return False

    names = names.get_object()

    embedded_files = names.get("/EmbeddedFiles")

    return embedded_files is not None


def detect_pdf_actions(reader: PdfReader) -> bool:
    """
    Detect PDF OpenAction or Additional Actions.
    """

    root = reader.root_object

    if root.get("/OpenAction"):
        return True

    if root.get("/AA"):
        return True

    return False


def analyze_pdf(file_path: str) -> dict:
    """
    Perform PDF analysis.
    """

    path = Path(file_path)

    reader = PdfReader(path)

    findings = []

    # --------------------------------
    # Basic PDF information
    # --------------------------------

    if reader.is_encrypted:
        findings.append("PDF is encrypted")

    # --------------------------------
    # JavaScript detection
    # --------------------------------

    javascript_detected = False

    root = reader.root_object

    names = root.get("/Names")

    if names:
        names = names.get_object()

        if names.get("/JavaScript"):
            javascript_detected = True

    if javascript_detected:
        findings.append("JavaScript detected")

    # --------------------------------
    # URL extraction and analysis
    # --------------------------------

    urls = extract_urls(reader)

    url_analysis = analyze_urls(urls)

    if urls:
        findings.append("External URL(s) detected")

    # --------------------------------
    # Embedded file detection
    # --------------------------------

    embedded_files_detected = detect_embedded_files(reader)

    if embedded_files_detected:
        findings.append("Embedded file(s) detected")

    # --------------------------------
    # PDF action detection
    # --------------------------------

    actions_detected = detect_pdf_actions(reader)

    if actions_detected:
        findings.append("PDF action detected")

    # --------------------------------
    # Return results
    # --------------------------------

    return {
        "pages": len(reader.pages),
        "encrypted": reader.is_encrypted,
        "javascript_detected": javascript_detected,
        "urls": urls,
        "url_analysis": url_analysis,
        "embedded_files_detected": embedded_files_detected,
        "actions_detected": actions_detected,
        "findings": findings,
    }