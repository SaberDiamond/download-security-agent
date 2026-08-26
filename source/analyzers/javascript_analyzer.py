import re
from pathlib import Path

from pypdf import PdfReader


def extract_javascript(file_path: str) -> list[dict]:
    """
    Extract embedded JavaScript from a PDF without executing it.
    """

    path = Path(file_path)
    reader = PdfReader(path)

    javascript = []

    root = reader.root_object

    names = root.get("/Names")

    if not names:
        return javascript

    names = names.get_object()

    javascript_tree = names.get("/JavaScript")

    if not javascript_tree:
        return javascript

    javascript_tree = javascript_tree.get_object()

    js_names = javascript_tree.get("/Names")

    if not js_names:
        return javascript

    js_names = js_names.get_object()

    # The /Names array contains alternating:
    # [name, object, name, object, ...]

    for index in range(0, len(js_names), 2):

        if index + 1 >= len(js_names):
            break

        name = str(js_names[index])

        action = js_names[index + 1].get_object()

        if action.get("/S") != "/JavaScript":
            continue

        code = action.get("/JS")

        if code is None:
            continue

        javascript.append({
            "name": name,
            "code": str(code),
        })

    return javascript


SUSPICIOUS_PATTERNS = {
    "eval": r"\beval\s*\(",

    "function_constructor": r"\bFunction\s*\(",

    "unescape": r"\bunescape\s*\(",

    "decode_uri": r"\bdecodeURI(?:Component)?\s*\(",

    "shell_execution": r"\b(?:app\.exec|util\.shell|shell)\b",

    "document_write": r"\bdocument\.write\s*\(",

    "external_url": r"https?://",
}


def analyze_javascript(code: str) -> dict:
    """
    Perform static analysis on JavaScript without executing it.
    """

    findings = []

    for indicator, pattern in SUSPICIOUS_PATTERNS.items():

        if re.search(pattern, code, re.IGNORECASE):
            findings.append(indicator)

    return {
        "suspicious": bool(findings),
        "findings": findings,
    }


def analyze_embedded_javascript(file_path: str) -> list[dict]:
    """
    Extract and statically analyze embedded JavaScript.

    JavaScript is never executed.
    """

    scripts = extract_javascript(file_path)

    results = []

    for script in scripts:

        analysis = analyze_javascript(script["code"])

        results.append({
            "name": script["name"],
            "code": script["code"],
            "suspicious": analysis["suspicious"],
            "findings": analysis["findings"],
        })

    return results