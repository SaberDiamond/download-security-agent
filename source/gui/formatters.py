"""
Presentation formatting helpers for the Download Security Agent GUI.

This module contains ONLY display formatting logic.

It does not:
- perform security analysis
- calculate risk
- parse PDFs
- make network requests

It only converts the structured result already produced by
``source.processor.process_file`` into strings suitable for display.
"""

from __future__ import annotations

from datetime import datetime, date
from typing import Any, Optional


PLACEHOLDER = "Not available"


def fmt(value: Any, placeholder: str = PLACEHOLDER) -> str:
    """Format an arbitrary scalar value for display, handling None cleanly."""

    if value is None:
        return placeholder

    if isinstance(value, bool):
        return "Yes" if value else "No"

    if isinstance(value, (datetime, date)):
        try:
            return value.strftime("%Y-%m-%d")
        except Exception:
            return str(value)

    text = str(value).strip()

    return text if text else placeholder


def format_size(size: Optional[int]) -> str:
    """Format a byte count as a human-readable size string."""

    if size is None:
        return PLACEHOLDER

    try:
        size = int(size)
    except (TypeError, ValueError):
        return PLACEHOLDER

    if size < 1024:
        return f"{size} bytes"

    for unit in ("KB", "MB", "GB"):
        size /= 1024.0
        if size < 1024:
            return f"{size:.1f} {unit}"

    return f"{size:.1f} TB"


def truncate_hash(value: Optional[str], head: int = 12, tail: int = 8) -> str:
    """Shorten a long hash for compact display; full value is shown elsewhere."""

    if not value:
        return PLACEHOLDER

    if len(value) <= head + tail + 3:
        return value

    return f"{value[:head]}...{value[-tail:]}"


def risk_level_summary(level: Optional[str]) -> str:
    """
    A short, evidence-neutral one-line summary tied to the risk level.

    This does not invent findings; the actual evidence is shown separately
    in the "Why was this flagged?" section, sourced directly from
    result["risk"]["findings"].
    """

    level = (level or "UNKNOWN").upper()

    messages = {
        "LOW": "No significant risk indicators were found.",
        "MEDIUM": "This file has some characteristics that warrant a closer look.",
        "HIGH": "This file contains suspicious characteristics.",
        "CRITICAL": "This file contains multiple serious risk indicators.",
        "UNKNOWN": "Risk could not be fully determined for this file.",
    }

    return messages.get(level, messages["UNKNOWN"])


def status_title(status: Optional[str]) -> str:
    titles = {
        "analyzed": "Analysis Complete",
        "unsupported": "Unsupported File Type",
        "identification_failed": "File Identification Failed",
        "analysis_failed": "Analysis Failed",
        "risk_assessment_failed": "Risk Assessment Failed",
    }

    return titles.get(status or "", "Unknown Status")


def format_findings(findings: Optional[list]) -> list:
    """
    Return the list of findings exactly as reported by the backend.

    Never invents or embellishes findings. If empty, callers should
    display a clear "no findings" message instead of an empty list.
    """

    if not findings:
        return []

    return [str(finding) for finding in findings]


def format_whois(whois: Optional[dict]) -> dict:
    """
    Build a display-ready dict of WHOIS fields.

    Returns a dict with keys: registrar, created, expires, age, unavailable_reason
    """

    if not whois:
        return {
            "registrar": PLACEHOLDER,
            "created": PLACEHOLDER,
            "expires": PLACEHOLDER,
            "age": PLACEHOLDER,
            "unavailable_reason": "WHOIS information was not collected.",
        }

    if whois.get("error"):
        return {
            "registrar": PLACEHOLDER,
            "created": PLACEHOLDER,
            "expires": PLACEHOLDER,
            "age": PLACEHOLDER,
            "unavailable_reason": f"WHOIS lookup failed: {whois['error']}",
        }

    age_days = whois.get("domain_age_days")
    age_text = f"{age_days} days" if age_days is not None else PLACEHOLDER

    return {
        "registrar": fmt(whois.get("registrar")),
        "created": fmt(whois.get("creation_date")),
        "expires": fmt(whois.get("expiration_date")),
        "age": age_text,
        "unavailable_reason": None,
    }


def format_dnsbl_rows(dnsbl_results: Optional[list]) -> list:
    """Return a list of (ip, status, listed) tuples for display."""

    rows = []

    for entry in dnsbl_results or []:
        rows.append(
            (
                fmt(entry.get("ip")),
                fmt(entry.get("status")),
                entry.get("listed") is True,
            )
        )

    return rows


def verdict_label(verdict: Optional[str]) -> str:
    labels = {
        "LOW_RISK": "Low Risk",
        "CAUTION": "Caution",
        "SUSPICIOUS": "Suspicious",
        "UNKNOWN": "Unknown",
    }

    return labels.get((verdict or "UNKNOWN").upper(), "Unknown")
