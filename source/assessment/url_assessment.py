from datetime import datetime, timezone


def assess_domain_age(domain_age_days: int | None) -> dict:
    """
    Assess the age of a domain.

    Domain age is only an indicator.
    A new domain is not automatically malicious.
    """

    if domain_age_days is None:
        return {
            "status": "unknown",
            "reason": "Domain age could not be determined.",
        }

    if domain_age_days < 30:
        return {
            "status": "concerning",
            "reason": "Domain is less than 30 days old.",
        }

    if domain_age_days < 180:
        return {
            "status": "caution",
            "reason": "Domain is less than 180 days old.",
        }

    return {
        "status": "established",
        "reason": "Domain has been registered for more than 180 days.",
    }


def assess_expiration(expiration_date) -> dict:
    """
    Assess whether the domain has an upcoming expiration date.
    """

    if expiration_date is None:
        return {
            "status": "unknown",
            "reason": "Domain expiration date could not be determined.",
        }

    now = datetime.now(timezone.utc)

    if expiration_date.tzinfo is None:
        expiration_date = expiration_date.replace(
            tzinfo=timezone.utc
        )

    days_until_expiration = (expiration_date - now).days

    if days_until_expiration < 0:
        return {
            "status": "concerning",
            "reason": "Domain expiration date has passed.",
            "days_until_expiration": days_until_expiration,
        }

    if days_until_expiration <= 30:
        return {
            "status": "caution",
            "reason": "Domain expires within 30 days.",
            "days_until_expiration": days_until_expiration,
        }

    return {
        "status": "valid",
        "reason": "Domain has more than 30 days until expiration.",
        "days_until_expiration": days_until_expiration,
    }


def assess_dnsbl(dnsbl_results: list[dict]) -> dict:
    """
    Assess DNSBL results.

    A listed IP is a significant reputation concern.
    A non-listed IP does not prove that the domain is safe.
    """

    if not dnsbl_results:
        return {
            "status": "unknown",
            "reason": "No DNSBL results were available.",
        }

    listed_ips = [
        result["ip"]
        for result in dnsbl_results
        if result.get("listed") is True
    ]

    lookup_errors = [
        result
        for result in dnsbl_results
        if result.get("listed") is None
    ]

    if listed_ips:
        return {
            "status": "concerning",
            "reason": (
                "One or more resolved IP addresses "
                "are listed by DNSBL."
            ),
            "listed_ips": listed_ips,
        }

    if lookup_errors:
        return {
            "status": "unknown",
            "reason": (
                "DNSBL checks could not be completed "
                "for all resolved IP addresses."
            ),
            "listed_ips": [],
        }

    return {
        "status": "not_listed",
        "reason": (
            "Resolved IP addresses were not listed by DNSBL."
        ),
        "listed_ips": [],
    }


def assess_https(scheme: str) -> dict:
    """
    Assess whether HTTPS is being used.

    HTTPS provides encrypted transport but does not establish
    that a website itself is trustworthy.
    """

    if scheme.lower() == "https":
        return {
            "status": "positive",
            "reason": "URL uses HTTPS.",
        }

    return {
        "status": "caution",
        "reason": "URL does not use HTTPS.",
    }


def determine_verdict(
    dnsbl_result: dict,
    domain_age_result: dict,
    expiration_result: dict,
    https_result: dict,
) -> str:
    """
    Determine an overall reputation verdict.

    The verdict is based only on the available reputation
    indicators. It does not claim that a URL is definitively
    malicious or safe.
    """

    if dnsbl_result["status"] == "concerning":
        return "SUSPICIOUS"

    if (
        domain_age_result["status"] == "concerning"
        or expiration_result["status"] == "concerning"
    ):
        return "SUSPICIOUS"

    if (
        dnsbl_result["status"] == "unknown"
        or domain_age_result["status"] == "unknown"
        or expiration_result["status"] == "unknown"
    ):
        return "UNKNOWN"

    if (
        domain_age_result["status"] == "caution"
        or expiration_result["status"] == "caution"
        or https_result["status"] == "caution"
    ):
        return "CAUTION"

    return "LOW_RISK"


def assess_url(url_analysis: dict) -> dict:
    """
    Perform an overall reputation assessment of a URL.

    The assessment summarizes WHOIS, DNSBL, domain age,
    expiration, and HTTPS indicators.

    It does not declare a URL definitively safe or malicious.
    """

    url = url_analysis.get("url")
    domain = url_analysis.get("domain")
    scheme = url_analysis.get("scheme")
    whois = url_analysis.get("whois")
    dnsbl = url_analysis.get("dnsbl", [])

    findings = []

    # Handle URL analysis failure.
    if url_analysis.get("error"):
        return {
            "url": url,
            "domain": domain,
            "verdict": "UNKNOWN",
            "assessment": "unknown",
            "findings": [
                f"URL analysis failed: {url_analysis['error']}"
            ],
        }

    # -----------------------------
    # WHOIS
    # -----------------------------

    if whois:
        domain_age_result = assess_domain_age(
            whois.get("domain_age_days")
        )

        expiration_result = assess_expiration(
            whois.get("expiration_date")
        )
    else:
        domain_age_result = {
            "status": "unknown",
            "reason": "Domain age could not be determined.",
        }

        expiration_result = {
            "status": "unknown",
            "reason": "Domain expiration date could not be determined.",
        }

    # Add relevant WHOIS findings.
    if domain_age_result["status"] in {
        "concerning",
        "caution",
    }:
        findings.append(domain_age_result["reason"])

    if expiration_result["status"] in {
        "concerning",
        "caution",
    }:
        findings.append(expiration_result["reason"])

    # -----------------------------
    # DNSBL
    # -----------------------------

    dnsbl_result = assess_dnsbl(dnsbl)

    if dnsbl_result["status"] == "concerning":
        findings.append(dnsbl_result["reason"])

    elif dnsbl_result["status"] == "unknown":
        findings.append(dnsbl_result["reason"])

    # -----------------------------
    # HTTPS
    # -----------------------------

    https_result = assess_https(scheme or "")

    if https_result["status"] == "caution":
        findings.append(https_result["reason"])

    # -----------------------------
    # Overall verdict
    # -----------------------------

    verdict = determine_verdict(
        dnsbl_result,
        domain_age_result,
        expiration_result,
        https_result,
    )

    # Keep the existing assessment field for compatibility
    # with the rest of the project.
    assessment_map = {
        "LOW_RISK": "no_obvious_concerns",
        "CAUTION": "caution",
        "SUSPICIOUS": "suspicious",
        "UNKNOWN": "unknown",
    }

    return {
        "url": url,
        "domain": domain,
        "verdict": verdict,
        "assessment": assessment_map[verdict],
        "findings": findings,
        "domain_age": domain_age_result,
        "expiration": expiration_result,
        "dnsbl": dnsbl_result,
        "https": https_result,
    }


def assess_urls(url_analyses: list[dict]) -> list[dict]:
    """
    Assess multiple analyzed URLs.
    """

    results = []

    for url_analysis in url_analyses:
        results.append(assess_url(url_analysis))

    return results