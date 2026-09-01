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

    # Handle datetime objects without timezone information.
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

    if listed_ips:
        return {
            "status": "concerning",
            "reason": "One or more resolved IP addresses are listed by DNSBL.",
            "listed_ips": listed_ips,
        }

    return {
        "status": "not_listed",
        "reason": "Resolved IP addresses were not listed by DNSBL.",
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


def assess_url(url_analysis: dict) -> dict:
    """
    Perform an overall assessment of a single analyzed URL.

    This function does not declare a URL malicious.
    It summarizes security-relevant indicators and provides
    an overall assessment based on the available evidence.
    """

    findings = []

    domain = url_analysis.get("domain")
    scheme = url_analysis.get("scheme")
    whois = url_analysis.get("whois")
    dnsbl = url_analysis.get("dnsbl", [])

    # If URL analysis itself failed.
    if url_analysis.get("error"):
        return {
            "url": url_analysis.get("url"),
            "domain": domain,
            "assessment": "unknown",
            "findings": [
                f"URL analysis failed: {url_analysis['error']}"
            ],
        }

    # WHOIS and domain age assessment.
    domain_age_result = {
        "status": "unknown",
        "reason": "Domain age could not be determined.",
    }

    expiration_result = {
        "status": "unknown",
        "reason": "Domain expiration date could not be determined.",
    }

    if whois:
        domain_age_result = assess_domain_age(
            whois.get("domain_age_days")
        )

        expiration_result = assess_expiration(
            whois.get("expiration_date")
        )

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

    else:
        findings.append(
            "WHOIS information could not be determined."
        )

    # DNSBL assessment.
    dnsbl_result = assess_dnsbl(dnsbl)

    if dnsbl_result["status"] == "concerning":
        findings.append(dnsbl_result["reason"])

    # HTTPS assessment.
    https_result = assess_https(scheme or "")

    if https_result["status"] == "caution":
        findings.append(https_result["reason"])

    # Determine overall assessment.
    dnsbl_concerning = dnsbl_result["status"] == "concerning"

    domain_age_concerning = (
        domain_age_result["status"] == "concerning"
    )

    expiration_concerning = (
        expiration_result["status"] == "concerning"
    )

    dnsbl_unknown = dnsbl_result["status"] == "unknown"

    domain_age_caution = (
        domain_age_result["status"] == "caution"
    )

    expiration_caution = (
        expiration_result["status"] == "caution"
    )

    https_caution = (
        https_result["status"] == "caution"
    )

    if dnsbl_concerning:
        assessment = "concerning"

    elif domain_age_concerning or expiration_concerning:
        assessment = "suspicious"

    elif (
        dnsbl_unknown
        or domain_age_caution
        or expiration_caution
        or https_caution
    ):
        assessment = "caution"

    else:
        assessment = "no_obvious_concerns"

    return {
        "url": url_analysis.get("url"),
        "domain": domain,
        "assessment": assessment,
        "findings": findings,
    }


def assess_urls(url_analyses: list[dict]) -> list[dict]:
    """
    Assess multiple analyzed URLs.
    """

    results = []

    for url_analysis in url_analyses:
        results.append(assess_url(url_analysis))

    return results