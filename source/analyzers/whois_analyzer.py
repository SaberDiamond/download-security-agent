from datetime import datetime, timezone

import whois


def normalize_whois_date(value):
    """
    Normalize a WHOIS date value.

    Some WHOIS servers return a single datetime while others
    may return a list of datetime values.
    """

    if isinstance(value, list):
        if not value:
            return None

        value = value[0]

    return value


def analyze_domain(domain: str) -> dict:
    """
    Perform WHOIS analysis on a domain.

    Returns:
    - domain
    - registrar
    - creation date
    - expiration date
    - domain age in days

    WHOIS information is treated as evidence for assessment.
    It does not by itself determine whether a domain is malicious.
    """

    try:
        result = whois.whois(domain)

        creation_date = normalize_whois_date(
            result.creation_date
        )

        expiration_date = normalize_whois_date(
            result.expiration_date
        )

        now = datetime.now(timezone.utc)

        # Calculate domain age.
        domain_age_days = None

        if creation_date:
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(
                    tzinfo=timezone.utc
                )

            domain_age_days = (now - creation_date).days

        return {
            "domain": domain,
            "registrar": result.registrar,
            "creation_date": creation_date,
            "expiration_date": expiration_date,
            "domain_age_days": domain_age_days,
        }

    except Exception as error:
        return {
            "domain": domain,
            "error": str(error),
        }