from datetime import datetime, timezone

import whois


def analyze_domain(domain: str) -> dict:
    """
    Perform WHOIS analysis on a domain.

    Returns registration and expiration information
    that can later be used by the risk assessment engine.
    """

    try:
        result = whois.whois(domain)

        creation_date = result.creation_date
        expiration_date = result.expiration_date

        # Some WHOIS servers return multiple dates.
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        now = datetime.now(timezone.utc)

        # Calculate domain age.
        domain_age_days = None

        if creation_date:
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)

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