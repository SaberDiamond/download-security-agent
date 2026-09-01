import socket
from urllib.parse import urlparse

from source.analyzers.whois_analyzer import analyze_domain
from source.analyzers.dnsbl_analyzer import check_dnsbl


def normalize_url(url: str) -> str:
    """
    Normalize a URL by ensuring it has an HTTP or HTTPS scheme.
    """

    url = str(url).strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url


def resolve_domain(domain: str | None) -> list[str]:
    """
    Resolve a domain to its IP addresses.
    """

    if not domain:
        return []

    try:
        results = socket.getaddrinfo(
            domain,
            None,
            type=socket.SOCK_STREAM,
        )

        ip_addresses = set()

        for result in results:
            ip_addresses.add(result[4][0])

        return sorted(ip_addresses)

    except socket.gaierror:
        return []

    except Exception:
        return []


def analyze_url(url: str) -> dict:
    """
    Analyze a single URL.

    Collects:
    - normalized URL information
    - domain information
    - resolved IP addresses
    - WHOIS information
    - DNSBL reputation information

    This function collects evidence. It does not determine
    whether the URL is safe or malicious.
    """

    normalized_url = normalize_url(url)
    parsed = urlparse(normalized_url)

    domain = parsed.hostname

    # Resolve domain to IP addresses.
    ip_addresses = resolve_domain(domain)

    # WHOIS analysis.
    if domain:
        whois_analysis = analyze_domain(domain)
    else:
        whois_analysis = {
            "domain": None,
            "error": "Could not extract domain",
        }

    # DNSBL analysis for each resolved IPv4 address.
    dnsbl_analysis = []

    for ip_address in ip_addresses:
        if ":" in ip_address:
            continue

        dnsbl_result = check_dnsbl(ip_address)
        dnsbl_analysis.append(dnsbl_result)

    return {
        "url": normalized_url,
        "scheme": parsed.scheme,
        "domain": domain,
        "port": parsed.port,
        "path": parsed.path,
        "query": parsed.query,
        "fragment": parsed.fragment,
        "ip_addresses": ip_addresses,
        "whois": whois_analysis,
        "dnsbl": dnsbl_analysis,
    }


def analyze_urls(urls: list[str]) -> list[dict]:
    """
    Analyze multiple URLs.

    Individual URL failures are captured so that one
    problematic URL does not stop analysis of the others.
    """

    results = []

    for url in urls:
        try:
            results.append(analyze_url(url))

        except Exception as error:
            results.append(
                {
                    "url": str(url),
                    "error": str(error),
                }
            )

    return results