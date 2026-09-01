import os
import socket


def check_dnsbl(ip_address: str) -> dict:
    """
    Check whether an IPv4 address is listed by Spamhaus DQS.

    The Spamhaus DQS key is read from the
    SPAMHAUS_DQS_KEY environment variable.

    Returns:
    - listed=True if the IP is listed
    - listed=False if the IP is not listed
    - listed=None if the lookup could not be performed
    """

    # This POC currently supports IPv4 DNSBL lookups.
    if ":" in ip_address:
        return {
            "ip": ip_address,
            "listed": None,
            "status": "IPv6 not supported",
        }

    dqs_key = os.getenv("SPAMHAUS_DQS_KEY")

    if not dqs_key:
        return {
            "ip": ip_address,
            "listed": None,
            "status": "DQS key not configured",
        }

    # DNSBL lookups use the IP address in reverse order.
    reversed_ip = ".".join(ip_address.split(".")[::-1])

    # Spamhaus DQS query format.
    query = f"{reversed_ip}.{dqs_key}.zen.dq.spamhaus.net"

    try:
        socket.gethostbyname(query)

        return {
            "ip": ip_address,
            "listed": True,
            "status": "Listed",
        }

    except socket.gaierror:
        return {
            "ip": ip_address,
            "listed": False,
            "status": "Not listed",
        }

    except Exception as error:
        return {
            "ip": ip_address,
            "listed": None,
            "status": "Lookup error",
            "error": str(error),
        }