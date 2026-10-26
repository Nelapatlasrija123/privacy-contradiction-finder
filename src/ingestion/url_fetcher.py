"""Safe URL fetching module with Server-Side Request Forgery (SSRF) protection.

Ensures only publicly routable HTTP/HTTPS web endpoints can be audited, protecting
internal networks, loopback interfaces, and cloud metadata services.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import requests

from src.ingestion.text_extractor import clean_text


class SSRFProtectionError(Exception):
    """Raised when an attempt is made to access an internal, private, or loopback network address."""
    pass


class WebRetrievalError(Exception):
    """Raised when web page retrieval fails due to network, HTTP, or parsing errors."""
    pass


# Maximum allowed response size: 5 Megabytes
MAX_RESPONSE_SIZE_BYTES = 5 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 10
CUSTOM_USER_AGENT = (
    "PrivacyContradictionFinder/1.0 (+https://github.com/privacy-contradiction-finder; Academic Research)"
)


def is_ip_publicly_routable(ip_str: str) -> bool:
    """Check whether an IP address is publicly routable on the global internet.

    Blocks:
        - Loopback (127.0.0.0/8, ::1)
        - Private / RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
        - Link-Local (169.254.0.0/16 - Cloud metadata endpoints, fe80::/10)
        - Carrier-Grade NAT (100.64.0.0/10)
        - Multicast, Reserved, and Unspecified addresses (0.0.0.0)
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        if (
            ip.is_loopback
            or ip.is_private
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return False
        return True
    except ValueError:
        return False


def validate_url_safety(target_url: str) -> str:
    """Validate that the given URL uses http/https and resolves exclusively to public IPs.

    Args:
        target_url: The URL entered by the user.

    Returns:
        The validated URL.

    Raises:
        SSRFProtectionError: If scheme is disallowed or destination resolves to a private IP.
        WebRetrievalError: If URL is malformed or DNS resolution fails.
    """
    if not target_url or not isinstance(target_url, str):
        raise WebRetrievalError("URL must be a non-empty string.")

    target_url = target_url.strip()
    parsed = urlparse(target_url)

    if parsed.scheme.lower() not in ("http", "https"):
        raise SSRFProtectionError(
            f"Unsupported URL scheme '{parsed.scheme}'. Only 'http' and 'https' protocols are permitted."
        )

    hostname = parsed.hostname
    if not hostname:
        raise WebRetrievalError("URL does not contain a valid hostname.")

    # Check for localhost literal
    if hostname.lower() in ("localhost", "localhost.localdomain", "ip6-localhost"):
        raise SSRFProtectionError(f"Access to local host '{hostname}' is blocked for security (SSRF prevention).")

    # Resolve hostname via DNS and check every resolved address
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    try:
        addr_info = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise WebRetrievalError(f"DNS resolution failed for host '{hostname}': {exc}") from exc

    resolved_ips = set()
    for item in addr_info:
        sockaddr = item[4]
        ip_addr = sockaddr[0]
        resolved_ips.add(ip_addr)

    for ip_str in resolved_ips:
        if not is_ip_publicly_routable(ip_str):
            raise SSRFProtectionError(
                f"Security Alert: Destination '{hostname}' resolves to private/internal IP {ip_str}. "
                "Retrieval blocked by SSRF protection policy."
            )

    return target_url


def extract_policy_from_html(html_content: str) -> str:
    """Extract clean readable text from HTML, stripping boilerplate and scripts.

    Args:
        html_content: Raw HTML text from HTTP response.

    Returns:
        Extracted and sanitized text content.
    """
    soup = BeautifulSoup(html_content, "html.parser")

    # Remove non-content elements
    for tag_name in (
        "script",
        "style",
        "nav",
        "header",
        "footer",
        "aside",
        "form",
        "noscript",
        "svg",
        "iframe",
        "button",
    ):
        for element in soup.find_all(tag_name):
            element.decompose()

    # Prioritize main content containers if present
    main_container = (
        soup.find("article")
        or soup.find("main")
        or soup.find(id=lambda v: v and "privacy" in v.lower())
        or soup.find(class_=lambda v: v and "privacy" in v.lower())
        or soup.body
        or soup
    )

    raw_text = main_container.get_text(separator="\n")
    return clean_text(raw_text)


def fetch_policy_from_url(
    target_url: str,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    max_bytes: int = MAX_RESPONSE_SIZE_BYTES,
) -> str:
    """Safely fetch and parse a public privacy policy webpage.

    Args:
        target_url: The web URL to retrieve.
        timeout_seconds: Network connection and read timeout.
        max_bytes: Maximum allowed byte download limit.

    Returns:
        Sanitized plain text extracted from the policy page.

    Raises:
        SSRFProtectionError: If URL targets private or internal networks.
        WebRetrievalError: If HTTP transfer fails or content is not text/html.
    """
    safe_url = validate_url_safety(target_url)

    headers = {
        "User-Agent": CUSTOM_USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }

    try:
        with requests.get(
            safe_url,
            headers=headers,
            timeout=timeout_seconds,
            stream=True,
            allow_redirects=True,
        ) as response:
            response.raise_for_status()

            # Validate Content-Type
            content_type = response.headers.get("Content-Type", "").lower()
            if not ("text/html" in content_type or "text/plain" in content_type):
                raise WebRetrievalError(
                    f"Unsupported content type '{content_type}'. Expected HTML or plain text."
                )

            # Stream download with size cap
            chunks = []
            downloaded_bytes = 0
            for chunk in response.iter_content(chunk_size=8192, decode_unicode=False):
                downloaded_bytes += len(chunk)
                if downloaded_bytes > max_bytes:
                    raise WebRetrievalError(
                        f"Target document exceeds maximum allowed size ({max_bytes / (1024 * 1024):.1f} MB)."
                    )
                chunks.append(chunk)

            raw_bytes = b"".join(chunks)

            # Detect encoding or fallback to utf-8
            encoding = response.encoding or "utf-8"
            html_text = raw_bytes.decode(encoding, errors="replace")

    except requests.exceptions.Timeout as exc:
        raise WebRetrievalError(
            f"Connection timed out after {timeout_seconds} seconds while fetching {target_url}."
        ) from exc
    except requests.exceptions.RequestException as exc:
        raise WebRetrievalError(f"HTTP request failed: {exc}") from exc

    extracted = extract_policy_from_html(html_text)
    if not extracted:
        raise WebRetrievalError(
            "The webpage was retrieved successfully, but no readable policy text could be extracted."
        )

    return extracted
