"""
URL utilities - URL extraction, cleaning, normalization, and validation.
Enhanced for mailforensic threat analysis.
"""

import re
import logging
import ipaddress
from typing import List
from urllib.parse import urlparse, urlunparse

logger = logging.getLogger(__name__)

# Broader URL matcher that also captures www-prefixed URLs and trims trailing punctuation
URL_PATTERN = re.compile(r"(https?://[^\s<>'\"()]+|www\.[^\s<>'\"()]+)", re.IGNORECASE)
# IP pattern for IPv4
IPV4_PATTERN = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")


def _clean_url(found: str) -> str:
    """Strip trailing punctuation that commonly clings to URLs in prose."""
    cleaned = found.rstrip(".,);'\"]")
    if cleaned.lower().startswith("www."):
        cleaned = f"https://{cleaned}"
    return cleaned


def normalize_url(url: str) -> str:
    """
    Normalize URLs for consistent downstream checks: ensure scheme, lowercase host, drop fragments.
    Returns an empty string if parsing fails.
    """
    if not url or not isinstance(url, str):
        return ""

    try:
        parsed = urlparse(url.strip())

        # Add default scheme if missing
        if not parsed.scheme:
            parsed = urlparse(f"http://{url}")

        # If netloc is empty but path has content, treat path as netloc (handles bare domains)
        if not parsed.netloc and parsed.path:
            parsed = urlparse(f"{parsed.scheme}://{parsed.path}")

        # Lowercase host, strip fragments
        netloc = parsed.netloc.lower()
        normalized = parsed._replace(netloc=netloc, fragment="")
        return urlunparse(normalized)
    except Exception as e:
        logger.debug(f"URL normalization error for '{url}': {e}")
        return ""


def is_valid_url(url: str, max_length: int = 2048) -> bool:
    """Basic sanity checks to avoid obviously invalid or abusive inputs."""
    if not url or len(url) > max_length or " " in url:
        return False

    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return False
    if not parsed.netloc:
        return False
    return True


def extract_urls(text: str) -> List[str]:
    """
    Extract HTTP/HTTPS URLs from text with precision:
    - Matches explicit schemes or www-prefixed domains
    - Removes trailing punctuation
    - Normalizes scheme and host casing
    """
    if not text:
        return []

    found = [_clean_url(match) for match in URL_PATTERN.findall(text)]
    normalized = []
    seen = set()
    for url in found:
        norm = normalize_url(url)
        if not norm or norm in seen:
            continue
        if is_valid_url(norm):
            seen.add(norm)
            normalized.append(norm)
    return normalized


def is_valid_ipv4(ip: str) -> bool:
    """Check if string is a valid IPv4 address."""
    if not ip or not isinstance(ip, str):
        return False
    return bool(IPV4_PATTERN.match(ip.strip()))


def is_valid_ipv6(ip: str) -> bool:
    """Check if string is a valid IPv6 address."""
    if not ip or not isinstance(ip, str):
        return False
    try:
        ipaddress.IPv6Address(ip.strip())
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def is_valid_ip(ip: str) -> bool:
    """Check if string is a valid IPv4 or IPv6 address."""
    return is_valid_ipv4(ip) or is_valid_ipv6(ip)


def is_valid_query(query: str) -> bool:
    """
    Check if query is valid URL, IP, or domain.
    Returns True if query is any of: URL, IPv4, IPv6, or domain name.
    """
    if not query or not isinstance(query, str):
        return False
    
    query = query.strip()
    
    if is_valid_url(query):
        return True
    
    if is_valid_ip(query):
        return True
    
    if "." in query and len(query) <= 255:
        domain = query.lower()
        if domain.startswith("http://"):
            domain = domain[7:]
        elif domain.startswith("https://"):
            domain = domain[8:]
        
        if ".." in domain or domain.startswith(".") or domain.endswith("."):
            return False
        
        labels = domain.split(".")
        if len(labels) < 2:
            return False
        
        for label in labels:
            if not label or len(label) > 63:
                return False
            if label.startswith("-") or label.endswith("-"):
                return False
            if not all(c.isalnum() or c == "-" for c in label):
                return False
        
        return True
    
    return False
