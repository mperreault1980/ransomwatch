"""IP deobfuscation — convert defanged IPs back to normal form."""

from __future__ import annotations

import re

# Patterns that replace the dot in defanged IPs
_DOT_PATTERNS = [
    r"\[\.\]",
    r"\[dot\]",
    r"\(dot\)",
    r"\(\.\)",
]
_DOT_RE = re.compile("|".join(_DOT_PATTERNS), re.IGNORECASE)

# Match an IPv4 address (after refanging)
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)


def refang_ip(text: str) -> str:
    """Replace defanged dot notations with actual dots.

    Handles: [.] [dot] (dot) (.)
    """
    return _DOT_RE.sub(".", text)


def extract_ips_from_text(text: str) -> list[str]:
    """Extract all IPv4 addresses from text, handling defanged formats.

    Returns deduplicated list preserving first-seen order.
    """
    cleaned = refang_ip(text)
    seen: set[str] = set()
    result: list[str] = []
    for match in _IPV4_RE.finditer(cleaned):
        ip = match.group()
        if ip not in seen:
            seen.add(ip)
            result.append(ip)
    return result
