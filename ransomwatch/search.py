"""IP lookup engine — wire defanging with database search."""

from __future__ import annotations

from .database import search_ip
from .defang import refang_ip
from .models import SearchResult


def lookup_ip(raw_query: str) -> SearchResult:
    """Look up an IP address, handling defanged input.

    Accepts formats like:
        192.168.1.1
        192[.]168[.]1[.]1
        192(dot)168(dot)1(dot)1
    """
    normalized = refang_ip(raw_query.strip())
    result = search_ip(normalized)
    # Preserve the original query
    result.query = raw_query.strip()
    result.normalized_ip = normalized
    return result
