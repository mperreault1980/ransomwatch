"""Dataclasses for advisories, IOC records, and search results."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Advisory:
    """A CISA #StopRansomware advisory."""

    advisory_id: str  # e.g. "aa23-061a"
    title: str
    url: str
    published: datetime | None = None
    stix_url: str | None = None
    pdf_url: str | None = None


@dataclass
class IOCRecord:
    """A single Indicator of Compromise extracted from an advisory."""

    ioc_type: str  # "ipv4-addr", "domain-name", "url", "file:hashes"
    value: str
    advisory_id: str
    source: str  # "stix" or "pdf"


@dataclass
class SearchResult:
    """Result of looking up an IP in the database."""

    query: str
    normalized_ip: str
    found: bool
    matches: list[MatchDetail] = field(default_factory=list)


@dataclass
class MatchDetail:
    """One advisory match for a searched IP."""

    advisory_id: str
    title: str
    url: str
    source: str  # "stix" or "pdf"
    published: datetime | None = None
