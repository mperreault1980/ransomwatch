"""STIX 2.1 JSON IOC extraction."""

from __future__ import annotations

import json
import re
from pathlib import Path

from .models import IOCRecord

# STIX 2.1 indicator patterns we extract
# e.g. [ipv4-addr:value = '1.2.3.4']
# e.g. [domain-name:value = 'evil.com']
# e.g. [url:value = 'http://evil.com/payload']
# e.g. [file:hashes.'SHA-256' = 'abc123...']
_PATTERN_RE = re.compile(
    r"\[(\S+?)(?::value|\:hashes\.\S+?)\s*=\s*'([^']+)'\]"
)

# Map STIX object types to our ioc_type values
_TYPE_MAP = {
    "ipv4-addr": "ipv4-addr",
    "ipv6-addr": "ipv6-addr",
    "domain-name": "domain-name",
    "url": "url",
    "file": "file:hashes",
}


def parse_stix_file(path: Path, advisory_id: str) -> list[IOCRecord]:
    """Parse a STIX 2.1 JSON file and extract IOC records."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    objects = data.get("objects", [])
    records: list[IOCRecord] = []
    seen: set[tuple[str, str]] = set()

    for obj in objects:
        if obj.get("type") != "indicator":
            continue

        pattern = obj.get("pattern", "")
        for match in _PATTERN_RE.finditer(pattern):
            raw_type = match.group(1)
            value = match.group(2)

            ioc_type = _TYPE_MAP.get(raw_type, raw_type)
            key = (ioc_type, value)
            if key not in seen:
                seen.add(key)
                records.append(
                    IOCRecord(
                        ioc_type=ioc_type,
                        value=value,
                        advisory_id=advisory_id,
                        source="stix",
                    )
                )

    return records
