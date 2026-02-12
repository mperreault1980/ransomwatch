"""PDF IOC extraction using pdfplumber."""

from __future__ import annotations

from pathlib import Path

import pdfplumber

from .defang import extract_ips_from_text
from .models import IOCRecord


def parse_pdf_file(path: Path, advisory_id: str) -> list[IOCRecord]:
    """Extract IPv4 IOCs from a PDF advisory file."""
    text_parts: list[str] = []

    with pdfplumber.open(path) as pdf:
        for page in pdf.pages:
            page_text = page.extract_text()
            if page_text:
                text_parts.append(page_text)

    full_text = "\n".join(text_parts)
    ips = extract_ips_from_text(full_text)

    return [
        IOCRecord(
            ioc_type="ipv4-addr",
            value=ip,
            advisory_id=advisory_id,
            source="pdf",
        )
        for ip in ips
    ]
