"""CISA advisory discovery and file download.

CISA's advisory listing page is JS-rendered, so we maintain a catalog of
known #StopRansomware advisory IDs and scrape each advisory page directly
to discover STIX JSON and PDF download links.
"""

from __future__ import annotations

import time
from pathlib import Path
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

from .config import (
    CISA_BASE_URL,
    PDF_DIR,
    REQUEST_DELAY,
    REQUEST_TIMEOUT,
    STIX_DIR,
    USER_AGENT,
)
from .models import Advisory

_SESSION: requests.Session | None = None

# Known #StopRansomware advisory catalog.
# (advisory_id, title)
# The CISA listing page is JS-rendered and can't be scraped with requests,
# so we maintain this list. Run `ransomwatch update --refresh-catalog` or
# contribute new entries as CISA publishes them.
_ADVISORY_CATALOG: list[tuple[str, str]] = [
    ("aa25-203a", "#StopRansomware: Interlock"),
    ("aa25-071a", "#StopRansomware: Medusa"),
    ("aa25-050a", "#StopRansomware: Ghost/Cring"),
    ("aa24-242a", "#StopRansomware: RansomHub Ransomware"),
    ("aa24-241a", "#StopRansomware: Br0k3r (NoEscape, Ransomhouse, BlackCat, Pay2Key)"),
    ("aa24-131a", "#StopRansomware: Black Basta"),
    ("aa24-109a", "#StopRansomware: Akira Ransomware"),
    ("aa24-060a", "#StopRansomware: Phobos Ransomware"),
    ("aa23-353a", "#StopRansomware: ALPHV Blackcat"),
    ("aa23-352a", "#StopRansomware: Play Ransomware"),
    ("aa23-325a", "#StopRansomware: LockBit 3.0 Ransomware"),
    ("aa23-320a", "#StopRansomware: Scattered Spider"),
    ("aa23-319a", "#StopRansomware: Rhysida Ransomware"),
    ("aa23-284a", "#StopRansomware: AvosLocker Ransomware"),
    ("aa23-263a", "#StopRansomware: Snatch Ransomware"),
    ("aa23-165a", "#StopRansomware: LockBit Ransomware"),
    ("aa23-158a", "#StopRansomware: CL0P Ransomware"),
    ("aa23-136a", "#StopRansomware: BianLian Ransomware"),
    ("aa23-075a", "#StopRansomware: LockBit 3.0"),
    ("aa23-061a", "#StopRansomware: Blacksuit (Royal) Ransomware"),
    ("aa23-040a", "#StopRansomware: Ransomware Attacks on Critical Infrastructure Fund DPRK"),
    ("aa22-335a", "#StopRansomware: Cuba Ransomware"),
    ("aa22-321a", "#StopRansomware: Hive Ransomware"),
    ("aa22-294a", "#StopRansomware: Daixin Team"),
    ("aa22-249a", "#StopRansomware: Vice Society"),
    ("aa22-223a", "#StopRansomware: Zeppelin Ransomware"),
    ("aa22-181a", "#StopRansomware: MedusaLocker"),
    ("aa22-152a", "#StopRansomware: Karakurt Data Extortion Group"),
    ("aa21-291a", "#StopRansomware: BlackMatter Ransomware"),
    ("aa21-265a", "#StopRansomware: Conti Ransomware"),
    ("aa21-131a", "#StopRansomware: DarkSide Ransomware"),
]


def _get_session() -> requests.Session:
    global _SESSION
    if _SESSION is None:
        _SESSION = requests.Session()
        _SESSION.headers.update({"User-Agent": USER_AGENT})
    return _SESSION


def _polite_get(url: str) -> requests.Response:
    """GET with delay and timeout."""
    time.sleep(REQUEST_DELAY)
    session = _get_session()
    resp = session.get(url, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    return resp


def discover_advisories(progress_callback=None) -> list[Advisory]:
    """Return known #StopRansomware advisories from the built-in catalog."""
    advisories: list[Advisory] = []

    for adv_id, title in _ADVISORY_CATALOG:
        # Standard CISA advisory URL pattern
        # Some older advisories use a "-0" suffix variant
        url = f"{CISA_BASE_URL}/news-events/cybersecurity-advisories/{adv_id}"
        advisories.append(
            Advisory(
                advisory_id=adv_id,
                title=title,
                url=url,
            )
        )

    if progress_callback:
        progress_callback(f"Loaded {len(advisories)} advisories from catalog")

    return advisories


def enrich_advisory(advisory: Advisory) -> Advisory:
    """Visit an advisory page to find STIX JSON and PDF download links.

    Collects ALL STIX JSON URLs (some advisories have multiple revisions)
    and the latest PDF URL.
    """
    try:
        resp = _polite_get(advisory.url)
    except requests.RequestException:
        return advisory

    soup = BeautifulSoup(resp.text, "html.parser")

    stix_urls: list[str] = []

    for link in soup.find_all("a", href=True):
        href = link["href"]

        if not href.startswith("http"):
            href = urljoin(CISA_BASE_URL, href)

        # STIX JSON files — collect all of them
        if href.endswith(".json") and "stix" in href.lower():
            stix_urls.append(href)
        elif href.endswith(".json"):
            # Some STIX files don't have "stix" in URL but are JSON on CISA
            link_text = link.get_text(strip=True).lower()
            if "stix" in link_text or "json" in link_text:
                stix_urls.append(href)

        # PDF files — take the last one found (usually the most recent)
        if href.endswith(".pdf"):
            advisory.pdf_url = href

    # Store the latest STIX URL (last in page order = most recent revision)
    if stix_urls:
        advisory.stix_url = stix_urls[-1]

    return advisory


def download_file(url: str, dest_dir: Path, filename: str | None = None) -> Path | None:
    """Download a file to dest_dir, return the local path."""
    dest_dir.mkdir(parents=True, exist_ok=True)

    if filename is None:
        filename = url.split("/")[-1].split("?")[0]

    dest = dest_dir / filename
    if dest.exists():
        return dest

    try:
        resp = _polite_get(url)
        dest.write_bytes(resp.content)
        return dest
    except requests.RequestException:
        return None


def download_stix(advisory: Advisory) -> Path | None:
    """Download the STIX JSON file for an advisory."""
    if not advisory.stix_url:
        return None
    filename = f"{advisory.advisory_id}.json"
    return download_file(advisory.stix_url, STIX_DIR, filename)


def download_pdf(advisory: Advisory) -> Path | None:
    """Download the PDF file for an advisory."""
    if not advisory.pdf_url:
        return None
    filename = f"{advisory.advisory_id}.pdf"
    return download_file(advisory.pdf_url, PDF_DIR, filename)
