"""SQLite cache layer for advisories and IOCs."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

from .config import DATA_DIR, DB_PATH
from .models import Advisory, IOCRecord, MatchDetail, SearchResult


def _get_connection() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    """Create tables if they don't exist."""
    conn = _get_connection()
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS advisories (
                advisory_id TEXT PRIMARY KEY,
                title       TEXT NOT NULL,
                url         TEXT NOT NULL,
                published   TEXT,
                stix_url    TEXT,
                pdf_url     TEXT
            );

            CREATE TABLE IF NOT EXISTS iocs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc_type    TEXT NOT NULL,
                value       TEXT NOT NULL,
                advisory_id TEXT NOT NULL,
                source      TEXT NOT NULL,
                FOREIGN KEY (advisory_id) REFERENCES advisories(advisory_id)
            );

            CREATE INDEX IF NOT EXISTS idx_iocs_value
                ON iocs(value);

            CREATE INDEX IF NOT EXISTS idx_iocs_advisory
                ON iocs(advisory_id);
        """)
        conn.commit()
    finally:
        conn.close()


def upsert_advisory(adv: Advisory) -> None:
    """Insert or update an advisory record."""
    conn = _get_connection()
    try:
        conn.execute(
            """
            INSERT INTO advisories (advisory_id, title, url, published, stix_url, pdf_url)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(advisory_id) DO UPDATE SET
                title    = excluded.title,
                url      = excluded.url,
                published = excluded.published,
                stix_url = excluded.stix_url,
                pdf_url  = excluded.pdf_url
            """,
            (
                adv.advisory_id,
                adv.title,
                adv.url,
                adv.published.isoformat() if adv.published else None,
                adv.stix_url,
                adv.pdf_url,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def insert_iocs(records: list[IOCRecord]) -> int:
    """Bulk-insert IOC records. Returns count inserted."""
    if not records:
        return 0
    conn = _get_connection()
    try:
        conn.executemany(
            """
            INSERT INTO iocs (ioc_type, value, advisory_id, source)
            VALUES (?, ?, ?, ?)
            """,
            [(r.ioc_type, r.value, r.advisory_id, r.source) for r in records],
        )
        conn.commit()
        return len(records)
    finally:
        conn.close()


def clear_iocs_for_advisory(advisory_id: str, source: str | None = None) -> None:
    """Remove IOCs for an advisory (optionally filtered by source)."""
    conn = _get_connection()
    try:
        if source:
            conn.execute(
                "DELETE FROM iocs WHERE advisory_id = ? AND source = ?",
                (advisory_id, source),
            )
        else:
            conn.execute(
                "DELETE FROM iocs WHERE advisory_id = ?",
                (advisory_id,),
            )
        conn.commit()
    finally:
        conn.close()


def search_ip(ip: str) -> SearchResult:
    """Look up an IP address in the IOC database."""
    conn = _get_connection()
    try:
        rows = conn.execute(
            """
            SELECT i.advisory_id, a.title, a.url, i.source, a.published
            FROM iocs i
            JOIN advisories a ON i.advisory_id = a.advisory_id
            WHERE i.value = ? AND i.ioc_type = 'ipv4-addr'
            """,
            (ip,),
        ).fetchall()

        matches = []
        for row in rows:
            pub = None
            if row[4]:
                try:
                    pub = datetime.fromisoformat(row[4])
                except ValueError:
                    pass
            matches.append(
                MatchDetail(
                    advisory_id=row[0],
                    title=row[1],
                    url=row[2],
                    source=row[3],
                    published=pub,
                )
            )

        return SearchResult(
            query=ip,
            normalized_ip=ip,
            found=len(matches) > 0,
            matches=matches,
        )
    finally:
        conn.close()


def get_stats() -> dict:
    """Return database statistics."""
    conn = _get_connection()
    try:
        advisory_count = conn.execute(
            "SELECT COUNT(*) FROM advisories"
        ).fetchone()[0]

        ioc_count = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]

        type_counts = dict(
            conn.execute(
                "SELECT ioc_type, COUNT(*) FROM iocs GROUP BY ioc_type"
            ).fetchall()
        )

        source_counts = dict(
            conn.execute(
                "SELECT source, COUNT(*) FROM iocs GROUP BY source"
            ).fetchall()
        )

        return {
            "advisories": advisory_count,
            "total_iocs": ioc_count,
            "by_type": type_counts,
            "by_source": source_counts,
        }
    finally:
        conn.close()


def list_groups() -> list[tuple[str, str]]:
    """List ransomware groups (extracted from advisory titles).

    Returns list of (group_name, advisory_id) sorted by group name.
    The group name is derived from the advisory title by stripping
    the '#StopRansomware: ' prefix.
    """
    conn = _get_connection()
    try:
        rows = conn.execute(
            """
            SELECT title, advisory_id FROM advisories
            ORDER BY title
            """
        ).fetchall()

        results = []
        for title, adv_id in rows:
            # Strip the common prefix
            name = title
            for prefix in ("#StopRansomware: ", "#StopRansomware:"):
                if name.startswith(prefix):
                    name = name[len(prefix):].strip()
                    break
            results.append((name, adv_id))
        return results
    finally:
        conn.close()


def advisory_exists(advisory_id: str) -> bool:
    """Check if an advisory is already in the database."""
    conn = _get_connection()
    try:
        row = conn.execute(
            "SELECT 1 FROM advisories WHERE advisory_id = ?",
            (advisory_id,),
        ).fetchone()
        return row is not None
    finally:
        conn.close()
