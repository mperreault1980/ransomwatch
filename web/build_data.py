"""Export the ransomwatch SQLite database to a static JSON file for the web app."""

import json
import sqlite3
import sys
from pathlib import Path

# Allow running from project root or web/ directory
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ransomwatch.config import DB_PATH


def export():
    if not DB_PATH.exists():
        print(f"Database not found at {DB_PATH}")
        print("Run 'ransomwatch update' first.")
        sys.exit(1)

    conn = sqlite3.connect(str(DB_PATH))

    # Fetch all advisories
    advisories = {}
    for row in conn.execute(
        "SELECT advisory_id, title, url, published FROM advisories"
    ):
        advisories[row[0]] = {
            "title": row[1],
            "url": row[2],
            "published": row[3],
        }

    # Fetch all IOCs
    iocs = []
    for row in conn.execute(
        "SELECT ioc_type, value, advisory_id, source FROM iocs"
    ):
        iocs.append({
            "type": row[0],
            "value": row[1],
            "advisory_id": row[2],
            "source": row[3],
        })

    conn.close()

    data = {
        "advisories": advisories,
        "iocs": iocs,
        "stats": {
            "advisory_count": len(advisories),
            "ioc_count": len(iocs),
        },
    }

    out_path = Path(__file__).resolve().parent / "data.json"
    out_path.write_text(json.dumps(data, separators=(",", ":")))
    print(f"Exported {len(advisories)} advisories, {len(iocs)} IOCs to {out_path}")


if __name__ == "__main__":
    export()
