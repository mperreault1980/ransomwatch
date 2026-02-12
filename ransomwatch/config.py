"""Paths, constants, and HTTP settings."""

from pathlib import Path

from platformdirs import user_cache_dir, user_data_dir

APP_NAME = "ransomwatch"

# CISA advisory listing (paginated)
CISA_SEARCH_URL = "https://www.cisa.gov/search"
CISA_BASE_URL = "https://www.cisa.gov"
SEARCH_QUERY = "#StopRansomware"

# Local storage
DATA_DIR = Path(user_data_dir(APP_NAME))
CACHE_DIR = Path(user_cache_dir(APP_NAME))
STIX_DIR = CACHE_DIR / "stix"
PDF_DIR = CACHE_DIR / "pdfs"
DB_PATH = DATA_DIR / "ransomwatch.db"

# HTTP
USER_AGENT = (
    "ransomwatch/0.1.0 "
    "(+https://github.com/example/ransomwatch; security-research)"
)
REQUEST_TIMEOUT = 30
REQUEST_DELAY = 1.0  # seconds between requests
