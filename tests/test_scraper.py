"""Tests for the scraper discovery module."""

from unittest.mock import MagicMock, patch

import pytest
import requests

from ransomwatch.models import Advisory
from ransomwatch.scraper import (
    _catalog_advisories,
    discover_advisories,
    discover_advisories_live,
)


def _make_listing_html(entries):
    """Build a fake CISA advisory listing page with the given entries.

    Each entry is (advisory_id, title).  Non-advisory links are also included
    to verify they are filtered out.
    """
    links = []
    for adv_id, title in entries:
        links.append(
            f'<a href="/news-events/cybersecurity-advisories/{adv_id}">{title}</a>'
        )
    # Add a non-advisory link to ensure it's ignored
    links.append('<a href="/about">About CISA</a>')
    return f"<html><body>{''.join(links)}</body></html>"


def _mock_response(html):
    """Create a mock requests.Response with the given HTML body."""
    resp = MagicMock(spec=requests.Response)
    resp.text = html
    resp.status_code = 200
    resp.raise_for_status = MagicMock()
    return resp


class TestDiscoverAdvisoriesLive:
    """Tests for discover_advisories_live()."""

    @patch("ransomwatch.scraper._polite_get")
    def test_discovers_stopransomware_advisories(self, mock_get):
        """Finds #StopRansomware entries and ignores others."""
        html = _make_listing_html([
            ("aa25-100a", "#StopRansomware: FakeLocker"),
            ("aa25-099a", "Alert: Something Else"),
            ("aa25-098a", "#StopRansomware: AnotherRansom"),
        ])
        # Page 0 has results, page 1 has no StopRansomware (triggers stop)
        html_empty = _make_listing_html([
            ("aa24-050a", "Alert: Unrelated Advisory"),
        ])
        mock_get.side_effect = [_mock_response(html), _mock_response(html_empty)]

        result = discover_advisories_live(known_ids=set())

        assert len(result) == 2
        ids = {a.advisory_id for a in result}
        assert "aa25-100a" in ids
        assert "aa25-098a" in ids
        assert "aa25-099a" not in ids  # Not a StopRansomware advisory

    @patch("ransomwatch.scraper._polite_get")
    def test_skips_known_ids(self, mock_get):
        """Advisories already in known_ids are not returned."""
        html = _make_listing_html([
            ("aa25-100a", "#StopRansomware: FakeLocker"),
            ("aa25-098a", "#StopRansomware: AnotherRansom"),
        ])
        html_empty = _make_listing_html([])
        mock_get.side_effect = [_mock_response(html), _mock_response(html_empty)]

        result = discover_advisories_live(known_ids={"aa25-100a"})

        assert len(result) == 1
        assert result[0].advisory_id == "aa25-098a"

    @patch("ransomwatch.scraper._polite_get")
    def test_stops_when_no_advisory_links(self, mock_get):
        """Pagination stops when a page has no advisory links at all."""
        html_page0 = _make_listing_html([
            ("aa25-100a", "#StopRansomware: FakeLocker"),
        ])
        html_empty = _make_listing_html([])
        mock_get.side_effect = [
            _mock_response(html_page0),
            _mock_response(html_empty),
        ]

        result = discover_advisories_live(known_ids=set())

        assert len(result) == 1
        # Only 2 pages fetched (page 0 + page 1 which was empty)
        assert mock_get.call_count == 2

    @patch("ransomwatch.scraper._polite_get")
    def test_stops_when_all_known(self, mock_get):
        """Pagination stops when a page has StopRansomware links but all known."""
        html = _make_listing_html([
            ("aa25-100a", "#StopRansomware: FakeLocker"),
        ])
        mock_get.side_effect = [_mock_response(html)]

        result = discover_advisories_live(known_ids={"aa25-100a"})

        assert len(result) == 0
        # Only 1 page fetched — stopped because all were known
        assert mock_get.call_count == 1

    @patch("ransomwatch.scraper._polite_get")
    def test_stops_on_request_error(self, mock_get):
        """Pagination stops gracefully if a request fails."""
        html = _make_listing_html([
            ("aa25-100a", "#StopRansomware: FakeLocker"),
        ])
        mock_get.side_effect = [
            _mock_response(html),
            requests.RequestException("Connection failed"),
        ]

        result = discover_advisories_live(known_ids=set())

        assert len(result) == 1
        assert result[0].advisory_id == "aa25-100a"

    @patch("ransomwatch.scraper._polite_get")
    def test_progress_callback_called(self, mock_get):
        """Progress callback is invoked for each page."""
        html = _make_listing_html([
            ("aa25-100a", "#StopRansomware: FakeLocker"),
        ])
        html_empty = _make_listing_html([])
        mock_get.side_effect = [_mock_response(html), _mock_response(html_empty)]

        callback = MagicMock()
        discover_advisories_live(known_ids=set(), progress_callback=callback)

        assert callback.call_count >= 1
        # First call should mention page number
        callback.assert_any_call("Scanning advisory listing page 1...")

    @patch("ransomwatch.scraper._polite_get")
    def test_advisory_url_is_correct(self, mock_get):
        """Discovered advisories have the canonical CISA URL."""
        html = _make_listing_html([
            ("aa25-100a", "#StopRansomware: FakeLocker"),
        ])
        html_empty = _make_listing_html([])
        mock_get.side_effect = [_mock_response(html), _mock_response(html_empty)]

        result = discover_advisories_live(known_ids=set())

        assert result[0].url == (
            "https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-100a"
        )

    @patch("ransomwatch.scraper.MAX_DISCOVERY_PAGES", 3)
    @patch("ransomwatch.scraper._polite_get")
    def test_respects_max_pages(self, mock_get):
        """Pagination stops at MAX_DISCOVERY_PAGES."""
        # Every page has a unique new advisory, so early-stop won't trigger
        pages = []
        for i in range(5):
            html = _make_listing_html([
                (f"aa25-{100 + i:03d}a", f"#StopRansomware: Ransom{i}"),
            ])
            pages.append(_mock_response(html))
        mock_get.side_effect = pages

        result = discover_advisories_live(known_ids=set())

        # Should have stopped after 3 pages despite more being available
        assert mock_get.call_count == 3
        assert len(result) == 3


class TestDiscoverAdvisories:
    """Tests for the main discover_advisories() dispatcher."""

    def test_catalog_only_by_default(self):
        """Without refresh, returns only catalog entries."""
        result = discover_advisories(refresh=False)

        catalog = _catalog_advisories()
        assert len(result) == len(catalog)
        result_ids = {a.advisory_id for a in result}
        catalog_ids = {a.advisory_id for a in catalog}
        assert result_ids == catalog_ids

    @patch("ransomwatch.scraper.discover_advisories_live")
    def test_refresh_merges_live_and_catalog(self, mock_live):
        """With refresh=True, live results are merged with catalog."""
        # Simulate live discovering one new advisory
        mock_live.return_value = [
            Advisory(
                advisory_id="aa25-999a",
                title="#StopRansomware: BrandNew",
                url="https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-999a",
            ),
        ]

        result = discover_advisories(refresh=True)

        catalog = _catalog_advisories()
        # Should have all catalog entries plus the new one
        assert len(result) == len(catalog) + 1
        result_ids = {a.advisory_id for a in result}
        assert "aa25-999a" in result_ids
        for a in catalog:
            assert a.advisory_id in result_ids

    @patch("ransomwatch.scraper.discover_advisories_live")
    def test_refresh_live_takes_precedence(self, mock_live):
        """Live results override catalog titles for the same advisory_id."""
        catalog = _catalog_advisories()
        existing_id = catalog[0].advisory_id

        mock_live.return_value = [
            Advisory(
                advisory_id=existing_id,
                title="#StopRansomware: Updated Title From Live",
                url=f"https://www.cisa.gov/news-events/cybersecurity-advisories/{existing_id}",
            ),
        ]

        result = discover_advisories(refresh=True)

        matched = [a for a in result if a.advisory_id == existing_id]
        assert len(matched) == 1
        assert matched[0].title == "#StopRansomware: Updated Title From Live"

    @patch("ransomwatch.scraper.discover_advisories_live")
    def test_refresh_no_new(self, mock_live):
        """When live finds nothing new, result equals catalog."""
        mock_live.return_value = []

        result = discover_advisories(refresh=True)

        catalog = _catalog_advisories()
        assert len(result) == len(catalog)

    def test_catalog_only_with_progress_callback(self):
        """Progress callback fires in catalog-only mode."""
        callback = MagicMock()
        discover_advisories(refresh=False, progress_callback=callback)

        callback.assert_called_once()
        assert "catalog" in callback.call_args[0][0].lower()
