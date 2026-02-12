"""Tests for the database module."""

from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from ransomwatch.database import (
    advisory_exists,
    clear_iocs_for_advisory,
    get_stats,
    init_db,
    insert_iocs,
    list_groups,
    search_ip,
    upsert_advisory,
)
from ransomwatch.models import Advisory, IOCRecord


@pytest.fixture(autouse=True)
def tmp_db(tmp_path, monkeypatch):
    """Use a temporary database for each test."""
    db_path = tmp_path / "test.db"
    data_dir = tmp_path

    monkeypatch.setattr("ransomwatch.database.DB_PATH", db_path)
    monkeypatch.setattr("ransomwatch.database.DATA_DIR", data_dir)
    init_db()
    return db_path


@pytest.fixture
def sample_advisory():
    return Advisory(
        advisory_id="aa23-061a",
        title="#StopRansomware: Royal Ransomware",
        url="https://www.cisa.gov/cybersecurity-advisories/aa23-061a",
        published=datetime(2023, 3, 2, tzinfo=timezone.utc),
        stix_url="https://example.com/stix.json",
        pdf_url="https://example.com/advisory.pdf",
    )


@pytest.fixture
def sample_iocs():
    return [
        IOCRecord(
            ioc_type="ipv4-addr",
            value="193.233.254.21",
            advisory_id="aa23-061a",
            source="stix",
        ),
        IOCRecord(
            ioc_type="ipv4-addr",
            value="45.11.181.44",
            advisory_id="aa23-061a",
            source="stix",
        ),
        IOCRecord(
            ioc_type="domain-name",
            value="evil.example.com",
            advisory_id="aa23-061a",
            source="stix",
        ),
    ]


class TestUpsertAdvisory:
    def test_insert(self, sample_advisory):
        upsert_advisory(sample_advisory)
        assert advisory_exists("aa23-061a")

    def test_update(self, sample_advisory):
        upsert_advisory(sample_advisory)
        sample_advisory.title = "#StopRansomware: Royal Ransomware (Updated)"
        upsert_advisory(sample_advisory)
        assert advisory_exists("aa23-061a")

    def test_nonexistent(self):
        assert not advisory_exists("aa99-999z")


class TestInsertIOCs:
    def test_insert(self, sample_advisory, sample_iocs):
        upsert_advisory(sample_advisory)
        count = insert_iocs(sample_iocs)
        assert count == 3

    def test_empty_list(self):
        assert insert_iocs([]) == 0


class TestSearchIP:
    def test_found(self, sample_advisory, sample_iocs):
        upsert_advisory(sample_advisory)
        insert_iocs(sample_iocs)

        result = search_ip("193.233.254.21")
        assert result.found is True
        assert len(result.matches) == 1
        assert result.matches[0].advisory_id == "aa23-061a"
        assert result.matches[0].source == "stix"

    def test_not_found(self, sample_advisory, sample_iocs):
        upsert_advisory(sample_advisory)
        insert_iocs(sample_iocs)

        result = search_ip("8.8.8.8")
        assert result.found is False
        assert len(result.matches) == 0

    def test_domain_not_returned_for_ip_search(self, sample_advisory, sample_iocs):
        upsert_advisory(sample_advisory)
        insert_iocs(sample_iocs)

        result = search_ip("evil.example.com")
        assert result.found is False


class TestClearIOCs:
    def test_clear_all(self, sample_advisory, sample_iocs):
        upsert_advisory(sample_advisory)
        insert_iocs(sample_iocs)

        clear_iocs_for_advisory("aa23-061a")

        result = search_ip("193.233.254.21")
        assert result.found is False

    def test_clear_by_source(self, sample_advisory, sample_iocs):
        upsert_advisory(sample_advisory)
        insert_iocs(sample_iocs)

        # Add a PDF-sourced IOC for the same IP
        pdf_ioc = IOCRecord(
            ioc_type="ipv4-addr",
            value="193.233.254.21",
            advisory_id="aa23-061a",
            source="pdf",
        )
        insert_iocs([pdf_ioc])

        # Clear only STIX source
        clear_iocs_for_advisory("aa23-061a", source="stix")

        result = search_ip("193.233.254.21")
        assert result.found is True
        assert result.matches[0].source == "pdf"


class TestGetStats:
    def test_empty_db(self):
        stats = get_stats()
        assert stats["advisories"] == 0
        assert stats["total_iocs"] == 0

    def test_with_data(self, sample_advisory, sample_iocs):
        upsert_advisory(sample_advisory)
        insert_iocs(sample_iocs)

        stats = get_stats()
        assert stats["advisories"] == 1
        assert stats["total_iocs"] == 3
        assert stats["by_type"]["ipv4-addr"] == 2
        assert stats["by_type"]["domain-name"] == 1
        assert stats["by_source"]["stix"] == 3


class TestListGroups:
    def test_strips_prefix(self, sample_advisory):
        upsert_advisory(sample_advisory)
        groups = list_groups()
        assert len(groups) == 1
        assert groups[0][0] == "Royal Ransomware"
        assert groups[0][1] == "aa23-061a"

    def test_empty_db(self):
        groups = list_groups()
        assert groups == []
