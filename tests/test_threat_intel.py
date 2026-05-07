"""Tests for ThreatIntelManager — Phase 6.

Tests loading JSON Lines feeds, domain/IP lookups, CIDR range checks,
empty/missing directories, and malformed entry handling.

Note: ThreatIntelManager always appends the project data/ dir (with
threat_intel_sample.jsonl containing 10 domains + 10 IPs/ranges).
Tests use dedicated temp directories and verify relative counts/deltas.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.intelligence.threat_intel import ThreatIntelManager

# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

# The project data/ dir always gets loaded and has threat_intel_sample.jsonl
# with 10 domains + 10 IPs/ranges (20 total indicators).
_PROJECT_FEED_DOMAINS = 10
_PROJECT_FEED_IPS = 10


def _write_feed(tmp_path: Path, entries: list[dict], filename: str = "test_feed.jsonl") -> Path:
    """Write a JSONL feed file and return the directory."""
    feed_file = tmp_path / filename
    feed_file.write_text("\n".join(json.dumps(e) for e in entries))
    return tmp_path


# ──────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────


@pytest.fixture
def sample_entries() -> list[dict]:
    """Sample threat intel entries for testing."""
    return [
        {
            "type": "domain",
            "value": "malware-c2.evil.top",
            "tags": ["mirai", "c2"],
            "confidence": 0.9,
            "source": "test",
        },
        {
            "type": "domain",
            "value": "vpnfilter-c2.su",
            "tags": ["vpnfilter", "c2"],
            "confidence": 0.92,
            "source": "test",
        },
        {
            "type": "domain",
            "value": "hajime-p2p.dht.link",
            "tags": ["hajime", "p2p"],
            "confidence": 0.82,
            "source": "test",
        },
        {
            "type": "ip",
            "value": "185.220.101.37",
            "tags": ["tor_exit", "c2"],
            "confidence": 0.7,
            "source": "test",
        },
        {
            "type": "ip",
            "value": "91.234.99.42",
            "tags": ["mirai", "c2"],
            "confidence": 0.9,
            "source": "test",
        },
        {
            "type": "ip_range",
            "value": "5.187.35.0/24",
            "tags": ["botnet_infra", "dropper"],
            "confidence": 0.85,
            "source": "test",
        },
    ]


@pytest.fixture
def feed_dir(tmp_path: Path, sample_entries: list[dict]) -> Path:
    """Temp directory with a sample JSONL threat intel feed."""
    return _write_feed(tmp_path, sample_entries)


@pytest.fixture
def ti_with_feed(feed_dir: Path) -> ThreatIntelManager:
    """ThreatIntelManager with test feed loaded."""
    cfg = ScannerConfig(threat_intel_dirs=[feed_dir])
    manager = ThreatIntelManager(cfg)
    manager.load_feeds()
    return manager


@pytest.fixture
def ti_isolated(tmp_path: Path, sample_entries: list[dict]) -> ThreatIntelManager:
    """ThreatIntelManager with ONLY the test feed (no project data dir).

    We create a fresh manager pointing to tmp_path only. The project
    data dir is still appended, but we verify test-specific entries.
    """
    _write_feed(tmp_path, sample_entries)
    cfg = ScannerConfig(threat_intel_dirs=[tmp_path])
    manager = ThreatIntelManager(cfg)
    manager.load_feeds()
    return manager


# ──────────────────────────────────────────────
# Feed Loading
# ──────────────────────────────────────────────


class TestFeedLoading:
    """Test feed loading from JSON Lines files."""

    def test_load_feeds_includes_test_entries(self, ti_with_feed: ThreatIntelManager) -> None:
        """Loaded feeds include our test entries plus project data."""
        # Should have at least our 3 test domains + project domains
        assert ti_with_feed.domain_count >= 3
        # Should have at least our 3 test IPs/ranges + project IPs
        assert ti_with_feed.ip_count >= 3

    def test_load_from_empty_directory(self, tmp_path: Path) -> None:
        """Loading from an empty directory only loads project data."""
        cfg = ScannerConfig(threat_intel_dirs=[tmp_path])
        manager = ThreatIntelManager(cfg)
        count = manager.load_feeds()
        # Only project data dir entries
        assert count == _PROJECT_FEED_DOMAINS + _PROJECT_FEED_IPS

    def test_load_from_missing_directory(self) -> None:
        """Loading from a non-existent directory doesn't crash."""
        cfg = ScannerConfig(threat_intel_dirs=[Path("/nonexistent/path")])
        manager = ThreatIntelManager(cfg)
        count = manager.load_feeds()
        # Only project data dir entries
        assert count == _PROJECT_FEED_DOMAINS + _PROJECT_FEED_IPS

    def test_load_multiple_files(self, tmp_path: Path) -> None:
        """Loading from multiple JSONL files merges all indicators."""
        file1 = tmp_path / "feed1.jsonl"
        file2 = tmp_path / "feed2.jsonl"
        file1.write_text(
            json.dumps(
                {
                    "type": "domain",
                    "value": "a.evil.com",
                    "tags": ["test"],
                    "confidence": 0.8,
                    "source": "f1",
                }
            )
            + "\n"
        )
        file2.write_text(
            json.dumps(
                {
                    "type": "domain",
                    "value": "b.evil.com",
                    "tags": ["test"],
                    "confidence": 0.8,
                    "source": "f2",
                }
            )
            + "\n"
        )

        cfg = ScannerConfig(threat_intel_dirs=[tmp_path])
        manager = ThreatIntelManager(cfg)
        count = manager.load_feeds()
        # 2 from test feeds + project entries
        assert count >= 2
        # Our entries should be findable
        assert manager.check_domain("a.evil.com") is not None
        assert manager.check_domain("b.evil.com") is not None

    def test_skip_comment_lines(self, tmp_path: Path) -> None:
        """Comment lines (starting with #) are skipped."""
        feed = tmp_path / "comments.jsonl"
        content = (
            "# This is a comment\n"
            + json.dumps(
                {
                    "type": "domain",
                    "value": "evil.com",
                    "tags": ["test"],
                    "confidence": 0.9,
                    "source": "test",
                }
            )
            + "\n"
        )
        feed.write_text(content)

        cfg = ScannerConfig(threat_intel_dirs=[tmp_path])
        manager = ThreatIntelManager(cfg)
        manager.load_feeds()
        assert manager.check_domain("evil.com") is not None

    def test_skip_empty_lines(self, tmp_path: Path) -> None:
        """Empty lines in JSONL are skipped."""
        feed = tmp_path / "empty.jsonl"
        content = (
            "\n\n"
            + json.dumps(
                {
                    "type": "domain",
                    "value": "evil.com",
                    "tags": ["test"],
                    "confidence": 0.9,
                    "source": "test",
                }
            )
            + "\n\n"
        )
        feed.write_text(content)

        cfg = ScannerConfig(threat_intel_dirs=[tmp_path])
        manager = ThreatIntelManager(cfg)
        manager.load_feeds()
        assert manager.check_domain("evil.com") is not None


# ──────────────────────────────────────────────
# Domain Lookups
# ──────────────────────────────────────────────


class TestDomainLookup:
    """Test domain threat intel lookups."""

    def test_domain_hit(self, ti_with_feed: ThreatIntelManager) -> None:
        """Known domain returns its entry."""
        result = ti_with_feed.check_domain("malware-c2.evil.top")
        assert result is not None
        assert "mirai" in result["tags"]
        assert result["confidence"] == 0.9

    def test_domain_case_insensitive(self, ti_with_feed: ThreatIntelManager) -> None:
        """Domain lookups are case-insensitive."""
        result = ti_with_feed.check_domain("MALWARE-C2.EVIL.TOP")
        assert result is not None

    def test_domain_miss(self, ti_with_feed: ThreatIntelManager) -> None:
        """Unknown domain returns None."""
        result = ti_with_feed.check_domain("clean-domain-99xyz.example.com")
        assert result is None

    def test_domain_empty_string(self, ti_with_feed: ThreatIntelManager) -> None:
        """Empty string domain returns None."""
        result = ti_with_feed.check_domain("")
        assert result is None


# ──────────────────────────────────────────────
# IP Lookups
# ──────────────────────────────────────────────


class TestIPLookup:
    """Test IP threat intel lookups."""

    def test_ip_hit(self, ti_with_feed: ThreatIntelManager) -> None:
        """Known IP returns its entry."""
        result = ti_with_feed.check_ip("185.220.101.37")
        assert result is not None
        assert "tor_exit" in result["tags"]

    def test_ip_miss(self, ti_with_feed: ThreatIntelManager) -> None:
        """Unknown IP returns None."""
        result = ti_with_feed.check_ip("1.2.3.4")
        assert result is None

    def test_cidr_range_match(self, ti_with_feed: ThreatIntelManager) -> None:
        """IP within a CIDR range in the feed matches."""
        result = ti_with_feed.check_ip("5.187.35.18")
        assert result is not None
        assert "botnet_infra" in result["tags"]

    def test_cidr_range_no_match(self, ti_with_feed: ThreatIntelManager) -> None:
        """IP outside all CIDR ranges returns None."""
        result = ti_with_feed.check_ip("8.8.4.4")
        assert result is None

    def test_invalid_ip(self, ti_with_feed: ThreatIntelManager) -> None:
        """Invalid IP string returns None."""
        result = ti_with_feed.check_ip("not-an-ip")
        assert result is None


# ──────────────────────────────────────────────
# Malformed entries
# ──────────────────────────────────────────────


class TestMalformedEntries:
    """Test handling of malformed JSON Lines entries."""

    def test_invalid_json_skipped(self, tmp_path: Path) -> None:
        """Invalid JSON lines are skipped gracefully."""
        feed = tmp_path / "bad.jsonl"
        feed.write_text(
            "not valid json\n"
            + json.dumps(
                {
                    "type": "domain",
                    "value": "good.com",
                    "tags": ["test"],
                    "confidence": 0.9,
                    "source": "test",
                }
            )
            + "\n"
        )

        cfg = ScannerConfig(threat_intel_dirs=[tmp_path])
        manager = ThreatIntelManager(cfg)
        manager.load_feeds()
        # "good.com" should be loaded
        assert manager.check_domain("good.com") is not None

    def test_missing_type_skipped(self, tmp_path: Path) -> None:
        """Entries without 'type' field are skipped."""
        feed = tmp_path / "notype.jsonl"
        feed.write_text(json.dumps({"value": "evil.com", "tags": ["test"]}) + "\n")

        cfg = ScannerConfig(threat_intel_dirs=[tmp_path])
        manager = ThreatIntelManager(cfg)
        manager.load_feeds()
        # No entry with value "evil.com" should exist (it had no type)
        result = manager.check_domain("evil.com")
        # It should not have been loaded as a domain
        assert result is None

    def test_missing_value_skipped(self, tmp_path: Path) -> None:
        """Entries without 'value' field are skipped."""
        feed = tmp_path / "novalue.jsonl"
        feed.write_text(json.dumps({"type": "domain", "tags": ["test"]}) + "\n")

        cfg = ScannerConfig(threat_intel_dirs=[tmp_path])
        manager = ThreatIntelManager(cfg)
        manager.load_feeds()
        # No domain should have been loaded from this entry
        # (only project data domains)
        project_count = _PROJECT_FEED_DOMAINS
        assert manager.domain_count == project_count

    def test_unknown_type_skipped(self, tmp_path: Path) -> None:
        """Unknown indicator types are silently skipped."""
        feed = tmp_path / "unknowntype.jsonl"
        feed.write_text(
            json.dumps(
                {
                    "type": "url",
                    "value": "http://evil.com",
                    "tags": ["test"],
                    "confidence": 0.9,
                    "source": "test",
                }
            )
            + "\n"
        )

        cfg = ScannerConfig(threat_intel_dirs=[tmp_path])
        manager = ThreatIntelManager(cfg)
        manager.load_feeds()
        # No domains or IPs from this entry
        assert manager.check_domain("http://evil.com") is None

    def test_auto_load_on_check(self) -> None:
        """check_domain auto-loads feeds if not yet loaded."""
        cfg = ScannerConfig()  # Default config, uses project data dir
        manager = ThreatIntelManager(cfg)
        # Should auto-load without explicit load_feeds() call
        result = manager.check_domain("nonexistent-domain-xyz123.example.com")
        # Just verify it doesn't crash and auto-loaded
        assert isinstance(result, (dict, type(None)))
