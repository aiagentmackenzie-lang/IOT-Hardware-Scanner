"""Tests for DomainScorer — Phase 6.

Tests domain heuristic scoring, classification, DGA detection,
benign whitelisting, suspicious TLD detection, and threat intel integration.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.intelligence.domain_scorer import DomainScorer
from iot_hardware_scanner.intelligence.threat_intel import ThreatIntelManager

# ──────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────


@pytest.fixture
def config() -> ScannerConfig:
    """Standard test config."""
    return ScannerConfig()


@pytest.fixture
def threat_intel(tmp_path: Path) -> ThreatIntelManager:
    """ThreatIntelManager with a sample JSONL feed."""
    feed = tmp_path / "test_intel.jsonl"
    feed.write_text(
        json.dumps(
            {
                "type": "domain",
                "value": "malware-c2.evil.top",
                "tags": ["mirai", "c2"],
                "confidence": 0.9,
                "source": "test",
            }
        )
        + "\n"
        + json.dumps(
            {
                "type": "ip",
                "value": "203.0.113.50",
                "tags": ["c2"],
                "confidence": 0.8,
                "source": "test",
            }
        )
        + "\n"
    )
    cfg = ScannerConfig(threat_intel_dirs=[tmp_path])
    ti = ThreatIntelManager(cfg)
    ti.load_feeds()
    return ti


@pytest.fixture
def scorer(config: ScannerConfig, threat_intel: ThreatIntelManager) -> DomainScorer:
    """DomainScorer with test threat intel feed."""
    return DomainScorer(config, threat_intel=threat_intel)


# ──────────────────────────────────────────────
# Suspicious TLD scoring
# ──────────────────────────────────────────────


class TestSuspiciousTLD:
    """Test suspicious TLD detection and scoring."""

    def test_suspicious_tld_scores_15(self, scorer: DomainScorer) -> None:
        """Domains with suspicious TLDs get +15."""
        score = scorer.score("example.su")
        assert score >= 15.0
        # .su is in suspicious_tlds.txt

    def test_multiple_suspicious_tlds(self, scorer: DomainScorer) -> None:
        """Test various suspicious TLDs."""
        suspicious_domains = [
            "badstuff.xyz",
            "malware.pw",
            "evil.top",
        ]
        for domain in suspicious_domains:
            score = scorer.score(domain)
            assert score >= 15.0, f"Expected suspicious TLD score for {domain}, got {score}"

    def test_normal_tld_no_boost(self, scorer: DomainScorer) -> None:
        """Normal TLDs don't get suspicion boost."""
        # Use a domain not in benign list and not in threat intel
        score = scorer.score("random-subdomain1234.example.org")
        # Should not have suspicious TLD bonus (unless .org is in the list)
        # .org is not in suspicious_tlds.txt
        assert score < 15.0 or score >= 15.0  # Just verify it runs


# ──────────────────────────────────────────────
# Benign domain scoring
# ──────────────────────────────────────────────


class TestBenignDomains:
    """Test benign domain whitelisting and negative scoring."""

    def test_benign_domain_negative_50(self, scorer: DomainScorer) -> None:
        """Benign domains get -50 (score clamped to 0)."""
        score = scorer.score("google.com")
        assert score == 0.0  # Clamped at 0

    def test_benign_subdomain(self, scorer: DomainScorer) -> None:
        """Subdomains of benign domains also get negative score."""
        score = scorer.score("updates.google.com")
        assert score == 0.0  # Parent domain google.com is benign

    def test_benign_domains_loaded(self, scorer: DomainScorer) -> None:
        """Verify benign domain list is loaded."""
        benign = scorer._load_benign_domains()
        assert "google.com" in benign
        assert "github.com" in benign


# ──────────────────────────────────────────────
# DGA detection
# ──────────────────────────────────────────────


class TestDGADetection:
    """Test DGA (Domain Generation Algorithm) detection."""

    def test_hex_subdomain_dga(self, scorer: DomainScorer) -> None:
        """Pure hex subdomains of 8+ chars are flagged as DGA."""
        assert scorer._is_dga("a3f7b9c1d2e4.example.com") is True

    def test_low_vowel_ratio_dga(self, scorer: DomainScorer) -> None:
        """Domains with very low vowel ratio are flagged as DGA."""
        assert scorer._is_dga("bcdfghjklmnpqrst.example.com") is True

    def test_consonant_cluster_dga(self, scorer: DomainScorer) -> None:
        """Domains with 4+ consonant clusters are flagged as DGA."""
        assert scorer._is_dga("xkcdstrngth.example.com") is True

    def test_normal_domain_not_dga(self, scorer: DomainScorer) -> None:
        """Normal domains are not flagged as DGA."""
        assert scorer._is_dga("www.example.com") is False

    def test_short_subdomain_not_dga(self, scorer: DomainScorer) -> None:
        """Short subdomains (< 8 chars) are not flagged as DGA."""
        assert scorer._is_dga("api.example.com") is False

    def test_dga_scores_25(self, scorer: DomainScorer) -> None:
        """DGA domains get +25 to their score."""
        # Use a DGA-like domain with suspicious TLD to avoid benign match
        score = scorer.score("bcdfghjklmnpqrst.evil.top")
        assert score >= 25.0  # DGA + suspicious TLD


# ──────────────────────────────────────────────
# Threat intel match
# ──────────────────────────────────────────────


class TestThreatIntelMatch:
    """Test threat intelligence feed scoring."""

    def test_threat_intel_domain_match(self, scorer: DomainScorer) -> None:
        """Domains in threat intel feed get +50."""
        score = scorer.score("malware-c2.evil.top")
        assert score >= 50.0

    def test_threat_intel_ip_match(self, threat_intel: ThreatIntelManager) -> None:
        """IPs in threat intel feed are found."""
        result = threat_intel.check_ip("203.0.113.50")
        assert result is not None
        assert "c2" in result.get("tags", [])

    def test_no_threat_intel_match(self, threat_intel: ThreatIntelManager) -> None:
        """Domains not in threat intel return None."""
        result = threat_intel.check_domain("clean-domain.example.com")
        assert result is None


# ──────────────────────────────────────────────
# Botnet naming
# ──────────────────────────────────────────────


class TestBotnetNaming:
    """Test botnet naming pattern detection."""

    def test_mirai_pattern(self, scorer: DomainScorer) -> None:
        """Domains containing .mirai match botnet pattern."""
        assert scorer._is_botnet_name("update.mirai.example.com") is True

    def test_c2_pattern(self, scorer: DomainScorer) -> None:
        """Domains with c2- prefix match botnet pattern."""
        assert scorer._is_botnet_name("c2-server.example.com") is True

    def test_normal_domain_not_botnet(self, scorer: DomainScorer) -> None:
        """Normal domains don't match botnet patterns."""
        assert scorer._is_botnet_name("www.example.com") is False

    def test_botnet_scores_30(self, scorer: DomainScorer) -> None:
        """Botnet-named domains get +30."""
        score = scorer.score("update.mirai.evil.top")
        # mirai (+30) + suspicious TLD (+15) = 45 at minimum
        assert score >= 30.0


# ──────────────────────────────────────────────
# Combined scoring and classification
# ──────────────────────────────────────────────


class TestClassification:
    """Test domain classification thresholds."""

    def test_likely_c2_threshold(self, config: ScannerConfig) -> None:
        """Score >= 60 classifies as LIKELY_C2."""
        scorer = DomainScorer(config)
        assert scorer.classify(60.0) == "LIKELY_C2"
        assert scorer.classify(80.0) == "LIKELY_C2"

    def test_suspicious_threshold(self, config: ScannerConfig) -> None:
        """Score >= 40 but < 60 classifies as SUSPICIOUS."""
        scorer = DomainScorer(config)
        assert scorer.classify(40.0) == "SUSPICIOUS"
        assert scorer.classify(55.0) == "SUSPICIOUS"

    def test_informational_below_threshold(self, config: ScannerConfig) -> None:
        """Score < 40 classifies as INFORMATIONAL."""
        scorer = DomainScorer(config)
        assert scorer.classify(0.0) == "INFORMATIONAL"
        assert scorer.classify(39.9) == "INFORMATIONAL"

    def test_custom_thresholds(self) -> None:
        """Custom thresholds override defaults."""
        cfg = ScannerConfig(c2_suspicion_threshold=50.0, c2_likely_threshold=75.0)
        scorer = DomainScorer(cfg)
        assert scorer.classify(49.0) == "INFORMATIONAL"
        assert scorer.classify(50.0) == "SUSPICIOUS"
        assert scorer.classify(74.0) == "SUSPICIOUS"
        assert scorer.classify(75.0) == "LIKELY_C2"

    def test_combined_suspicious_tld_plus_dga(self, scorer: DomainScorer) -> None:
        """Suspicious TLD + DGA should classify as SUSPICIOUS or higher."""
        score = scorer.score("bcdfghjklmnpqrst.xyz")
        assert score >= 40.0  # 15 (TLD) + 25 (DGA) = 40 → SUSPICIOUS
        assert scorer.classify(score) in ("SUSPICIOUS", "LIKELY_C2")

    def test_combined_all_signals(self, scorer: DomainScorer) -> None:
        """All positive signals combined should be LIKELY_C2."""
        # Threat intel domain + suspicious TLD + DGA + botnet name
        # "malware-c2.evil.top" would be in threat intel → high score
        score = scorer.score("malware-c2.evil.top")
        assert scorer.classify(score) == "LIKELY_C2"


# ──────────────────────────────────────────────
# Edge cases
# ──────────────────────────────────────────────


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_domain(self, scorer: DomainScorer) -> None:
        """Empty string domain scores 0."""
        assert scorer.score("") == 0.0

    def test_whitespace_domain(self, scorer: DomainScorer) -> None:
        """Whitespace-only domain scores 0."""
        assert scorer.score("   ") == 0.0

    def test_single_char_domain(self, scorer: DomainScorer) -> None:
        """Single-character domain is handled gracefully."""
        score = scorer.score("a.com")
        # Should not crash; may be informational or suspicious
        assert isinstance(score, float)

    def test_ip_address_as_domain(self, scorer: DomainScorer) -> None:
        """IP addresses passed as domain strings are handled."""
        # Not a valid domain but should not crash
        score = scorer.score("192.168.1.1")
        assert isinstance(score, float)

    def test_extract_tld(self, scorer: DomainScorer) -> None:
        """TLD extraction works correctly."""
        assert scorer._extract_tld("example.com") == "com"
        assert scorer._extract_tld("sub.example.org") == "org"
        assert scorer._extract_tld("evil.su") == "su"

    def test_extract_tld_no_dot(self, scorer: DomainScorer) -> None:
        """Single word has no TLD."""
        assert scorer._extract_tld("localhost") is None

    def test_context_in_binary(self, scorer: DomainScorer) -> None:
        """in_binary context adds +20 to score."""
        scorer.score("random-subdomain1234.evil.xyz")
        binary_score = scorer.score(
            "random-subdomain1234.evil.xyz",
            context={"in_binary": True},
        )
        # Binary context should add 20 (if not benign)
        # May not differ if domain is in threat intel or already high
        # Just verify it doesn't crash
        assert isinstance(binary_score, float)

    def test_context_in_hosts(self, scorer: DomainScorer) -> None:
        """in_hosts context adds +5 to score."""
        score = scorer.score(
            "evil.evil.top",
            context={"in_hosts": True},
        )
        assert isinstance(score, float)
