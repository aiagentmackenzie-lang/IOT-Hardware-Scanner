"""Tests for CVEScanner — Phase 5.

SDR §11 — CVE Matching & Vulnerability Correlation
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.intelligence.cpe_builder import PRODUCT_CPE_MAP, CPEBuilder
from iot_hardware_scanner.models import CVEFinding, Severity, SoftwareComponent
from iot_hardware_scanner.scanner.cve_scanner import CVEScanner


@pytest.fixture
def config() -> ScannerConfig:
    """Return a ScannerConfig with offline mode."""
    return ScannerConfig(offline_mode=True)


@pytest.fixture
def cve_scanner(config: ScannerConfig) -> CVEScanner:
    """Return a CVEScanner with offline mode."""
    return CVEScanner(config)


def _make_component(
    product: str = "busybox",
    version: str = "1.28.4",
) -> SoftwareComponent:
    """Create a test SoftwareComponent."""
    vendor, prod = PRODUCT_CPE_MAP.get(product, (product, product))
    return SoftwareComponent(
        vendor=vendor,
        product=prod,
        version=version,
        cpe_string=f"cpe:2.3:a:{vendor}:{prod}:{version}",
        source_file=Path("/usr/sbin/busybox"),
        source_method="string_extraction",
    )


# ──────────────────────────────────────────────
# CPEBuilder
# ──────────────────────────────────────────────


class TestCPEBuilder:
    def test_build_known_product(self) -> None:
        """Build CPE string for a known product."""
        builder = CPEBuilder()
        cpe = builder.build("busybox", "1.28.4")
        assert cpe == "cpe:2.3:a:busybox:busybox:1.28.4"

    def test_build_openssl(self) -> None:
        """Build CPE string for OpenSSL."""
        builder = CPEBuilder()
        cpe = builder.build("openssl", "1.1.1k")
        assert cpe == "cpe:2.3:a:openssl:openssl:1.1.1k"

    def test_build_unknown_product(self) -> None:
        """Unknown product returns None."""
        builder = CPEBuilder()
        cpe = builder.build("unknown_product", "1.0.0")
        assert cpe is None

    def test_build_from_component(self) -> None:
        """Build CPE string with explicit vendor and product."""
        builder = CPEBuilder()
        cpe = builder.build_from_component("apache", "log4j", "2.14.1")
        assert cpe == "cpe:2.3:a:apache:log4j:2.14.1"

    def test_lookup_product(self) -> None:
        """Lookup returns (vendor, product) tuple for known products."""
        builder = CPEBuilder()
        result = builder.lookup_product("busybox")
        assert result == ("busybox", "busybox")

    def test_lookup_unknown_product(self) -> None:
        """Lookup returns None for unknown products."""
        builder = CPEBuilder()
        result = builder.lookup_product("nonexistent")
        assert result is None


# ──────────────────────────────────────────────
# CVEScanner — Offline Mode
# ──────────────────────────────────────────────


class TestCVEScannerOffline:
    def test_scan_component_offline(self, cve_scanner: CVEScanner) -> None:
        """Offline mode returns no CVE findings (no NVD queries)."""
        component = _make_component()
        findings = cve_scanner.scan_component(component)
        # Offline mode — no API calls, empty results
        assert findings == []

    def test_scan_all_offline(self, cve_scanner: CVEScanner) -> None:
        """Offline mode scan_all returns empty list."""
        components = [_make_component("busybox", "1.28.4")]
        findings = cve_scanner.scan_all(components)
        assert findings == []

    def test_scan_all_empty(self, cve_scanner: CVEScanner) -> None:
        """scan_all with empty components list returns empty."""
        findings = cve_scanner.scan_all([])
        assert findings == []


# ──────────────────────────────────────────────
# CVEScanner — With Mocked NVD
# ──────────────────────────────────────────────


class TestCVEScannerWithMock:
    def test_scan_component_with_mock_results(self, config: ScannerConfig) -> None:
        """Scan component with mocked NVD results."""
        mock_results = [
            {
                "cve_id": "CVE-2023-12345",
                "description": "Test vulnerability in BusyBox",
                "cvss_v3_score": 7.5,
                "cvss_v3_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "published_date": "2023-01-15T00:00:00",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-12345"],
            },
            {
                "cve_id": "CVE-2023-67890",
                "description": "Another vulnerability in BusyBox",
                "cvss_v3_score": 9.8,
                "cvss_v3_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "published_date": "2023-03-20T00:00:00",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-67890"],
            },
        ]

        scanner = CVEScanner(config)
        with patch.object(scanner._nvd, "query_cpe", return_value=mock_results):
            component = _make_component()
            findings = scanner.scan_component(component)

            assert len(findings) == 2
            assert findings[0].cve_id == "CVE-2023-12345"
            assert findings[0].severity == Severity.HIGH
            assert findings[0].cvss_v3_score == 7.5
            assert findings[0].affected_product == "busybox"
            assert findings[0].affected_version == "1.28.4"
            assert findings[1].severity == Severity.CRITICAL  # CVSS 9.8

    def test_scan_component_keyword_fallback(self, config: ScannerConfig) -> None:
        """If CPE query returns empty, keyword query is tried."""
        mock_keyword_results = [
            {
                "cve_id": "CVE-2022-11111",
                "description": "BusyBox vulnerability",
                "cvss_v3_score": 5.5,
                "cvss_v3_vector": "AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "published_date": "2022-06-01T00:00:00",
                "references": [],
            },
        ]

        scanner = CVEScanner(config)
        with (
            patch.object(scanner._nvd, "query_cpe", return_value=[]),
            patch.object(scanner._nvd, "query_keyword", return_value=mock_keyword_results),
        ):
            component = _make_component()
            findings = scanner.scan_component(component)

            assert len(findings) == 1
            assert findings[0].cve_id == "CVE-2022-11111"
            assert findings[0].severity == Severity.MEDIUM

    def test_scan_all_deduplication(self, config: ScannerConfig) -> None:
        """Duplicate CVE IDs across components are deduplicated."""
        mock_results = [
            {
                "cve_id": "CVE-2023-12345",
                "description": "Shared vulnerability",
                "cvss_v3_score": 6.5,
                "cvss_v3_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "published_date": "2023-01-15T00:00:00",
                "references": [],
            },
        ]

        scanner = CVEScanner(config)
        with patch.object(scanner._nvd, "query_cpe", return_value=mock_results):
            # Same CVE could appear for both busybox versions
            components = [
                _make_component("busybox", "1.28.4"),
                _make_component("busybox", "1.30.0"),
            ]
            findings = scanner.scan_all(components)
            # Dedup by CVE ID
            cve_ids = [f.cve_id for f in findings]
            assert len(cve_ids) == len(set(cve_ids))

    def test_no_cpe_falls_back_to_keyword(self, config: ScannerConfig) -> None:
        """If CPE string is None and build fails, keyword is tried."""
        mock_keyword_results = [
            {
                "cve_id": "CVE-2022-99999",
                "description": "Unknown product vulnerability",
                "cvss_v3_score": 4.3,
                "cvss_v3_vector": None,
                "published_date": "2022-12-01T00:00:00",
                "references": [],
            },
        ]

        scanner = CVEScanner(config)
        component = SoftwareComponent(
            vendor="unknown_vendor",
            product="unknown_product",
            version="1.0.0",
            cpe_string="",
            source_file=Path("/usr/bin/unknown"),
            source_method="string_extraction",
        )
        with patch.object(scanner._nvd, "query_keyword", return_value=mock_keyword_results):
            findings = scanner.scan_component(component)
            assert len(findings) == 1
            assert findings[0].severity == Severity.MEDIUM


# ──────────────────────────────────────────────
# CVSS → Severity mapping
# ──────────────────────────────────────────────


class TestCVSSToSeverity:
    def test_critical_range(self) -> None:
        """CVSS 9.0-10.0 maps to CRITICAL."""
        assert CVEScanner._cvss_to_severity(9.0) == Severity.CRITICAL
        assert CVEScanner._cvss_to_severity(9.8) == Severity.CRITICAL
        assert CVEScanner._cvss_to_severity(10.0) == Severity.CRITICAL

    def test_high_range(self) -> None:
        """CVSS 7.0-8.9 maps to HIGH."""
        assert CVEScanner._cvss_to_severity(7.0) == Severity.HIGH
        assert CVEScanner._cvss_to_severity(8.5) == Severity.HIGH

    def test_medium_range(self) -> None:
        """CVSS 4.0-6.9 maps to MEDIUM."""
        assert CVEScanner._cvss_to_severity(4.0) == Severity.MEDIUM
        assert CVEScanner._cvss_to_severity(6.9) == Severity.MEDIUM

    def test_low_range(self) -> None:
        """CVSS 0.1-3.9 maps to LOW."""
        assert CVEScanner._cvss_to_severity(0.1) == Severity.LOW
        assert CVEScanner._cvss_to_severity(3.9) == Severity.LOW

    def test_none_maps_to_medium(self) -> None:
        """None CVSS score maps to MEDIUM (unknown severity)."""
        assert CVEScanner._cvss_to_severity(None) == Severity.MEDIUM

    def test_zero_maps_to_info(self) -> None:
        """CVSS 0.0 maps to INFO."""
        assert CVEScanner._cvss_to_severity(0.0) == Severity.INFO


# ──────────────────────────────────────────────
# KEV Catalog
# ──────────────────────────────────────────────


class TestKEVCatalog:
    def test_kev_catalog_loads(self, cve_scanner: CVEScanner) -> None:
        """KEV catalog loads from local file."""
        kev_ids = cve_scanner._load_kev_catalog()
        assert isinstance(kev_ids, set)
        # Should contain at least the sample entries
        assert "CVE-2021-44228" in kev_ids  # Log4Shell
        assert "CVE-2017-0144" in kev_ids  # EternalBlue

    def test_kev_escalation(self, config: ScannerConfig) -> None:
        """KEV entries are escalated to CRITICAL regardless of CVSS."""
        mock_results = [
            {
                "cve_id": "CVE-2021-44228",  # In KEV
                "description": "Log4Shell",
                "cvss_v3_score": 10.0,
                "cvss_v3_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "published_date": "2021-12-10T00:00:00",
                "references": [],
            },
        ]

        scanner = CVEScanner(config)
        with patch.object(scanner._nvd, "query_cpe", return_value=mock_results):
            component = _make_component()
            findings = scanner.scan_component(component)

            assert len(findings) == 1
            assert findings[0].is_in_kev is True
            assert findings[0].severity == Severity.CRITICAL
            assert findings[0].exploit_available is True

    def test_non_kev_not_escalated(self, config: ScannerConfig) -> None:
        """Non-KEV CVEs are not escalated beyond CVSS-based severity."""
        mock_results = [
            {
                "cve_id": "CVE-2099-99999",  # Not in KEV
                "description": "Some vulnerability",
                "cvss_v3_score": 5.5,
                "cvss_v3_vector": "AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "published_date": "2099-01-01T00:00:00",
                "references": [],
            },
        ]

        scanner = CVEScanner(config)
        with patch.object(scanner._nvd, "query_cpe", return_value=mock_results):
            component = _make_component()
            findings = scanner.scan_component(component)

            assert len(findings) == 1
            assert findings[0].is_in_kev is False
            assert findings[0].severity == Severity.MEDIUM  # CVSS 5.5


# ──────────────────────────────────────────────
# NVDClient — Caching
# ──────────────────────────────────────────────


class TestNVDClient:
    def test_nvd_client_init(self, config: ScannerConfig) -> None:
        """NVDClient initializes without errors."""
        from iot_hardware_scanner.intelligence.nvd_client import NVDClient

        client = NVDClient(config)
        assert client is not None

    def test_offline_mode_skips_requests(self, config: ScannerConfig) -> None:
        """Offline mode skips NVD API requests."""
        from iot_hardware_scanner.intelligence.nvd_client import NVDClient

        client = NVDClient(config)
        result = client.query_cpe("cpe:2.3:a:busybox:busybox:1.28.4")
        assert result == []

    def test_cache_round_trip(self, config: ScannerConfig) -> None:
        """Cache write and read works correctly."""
        from iot_hardware_scanner.intelligence.nvd_client import NVDClient

        client = NVDClient(config)
        test_data = [{"cve_id": "CVE-2023-0001", "description": "Test"}]

        # Write to cache
        client._set_cached("test_key", test_data)

        # Read from cache
        cached = client._get_cached("test_key")
        assert cached is not None
        assert len(cached) == 1
        assert cached[0]["cve_id"] == "CVE-2023-0001"

    def test_cache_expiry(self, config: ScannerConfig) -> None:
        """Expired cache entries are not returned."""
        from iot_hardware_scanner.intelligence.nvd_client import NVDClient

        client = NVDClient(config)
        test_data = [{"cve_id": "CVE-2023-0002", "description": "Expired"}]

        # Write with a very old timestamp
        client._set_cached("expired_key", test_data)
        # Manually set cached_at to past
        with sqlite3.connect(str(client._cache_db)) as conn:
            conn.execute(
                "UPDATE nvd_cache SET cached_at = ? WHERE query_key = ?",
                (0, "expired_key"),  # epoch time = very old
            )
            conn.commit()

        # Set TTL to 1 day, data is from epoch → expired
        config.nvd_cache_days = 1
        cached = client._get_cached("expired_key")
        assert cached is None

    def test_cache_miss(self, config: ScannerConfig) -> None:
        """Missing cache key returns None."""
        from iot_hardware_scanner.intelligence.nvd_client import NVDClient

        client = NVDClient(config)
        cached = client._get_cached("nonexistent_key")
        assert cached is None


# ──────────────────────────────────────────────
# SoftwareComponent model
# ──────────────────────────────────────────────


class TestSoftwareComponentModel:
    def test_component_creation(self) -> None:
        """SoftwareComponent can be created with expected fields."""
        comp = SoftwareComponent(
            vendor="busybox",
            product="busybox",
            version="1.28.4",
            cpe_string="cpe:2.3:a:busybox:busybox:1.28.4",
            source_file=Path("/usr/sbin/busybox"),
            source_method="string_extraction",
        )
        assert comp.vendor == "busybox"
        assert comp.product == "busybox"
        assert comp.version == "1.28.4"
        assert comp.cpe_string == "cpe:2.3:a:busybox:busybox:1.28.4"
        assert comp.source_method == "string_extraction"

    def test_cve_finding_creation(self) -> None:
        """CVEFinding can be created with expected fields."""
        finding = CVEFinding(
            cve_id="CVE-2023-12345",
            severity=Severity.HIGH,
            cvss_v3_score=7.5,
            cvss_v3_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            description="Test vulnerability",
            affected_product="busybox",
            affected_version="1.28.4",
            published_date="2023-01-15",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2023-12345"],
            is_in_kev=False,
            exploit_available=False,
        )
        assert finding.cve_id == "CVE-2023-12345"
        assert finding.severity == Severity.HIGH
        assert finding.cvss_v3_score == 7.5
        assert finding.is_in_kev is False
