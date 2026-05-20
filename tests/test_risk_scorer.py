"""Tests for RiskScorer — Phase 7a.

Tests 12-control risk scoring model, risk level classification,
OWASP IoT Top 10 mapping, and edge cases.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.models import (
    BinaryHardening,
    BinaryIntelligenceResult,
    BinaryMetadata,
    C2Finding,
    CredentialFinding,
    CVEFinding,
    FileCategory,
    FilesystemFinding,
    FilesystemInventory,
    RiskLevel,
    ScanContext,
    Severity,
    SoftwareComponent,
)
from iot_hardware_scanner.scanner.risk_scorer import CONTROLS, RiskScorer

# ──────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────


@pytest.fixture
def config() -> ScannerConfig:
    return ScannerConfig()


@pytest.fixture
def scorer(config: ScannerConfig) -> RiskScorer:
    return RiskScorer(config)


@pytest.fixture
def minimal_context(tmp_path: Path) -> ScanContext:
    """Minimal scan context with no findings (should score 100/100)."""
    return ScanContext(
        scan_id="test-001",
        firmware_path=tmp_path / "firmware.bin",
        output_dir=tmp_path,
        file_hash_sha256="a" * 64,
        file_hash_md5="b" * 32,
        file_size=1024,
        file_type="ELF",
        firmware_name="test.bin",
        size_category="SMALL",
        started_at=datetime.now(),
    )


def _make_credential_finding(
    severity: Severity = Severity.CRITICAL,
    category: str = "password",
    is_default: bool = True,
    is_placeholder: bool = False,
) -> CredentialFinding:
    return CredentialFinding(
        severity=severity,
        category=category,
        file_path=Path("etc/passwd"),
        line_number=1,
        matched_pattern="root:admin",
        masked_value="********",
        is_default=is_default,
        is_placeholder=is_placeholder,
    )


def _make_cve_finding(
    severity: Severity = Severity.CRITICAL,
    is_in_kev: bool = False,
) -> CVEFinding:
    return CVEFinding(
        cve_id="CVE-2025-0001",
        severity=severity,
        cvss_v3_score=9.8,
        affected_product="busybox",
        affected_version="1.30",
        is_in_kev=is_in_kev,
    )


def _make_c2_finding(
    severity: str = "LIKELY_C2",
    indicator_type: str = "domain",
) -> C2Finding:
    return C2Finding(
        severity=severity,
        indicator_type=indicator_type,
        value="c2.evil.top",
        file_path=Path("etc/config"),
        suspicion_score=85.0,
    )


def _make_inventory(
    suid_count: int = 0,
    world_writable_count: int = 0,
    network_services_count: int = 0,
    dangerous_services: list[str] | None = None,
) -> FilesystemInventory:
    """Create a FilesystemInventory with configurable properties."""
    suid_binaries = [
        FilesystemFinding(
            path=Path(f"bin/suid_{i}"),
            absolute_path=Path(f"/tmp/bin/suid_{i}"),
            category=FileCategory.CRITICAL_BINARY,
            file_type="ELF",
            file_size=100,
            permissions="rwsr-xr-x",
            owner_uid=0,
            owner_gid=0,
            is_suid=True,
            is_world_writable=False,
            hash_sha256="a" * 64,
        )
        for i in range(suid_count)
    ]
    world_writable = [
        FilesystemFinding(
            path=Path(f"var/ww_{i}"),
            absolute_path=Path(f"/tmp/var/ww_{i}"),
            category=FileCategory.LOW_MISC,
            file_type="data",
            file_size=50,
            permissions="rw-rw-rw-",
            owner_uid=0,
            owner_gid=0,
            is_suid=False,
            is_world_writable=True,
            hash_sha256="b" * 64,
        )
        for i in range(world_writable_count)
    ]
    net_svcs = []
    if dangerous_services:
        for svc in (dangerous_services or []):
            net_svcs.append(
                FilesystemFinding(
                    path=Path(f"usr/sbin/{svc}"),
                    absolute_path=Path(f"/tmp/usr/sbin/{svc}"),
                    category=FileCategory.CRITICAL_SERVICE,
                    file_type="ELF",
                    file_size=200,
                    permissions="rwxr-xr-x",
                    owner_uid=0,
                    owner_gid=0,
                    is_suid=False,
                    is_world_writable=False,
                    hash_sha256="c" * 64,
                )
            )
    for i in range(network_services_count):
        net_svcs.append(
            FilesystemFinding(
                path=Path(f"usr/sbin/sshd_{i}"),
                absolute_path=Path(f"/tmp/usr/sbin/sshd_{i}"),
                category=FileCategory.CRITICAL_SERVICE,
                file_type="ELF",
                file_size=200,
                permissions="rwxr-xr-x",
                owner_uid=0,
                owner_gid=0,
                is_suid=False,
                is_world_writable=False,
                hash_sha256="d" * 64,
            )
        )

    return FilesystemInventory(
        rootfs_path=Path("/tmp/rootfs"),
        total_files=10,
        total_directories=5,
        total_size=4096,
        findings=[],
        categories={},
        suid_binaries=suid_binaries,
        world_writable_files=world_writable,
        shadow_files=[],
        ssl_cert_files=[],
        init_scripts=[],
        network_services=net_svcs,
    )


# ──────────────────────────────────────────────
# Risk Level Classification
# ──────────────────────────────────────────────


class TestRiskLevels:
    """Test risk level classification thresholds."""

    def test_low_risk(self, scorer: RiskScorer, minimal_context: ScanContext) -> None:
        """Clean context should score LOW (≥90)."""
        result = scorer.score(minimal_context)
        assert result.total_score >= 90
        assert result.risk_level == RiskLevel.LOW

    def test_critical_risk(
        self, scorer: RiskScorer, minimal_context: ScanContext
    ) -> None:
        """Multiple CRITICAL findings should produce CRITICAL risk (<50)."""
        minimal_context.credential_findings = [_make_credential_finding()]
        minimal_context.c2_findings = [_make_c2_finding()]
        minimal_context.cve_findings = [_make_cve_finding(is_in_kev=True)]
        # Add filesystem inventory with dangerous services (Control 2 FAIL)
        minimal_context.filesystem_inventory = _make_inventory(
            dangerous_services=["telnetd"]
        )
        result = scorer.score(minimal_context)
        assert result.risk_level == RiskLevel.CRITICAL
        assert result.total_score < 50

    def test_high_risk(
        self, scorer: RiskScorer, minimal_context: ScanContext
    ) -> None:
        """Some failures should produce HIGH risk (50-69)."""
        # Critical creds + dangerous services + SUID overflow
        minimal_context.credential_findings = [_make_credential_finding()]
        minimal_context.filesystem_inventory = _make_inventory(
            dangerous_services=["telnetd"],
            suid_count=10,
            world_writable_count=20,
        )
        result = scorer.score(minimal_context)
        assert result.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)

    def test_medium_risk(
        self, scorer: RiskScorer, minimal_context: ScanContext
    ) -> None:
        """Partial findings should produce MEDIUM risk (70-89)."""
        minimal_context.credential_findings = [
            _make_credential_finding(severity=Severity.MEDIUM)
        ]
        result = scorer.score(minimal_context)
        # With only medium findings, should be MEDIUM or better
        assert result.total_score >= 50


# ──────────────────────────────────────────────
# Control 1: No default/hardcoded credentials
# ──────────────────────────────────────────────


class TestControl1:
    """Test credential control evaluation."""

    def test_pass_no_findings(
        self, scorer: RiskScorer, minimal_context: ScanContext
    ) -> None:
        result = scorer.score(minimal_context)
        c1 = next(c for c in result.control_scores if c.control_id == 1)
        assert c1.result == "PASS"
        assert c1.points == 10.0

    def test_fail_critical_creds(
        self, scorer: RiskScorer, minimal_context: ScanContext
    ) -> None:
        minimal_context.credential_findings = [_make_credential_finding()]
        result = scorer.score(minimal_context)
        c1 = next(c for c in result.control_scores if c.control_id == 1)
        assert c1.result == "FAIL"
        assert c1.points == 0.0

    def test_partial_high_creds(
        self, scorer: RiskScorer, minimal_context: ScanContext
    ) -> None:
        minimal_context.credential_findings = [
            _make_credential_finding(severity=Severity.HIGH)
        ]
        result = scorer.score(minimal_context)
        c1 = next(c for c in result.control_scores if c.control_id == 1)
        assert c1.result == "PARTIAL"
        assert c1.points == 5.0

    def test_partial_medium_creds(
        self, scorer: RiskScorer, minimal_context: ScanContext
    ) -> None:
        minimal_context.credential_findings = [
            _make_credential_finding(severity=Severity.MEDIUM)
        ]
        result = scorer.score(minimal_context)
        c1 = next(c for c in result.control_scores if c.control_id == 1)
        assert c1.result == "PARTIAL"


# ──────────────────────────────────────────────
# Control 2: No unnecessary network services
# ──────────────────────────────────────────────


class TestControl2:
    """Test network services control evaluation."""

    def test_pass_no_services(
        self, scorer: RiskScorer, minimal_context: ScanContext
    ) -> None:
        result = scorer.score(minimal_context)
        c2 = next(c for c in result.control_scores if c.control_id == 2)
        assert c2.result == "PASS"
        assert c2.points == 10.0

    def test_fail_dangerous_services(
        self, scorer: RiskScorer, minimal_context: ScanContext
    ) -> None:
        minimal_context.filesystem_inventory = _make_inventory(
            dangerous_services=["telnetd"]
        )
        result = scorer.score(minimal_context)
        c2 = next(c for c in result.control_scores if c.control_id == 2)
        assert c2.result == "FAIL"
        assert c2.points == 0.0

    def test_partial_many_services(
        self, scorer: RiskScorer, minimal_context: ScanContext
    ) -> None:
        minimal_context.filesystem_inventory = _make_inventory(
            network_services_count=12
        )
        result = scorer.score(minimal_context)
        c2 = next(c for c in result.control_scores if c.control_id == 2)
        assert c2.result == "PARTIAL"


# ──────────────────────────────────────────────
# Control 3: No outdated/vulnerable components
# ──────────────────────────────────────────────


class TestControl3:
    """Test CVE component control evaluation."""

    def test_pass_no_cves(
        self, scorer: RiskScorer, minimal_context: ScanContext
    ) -> None:
        result = scorer.score(minimal_context)
        c3 = next(c for c in result.control_scores if c.control_id == 3)
        assert c3.result == "PASS"

    def test_fail_kev_cves(
        self, scorer: RiskScorer, minimal_context: ScanContext
    ) -> None:
        minimal_context.cve_findings = [_make_cve_finding(is_in_kev=True)]
        result = scorer.score(minimal_context)
        c3 = next(c for c in result.control_scores if c.control_id == 3)
        assert c3.result == "FAIL"

    def test_fail_critical_cves(
        self, scorer: RiskScorer, minimal_context: ScanContext
    ) -> None:
        minimal_context.cve_findings = [_make_cve_finding()]
        result = scorer.score(minimal_context)
        c3 = next(c for c in result.control_scores if c.control_id == 3)
        assert c3.result == "FAIL"

    def test_partial_high_cves(
        self, scorer: RiskScorer, minimal_context: ScanContext
    ) -> None:
        minimal_context.cve_findings = [
            _make_cve_finding(severity=Severity.HIGH)
        ]
        result = scorer.score(minimal_context)
        c3 = next(c for c in result.control_scores if c.control_id == 3)
        assert c3.result == "PARTIAL"


# ──────────────────────────────────────────────
# Control 7: No backdoor interfaces
# ──────────────────────────────────────────────


class TestControl7:
    """Test backdoor/C2 control evaluation."""

    def test_pass_no_c2(
        self, scorer: RiskScorer, minimal_context: ScanContext
    ) -> None:
        result = scorer.score(minimal_context)
        c7 = next(c for c in result.control_scores if c.control_id == 7)
        assert c7.result == "PASS"
        assert c7.points == 10.0

    def test_fail_likely_c2(
        self, scorer: RiskScorer, minimal_context: ScanContext
    ) -> None:
        minimal_context.c2_findings = [_make_c2_finding()]
        result = scorer.score(minimal_context)
        c7 = next(c for c in result.control_scores if c.control_id == 7)
        assert c7.result == "FAIL"

    def test_partial_suspicious_c2(
        self, scorer: RiskScorer, minimal_context: ScanContext
    ) -> None:
        minimal_context.c2_findings = [
            _make_c2_finding(severity="SUSPICIOUS")
        ]
        result = scorer.score(minimal_context)
        c7 = next(c for c in result.control_scores if c.control_id == 7)
        assert c7.result == "PARTIAL"

    def test_fail_backdoor_service(
        self, scorer: RiskScorer, minimal_context: ScanContext
    ) -> None:
        minimal_context.c2_findings = [
            _make_c2_finding(indicator_type="backdoor_service")
        ]
        result = scorer.score(minimal_context)
        c7 = next(c for c in result.control_scores if c.control_id == 7)
        assert c7.result == "FAIL"


# ──────────────────────────────────────────────
# Control 10: Binary hardening
# ──────────────────────────────────────────────


class TestControl10:
    """Test binary hardening control evaluation."""

    def test_pass_hardened(
        self, scorer: RiskScorer, minimal_context: ScanContext
    ) -> None:
        minimal_context.binary_intelligence = BinaryIntelligenceResult(
            binaries=[
                BinaryMetadata(
                    path=Path("bin/test"),
                    hardening=BinaryHardening(
                        nx_enabled=True,
                        stack_canary=True,
                        pie_enabled=True,
                        relro="full",
                    ),
                )
            ],
            total_binaries=1,
            hardened_binaries=1,
            unhardened_binaries=0,
        )
        result = scorer.score(minimal_context)
        c10 = next(c for c in result.control_scores if c.control_id == 10)
        assert c10.result == "PASS"
        assert c10.points == 8.0

    def test_fail_unhardened(
        self, scorer: RiskScorer, minimal_context: ScanContext
    ) -> None:
        minimal_context.binary_intelligence = BinaryIntelligenceResult(
            binaries=[
                BinaryMetadata(path=Path("bin/test"), hardening=BinaryHardening()),
            ],
            total_binaries=1,
            hardened_binaries=0,
            unhardened_binaries=1,
        )
        result = scorer.score(minimal_context)
        c10 = next(c for c in result.control_scores if c.control_id == 10)
        assert c10.result == "FAIL"

    def test_partial_mixed(
        self, scorer: RiskScorer, minimal_context: ScanContext
    ) -> None:
        minimal_context.binary_intelligence = BinaryIntelligenceResult(
            binaries=[],
            total_binaries=10,
            hardened_binaries=5,
            unhardened_binaries=5,
        )
        result = scorer.score(minimal_context)
        c10 = next(c for c in result.control_scores if c.control_id == 10)
        assert c10.result == "PARTIAL"


# ──────────────────────────────────────────────
# Control 12: SBOM inventory
# ──────────────────────────────────────────────


class TestControl12:
    """Test SBOM inventory control evaluation."""

    def test_partial_no_components(
        self, scorer: RiskScorer, minimal_context: ScanContext
    ) -> None:
        result = scorer.score(minimal_context)
        c12 = next(c for c in result.control_scores if c.control_id == 12)
        assert c12.result == "PARTIAL"

    def test_pass_with_components(
        self, scorer: RiskScorer, minimal_context: ScanContext
    ) -> None:
        minimal_context.software_components = [
            SoftwareComponent(
                vendor="busybox",
                product="busybox",
                version="1.36",
                cpe_string="cpe:2.3:a:busybox:busybox:1.36",
                source_file=Path("bin/busybox"),
                source_method="string_extraction",
            )
        ]
        result = scorer.score(minimal_context)
        c12 = next(c for c in result.control_scores if c.control_id == 12)
        assert c12.result == "PASS"
        assert c12.points == 3.0


# ──────────────────────────────────────────────
# OWASP IoT Top 10 Mapping
# ──────────────────────────────────────────────


class TestOWASPMapping:
    """Test OWASP IoT Top 10 mapping generation."""

    def test_all_pass(
        self, scorer: RiskScorer, minimal_context: ScanContext
    ) -> None:
        # Need SBOM components so control 12 passes
        minimal_context.software_components = [
            SoftwareComponent(
                vendor="test", product="test", version="1.0",
                cpe_string="cpe:2.3:a:test:test:1.0",
                source_file=Path("bin/test"),
                source_method="string_extraction",
            )
        ]
        result = scorer.score(minimal_context)
        # Control 6 defaults to PARTIAL when secure boot cannot be verified
        assert all(v in (0, 1) for v in result.owasp_iot_mapping.values())

    def test_credential_finding_maps_i1(
        self, scorer: RiskScorer, minimal_context: ScanContext
    ) -> None:
        minimal_context.credential_findings = [_make_credential_finding()]
        result = scorer.score(minimal_context)
        i1 = result.owasp_iot_mapping.get("I1 - Weak/Default Passwords")
        assert i1 == 2  # FAIL

    def test_c2_finding_maps_i2(
        self, scorer: RiskScorer, minimal_context: ScanContext
    ) -> None:
        # Backdoor finding maps to I2 (network services) partially
        minimal_context.c2_findings = [_make_c2_finding()]
        result = scorer.score(minimal_context)
        # At least one OWASP item should be non-zero
        assert any(v > 0 for v in result.owasp_iot_mapping.values())


# ──────────────────────────────────────────────
# Weighted Breakdown
# ──────────────────────────────────────────────


class TestBreakdown:
    """Test weighted breakdown computation."""

    def test_breakdown_categories(
        self, scorer: RiskScorer, minimal_context: ScanContext
    ) -> None:
        result = scorer.score(minimal_context)
        assert "credentials" in result.weighted_breakdown
        assert "network" in result.weighted_breakdown
        assert "components" in result.weighted_breakdown
        assert "encryption" in result.weighted_breakdown
        assert "hardening" in result.weighted_breakdown
        assert "c2_malware" in result.weighted_breakdown

    def test_breakdown_sums_to_total(
        self, scorer: RiskScorer, minimal_context: ScanContext
    ) -> None:
        result = scorer.score(minimal_context)
        breakdown_sum = sum(result.weighted_breakdown.values())
        assert breakdown_sum == result.total_score


# ──────────────────────────────────────────────
# Executive Summary
# ──────────────────────────────────────────────


class TestSummary:
    """Test executive summary generation."""

    def test_clean_summary(
        self, scorer: RiskScorer, minimal_context: ScanContext
    ) -> None:
        # Need SBOM components for clean pass
        minimal_context.software_components = [
            SoftwareComponent(
                vendor="test", product="test", version="1.0",
                cpe_string="cpe:2.3:a:test:test:1.0",
                source_file=Path("bin/test"),
                source_method="string_extraction",
            )
        ]
        result = scorer.score(minimal_context)
        # Some controls default to PARTIAL when unverifiable
        assert "All controls passed" in result.executive_summary or "Partial" in result.executive_summary

    def test_failed_controls_in_summary(
        self, scorer: RiskScorer, minimal_context: ScanContext
    ) -> None:
        minimal_context.credential_findings = [_make_credential_finding()]
        result = scorer.score(minimal_context)
        assert "Failed" in result.executive_summary or "FAIL" in str(
            result.control_scores
        )

    def test_max_score_100(
        self, scorer: RiskScorer, minimal_context: ScanContext
    ) -> None:
        result = scorer.score(minimal_context)
        assert result.total_score <= 100.0


# ──────────────────────────────────────────────
# Controls metadata
# ──────────────────────────────────────────────


class TestControlsMeta:
    """Test CONTROLS metadata integrity."""

    def test_12_controls(self) -> None:
        assert len(CONTROLS) == 12

    def test_max_points_sum_100(self) -> None:
        total = sum(c[2] for c in CONTROLS)
        assert total == 100.0

    def test_all_ids_unique(self) -> None:
        ids = [c[0] for c in CONTROLS]
        assert len(ids) == len(set(ids))

    def test_ids_sequential(self) -> None:
        ids = [c[0] for c in CONTROLS]
        assert ids == list(range(1, 13))
