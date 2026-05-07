"""Tests for Data Models — Phase 1.

Covers:
- ScanContext creation and defaults
- FirmwareMetadata structure
- Enum values
- Finding severity taxonomy
"""

from datetime import datetime, timezone
from pathlib import Path

from iot_hardware_scanner.models import (
    C2Finding,
    CredentialFinding,
    CVEFinding,
    EntropyBlock,
    EntropyProfile,
    FileCategory,
    FirmwareMetadata,
    FirmwareSizeCategory,
    RiskLevel,
    ScanContext,
    Severity,
)


class TestScanContext:
    """Test ScanContext dataclass."""

    def test_creation(self) -> None:
        ctx = ScanContext(
            scan_id="test-001",
            firmware_path=Path("/tmp/fw.bin"),
            output_dir=Path("/tmp/output"),
            file_hash_sha256="a" * 64,
            file_hash_md5="b" * 32,
            file_size=1024,
            file_type="ELF",
            firmware_name="fw",
            size_category=FirmwareSizeCategory.SMALL,
            started_at=datetime.now(timezone.utc),
        )
        assert ctx.scan_id == "test-001"
        assert ctx.extracted_rootfs is None
        assert ctx.entropy_profile is None
        assert ctx.credential_findings == []
        assert ctx.cve_findings == []
        assert ctx.c2_findings == []
        assert ctx.risk_score is None

    def test_default_lists_are_independent(self) -> None:
        """Each ScanContext instance gets its own default list objects."""
        ctx1 = ScanContext(
            scan_id="1",
            firmware_path=Path("/a"),
            output_dir=Path("/b"),
            file_hash_sha256="a" * 64,
            file_hash_md5="b" * 32,
            file_size=1,
            file_type="",
            firmware_name="",
            size_category=FirmwareSizeCategory.SMALL,
            started_at=datetime.now(timezone.utc),
        )
        ctx2 = ScanContext(
            scan_id="2",
            firmware_path=Path("/c"),
            output_dir=Path("/d"),
            file_hash_sha256="c" * 64,
            file_hash_md5="d" * 32,
            file_size=2,
            file_type="",
            firmware_name="",
            size_category=FirmwareSizeCategory.SMALL,
            started_at=datetime.now(timezone.utc),
        )
        ctx1.credential_findings.append(
            CredentialFinding(severity=Severity.HIGH, category="password", file_path=Path("a"))
        )
        assert len(ctx1.credential_findings) == 1
        assert len(ctx2.credential_findings) == 0


class TestEnums:
    """Test enumeration values match SDR specification."""

    def test_severity_values(self) -> None:
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.MEDIUM.value == "MEDIUM"
        assert Severity.LOW.value == "LOW"
        assert Severity.INFO.value == "INFO"

    def test_risk_level_values(self) -> None:
        assert RiskLevel.LOW.value == "LOW"
        assert RiskLevel.MEDIUM.value == "MEDIUM"
        assert RiskLevel.HIGH.value == "HIGH"
        assert RiskLevel.CRITICAL.value == "CRITICAL"

    def test_file_categories(self) -> None:
        assert FileCategory.CRITICAL_CREDENTIAL.value == "CRITICAL_CREDENTIAL"
        assert FileCategory.LOW_MISC.value == "LOW_MISC"

    def test_size_categories(self) -> None:
        assert FirmwareSizeCategory.SMALL.value == "SMALL"
        assert FirmwareSizeCategory.MEDIUM.value == "MEDIUM"
        assert FirmwareSizeCategory.LARGE.value == "LARGE"


class TestFirmwareMetadata:
    """Test FirmwareMetadata structure."""

    def test_creation(self) -> None:
        meta = FirmwareMetadata(
            path=Path("/tmp/fw.bin"),
            name="fw",
            size_bytes=1024,
            size_category=FirmwareSizeCategory.SMALL,
            sha256="a" * 64,
            md5="b" * 32,
            file_type="ELF binary",
            extension=".bin",
            is_regular_file=True,
            is_readable=True,
        )
        assert meta.name == "fw"
        assert meta.size_bytes == 1024
        assert meta.extension == ".bin"


class TestEntropyModels:
    """Test entropy-related models."""

    def test_entropy_block(self) -> None:
        block = EntropyBlock(offset=0, entropy=0.75, byte_distribution={})
        assert block.offset == 0
        assert block.entropy == 0.75

    def test_entropy_profile_defaults(self) -> None:
        profile = EntropyProfile(
            firmware_path=Path("test.bin"),
            total_blocks=10,
            block_size=512,
        )
        assert profile.has_encrypted_regions is False
        assert profile.has_compressed_regions is False
        assert profile.firmware_partially_readable is True
        assert profile.overall_entropy == 0.0


class TestFindingModels:
    """Test finding-related models."""

    def test_credential_finding(self) -> None:
        finding = CredentialFinding(
            severity=Severity.CRITICAL,
            category="password",
            file_path=Path("etc/shadow"),
            line_number=5,
            masked_value="roo***456",
        )
        assert finding.severity == Severity.CRITICAL
        assert finding.is_default is False
        assert finding.is_placeholder is False

    def test_cve_finding(self) -> None:
        finding = CVEFinding(
            cve_id="CVE-2024-0001",
            severity=Severity.HIGH,
            description="Test CVE",
        )
        assert finding.cve_id == "CVE-2024-0001"
        assert finding.is_in_kev is False

    def test_c2_finding(self) -> None:
        finding = C2Finding(
            severity="LIKELY_C2",
            indicator_type="domain",
            value="evil.example.su",
            file_path=Path("etc/hosts"),
            suspicion_score=72.0,
        )
        assert finding.severity == "LIKELY_C2"
        assert finding.suspicion_score == 72.0
