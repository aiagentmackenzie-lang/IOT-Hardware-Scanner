"""Tests for ReportGenerator — Phase 7b.

Tests JSON, Markdown, and HTML report generation with various
scan context configurations.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.models import (
    C2Finding,
    ControlScore,
    CredentialFinding,
    CVEFinding,
    EntropyProfile,
    ExtractionResult,
    RiskLevel,
    RiskScore,
    ScanContext,
    Severity,
    SoftwareComponent,
)
from iot_hardware_scanner.scanner.report_generator import ReportGenerator

# ──────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────


@pytest.fixture
def output_dir(tmp_path: Path) -> Path:
    return tmp_path / "reports"


@pytest.fixture
def config(output_dir: Path) -> ScannerConfig:
    return ScannerConfig(
        output_dir=output_dir,
        report_formats=["json", "markdown", "html"],
    )


@pytest.fixture
def generator(config: ScannerConfig) -> ReportGenerator:
    return ReportGenerator(config)


@pytest.fixture
def minimal_context(output_dir: Path) -> ScanContext:
    """Minimal scan context with no findings."""
    output_dir.mkdir(parents=True, exist_ok=True)
    return ScanContext(
        scan_id="test-report-001",
        firmware_path=Path("/tmp/firmware.bin"),
        output_dir=output_dir,
        file_hash_sha256="a" * 64,
        file_hash_md5="b" * 32,
        file_size=2048,
        file_type="ELF 32-bit",
        firmware_name="test_firmware.bin",
        size_category="SMALL",
        started_at=datetime(2026, 5, 7, 17, 0, 0),
    )


@pytest.fixture
def full_context(output_dir: Path) -> ScanContext:
    """Full scan context with all finding types."""
    output_dir.mkdir(parents=True, exist_ok=True)
    ctx = ScanContext(
        scan_id="test-full-001",
        firmware_path=Path("/tmp/router.bin"),
        output_dir=output_dir,
        file_hash_sha256="c" * 64,
        file_hash_md5="d" * 32,
        file_size=8192,
        file_type="ELF 32-bit MIPS",
        firmware_name="router_firmware.bin",
        size_category="MEDIUM",
        started_at=datetime(2026, 5, 7, 12, 0, 0),
    )
    ctx.credential_findings = [
        CredentialFinding(
            severity=Severity.CRITICAL,
            category="password",
            file_path=Path("etc/shadow"),
            line_number=3,
            matched_pattern="root:admin",
            masked_value="********",
            is_default=True,
            is_placeholder=False,
        ),
    ]
    ctx.cve_findings = [
        CVEFinding(
            cve_id="CVE-2025-1234",
            severity=Severity.HIGH,
            cvss_v3_score=7.5,
            affected_product="busybox",
            affected_version="1.30",
            is_in_kev=False,
        ),
    ]
    ctx.c2_findings = [
        C2Finding(
            severity="LIKELY_C2",
            indicator_type="domain",
            value="c2.malware.top",
            file_path=Path("etc/config"),
            suspicion_score=85.0,
        ),
    ]
    ctx.software_components = [
        SoftwareComponent(
            vendor="busybox",
            product="busybox",
            version="1.30",
            cpe_string="cpe:2.3:a:busybox:busybox:1.30",
            source_file=Path("bin/busybox"),
            source_method="string_extraction",
        ),
    ]
    ctx.entropy_profile = EntropyProfile(
        firmware_path=Path("/tmp/router.bin"),
        total_blocks=100,
        block_size=256,
        overall_entropy=6.8,
        has_encrypted_regions=False,
        has_compressed_regions=True,
    )
    ctx.extraction_result = ExtractionResult(
        success=True,
        extraction_dir=output_dir,
        root_filesystems=[output_dir / "rootfs"],
        file_count=256,
        total_size=8192,
    )
    ctx.risk_score = RiskScore(
        total_score=55.0,
        risk_level=RiskLevel.HIGH,
        control_scores=[
            ControlScore(
                control_id=1,
                control_name="No default/hardcoded credentials",
                result="FAIL",
                points=0.0,
                max_points=10.0,
                evidence=["1 CRITICAL credential findings"],
                remediation="Remove all hardcoded credentials.",
            ),
        ],
        weighted_breakdown={"credentials": 0.0, "network": 10.0},
        executive_summary="Risk Score: 55/100 (HIGH). Failed controls: credentials.",
        owasp_iot_mapping={"I1 - Weak/Default Passwords": 2},
    )
    return ctx


# ──────────────────────────────────────────────
# JSON Report
# ──────────────────────────────────────────────


class TestJSONReport:
    """Test JSON report generation."""

    def test_generates_json_file(
        self, generator: ReportGenerator, minimal_context: ScanContext
    ) -> None:
        paths = generator.generate(minimal_context)
        assert "json" in paths
        assert paths["json"].exists()

    def test_json_valid(
        self, generator: ReportGenerator, minimal_context: ScanContext
    ) -> None:
        paths = generator.generate(minimal_context)
        content = paths["json"].read_text()
        data = json.loads(content)
        assert data["scan_id"] == "test-report-001"

    def test_json_firmware_section(
        self, generator: ReportGenerator, minimal_context: ScanContext
    ) -> None:
        paths = generator.generate(minimal_context)
        data = json.loads(paths["json"].read_text())
        fw = data["firmware"]
        assert fw["name"] == "test_firmware.bin"
        assert fw["sha256"] == "a" * 64
        assert fw["size"] == 2048

    def test_json_with_findings(
        self, generator: ReportGenerator, full_context: ScanContext
    ) -> None:
        paths = generator.generate(full_context)
        data = json.loads(paths["json"].read_text())
        assert len(data["credentials"]["findings"]) == 1
        assert len(data["cve"]["findings"]) == 1
        assert len(data["c2_malware"]["findings"]) == 1
        assert data["sbom"]["total"] == 1

    def test_json_risk_score(
        self, generator: ReportGenerator, full_context: ScanContext
    ) -> None:
        paths = generator.generate(full_context)
        data = json.loads(paths["json"].read_text())
        assert data["risk_score"]["total_score"] == 55.0
        assert data["risk_score"]["risk_level"] == "HIGH"


# ──────────────────────────────────────────────
# Markdown Report
# ──────────────────────────────────────────────


class TestMarkdownReport:
    """Test Markdown report generation."""

    def test_generates_md_file(
        self, generator: ReportGenerator, minimal_context: ScanContext
    ) -> None:
        paths = generator.generate(minimal_context)
        assert "markdown" in paths
        assert paths["markdown"].exists()

    def test_md_header(
        self, generator: ReportGenerator, minimal_context: ScanContext
    ) -> None:
        paths = generator.generate(minimal_context)
        content = paths["markdown"].read_text()
        assert "# IoT Hardware Scanner" in content
        assert "test_firmware.bin" in content

    def test_md_risk_scorecard(
        self, generator: ReportGenerator, full_context: ScanContext
    ) -> None:
        paths = generator.generate(full_context)
        content = paths["markdown"].read_text()
        assert "## Risk Scorecard" in content
        assert "FAIL" in content

    def test_md_owasp_mapping(
        self, generator: ReportGenerator, full_context: ScanContext
    ) -> None:
        paths = generator.generate(full_context)
        content = paths["markdown"].read_text()
        assert "## OWASP IoT Top 10 Mapping" in content

    def test_md_credential_findings(
        self, generator: ReportGenerator, full_context: ScanContext
    ) -> None:
        paths = generator.generate(full_context)
        content = paths["markdown"].read_text()
        assert "## Credential Findings" in content
        assert "CRITICAL" in content

    def test_md_cve_findings(
        self, generator: ReportGenerator, full_context: ScanContext
    ) -> None:
        paths = generator.generate(full_context)
        content = paths["markdown"].read_text()
        assert "## CVE Findings" in content
        assert "CVE-2025-1234" in content

    def test_md_c2_findings(
        self, generator: ReportGenerator, full_context: ScanContext
    ) -> None:
        paths = generator.generate(full_context)
        content = paths["markdown"].read_text()
        assert "## C2 / Malware Indicators" in content
        assert "c2.malware.top" in content

    def test_md_sbom(
        self, generator: ReportGenerator, full_context: ScanContext
    ) -> None:
        paths = generator.generate(full_context)
        content = paths["markdown"].read_text()
        assert "## Software Bill of Materials" in content
        assert "busybox" in content


# ──────────────────────────────────────────────
# HTML Report
# ──────────────────────────────────────────────


class TestHTMLReport:
    """Test HTML report generation."""

    def test_generates_html_file(
        self, generator: ReportGenerator, minimal_context: ScanContext
    ) -> None:
        paths = generator.generate(minimal_context)
        assert "html" in paths
        assert paths["html"].exists()

    def test_html_structure(
        self, generator: ReportGenerator, minimal_context: ScanContext
    ) -> None:
        paths = generator.generate(minimal_context)
        content = paths["html"].read_text()
        assert "<!DOCTYPE html>" in content
        assert "<html" in content
        assert "</html>" in content
        assert "<style>" in content

    def test_html_contains_data(
        self, generator: ReportGenerator, full_context: ScanContext
    ) -> None:
        paths = generator.generate(full_context)
        content = paths["html"].read_text()
        assert "test-full-001" in content or "router_firmware" in content


# ──────────────────────────────────────────────
# Terminal Report
# ──────────────────────────────────────────────


class TestTerminalReport:
    """Test terminal format handling (no file output)."""

    def test_terminal_no_file(
        self, output_dir: Path, minimal_context: ScanContext
    ) -> None:
        cfg = ScannerConfig(
            output_dir=output_dir,
            report_formats=["terminal"],
        )
        gen = ReportGenerator(cfg)
        paths = gen.generate(minimal_context)
        # Terminal format does not produce files
        assert "terminal" not in paths


# ──────────────────────────────────────────────
# Edge Cases
# ──────────────────────────────────────────────


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_context(
        self, generator: ReportGenerator, minimal_context: ScanContext
    ) -> None:
        """Context with no findings produces valid reports."""
        paths = generator.generate(minimal_context)
        assert "json" in paths
        assert "markdown" in paths

    def test_json_empty_findings(
        self, generator: ReportGenerator, minimal_context: ScanContext
    ) -> None:
        """JSON with no findings has correct structure."""
        paths = generator.generate(minimal_context)
        data = json.loads(paths["json"].read_text())
        assert data["credentials"]["total"] == 0
        assert data["cve"]["total"] == 0
        assert data["c2_malware"]["total"] == 0

    def test_entropy_section(
        self, generator: ReportGenerator, minimal_context: ScanContext
    ) -> None:
        """Entropy profile section is included when available."""
        minimal_context.entropy_profile = EntropyProfile(
            firmware_path=Path("/tmp/firmware.bin"),
            total_blocks=50,
            block_size=128,
            overall_entropy=7.2,
            has_encrypted_regions=True,
            has_compressed_regions=True,
        )
        paths = generator.generate(minimal_context)
        data = json.loads(paths["json"].read_text())
        assert data["entropy"] is not None
        assert data["entropy"]["overall_entropy"] == 7.2

    def test_no_entropy_section(
        self, generator: ReportGenerator, minimal_context: ScanContext
    ) -> None:
        """No entropy profile → null section in JSON."""
        paths = generator.generate(minimal_context)
        data = json.loads(paths["json"].read_text())
        assert data["entropy"] is None

    def test_risk_score_none(
        self, generator: ReportGenerator, minimal_context: ScanContext
    ) -> None:
        """No risk score → null section in JSON."""
        paths = generator.generate(minimal_context)
        data = json.loads(paths["json"].read_text())
        # minimal_context has no risk_score set (None by default)
        assert data["risk_score"] is None

    def test_multiple_report_formats(
        self, output_dir: Path, full_context: ScanContext
    ) -> None:
        """Multiple formats generate multiple files."""
        output_dir.mkdir(parents=True, exist_ok=True)
        cfg = ScannerConfig(
            output_dir=output_dir,
            report_formats=["json", "markdown", "html"],
        )
        gen = ReportGenerator(cfg)
        paths = gen.generate(full_context)
        assert "json" in paths
        assert "markdown" in paths
        assert "html" in paths

    def test_md_to_html_converter(
        self, generator: ReportGenerator
    ) -> None:
        """Markdown to HTML converter handles basic formatting."""
        md = "# Title\n## Section\n- item 1\n| A | B |\n|---|---|\n| 1 | 2 |"
        html = generator._md_to_html(md)
        assert "<h1>" in html
        assert "<h2>" in html
        assert "<li>" in html
        assert "<table>" in html
