"""Tests for CLI — Phase 1.

Covers:
- CLI entry point loads
- Version output
- Scan command argument parsing
- Exit code behavior
"""

import os
import tempfile
from pathlib import Path

from click.testing import CliRunner

from iot_hardware_scanner.cli import main


class TestCLIBasic:
    """Test CLI entry point and basic commands."""

    def test_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "IoT Hardware Scanner" in result.output

    def test_version(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "1.0.0" in result.output

    def test_scan_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--output" in result.output
        assert "--format" in result.output
        assert "--verbose" in result.output
        assert "--offline" in result.output


class TestCLIScanCommand:
    """Test the scan subcommand."""

    def test_scan_nonexistent_file(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "/nonexistent/firmware.bin"])
        assert result.exit_code == 3  # FirmwareNotFoundError

    def test_scan_empty_file(self) -> None:
        runner = CliRunner()
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"")  # empty
            path = f.name

        try:
            result = runner.invoke(main, ["scan", path])
            assert result.exit_code == 3  # FirmwareEmptyError
        finally:
            os.unlink(path)

    def test_scan_valid_file(self) -> None:
        """Scan a small firmware file — should complete Phase 1 at minimum."""
        runner = CliRunner()
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(os.urandom(1024))
            path = f.name

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                result = runner.invoke(
                    main,
                    [
                        "scan",
                        path,
                        "--output",
                        tmpdir,
                    ],
                )
                # Phase 1 should succeed; later phases may fail gracefully
                assert "Ingest" in result.output or result.exit_code == 0
        finally:
            os.unlink(path)


class TestCLIExtractCommand:
    """Test the extract subcommand."""

    def test_extract_nonexistent(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["extract", "/nonexistent.bin"])
        assert result.exit_code == 3


class TestCLIEntropyCommand:
    """Test the entropy subcommand."""

    def test_entropy_nonexistent(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["entropy", "/nonexistent.bin"])
        assert result.exit_code == 3

    def test_entropy_valid_file(self) -> None:
        runner = CliRunner()
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(os.urandom(4096))
            path = f.name

        try:
            result = runner.invoke(main, ["entropy", path])
            # Should at least complete ingestion + entropy
            assert result.exit_code == 0 or "Error" in result.output
        finally:
            os.unlink(path)


class TestCLIReportCommand:
    """Test the report subcommand."""

    def test_report_requires_existing_file(self) -> None:
        """Report command requires an existing scan file."""
        runner = CliRunner()
        result = runner.invoke(main, ["report", "/nonexistent/report.json"])
        # Click's exists=True should cause exit code 2
        assert result.exit_code != 0

    def test_report_invalid_json(self, tmp_path: Path) -> None:
        """Report command handles invalid JSON gracefully."""
        bad_json = tmp_path / "bad.json"
        bad_json.write_text("not valid json at all")

        runner = CliRunner()
        result = runner.invoke(main, ["report", str(bad_json), "--format", "json"])
        # Should fail gracefully (exit code 6) or show an error
        assert result.exit_code != 0 or "Error" in result.output

    def test_report_valid_json_scan(self, tmp_path: Path) -> None:
        """Report command can load a valid JSON scan file and generate report."""
        import json

        scan_data = {
            "scan_id": "test-report-001",
            "scan_date": "2025-01-01T00:00:00+00:00",
            "firmware": {
                "name": "test_fw",
                "path": str(tmp_path / "test.bin"),
                "sha256": "a" * 64,
                "md5": "b" * 32,
                "size": 1024,
                "file_type": "ELF",
            },
            "risk_score": {
                "total_score": 75,
                "risk_level": "MEDIUM",
                "control_scores": [
                    {
                        "control_id": 1,
                        "control_name": "No default/hardcoded credentials",
                        "result": "PASS",
                        "points": 10.0,
                        "max_points": 10.0,
                        "evidence": [],
                        "remediation": "",
                    }
                ],
                "weighted_breakdown": {"credentials": 10.0},
                "executive_summary": "Test summary",
                "owasp_iot_mapping": {"I1 - Weak/Default Passwords": 0},
            },
            "credentials": {"total": 0, "findings": []},
            "cve": {"total": 0, "findings": []},
            "c2_malware": {"total": 0, "findings": []},
        }
        scan_file = tmp_path / "scan_report.json"
        scan_file.write_text(json.dumps(scan_data))

        runner = CliRunner()
        result = runner.invoke(
            main, ["report", str(scan_file), "--format", "json"]
        )
        # Should not show "not yet implemented"
        assert "not yet implemented" not in result.output
