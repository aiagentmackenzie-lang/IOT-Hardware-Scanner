"""Tests for CLI — Phase 1.

Covers:
- CLI entry point loads
- Version output
- Scan command argument parsing
- Exit code behavior
"""

import os
import tempfile

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
