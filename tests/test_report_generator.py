"""ReportGenerator: the thin delegation wrapper, exercised where it can fail.

The generator holds no rendering logic — every format comes from
:mod:`iot_hardware_scanner.scanner.report_document`, and the CLI writes through
that module directly. Its own code is therefore short, and the two behaviours
that are its own are the ones worth a case: ``generate`` writes every configured
format from **one** document, and a destination it cannot write raises rather
than reporting success.

These are contract cases, not coverage cases: a test that only executed a line
would leave the failure this class can actually produce untested.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.models import ScanContext
from iot_hardware_scanner.scanner.report_document import SCHEMA_VERSION, ReportWriteError
from iot_hardware_scanner.scanner.report_generator import ReportGenerator


def _generator(tmp_path: Path, formats: list[str]) -> ReportGenerator:
    config = ScannerConfig(output_dir=tmp_path / "reports", report_formats=formats)
    return ReportGenerator(config)


class TestGenerate:
    def test_every_configured_format_is_written_from_one_document(
        self, sample_scan_context: ScanContext, tmp_path: Path
    ) -> None:
        sample_scan_context.output_dir.mkdir(parents=True, exist_ok=True)
        generator = _generator(tmp_path, ["json", "markdown"])

        paths = generator.generate(sample_scan_context)

        assert set(paths) == {"json", "markdown"}
        for fmt, path in paths.items():
            assert path.is_file(), fmt
            assert path.name == ("report.json" if fmt == "json" else "report.md")
        # One document, two renderings of it.
        document = generator.document(sample_scan_context)
        assert '"schema_version"' in paths["json"].read_text()
        assert "IoT Hardware Scanner" in paths["markdown"].read_text()
        assert document["schema_version"] == SCHEMA_VERSION

    def test_terminal_is_not_written_to_a_file(
        self, sample_scan_context: ScanContext, tmp_path: Path
    ) -> None:
        sample_scan_context.output_dir.mkdir(parents=True, exist_ok=True)
        paths = _generator(tmp_path, ["terminal", "json"]).generate(sample_scan_context)
        assert set(paths) == {"json"}

    def test_an_unsupported_format_is_refused_before_anything_is_written(
        self, sample_scan_context: ScanContext, tmp_path: Path
    ) -> None:
        """Configuration rejects the format, so no renderer is ever reached."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError) as excinfo:
            _generator(tmp_path, ["pdf"])
        assert "Invalid report format" in str(excinfo.value)
        assert not (tmp_path / "reports").exists()

    def test_an_unwritable_destination_raises_instead_of_reporting_success(
        self, sample_scan_context: ScanContext, tmp_path: Path
    ) -> None:
        output_dir = tmp_path / "blocked"
        output_dir.mkdir()
        blocker = output_dir / "report.json"
        blocker.write_text("not a directory")
        # A file where the directory must be makes the write fail.
        sample_scan_context.output_dir = blocker

        with pytest.raises(ReportWriteError):
            _generator(tmp_path, ["json"]).generate(sample_scan_context)
