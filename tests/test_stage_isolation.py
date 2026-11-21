"""Stage isolation and the CLI backstop (slice 2E).

Two independent guarantees, tested separately:

* a parser bug **inside** a phase becomes that stage's ``FAILED`` with a reason,
  the run continues, and the assessment is ``INCOMPLETE`` (exit 4);
* a bug **outside** every stage (orchestrator construction, an unexpected raise
  in the pipeline driver) is exit 6 with one line — never a Python traceback.

A documented ``ScannerError`` is neither: it keeps its own exit code.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from iot_hardware_scanner.cli import main
from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.exceptions import ExtractionFailedError
from iot_hardware_scanner.models import StageStatus
from iot_hardware_scanner.orchestrator import Orchestrator
from iot_hardware_scanner.scanner.assessment import collect_findings, decide_exit


def _tree(tmp_path: Path) -> Path:
    root = tmp_path / "tree"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/sh\n")
    return root


def _stage(context, stage_id: str):
    return next(item for item in context.stages if item.stage_id.value == stage_id)


def test_an_unexpected_parser_bug_becomes_incomplete_work(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A ``RuntimeError`` from a phase is stage FAILED + exit 4, not a crash."""
    tree = _tree(tmp_path)

    def explode(self, context):
        raise RuntimeError("simulated parser defect")

    monkeypatch.setattr(Orchestrator, "_phase_opkg", explode)
    context = Orchestrator(ScannerConfig(output_dir=tmp_path / "out"), input_tree=True).run(tree)

    stage = _stage(context, "opkg_inventory")
    assert stage.status is StageStatus.FAILED
    assert "package database hit an unexpected error" in stage.reason
    assert "RuntimeError: simulated parser defect" in stage.reason

    decision = decide_exit(collect_findings(context), context.assessment)
    assert decision.exit_code == 4
    assert context.assessment.completion.value == "INCOMPLETE"


def test_findings_collected_before_a_bug_survive(tmp_path: Path, monkeypatch) -> None:
    """Isolation must not throw away evidence a later stage never produced."""
    tree = _tree(tmp_path)
    (tree / "etc" / "shadow").write_text("root::19000:0:99999:7:::\n")  # empty password

    def explode(self, context):
        raise RuntimeError("simulated parser defect")

    monkeypatch.setattr(Orchestrator, "_phase_c2", explode)
    context = Orchestrator(ScannerConfig(output_dir=tmp_path / "out"), input_tree=True).run(tree)

    findings = collect_findings(context)
    assert any(f.rule_id.startswith("credential.") for f in findings), (
        "a critical credential observation must survive an unrelated stage failure"
    )
    assert _stage(context, "c2_indicators").status is StageStatus.FAILED
    assert decide_exit(findings, context.assessment).exit_code == 1


def test_a_documented_error_is_not_flattened(tmp_path: Path, monkeypatch) -> None:
    """``ScannerError`` carries the exit code the operator is owed."""
    tree = _tree(tmp_path)

    def documented(self, context):
        raise ExtractionFailedError("the helper returned a partial tree")

    monkeypatch.setattr(Orchestrator, "_phase_tree_filesystem", documented)
    with pytest.raises(ExtractionFailedError):
        Orchestrator(ScannerConfig(output_dir=tmp_path / "out"), input_tree=True).run(tree)


def test_the_cli_backstop_is_exit_6_without_a_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A defect outside every stage is an internal error, stated in one line."""
    target = tmp_path / "firmware.bin"
    target.write_bytes(b"\x00" * 4096)
    out = tmp_path / "report.json"

    def explode(self, path):
        raise RuntimeError("pipeline driver defect")

    monkeypatch.setattr(Orchestrator, "run", explode)
    result = CliRunner().invoke(
        main,
        ["scan", str(target), "--offline", "--format", "json", "--out", str(out)],
    )

    assert result.exit_code == 6
    assert "Traceback" not in result.output
    assert "Internal error" in result.output
    assert not out.exists(), "no partial report may be presented as the result"


def _saved_scan(path: Path) -> Path:
    path.write_text(
        json.dumps(
            {
                "schema_version": 6,
                "artifact": {"name": "a.bin", "kind": "file", "sha256": "0" * 64},
                "assessment": {"completion": "COMPLETE"},
            }
        )
    )
    return path


def test_a_renderer_defect_is_exit_6(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A document that validates but breaks the renderer is our bug, not bad input."""
    from iot_hardware_scanner import cli as cli_module

    document = _saved_scan(tmp_path / "scan.json")

    def explode(payload, fmt):
        raise RuntimeError("renderer defect")

    monkeypatch.setattr(cli_module, "render", explode)
    result = CliRunner().invoke(main, ["report", str(document), "--format", "markdown"])

    assert result.exit_code == 6
    assert "Traceback" not in result.output
    assert "Internal error" in result.output


def test_a_comparison_defect_is_exit_6(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``compare`` degrades the same way rather than leaking a traceback."""
    from iot_hardware_scanner.scanner import comparison

    base = _saved_scan(tmp_path / "base.json")
    target = _saved_scan(tmp_path / "target.json")

    def explode(*args, **kwargs):
        raise RuntimeError("comparison defect")

    monkeypatch.setattr(comparison, "compare_documents", explode)
    result = CliRunner().invoke(main, ["compare", str(base), str(target)])

    assert result.exit_code == 6
    assert "Traceback" not in result.output
    assert "Internal error" in result.output


def test_an_export_defect_is_exit_6(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``sbom`` reports an export defect as an internal error, not a crash."""
    from iot_hardware_scanner.scanner import sbom_export

    document = _saved_scan(tmp_path / "scan.json")

    def explode(*args, **kwargs):
        raise RuntimeError("export defect")

    monkeypatch.setattr(sbom_export, "export_sbom", explode)
    result = CliRunner().invoke(main, ["sbom", str(document)])

    assert result.exit_code == 6
    assert "Traceback" not in result.output
    assert "Internal error" in result.output
