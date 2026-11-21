"""CLI contract tests: exit precedence, report delivery and replay.

Every assertion here is about what a caller can observe: the process status,
the files that exist afterwards, and the content of the saved document.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from iot_hardware_scanner.cli import main


def _run(args: list[str]) -> tuple[int, str]:
    result = CliRunner().invoke(main, args)
    return result.exit_code, result.output


class TestEntrypointBasics:
    def test_help(self) -> None:
        code, output = _run(["--help"])
        assert code == 0
        assert "IoT Hardware Scanner" in output

    def test_version_is_major_2(self) -> None:
        code, output = _run(["--version"])
        assert code == 0
        assert "2.2.0" in output

    def test_scan_help_documents_the_contract(self) -> None:
        code, output = _run(["scan", "--help"])
        assert code == 0
        for flag in (
            "--output",
            "--format",
            "--out",
            "--offline",
            "--profile",
            "--config",
            "--input-tree",
            "--build-manifest",
            "--worker",
        ):
            assert flag in output


class TestScanValidation:
    def test_missing_input_is_exit_3(self) -> None:
        code, output = _run(["scan", "/nonexistent/firmware.bin"])
        assert code == 3
        assert "Error" in output

    def test_empty_input_is_exit_3(self, tmp_path: Path) -> None:
        target = tmp_path / "empty.bin"
        target.write_bytes(b"")
        code, _ = _run(["scan", str(target)])
        assert code == 3

    def test_traversal_path_is_exit_3(self) -> None:
        code, _ = _run(["scan", "../etc/passwd"])
        assert code == 3


class TestOpaqueInput:
    """1A/1B — an opaque artifact must not receive a clean verdict."""

    def test_blank_image_is_incomplete_and_not_graded(
        self, blank_image: Path, tmp_path: Path
    ) -> None:
        destination = tmp_path / "requested.json"
        code, output = _run(
            [
                "scan",
                str(blank_image),
                "--offline",
                "--format",
                "json",
                "--out",
                str(destination),
            ]
        )

        # Unsupported input: 4,096 zero bytes are neither a gzip wrapper nor a
        # SquashFS filesystem. That is incomplete analysis (exit 4), not a
        # missing dependency -- no backend would make this image decodable.
        assert code == 4
        assert destination.is_file()

        document = json.loads(destination.read_text())
        assert document["schema_version"] == 4
        assert document["assessment"]["completion"] == "INCOMPLETE"
        assert not document["assessment"]["missing_required_dependencies"]
        assert any(
            "not decodable" in reason for reason in document["assessment"]["incomplete_reasons"]
        )
        assert document["findings"] == []
        # The retired grade must not appear for a new scan.
        assert document["risk_score"] is None
        assert "risk_level" not in document
        assert "/100" not in output
        assert "LOW" not in output

    def test_requested_destination_is_the_only_report_written(
        self, blank_image: Path, tmp_path: Path
    ) -> None:
        destination = tmp_path / "exact.json"
        _run(
            [
                "scan",
                str(blank_image),
                "--offline",
                "--format",
                "json",
                "--out",
                str(destination),
                "--output",
                str(tmp_path / "scans"),
            ]
        )
        assert destination.is_file()
        reports = list((tmp_path / "scans").rglob("report.json"))
        assert reports == [], "no second copy may be written behind the caller's back"

    def test_unwritable_destination_is_exit_6_and_never_success(
        self, blank_image: Path, tmp_path: Path
    ) -> None:
        blocked = tmp_path / "blocked"
        blocked.mkdir()
        destination = blocked / "report.json"
        destination.mkdir()  # a directory where a file was requested

        code, output = _run(
            ["scan", str(blank_image), "--offline", "--format", "json", "--out", str(destination)]
        )

        assert code == 6
        assert "not written" in output.lower()
        assert "Report written" not in output


class TestFindingsSurviveIncompleteStages:
    """A qualified critical finding outranks an unrelated incomplete stage."""

    def test_critical_finding_with_incomplete_assessment_is_exit_1(
        self, opaque_image: Path, tmp_path: Path
    ) -> None:
        destination = tmp_path / "opaque.json"
        code, _output = _run(
            [
                "scan",
                str(opaque_image),
                "--offline",
                "--format",
                "json",
                "--out",
                str(destination),
            ]
        )

        assert code == 1
        document = json.loads(destination.read_text())
        assert document["assessment"]["completion"] == "INCOMPLETE"
        assert document["outcome"]["exit_code"] == 1
        assert document["outcome"]["exit_reason"] == "CRITICAL_FINDING"
        critical = [f for f in document["findings"] if f["critical_qualified"]]
        assert len(critical) == 1
        assert critical[0]["rule_id"] == "credential.regex.password"
        # The secret itself must never reach the report.
        assert "Xk9#mQ2vLp7" not in destination.read_text()


class TestCredentialsProfile:
    def test_clean_tree_completes_with_exit_0(self, fixture_tree: Path, tmp_path: Path) -> None:
        destination = tmp_path / "clean.json"
        code, output = _run(
            [
                "scan",
                str(fixture_tree),
                "--creds",
                "--format",
                "json",
                "--out",
                str(destination),
            ]
        )

        assert code == 0
        document = json.loads(destination.read_text())
        assert document["assessment"]["completion"] == "COMPLETE"
        assert document["outcome"]["exit_reason"] == "COMPLETE_NO_FINDINGS"
        assert document["findings"] == []
        assert "Risk Score" not in output

    def test_locked_root_is_not_a_critical_password_finding(
        self, fixture_tree: Path, tmp_path: Path
    ) -> None:
        destination = tmp_path / "locked.json"
        code, _ = _run(
            ["scan", str(fixture_tree), "--creds", "--format", "json", "--out", str(destination)]
        )
        document = json.loads(destination.read_text())
        assert code == 0
        rules = {f["rule_id"] for f in document["findings"]}
        assert "credential.unix.empty_password" not in rules
        assert not any(f["category"] == "password" for f in document["findings"])

    def test_empty_password_is_exit_1(self, tmp_path: Path) -> None:
        root = tmp_path / "empty_pw"
        (root / "etc").mkdir(parents=True)
        (root / "etc" / "passwd").write_text(
            "root:x:0:0:root:/root:/bin/ash\nadmin::0:0::/root:/bin/sh\n"
        )
        (root / "etc" / "shadow").write_text("root:!$6$salt$hash:19000:0:99999:7:::\n")
        destination = tmp_path / "empty.json"

        code, _ = _run(
            ["scan", str(root), "--creds", "--format", "json", "--out", str(destination)]
        )

        assert code == 1
        document = json.loads(destination.read_text())
        critical = [f for f in document["findings"] if f["critical_qualified"]]
        assert [f["rule_id"] for f in critical] == ["credential.unix.empty_password"]
        # The extra UID 0 account is separately visible for review.
        assert any(f["rule_id"] == "credential.unix.uid0_account" for f in document["findings"])


class TestExtractAndEntropyCommands:
    def test_extract_missing_input_is_exit_3(self) -> None:
        code, _ = _run(["extract", "/nonexistent.bin"])
        assert code == 3

    def test_entropy_invalid_block_size_is_exit_3(self, blank_image: Path) -> None:
        code, output = _run(["entropy", str(blank_image), "--block-size", "0"])
        assert code == 3
        assert "Configuration error" in output

    def test_entropy_reports_bits_per_byte(self, blank_image: Path) -> None:
        code, output = _run(["entropy", str(blank_image), "--block-size", "128"])
        assert code == 0
        assert "bits/byte" in output
        assert "0.0000" in output

    def test_entropy_json_carries_units(self, blank_image: Path) -> None:
        code, output = _run(["entropy", str(blank_image), "--format", "json"])
        assert code == 0
        payload = json.loads(output)
        assert payload["units"] == "bits/byte"
        assert payload["overall_entropy"] == 0.0


class TestReplay:
    def test_v1_finding_and_grade_survive_replay(
        self, legacy_v1_report: Path, tmp_path: Path
    ) -> None:
        destination = tmp_path / "replayed.json"
        before = legacy_v1_report.read_bytes()

        code, _ = _run(
            ["report", str(legacy_v1_report), "--format", "json", "--out", str(destination)]
        )

        assert code == 0
        # The input document is never modified.
        assert legacy_v1_report.read_bytes() == before

        document = json.loads(destination.read_text())
        assert len(document["findings"]) == 1
        assert document["findings"][0]["severity"] == "HIGH"
        assert document["legacy_grade"]["total_score"] == 88.0
        assert document["legacy_grade"]["method"] == "v1-12-control-weighted"
        assert document["assessment"]["coverage"] == "UNKNOWN"

    def test_replay_to_markdown_keeps_the_finding(
        self, legacy_v1_report: Path, tmp_path: Path
    ) -> None:
        destination = tmp_path / "replayed.md"
        code, _ = _run(
            ["report", str(legacy_v1_report), "--format", "markdown", "--out", str(destination)]
        )
        assert code == 0
        text = destination.read_text()
        assert "etc/config/system" in text
        assert "Legacy grade" in text
        assert "Coverage unknown" in text

    def test_replay_exit_reports_rendering_only(
        self, legacy_v1_report: Path, tmp_path: Path
    ) -> None:
        code, _ = _run(
            [
                "report",
                str(legacy_v1_report),
                "--format",
                "html",
                "--out",
                str(tmp_path / "out.html"),
            ]
        )
        assert code == 0  # a rendered legacy document with a finding is still a success

    def test_replay_unreadable_input_is_exit_3(self, tmp_path: Path) -> None:
        broken = tmp_path / "broken.json"
        broken.write_text("not json")
        code, _ = _run(["report", str(broken)])
        assert code == 3

    def test_replay_unwritable_destination_is_exit_6(
        self, legacy_v1_report: Path, tmp_path: Path
    ) -> None:
        blocked = tmp_path / "blocked.json"
        blocked.mkdir()
        code, output = _run(["report", str(legacy_v1_report), "--out", str(blocked)])
        assert code == 6
        assert "not written" in output.lower()


class TestConfigFilePrecedence:
    def test_toml_config_is_honoured(self, blank_image: Path, tmp_path: Path) -> None:
        config = tmp_path / "scanner.toml"
        config.write_text("max_file_size_mb = 1\n")
        code, _ = _run(["scan", str(blank_image), "--config", str(config), "--offline"])
        assert code in (4, 5)  # accepted: the scan ran and is incomplete

    def test_cli_beats_config_file(self, blank_image: Path, tmp_path: Path) -> None:
        config = tmp_path / "scanner.toml"
        config.write_text("max_file_size_mb = 1\n")
        # The CLI value must win, so a 4 KiB file is accepted.
        code, output = _run(
            ["scan", str(blank_image), "--config", str(config), "--max-size", "2", "--offline"]
        )
        assert code in (4, 5)
        assert "File validated" in output

    def test_missing_config_file_is_exit_3(self, blank_image: Path, tmp_path: Path) -> None:
        code, output = _run(["scan", str(blank_image), "--config", str(tmp_path / "absent.toml")])
        assert code == 3
        assert "Configuration error" in output

    def test_environment_is_overridden_by_cli(
        self, blank_image: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("IOT_HARDWARE_SCANNER_MAX_FILE_SIZE_MB", "1")
        code, output = _run(["scan", str(blank_image), "--max-size", "2", "--offline"])
        assert code in (4, 5)
        assert "File validated" in output

    def test_environment_is_used_when_cli_silent(
        self,
        blank_image: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        env_out = tmp_path / "from_env"
        monkeypatch.setenv("IOT_HARDWARE_SCANNER_OUTPUT_DIR", str(env_out))
        code, _ = _run(["scan", str(blank_image), "--offline", "--format", "json"])
        assert code in (4, 5)
        assert list(env_out.rglob("report.json")), "output_dir from the environment was ignored"

    def test_cli_output_directory_beats_environment(
        self,
        blank_image: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("IOT_HARDWARE_SCANNER_OUTPUT_DIR", str(tmp_path / "from_env"))
        cli_out = tmp_path / "from_cli"
        code, _ = _run(
            ["scan", str(blank_image), "--offline", "--format", "json", "--output", str(cli_out)]
        )
        assert code in (4, 5)
        assert list(cli_out.rglob("report.json"))
        assert not list((tmp_path / "from_env").rglob("report.json"))


class TestAmbientRulesDoNotChangeVerdicts:
    def test_cwd_rules_are_ignored(self, blank_image: Path, tmp_path: Path) -> None:
        """A rule file next to the caller must not change the scan."""
        workdir = tmp_path / "work"
        (workdir / "yara_rules").mkdir(parents=True)
        (workdir / "yara_rules" / "ambient.yar").write_text("rule ambient { condition: true }\n")
        previous = os.getcwd()
        os.chdir(workdir)
        try:
            code, output = _run(["scan", str(blank_image), "--offline"])
        finally:
            os.chdir(previous)
        assert code in (4, 5)
        assert "ambient" not in output


class TestExtractCommand:
    """`extract` decodes an image without analysing it."""

    def test_unsupported_input_is_incomplete_not_a_dependency(self, blank_image: Path) -> None:
        code, output = _run(["extract", str(blank_image)])
        assert code == 4
        assert "not a decodable" in output

    def test_missing_worker_is_exit_5(self, reference_image: Path, tmp_path: Path) -> None:
        code, output = _run(
            ["extract", str(reference_image), "--output", str(tmp_path / "out"), "--worker", "none"]
        )
        assert code == 5
        assert "UNAVAILABLE" in output
