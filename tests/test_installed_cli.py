"""1A — the acceptance harness runs the *installed* product, not the checkout.

Two execution modes, chosen automatically:

``IHS_INSTALLED_CLI`` set
    The path to a console script installed from the built wheel in a clean
    environment. This is what CI uses, and it is the only mode that proves the
    wheel contains its rules and data.

otherwise
    The package is copied out of the checkout into a temporary site directory
    and run with ``python -m iot_hardware_scanner`` and ``PYTHONPATH`` pointing
    there. That still proves the import path and resource loading do not depend
    on the source tree, but it does not prove wheel packaging. A separate test
    (:class:`TestWheelContents`) checks the wheel directly when one was built.

Neither mode reaches the network: every scan passes ``--offline`` and the
fixtures are generated locally.
"""

from __future__ import annotations

import json
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import REPO_ROOT, Runner, make_tree

from iot_hardware_scanner import __version__
from iot_hardware_scanner.scanner.report_document import SCHEMA_VERSION

PASSWD = "root:x:0:0:root:/root:/bin/ash\nuser:x:1000:1000:user:/home/user:/bin/ash\n"
SHADOW_LOCKED = "root:!$6$salt$hash:19000:0:99999:7:::\nuser:$6$salt$hash:19000:0:99999:7:::\n"


class TestObservedFailuresStayFixed:
    """The three v1 observations, re-run through the installed entrypoints."""

    def test_blank_image_writes_the_requested_file_and_does_not_grade(
        self, runner: Runner, tmp_path: Path
    ) -> None:
        work = tmp_path / "work"
        work.mkdir()
        (work / "blank.bin").write_bytes(b"\x00" * 4096)

        result = runner(
            [
                "scan",
                "blank.bin",
                "--offline",
                "--format",
                "json",
                "--out",
                "requested.json",
            ],
            cwd=work,
        )

        assert (work / "requested.json").is_file(), result.stderr
        assert result.returncode != 0, "an unanalysed image must not report success"
        document = json.loads((work / "requested.json").read_text())
        assert document["assessment"]["completion"] == "INCOMPLETE"
        assert document["risk_score"] is None
        assert "/100" not in result.stdout

    def test_replay_keeps_the_finding(self, runner: Runner, tmp_path: Path) -> None:
        legacy = {
            "scan_id": "legacy",
            "scan_date": "2025-01-01T00:00:00+00:00",
            "firmware": {"name": "fw", "path": "fw.bin", "sha256": "a" * 64, "size": 1},
            "credentials": {
                "total": 1,
                "findings": [
                    {
                        "severity": "HIGH",
                        "category": "password",
                        "file_path": "etc/config",
                        "masked_value": "****",
                    }
                ],
            },
            "risk_score": {"total_score": 81.0, "risk_level": "MEDIUM"},
        }
        source = tmp_path / "legacy.json"
        source.write_text(json.dumps(legacy))
        before = source.read_bytes()

        result = runner(
            ["report", "legacy.json", "--format", "json", "--out", "replayed.json"],
            cwd=tmp_path,
        )

        assert result.returncode == 0, result.stderr
        assert source.read_bytes() == before
        replayed = json.loads((tmp_path / "replayed.json").read_text())
        assert len(replayed["findings"]) == 1
        assert replayed["legacy_grade"]["total_score"] == 81.0

    def test_entropy_of_constant_bytes_is_zero(self, runner: Runner, tmp_path: Path) -> None:
        (tmp_path / "flat.bin").write_bytes(b"\x41" * 256)
        result = runner(["entropy", "flat.bin", "--format", "json"], cwd=tmp_path)
        assert result.returncode == 0, result.stderr
        payload = json.loads(result.stdout)
        assert payload["overall_entropy"] == 0.0
        assert payload["units"] == "bits/byte"


class TestBothEntrypoints:
    def test_module_entrypoint_prints_version(self, runner: Runner, tmp_path: Path) -> None:
        result = runner(["--version"], cwd=tmp_path)
        assert result.returncode == 0
        assert __version__ in result.stdout

    def test_credentials_profile_runs_end_to_end(self, runner: Runner, tmp_path: Path) -> None:
        tree = make_tree(tmp_path / "rootfs", SHADOW_LOCKED)
        result = runner(["scan", str(tree), "--creds"], cwd=tmp_path)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "COMPLETE" in result.stdout

    def test_openwrt_image_is_identified_and_reported_incomplete(
        self, runner: Runner, reference_image: Path, tmp_path: Path
    ) -> None:
        """The release gate: real image, backend absent, honest result."""
        destination = tmp_path / "openwrt.json"
        result = runner(
            [
                "scan",
                str(reference_image),
                "--offline",
                "--format",
                "json",
                "--out",
                str(destination),
                # Turn the worker off explicitly: this is the partial-report case
                # that must keep working, and it must name the dependency.
                "--worker",
                "none",
            ],
            cwd=tmp_path,
        )

        assert destination.is_file(), result.stderr
        assert result.returncode == 5, result.stdout
        document = json.loads(destination.read_text())
        assert (
            document["artifact"]["sha256"]
            == "8b5aa82659cafd90b26333dd419a0df9ad63c517ad94a2159e970a5bb5b6ff02"
        )
        assert document["assessment"]["completion"] == "INCOMPLETE"
        assert document["findings"] == []
        assert document["risk_score"] is None


class TestResourcesComeFromThePackage:
    def test_bundled_data_loads_without_a_source_tree(self, runner: Runner, tmp_path: Path) -> None:
        """Nothing may be loaded from the checkout or the working directory."""
        # A decoy data directory beside the working directory must be ignored.
        decoy = tmp_path / "data"
        decoy.mkdir()
        (decoy / "default_credentials.json").write_text('{"credentials": []}')

        tree = make_tree(tmp_path / "r", SHADOW_LOCKED)
        result = runner(["scan", str(tree), "--creds"], cwd=tmp_path)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "default_credentials" not in result.stdout

    def test_scan_records_the_data_it_loaded(self, runner: Runner, tmp_path: Path) -> None:
        destination = tmp_path / "doc.json"
        (tmp_path / "fw.bin").write_bytes(b"\x00" * 64)
        result = runner(
            ["scan", "fw.bin", "--offline", "--format", "json", "--out", str(destination)],
            cwd=tmp_path,
        )
        assert destination.is_file(), result.stderr
        names = {entry["name"] for entry in json.loads(destination.read_text())["data_sources"]}
        assert "kev_catalog.json" in names
        assert "default_credentials.json" in names


@pytest.fixture(scope="module")
def wheel() -> Path:
    """The most recently built wheel, if any."""
    wheels = sorted((REPO_ROOT / "dist").glob("iot_hardware_scanner-*.whl"))
    if not wheels:
        pytest.skip("no wheel in dist/ — run `uv build` (CI builds one)")
    return wheels[-1]


class TestWheelContents:
    """Packaging regression: the wheel must carry its rules and data."""

    def test_data_files_ship(self, wheel: Path) -> None:
        with zipfile.ZipFile(wheel) as archive:
            names = archive.namelist()
        for expected in (
            "iot_hardware_scanner/data/default_credentials.json",
            "iot_hardware_scanner/data/kev_catalog.json",
            "iot_hardware_scanner/data/component_cpe_map.json",
            "iot_hardware_scanner/data/benign_domains.txt",
            "iot_hardware_scanner/data/suspicious_tlds.txt",
            "iot_hardware_scanner/data/domain_suffixes.txt",
            "iot_hardware_scanner/data/threat_intel_sample.jsonl",
        ):
            assert expected in names, expected

    def test_yara_rules_ship(self, wheel: Path) -> None:
        with zipfile.ZipFile(wheel) as archive:
            rules = [n for n in archive.namelist() if n.endswith(".yar")]
        assert len(rules) >= 12

    def test_no_unresolvable_extra_is_advertised(self, wheel: Path) -> None:
        """An extra that cannot be installed must not be advertised.

        ``pybinwalk`` has no release satisfying ``>=3.0``, so there is no
        ``extraction`` extra. ``sbom`` is advertised again — deliberately — now
        that ``iot-hardware-scanner sbom --validate`` exists and needs
        ``jsonschema``; it is re-added only with a working export path.
        """
        with zipfile.ZipFile(wheel) as archive:
            metadata = next(
                archive.read(n).decode() for n in archive.namelist() if n.endswith("METADATA")
            )
        extras = [
            line.split(":", 1)[1].strip().lower()
            for line in metadata.splitlines()
            if line.startswith("Provides-Extra:")
        ]
        assert "extraction" not in extras
        assert "sbom" in extras
        assert "nvd" in extras
        assert "yaml-support" in extras


# ──────────────────────────────────────────────
# Slice 3D — the boot-manifest profile, through the installed wheel
# ──────────────────────────────────────────────


class TestBootManifestProfile:
    """A DTB or FIT is accepted, parsed and reported without a container."""

    @staticmethod
    def _scan(runner: Runner, work: Path, name: str, data: bytes, *extra: str):
        (work / name).write_bytes(data)
        report = work / f"{name}.json"
        result = runner(
            [
                "scan",
                name,
                "--offline",
                "--format",
                "json",
                "--out",
                report.name,
                *extra,
            ],
            cwd=work,
        )
        assert report.is_file(), result.stderr
        return result, json.loads(report.read_text())

    def test_a_fit_dtb_pair_resolves_kernel_and_device_tree(
        self, runner: Runner, tmp_path: Path
    ) -> None:
        from fdt_fixtures import build_fit

        from iot_hardware_scanner.models import StageId

        fixture = build_fit()
        result, document = self._scan(
            runner, tmp_path, "board.itb", fixture.data, "--profile", "firmware-boot"
        )

        assert result.returncode == 0, result.stdout + result.stderr
        assert document["assessment"]["profile"] == "firmware-boot"
        assert document["assessment"]["completion"] == "COMPLETE"
        assert document["artifact"]["kind"] == "boot"
        artifact = document["boot"]["artifacts"][0]
        assert artifact["kind"] == "fit"
        assert artifact["default_config"] == "config-1"
        configuration = artifact["configurations"][0]
        assert (configuration["kernel"], configuration["fdt"]) == ("kernel-1", "fdt-1")
        payloads = {item["kind"]: item for item in artifact["referenced_payloads"]}
        assert payloads["kernel"]["integrity"] == "match"
        assert payloads["fdt"]["integrity"] == "match"
        assert payloads["fdt"]["board"]["compatible"] == ["test,board", "test,soc"]
        assert payloads["fdt"]["board"]["partitions"][0]["label"] == "firmware"
        assert artifact["boot_enforcement"] == "unknown"
        stages = {stage["stage"]: stage for stage in document["stages"]}
        assert stages[StageId.OPKG_INVENTORY.value]["status"] == "NOT_APPLICABLE"
        assert stages[StageId.EXTRACTION.value]["status"] == "NOT_APPLICABLE"
        assert document["schema_version"] == SCHEMA_VERSION

    def test_a_mismatched_payload_is_a_reportable_observation(
        self, runner: Runner, tmp_path: Path
    ) -> None:
        from fdt_fixtures import build_fit

        fixture = build_fit(declare_wrong_hash=True)
        result, document = self._scan(
            runner, tmp_path, "bad-hash.itb", fixture.data, "--profile", "firmware-boot"
        )

        assert result.returncode == 2, result.stdout + result.stderr
        finding = next(
            item for item in document["findings"] if item["rule_id"] == "boot.payload_integrity"
        )
        assert finding["severity"] == "HIGH"
        assert finding["critical_qualified"] is False
        payload = next(
            item
            for item in document["boot"]["artifacts"][0]["referenced_payloads"]
            if item["kind"] == "fdt"
        )
        assert payload["integrity"] == "mismatch"
        control = next(c for c in document["controls"] if c["control_id"] == 5)
        assert control["result"] == "FAIL"

    def test_an_absent_key_leaves_signature_presence_but_not_verification(
        self, runner: Runner, tmp_path: Path
    ) -> None:
        from fdt_fixtures import build_fit

        fixture = build_fit(sign_config="config-1")
        result, document = self._scan(
            runner, tmp_path, "signed.itb", fixture.data, "--profile", "firmware-boot"
        )

        assert result.returncode == 0, result.stdout + result.stderr
        signature = document["boot"]["artifacts"][0]["configurations"][0]["signature"]
        assert signature["present"] is True
        assert signature["verified"] is None
        assert signature["key_source"] == "none"
        control = next(c for c in document["controls"] if c["control_id"] == 5)
        assert control["status"] == "PERFORMED"
        assert control["result"] == "REVIEW"
        assert any("not verified" in item for item in control["evidence"])

    def test_a_supplied_key_verifies_only_the_selected_configuration(
        self, runner: Runner, tmp_path: Path
    ) -> None:
        from fdt_fixtures import build_fit, public_key_pem

        (tmp_path / "operator-key.pem").write_bytes(public_key_pem())
        fixture = build_fit(sign_config="config-1")
        result, document = self._scan(
            runner,
            tmp_path,
            "signed-key.itb",
            fixture.data,
            "--profile",
            "firmware-boot",
            "--trust-anchor",
            "operator-key.pem",
        )

        assert result.returncode == 0, result.stdout + result.stderr
        signature = document["boot"]["artifacts"][0]["configurations"][0]["signature"]
        assert signature["verified"] is True
        assert signature["key_source"] == "operator-supplied"
        control = next(c for c in document["controls"] if c["control_id"] == 5)
        assert control["status"] == "PERFORMED"
        assert any("verifies with the supplied key" in item for item in control["evidence"])
        secure_boot = next(c for c in document["controls"] if c["control_id"] == 6)
        assert secure_boot["status"] == "INCONCLUSIVE"
        assert secure_boot["result"] == "UNKNOWN"

    def test_a_signature_over_another_configuration_is_not_promoted(
        self, runner: Runner, tmp_path: Path
    ) -> None:
        from fdt_fixtures import build_fit, public_key_pem

        (tmp_path / "operator-key.pem").write_bytes(public_key_pem())
        fixture = build_fit(sign_config="config-2", extra_configurations=["config-2"])
        _result, document = self._scan(
            runner,
            tmp_path,
            "other-config.itb",
            fixture.data,
            "--profile",
            "firmware-boot",
            "--trust-anchor",
            "operator-key.pem",
        )

        configurations = {
            item["name"]: item for item in document["boot"]["artifacts"][0]["configurations"]
        }
        assert configurations["config-1"]["signature"]["present"] is False
        assert configurations["config-1"]["signature"]["verified"] is None
        assert configurations["config-2"]["signature"]["verified"] is True
        control = next(c for c in document["controls"] if c["control_id"] == 5)
        assert not any("verifies with the supplied key" in item for item in control["evidence"])

    def test_a_truncated_artifact_is_incomplete_not_a_finding(
        self, runner: Runner, tmp_path: Path
    ) -> None:
        from fdt_fixtures import build_fit

        fixture = build_fit(truncated=200)
        result, document = self._scan(
            runner, tmp_path, "truncated.itb", fixture.data, "--profile", "firmware-boot"
        )

        assert result.returncode == 4, result.stdout + result.stderr
        assert document["assessment"]["completion"] == "INCOMPLETE"
        stage = next(item for item in document["stages"] if item["stage"] == "boot_analysis")
        assert stage["status"] == "FAILED"
        assert document["boot"] is None
        assert document["findings"] == []

    def test_an_out_of_bounds_payload_range_is_incomplete(
        self, runner: Runner, tmp_path: Path
    ) -> None:
        from fdt_fixtures import build_fit

        fixture = build_fit(out_of_bounds=True)
        result, document = self._scan(
            runner, tmp_path, "oob.itb", fixture.data, "--profile", "firmware-boot"
        )

        assert result.returncode == 4, result.stdout + result.stderr
        stage = next(item for item in document["stages"] if item["stage"] == "boot_analysis")
        assert stage["status"] == "PARTIAL"
        payload = next(
            item
            for item in document["boot"]["artifacts"][0]["referenced_payloads"]
            if item["kind"] == "fdt"
        )
        assert payload["integrity"] == "out-of-bounds"

    def test_deep_nesting_is_rejected(self, runner: Runner, tmp_path: Path) -> None:
        from fdt_fixtures import Node, build_fdt

        root = Node("")
        current = root
        for index in range(40):
            child = Node(f"level{index}")
            current.child(child)
            current = child
        result, document = self._scan(
            runner,
            tmp_path,
            "deep.dtb",
            build_fdt(root),
            "--profile",
            "firmware-boot",
        )

        assert result.returncode == 4, result.stdout + result.stderr
        stage = next(item for item in document["stages"] if item["stage"] == "boot_analysis")
        assert stage["status"] == "FAILED"
        assert "nesting deeper" in stage["reason"]

    def test_a_plain_device_tree_is_recognised_and_unknown_default_is_not_guessed(
        self, runner: Runner, tmp_path: Path
    ) -> None:
        from fdt_fixtures import board_dtb

        result, document = self._scan(runner, tmp_path, "board.dtb", board_dtb())

        assert result.returncode == 0, result.stdout + result.stderr
        assert document["assessment"]["profile"] == "firmware-boot"
        artifact = document["boot"]["artifacts"][0]
        assert artifact["kind"] == "dtb"
        assert artifact["default_config"] is None
        assert artifact["compatible"] == ["test,board", "test,soc"]
        assert artifact["boot_enforcement"] == "unknown"
        assert document["findings"] == []

    def test_the_magic_selects_the_profile_without_a_flag(
        self, runner: Runner, tmp_path: Path
    ) -> None:
        from fdt_fixtures import build_fit

        fixture = build_fit()
        result, document = self._scan(runner, tmp_path, "auto.itb", fixture.data)

        assert result.returncode == 0, result.stdout + result.stderr
        assert document["assessment"]["profile"] == "firmware-boot"
        assert document["artifact"]["kind"] == "boot"


# ──────────────────────────────────────────────
# Slice 5C — repeated work, measured and cached
# ──────────────────────────────────────────────


def _stable(document: dict) -> dict:
    """Drop run-specific values, keeping every semantic fact."""
    volatile = {
        "scan_id",
        "scan_date",
        "report_generated",
        "cache",
        "started_at",
        "completed_at",
    }

    def scrub(value):
        if isinstance(value, dict):
            return {
                key: scrub(item)
                for key, item in value.items()
                if key not in volatile and not key.endswith("_path")
            }
        if isinstance(value, list):
            return [scrub(item) for item in value]
        return value

    return scrub(document)


class TestRepeatedWorkCache:
    """Cold and warm runs must produce the same report, from a bounded cache."""

    @staticmethod
    def _tree(root: Path) -> Path:
        from harness import make_tree

        make_tree(root, SHADOW_LOCKED)
        config = root / "etc" / "config"
        config.mkdir(parents=True)
        (config / "app.conf").write_text(
            'password = "Sup3rS3cretV4lue123!"\nserver = evil.example.com\n'
        )
        return root

    def test_a_warm_run_reproduces_the_cold_report(self, runner: Runner, tmp_path: Path) -> None:
        tree = self._tree(tmp_path / "rootfs")
        cache = tmp_path / "cache"

        def scan(name: str) -> tuple[int, dict]:
            report = tmp_path / name
            result = runner(
                [
                    "scan",
                    str(tree),
                    "--input-tree",
                    "--offline",
                    "--cache-dir",
                    str(cache),
                    "--format",
                    "json",
                    "--out",
                    str(report),
                ],
                cwd=tmp_path,
            )
            return result.returncode, json.loads(report.read_text())

        cold_code, cold = scan("cold.json")
        warm_code, warm = scan("warm.json")

        assert cold_code == warm_code
        assert _stable(cold) == _stable(warm)
        assert cold["cache"]["misses"] > 0
        assert warm["cache"]["misses"] == 0
        assert warm["cache"]["hits"] > 0
        assert warm["cache"]["writes"] == 0
        assert warm["cache"]["entries"] == cold["cache"]["entries"]

    def test_a_ruleset_change_invalidates_its_dependents(
        self, runner: Runner, tmp_path: Path
    ) -> None:
        tree = self._tree(tmp_path / "rootfs")
        (tree / "etc" / "config" / "app.conf").write_text("marker uniquemarker12345\n")
        cache = tmp_path / "cache"
        rules = tmp_path / "rules"
        rules.mkdir()
        (rules / "added.yar").write_text(
            "rule added_indicator {\n"
            "  meta:\n"
            '    category = "c2_indicator"\n'
            '    severity = "MEDIUM"\n'
            "  strings:\n"
            '    $a = "uniquemarker12345" ascii\n'
            "  condition:\n"
            "    $a\n"
            "}\n"
        )

        def scan(name: str) -> dict:
            report = tmp_path / name
            result = runner(
                [
                    "scan",
                    str(tree),
                    "--input-tree",
                    "--offline",
                    "--cache-dir",
                    str(cache),
                    "--yara-rules",
                    str(rules),
                    "--format",
                    "json",
                    "--out",
                    str(report),
                ],
                cwd=tmp_path,
            )
            assert report.is_file(), result.stderr
            return json.loads(report.read_text())

        first = scan("first.json")
        assert any(finding["rule_id"] == "c2.yara.added_indicator" for finding in first["findings"])
        # The rule set changed, so rule-match entries are re-derived; the
        # extractor identity did not change, so text-fact entries still hit.
        assert first["cache"]["misses"] > 0

        second = scan("second.json")
        assert second["cache"]["misses"] == 0
        assert second["cache"]["hits"] > 0
        assert any(
            finding["rule_id"] == "c2.yara.added_indicator" for finding in second["findings"]
        )
        assert _stable(first) == _stable(second)
