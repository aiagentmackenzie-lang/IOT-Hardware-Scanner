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
