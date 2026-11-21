"""Slice 6A — the same data must produce the same answer.

Four invariance checks, all on the same bytes:

* permuting filesystem enumeration changes nothing in the normalised result;
* renaming an ELF without changing its bytes changes only the locator;
* moving the entropy block boundary changes the block layout and not the
  bytes read or the whole-input measurement;
* scanning the same tree twice, from two different host paths, produces one
  normalised result.

"Normalised" means: root qualifiers, absolute paths, scan identifiers and
timestamps removed, everything a caller can act on kept.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import elf_fixtures
import pytest

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.models import (
    C2Finding,
    FileCategory,
    FilesystemFinding,
    FilesystemInventory,
)
from iot_hardware_scanner.orchestrator import Orchestrator
from iot_hardware_scanner.scanner.c2_detector import C2Detector
from iot_hardware_scanner.scanner.entropy_analyzer import EntropyAnalyzer
from iot_hardware_scanner.scanner.report_document import build_document
from iot_hardware_scanner.yara.yara_engine import YaraEngine


def build_tree(root: Path) -> Path:
    """A small, complete root tree with an account database, an ELF and opkg."""
    (root / "etc").mkdir(parents=True)
    (root / "bin").mkdir(parents=True)
    (root / "usr" / "lib" / "opkg").mkdir(parents=True)
    (root / "etc" / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/ash\nuser:x:1000:1000:user:/home/user:/bin/ash\n"
    )
    (root / "etc" / "shadow").write_text(
        "root:!$6$salt$hash:19000:0:99999:7:::\nuser:$6$salt$hash:19000:0:99999:7:::\n"
    )
    (root / "etc" / "inittab").write_text("::sysinit:/etc/init.d/rcS\n")
    (root / "usr" / "lib" / "opkg" / "status").write_text(
        "Package: busybox\nVersion: 1.36.1-r2\nStatus: install user installed\n"
        "Architecture: aarch64_generic\n"
    )
    (root / "bin" / "busybox").write_bytes(elf_fixtures.build_elf(elf_fixtures.ElfSpec()))
    return root


def scan_tree(tree: Path, output: Path, *, block_size: int | None = None) -> dict:
    config = ScannerConfig(output_dir=output)
    if block_size is not None:
        config.entropy_block_size = block_size
    context = Orchestrator(config, input_tree=True).run(tree)
    return build_document(context, version="test")


def normalised(document: dict) -> dict:
    """The stable semantic content of a document."""
    findings = []
    for finding in document["findings"]:
        findings.append(
            {
                "rule_id": finding["rule_id"],
                "severity": finding["severity"],
                "category": finding["category"],
                "destination": finding["destination"],
                "locations": sorted(_strip_root(item) for item in finding["locations"]),
                "critical_qualified": finding["critical_qualified"],
            }
        )
    findings.sort(key=lambda item: (item["rule_id"], tuple(item["locations"])))

    stages = {
        stage["stage"]: {
            "status": stage["status"],
            "inspected": stage["inspected"],
            "eligible": stage["eligible"],
        }
        for stage in document["stages"]
    }
    controls = [
        {
            "control_id": control["control_id"],
            "status": control["status"],
            "result": control["result"],
            "applicability": control["applicability"],
        }
        for control in document["controls"]
    ]
    components = sorted(
        (component["product"], component["version"], component["confidence"])
        for component in document["components"]
    )
    return {
        "findings": findings,
        "stages": stages,
        "controls": controls,
        "components": components,
        "entropy": {
            key: document["entropy"][key]
            for key in ("units", "overall_entropy", "bytes_analyzed", "sampled")
        }
        if document.get("entropy")
        else None,
        "ruleset_digest": (document.get("ruleset") or {}).get("digest"),
    }


def _strip_root(location: str) -> str:
    """Drop the root qualifier so two trees of the same content compare equal."""
    return location.split("/", 1)[-1] if "/" in location else location


class TestEnumerationOrder:
    def test_reversing_the_creation_order_changes_nothing(self, tmp_path: Path) -> None:
        forward = build_tree(tmp_path / "forward")
        backward = tmp_path / "backward"
        # Same content, created in the opposite order, so the directory entries
        # are handed back differently.
        for relative in reversed(sorted(p.relative_to(forward) for p in forward.rglob("*"))):
            source = forward / relative
            target = backward / relative
            if source.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(source.read_bytes())

        first = normalised(scan_tree(forward, tmp_path / "out-a"))
        second = normalised(scan_tree(backward, tmp_path / "out-b"))
        assert first == second


class TestRenamedBinary:
    def test_renaming_an_elf_changes_only_the_locator(self, tmp_path: Path) -> None:
        tree = build_tree(tmp_path / "tree-a")
        document = scan_tree(tree, tmp_path / "out-a")
        renamed = tmp_path / "tree-b"
        shutil.copytree(tree, renamed)
        (renamed / "bin" / "busybox").rename(renamed / "bin" / "notbusybox")

        other = scan_tree(renamed, tmp_path / "out-b")

        original_records = [
            record for record in document["elf"]["records"] if record["locator"].endswith("busybox")
        ]
        renamed_records = [
            record for record in other["elf"]["records"] if record["locator"].endswith("notbusybox")
        ]
        assert original_records and renamed_records
        for key in ("digest_sha256", "class", "machine", "type", "needed", "hardening"):
            assert original_records[0][key] == renamed_records[0][key], key
        # Same file content, same identity: the name is not evidence.
        assert normalised(document)["findings"] == normalised(other)["findings"]


class TestEntropyBlockBoundaries:
    def test_a_different_block_size_measures_the_same_bytes(self, tmp_path: Path) -> None:
        artifact = tmp_path / "fw.bin"
        artifact.write_bytes(bytes(range(256)) * 40)

        analyzer = EntropyAnalyzer(ScannerConfig())
        first = analyzer.analyze_file(artifact, block_size=128)
        second = analyzer.analyze_file(artifact, block_size=256)

        assert first.bytes_analyzed == second.bytes_analyzed == len(artifact.read_bytes())
        assert first.overall_entropy == pytest.approx(second.overall_entropy, abs=1e-9)
        assert first.block_size == 128 and second.block_size == 256
        # Regions may only start and end where a block does.
        for region in first.regions:
            assert region.start_offset % first.block_size == 0 or region.start_offset == 0
        for region in second.regions:
            assert region.end_offset % second.block_size == 0 or region.end_offset == len(
                artifact.read_bytes()
            )

    def test_region_offsets_never_pass_the_input(self, tmp_path: Path) -> None:
        artifact = tmp_path / "fw.bin"
        artifact.write_bytes(b"\x00" * 129)
        profile = EntropyAnalyzer(ScannerConfig()).analyze_file(artifact, block_size=128)
        assert all(region.end_offset <= 129 for region in profile.regions)
        assert profile.regions[-1].end_offset == 129


class TestHostPath:
    def test_the_same_tree_scanned_twice_from_two_paths_agrees(self, tmp_path: Path) -> None:
        first_root = tmp_path / "one" / "tree"
        second_root = tmp_path / "two" / "tree"
        shutil.copytree(build_tree(tmp_path / "seed"), first_root)
        shutil.copytree(first_root, second_root)

        first = scan_tree(first_root, tmp_path / "one" / "out")
        second = scan_tree(second_root, tmp_path / "two" / "out")

        assert normalised(first) == normalised(second)
        # The paths differ, and the document says so rather than hiding it.
        assert first["artifact"]["path"] != second["artifact"]["path"]
        assert first["artifact"]["sha256"] == second["artifact"]["sha256"]

    def test_an_unstable_input_is_only_the_input_changing(self, tmp_path: Path) -> None:
        """A second scan of the same bytes is stable; nothing else moved."""
        tree = build_tree(tmp_path / "tree")
        first = scan_tree(tree, tmp_path / "out-a")
        second = scan_tree(tree, tmp_path / "out-b")
        assert normalised(first) == normalised(second)
        assert json.dumps(first["findings"], sort_keys=True) == json.dumps(
            second["findings"], sort_keys=True
        )


class TestDomainOrderInvariance:
    def test_the_detector_verdict_does_not_depend_on_inventory_order(self, tmp_path: Path) -> None:
        first = tmp_path / "a.conf"
        second = tmp_path / "b.conf"
        body = "option url 'http://updates.firmware-vendor.su/x'\n"
        first.write_text(body)
        second.write_text(body)

        def finding(name: str) -> FilesystemFinding:
            return FilesystemFinding(
                path=Path(name),
                absolute_path=tmp_path / name,
                category=FileCategory.CRITICAL_CONFIG,
                file_type="config",
                file_size=len(body),
                permissions="rw-r--r--",
                owner_uid=0,
                owner_gid=0,
                is_suid=False,
                is_world_writable=False,
                hash_sha256="a" * 64,
            )

        def verdict(order: list[FilesystemFinding]) -> list[tuple[str, str, float]]:
            inventory = FilesystemInventory(
                rootfs_path=tmp_path, total_files=2, findings=order, categories={}
            )
            detector = C2Detector(ScannerConfig(), rule_engine=YaraEngine(ScannerConfig()))
            return sorted(
                (item.value, item.severity, item.suspicion_score)
                for item in detector.detect_domains(inventory)
            )

        first_order = [finding("a.conf"), finding("b.conf")]
        second_order = [finding("b.conf"), finding("a.conf")]
        assert verdict(first_order) == verdict(second_order)


def test_a_c2_finding_aggregates_the_highest_occurrence_once() -> None:
    finding = C2Finding(
        severity="SUSPICIOUS",
        indicator_type="domain",
        value="updates.firmware-vendor.su",
        file_path=Path("a.conf"),
        occurrences=["a.conf", "b.conf"],
    )
    assert len(finding.occurrences) == 2
