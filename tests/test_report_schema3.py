"""Schema 3: the image-inventory evidence sections and the v2 upgrade path."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from iot_hardware_scanner import __version__
from iot_hardware_scanner.models import (
    ArtifactNode,
    ElfReport,
    FilesystemInventory,
    FirmwareSizeCategory,
    ImageMap,
    InputKind,
    InputSnapshot,
    OpkgInventory,
    OpkgPackageRecord,
    ScanContext,
)
from iot_hardware_scanner.scanner.report_document import (
    SCHEMA_VERSION,
    build_document,
    load_document,
    render,
)


@pytest.fixture
def context(tmp_path: Path) -> ScanContext:
    return ScanContext(
        scan_id="scan-3",
        firmware_path=tmp_path / "rootfs.img.gz",
        output_dir=tmp_path / "out",
        file_hash_sha256="8b5a" + "0" * 60,
        file_hash_md5="b" * 32,
        file_size=4_451_127,
        file_type="gzip compressed data",
        firmware_name="rootfs.img.gz",
        size_category=FirmwareSizeCategory.SMALL,
        started_at=datetime.now(tz=timezone.utc),
    )


def populate(context: ScanContext) -> None:
    """Attach the evidence a completed image scan records."""
    context.input_snapshot = InputSnapshot(
        original_path=context.firmware_path,
        snapshot_path=context.output_dir / "input" / "rootfs.img.gz",
        declared_sha256=context.file_hash_sha256,
        verified_sha256=context.file_hash_sha256,
        size=context.file_size,
        budget_bytes=4096,
        immutable=True,
        source_reverified=True,
    )
    context.image_map = ImageMap(
        root_artifact_id="a0",
        nodes=[
            ArtifactNode(
                artifact_id="a0",
                parent_id=None,
                digest_sha256=context.file_hash_sha256,
                format="gzip",
                coordinate_system="container-bytes",
                length=context.file_size,
                decoder="python-zlib",
                decoder_version="1.2.12",
                locator="rootfs.img.gz",
            ),
            ArtifactNode(
                artifact_id="a1",
                parent_id="a0",
                digest_sha256="c" * 64,
                format="squashfs",
                coordinate_system="container-bytes",
                length=109_051_904,
                decoder="unsquashfs",
                decoder_version="unsquashfs version 4.5.1",
                depth=1,
                expanded_bytes=109_051_904,
                extent_bytes=4_348_264,
                details={"superblock": {"bytes_used": 4_348_264, "block_size": 262144}},
            ),
        ],
    )
    context.filesystem_inventory = FilesystemInventory(
        rootfs_path=Path("/tmp/rootfs"),
        total_files=1283,
        total_directories=110,
        total_size=18_403_184,
        metadata_source="image",
    )
    context.elf_metadata = [
        ElfReport(
            locator="rootfs/bin/busybox",
            digest_sha256="214a261c08545de6aa734442495f722fbe3ba71a0a9083cd010927f3c3ba696c",
            size=458_773,
            elf_class="ELF64",
            byte_order="little",
            machine=183,
            machine_name="AArch64",
            elf_type="EXEC",
            interpreter="/lib/ld-musl-aarch64.so.1",
            needed=["libc.so"],
            stack_executable=False,
            pie=False,
            relro="full",
            unknown=["no symbol table is present"],
            parser_version="0.33",
        )
    ]
    context.opkg_inventory = OpkgInventory(
        locator="rootfs/usr/lib/opkg/status",
        database_sha256="9442acbaf4ccc25115e770533ffe2b8a10d1c81e92d59b6d32035ba5ee6a3258",
        byte_length=45_527,
        records=[
            OpkgPackageRecord(
                name="busybox",
                version="1.36.1-r2",
                architecture="aarch64_generic",
                status="install user installed",
                installed=True,
                held=False,
                evidence_start=2804,
                evidence_end=3095,
                evidence_line=102,
            )
        ],
        installed_count=196,
        held_count=4,
    )


class TestSchemaThree:
    def test_version_is_three(self, context: ScanContext) -> None:
        document = build_document(context, version=__version__)
        assert document["schema_version"] == SCHEMA_VERSION == 3

    def test_image_map_keeps_the_three_sizes_apart(self, context: ScanContext) -> None:
        populate(context)
        document = build_document(context, version=__version__)
        nodes = document["image_map"]["nodes"]
        assert [node["format"] for node in nodes] == ["gzip", "squashfs"]
        assert nodes[1]["expanded_bytes"] == 109_051_904
        assert nodes[1]["extent_bytes"] == 4_348_264
        assert nodes[0]["length"] == 4_451_127
        assert nodes[1]["coordinate_system"] == "container-bytes"

    def test_elf_records_state_what_stayed_unknown(self, context: ScanContext) -> None:
        populate(context)
        document = build_document(context, version=__version__)
        record = document["elf"]["records"][0]
        assert record["machine"] == 183
        assert record["machine_name"] == "AArch64"
        assert record["hardening"]["canary"] is None
        assert record["unknown"]

    def test_opkg_records_carry_their_evidence_range(self, context: ScanContext) -> None:
        populate(context)
        document = build_document(context, version=__version__)
        assert document["opkg"]["installed"] == 196
        assert document["opkg"]["held"] == 4
        record = document["opkg"]["records"][0]
        assert record["version"] == "1.36.1-r2"
        assert record["evidence"] == {"start": 2804, "end": 3095, "line": 102}

    def test_input_binding_is_recorded(self, context: ScanContext) -> None:
        populate(context)
        document = build_document(context, version=__version__)
        binding = document["input_binding"]
        assert binding["digest_matches"] is True
        assert binding["source_changed"] is False
        assert binding["immutable"] is True

    def test_renderers_show_the_inventory_evidence(self, context: ScanContext) -> None:
        populate(context)
        document = build_document(context, version=__version__)

        terminal = render(document, "terminal")
        assert "busybox" in terminal or "Packages: 196 installed" in terminal
        assert "4,451,127" in terminal

        markdown = render(document, "markdown")
        assert "## Installed packages" in markdown
        assert "1.36.1-r2" in markdown
        assert "## Image map" in markdown
        assert "214a261c08545de6aa734442495f722fbe3ba71a0a9083cd010927f3c3ba696c" in markdown

        html = render(document, "html")
        assert "1.36.1-r2" in html
        assert "Image map" in html
        # Nothing firmware-derived reaches the markup unescaped.
        assert "<script>" not in html


class TestStagedTreeSections:
    def test_tree_manifest_and_declaration_are_rendered(self, context: ScanContext) -> None:
        from iot_hardware_scanner.models import TreeManifestEntry

        context.input_kind = InputKind.TREE
        context.tree_manifest = [
            TreeManifestEntry(
                relative_path="etc/shadow",
                kind="file",
                size=42,
                sha256="d" * 64,
                mode=0o640,
                uid=0,
                gid=0,
                metadata_source="declared",
            )
        ]
        context.tree_changes = ["etc/shadow: changed while being catalogued"]
        document = build_document(context, version=__version__)
        assert document["tree"]["entries"] == 1
        assert document["tree"]["by_kind"] == {"file": 1}
        assert document["tree"]["changes_during_traversal"]

        markdown = render(document, "markdown")
        assert "## Staged tree" in markdown
        assert "changed while being catalogued" in markdown


class TestVersionTwoUpgrade:
    def test_a_v2_document_keeps_its_facts_and_admits_the_gap(self) -> None:
        v2 = {
            "schema_version": 2,
            "tool": {"name": "iot-hardware-scanner", "version": "2.0.0"},
            "scan_id": "old-scan",
            "artifact": {"name": "fw.bin", "sha256": "a" * 64, "kind": "file"},
            "assessment": {"profile": "firmware-static", "completion": "INCOMPLETE"},
            "stages": [{"stage": "extraction", "status": "UNAVAILABLE"}],
            "controls": [],
            "findings": [
                {
                    "rule_id": "credential.regex.password",
                    "severity": "HIGH",
                    "title": "Password finding",
                    "description": "",
                    "category": "password",
                    "locations": ["etc/config"],
                    "evidence": [],
                    "critical_qualified": False,
                }
            ],
            "components": [],
            "risk_score": None,
        }

        document = load_document(v2)

        assert document["schema_version"] == 3
        assert document["findings"] == v2["findings"]
        assert document["stages"] == v2["stages"]
        assert document["migration"]["from"] == 2
        # Not recorded, and said so -- not silently empty.
        for section in ("image_map", "extraction", "input_binding", "opkg", "tree"):
            assert document[section] is None
        assert document["elf"]["records"] == []

        rendered = render(document, "markdown")
        assert "credential.regex.password" in rendered

    def test_a_v3_document_round_trips(self, context: ScanContext) -> None:
        populate(context)
        document = build_document(context, version=__version__)
        again = load_document(json.loads(render(document, "json")))
        assert again["schema_version"] == 3
        assert again["opkg"]["installed"] == 196
        assert again["image_map"]["nodes"][1]["extent_bytes"] == 4_348_264
