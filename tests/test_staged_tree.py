"""Staged trees (2D): deterministic manifests, declared metadata, no extraction."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.models import InputKind
from iot_hardware_scanner.scanner.firmware_ingest import FirmwareIngest


def make_tree(root: Path) -> Path:
    (root / "etc").mkdir(parents=True)
    (root / "bin").mkdir(parents=True)
    (root / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/ash\n")
    (root / "etc" / "shadow").write_text("root:!$6$salt$hash:19000:0:99999:7:::\n")
    (root / "bin" / "busybox").write_bytes(b"\x7fELF" + b"\x00" * 60)
    return root


@pytest.fixture
def ingest(tmp_path: Path) -> FirmwareIngest:
    return FirmwareIngest(ScannerConfig(output_dir=tmp_path / "out"))


class TestTreeIdentity:
    def test_digest_is_independent_of_enumeration_order(
        self, ingest: FirmwareIngest, tmp_path: Path
    ) -> None:
        first = make_tree(tmp_path / "a")
        second = make_tree(tmp_path / "b")
        # Recreate the same content in a different creation order.
        (second / "zz-last").write_text("x")
        (first / "zz-last").write_text("x")

        one = ingest.ingest_tree(first)
        two = ingest.ingest_tree(second)
        assert one.file_hash_sha256 == two.file_hash_sha256
        assert [entry.relative_path for entry in one.tree_manifest] == [
            entry.relative_path for entry in two.tree_manifest
        ]

    def test_manifest_records_kind_size_and_digest(
        self, ingest: FirmwareIngest, tmp_path: Path
    ) -> None:
        context = ingest.ingest_tree(make_tree(tmp_path / "tree"))
        assert context.input_kind is InputKind.TREE
        assert context.input_manifest_entries == 3
        entries = {entry.relative_path: entry for entry in context.tree_manifest}
        assert entries["etc/passwd"].kind == "file"
        assert entries["etc/passwd"].size > 0
        assert len(entries["etc/passwd"].sha256) == 64
        assert entries["etc/passwd"].metadata_source == "host"
        assert entries["etc/passwd"].mode is not None

    def test_symlinks_are_metadata_not_followed(
        self, ingest: FirmwareIngest, tmp_path: Path
    ) -> None:
        tree = make_tree(tmp_path / "tree")
        (tree / "bin" / "sh").symlink_to("/etc/shadow")
        context = ingest.ingest_tree(tree)
        entry = next(item for item in context.tree_manifest if item.relative_path == "bin/sh")
        assert entry.kind == "symlink"
        assert entry.link_target == "/etc/shadow"

    def test_hardlinks_are_grouped(self, ingest: FirmwareIngest, tmp_path: Path) -> None:
        tree = make_tree(tmp_path / "tree")
        (tree / "bin" / "busybox-copy").hardlink_to(tree / "bin" / "busybox")
        context = ingest.ingest_tree(tree)
        entries = {entry.relative_path: entry for entry in context.tree_manifest}
        assert entries["bin/busybox"].hardlink_group == "bin/busybox"
        assert entries["bin/busybox-copy"].kind == "hardlink"
        assert entries["bin/busybox-copy"].hardlink_group == "bin/busybox"

    def test_empty_tree_is_refused(self, ingest: FirmwareIngest, tmp_path: Path) -> None:
        from iot_hardware_scanner.exceptions import FirmwareEmptyError

        empty = tmp_path / "empty"
        empty.mkdir()
        with pytest.raises(FirmwareEmptyError):
            ingest.ingest_tree(empty)

    def test_a_directory_that_is_not_there_is_exit_3(
        self, ingest: FirmwareIngest, tmp_path: Path
    ) -> None:
        from iot_hardware_scanner.exceptions import FirmwareNotFoundError

        with pytest.raises(FirmwareNotFoundError):
            ingest.ingest_tree(tmp_path / "missing")


class TestDeclaredManifest:
    def test_declared_ownership_overrides_host_metadata(
        self, ingest: FirmwareIngest, tmp_path: Path
    ) -> None:
        tree = make_tree(tmp_path / "tree")
        manifest = tmp_path / "build-manifest.json"
        manifest.write_text(
            json.dumps({"entries": {"/etc/shadow": {"mode": 0o640, "uid": 0, "gid": 0}}})
        )

        context = ingest.ingest_tree(tree, build_manifest=manifest)

        assert context.declared_manifest is not None
        assert context.declared_manifest.entry_count == 1
        assert len(context.declared_manifest.sha256) == 64
        entries = {entry.relative_path: entry for entry in context.tree_manifest}
        assert entries["etc/shadow"].metadata_source == "declared"
        assert entries["etc/shadow"].mode == 0o640
        # A file the declaration does not name keeps its host observation, which
        # the scanner reports as host-derived rather than declared.
        assert entries["etc/passwd"].metadata_source == "host"

    def test_declared_only_and_observed_only_are_stated(
        self, ingest: FirmwareIngest, tmp_path: Path
    ) -> None:
        tree = make_tree(tmp_path / "tree")
        manifest = tmp_path / "build-manifest.json"
        manifest.write_text(
            json.dumps({"entries": {"etc/shadow": {"mode": 0o600}, "etc/absent": {"mode": 0o644}}})
        )
        context = ingest.ingest_tree(tree, build_manifest=manifest)
        declared = context.declared_manifest
        assert declared is not None
        assert declared.declared_only == ["etc/absent"]
        assert set(declared.observed_only) == {"bin/busybox", "etc/passwd"}

    def test_missing_manifest_is_input_error(self, ingest: FirmwareIngest, tmp_path: Path) -> None:
        from iot_hardware_scanner.exceptions import FirmwareNotFoundError

        with pytest.raises(FirmwareNotFoundError):
            ingest.ingest_tree(make_tree(tmp_path / "tree"), build_manifest=tmp_path / "nope.json")

    def test_unreadable_manifest_is_refused(self, ingest: FirmwareIngest, tmp_path: Path) -> None:
        from iot_hardware_scanner.exceptions import FirmwarePathTraversalError

        manifest = tmp_path / "build-manifest.json"
        manifest.write_text("[not, a, mapping]")
        with pytest.raises(FirmwarePathTraversalError):
            ingest.ingest_tree(make_tree(tmp_path / "tree"), build_manifest=manifest)


class TestFilesystemIdentity:
    def test_two_roots_keep_distinguishable_locators(self, tmp_path: Path) -> None:
        from iot_hardware_scanner.scanner.filesystem_scanner import FilesystemScanner

        slot_a = make_tree(tmp_path / "slot_a")
        slot_b = make_tree(tmp_path / "slot_b")
        scanner = FilesystemScanner(ScannerConfig())

        inventory = scanner.scan(slot_a, root_id="slot_a")
        inventory_b = scanner.scan(slot_b, root_id="slot_b")
        inventory.findings.extend(inventory_b.findings)
        inventory.roots.extend(inventory_b.roots)

        locators = sorted(str(finding.path) for finding in inventory.findings)
        assert "slot_a/etc/shadow" in locators
        assert "slot_b/etc/shadow" in locators
        assert len({str(finding.path) for finding in inventory.findings}) == len(locators)
        assert [root.root_id for root in inventory.roots] == ["slot_a", "slot_b"]

    def test_image_metadata_is_used_when_supplied(self, tmp_path: Path) -> None:
        from iot_hardware_scanner.scanner.filesystem_scanner import FilesystemScanner

        tree = make_tree(tmp_path / "rootfs")
        metadata = {
            "etc/shadow": {"mode": 0o640, "uid": 0, "gid": 0, "sha256": "a" * 64},
        }
        inventory = FilesystemScanner(ScannerConfig()).scan(tree, metadata=metadata)

        shadow = next(f for f in inventory.findings if str(f.path).endswith("etc/shadow"))
        assert shadow.metadata_source == "image"
        assert shadow.mode == 0o640
        assert shadow.hash_sha256 == "a" * 64
        assert shadow.permissions == "rw-r-----"
        assert inventory.metadata_source == "image"

    def test_unknown_permission_bits_are_counted(self, tmp_path: Path) -> None:
        from iot_hardware_scanner.scanner.filesystem_scanner import FilesystemScanner

        tree = make_tree(tmp_path / "rootfs")
        # A declared source with no entry for these files: the bits are unknown.
        inventory = FilesystemScanner(ScannerConfig()).scan(
            tree, metadata={"other/file": {"mode": 0o644}}, metadata_source="declared"
        )
        assert inventory.permission_unknown_count == 3
        shadow = next(f for f in inventory.findings if str(f.path).endswith("etc/shadow"))
        assert shadow.permissions == "unknown"
        assert shadow.is_suid is False

    def test_format_comes_from_the_header_not_the_suffix(self, tmp_path: Path) -> None:
        from iot_hardware_scanner.models import FileCategory
        from iot_hardware_scanner.scanner.filesystem_scanner import FilesystemScanner

        tree = tmp_path / "rootfs"
        (tree / "etc").mkdir(parents=True)
        (tree / "etc" / "config.js").write_bytes(b"\x7fELF" + b"\x00" * 60)
        inventory = FilesystemScanner(ScannerConfig()).scan(tree)
        assert inventory.findings[0].format == "elf"
        assert inventory.findings[0].category is FileCategory.CRITICAL_BINARY
