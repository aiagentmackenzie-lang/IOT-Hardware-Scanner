"""Extraction worker (2A): budgets, naming, states and scratch release."""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

import pytest

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.models import (
    EXTRACTION_CORRUPT,
    EXTRACTION_NO_ISOLATION,
    EXTRACTION_QUOTA,
    EXTRACTION_UNAVAILABLE,
)
from iot_hardware_scanner.scanner.bounded_reader import BoundedReadLimitError
from iot_hardware_scanner.scanner.extraction_worker import (
    ExtractedTree,
    ExtractionError,
    SquashfsWorker,
    _normalise_member,
    _safe_member_name,
    is_incomplete,
)


def make_tar(entries: dict[str, bytes | None], *, linknames: dict[str, str] | None = None) -> bytes:
    """Build a tar stream in memory: ``None`` means a symlink member."""
    buffer = io.BytesIO()
    linknames = linknames or {}
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, payload in entries.items():
            info = tarfile.TarInfo(name)
            if payload is None:
                info.type = tarfile.SYMTYPE
                info.linkname = linknames.get(name, "/etc/shadow")
                archive.addfile(info)
                continue
            info.size = len(payload)
            info.mode = 0o755
            info.uid = 0
            info.gid = 0
            archive.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


@pytest.fixture
def worker(tmp_path: Path) -> SquashfsWorker:
    return SquashfsWorker(ScannerConfig(output_dir=tmp_path))


class TestRuntimeSelection:
    def test_disabled_worker_is_a_missing_dependency(self, tmp_path: Path) -> None:
        worker = SquashfsWorker(ScannerConfig(output_dir=tmp_path, extraction_worker="none"))
        with pytest.raises(ExtractionError) as excinfo:
            worker.select_runtime()
        assert excinfo.value.state == EXTRACTION_UNAVAILABLE
        assert "disabled" in excinfo.value.message

    def test_absent_runtime_is_a_missing_dependency(self, tmp_path: Path) -> None:
        worker = SquashfsWorker(ScannerConfig(output_dir=tmp_path, extraction_worker="podman"))
        with pytest.raises(ExtractionError) as excinfo:
            worker.select_runtime()
        # Either podman is absent or its daemon is unreachable: both are a
        # dependency the operator must supply.
        assert excinfo.value.state == EXTRACTION_UNAVAILABLE

    def test_host_process_needs_isolation_permission(self, tmp_path: Path) -> None:
        worker = SquashfsWorker(
            ScannerConfig(output_dir=tmp_path, extraction_worker="host-process")
        )
        with pytest.raises(ExtractionError) as excinfo:
            worker.select_runtime()
        assert excinfo.value.state in (EXTRACTION_NO_ISOLATION, EXTRACTION_UNAVAILABLE)


class TestNameSafety:
    @pytest.mark.parametrize(
        "name",
        ["rootfs/etc/passwd", "usr/lib/opkg/status", "bin/busybox", "./etc/hosts"],
    )
    def test_ordinary_names_are_accepted(self, name: str) -> None:
        assert _safe_member_name(_normalise_member(name))

    @pytest.mark.parametrize(
        "name",
        ["/etc/shadow", "../escape", "a/../../escape", "~/secret", "\\windows"],
    )
    def test_escaping_names_are_refused(self, name: str) -> None:
        assert not _safe_member_name(_normalise_member(name))

    def test_leading_dot_slash_is_normalised(self) -> None:
        assert _normalise_member("./usr/bin/app") == "usr/bin/app"
        assert _normalise_member(".") == ""


class TestTarCollection:
    def test_files_are_written_with_a_manifest(
        self, worker: SquashfsWorker, tmp_path: Path
    ) -> None:
        rootfs = tmp_path / "rootfs"
        tree = ExtractedTree()
        stream = io.BytesIO(make_tar({"etc/passwd": b"root:x:0:0\n", "bin/app": b"\x7fELF"}))
        worker._collect_tar(stream, rootfs, tree, budget=1 << 20)

        assert (rootfs / "etc" / "passwd").read_bytes() == b"root:x:0:0\n"
        assert tree.file_count == 2
        assert {entry["path"] for entry in tree.entries} == {"etc/passwd", "bin/app"}
        assert all(entry["sha256"] for entry in tree.entries)

    def test_symlinks_are_metadata_and_never_created(
        self, worker: SquashfsWorker, tmp_path: Path
    ) -> None:
        rootfs = tmp_path / "rootfs"
        tree = ExtractedTree()
        stream = io.BytesIO(make_tar({"bin/sh": None, "bin/busybox": b"x"}))
        worker._collect_tar(stream, rootfs, tree, budget=1 << 20)

        assert not (rootfs / "bin" / "sh").exists()
        symlink = next(entry for entry in tree.entries if entry["kind"] == "symlink")
        assert symlink["link_target"] == "/etc/shadow"
        assert tree.skipped["symlink"] == 1
        assert any("metadata only" in omission for omission in tree.omissions)

    def test_escaping_member_is_refused(self, worker: SquashfsWorker, tmp_path: Path) -> None:
        rootfs = tmp_path / "rootfs"
        tree = ExtractedTree()
        stream = io.BytesIO(make_tar({"../escape": b"x"}))
        with pytest.raises(ExtractionError) as excinfo:
            worker._collect_tar(stream, rootfs, tree, budget=1 << 20)
        assert excinfo.value.state == EXTRACTION_CORRUPT
        assert not (tmp_path / "escape").exists()

    def test_entry_budget_is_enforced(self, tmp_path: Path) -> None:
        worker = SquashfsWorker(ScannerConfig(output_dir=tmp_path, max_extracted_entries=2))
        tree = ExtractedTree()
        stream = io.BytesIO(make_tar({"a": b"1", "b": b"2", "c": b"3"}))
        with pytest.raises(ExtractionError) as excinfo:
            worker._collect_tar(stream, tmp_path / "rootfs", tree, budget=1 << 20)
        assert excinfo.value.state == EXTRACTION_QUOTA

    def test_member_larger_than_the_budget_is_refused(
        self, worker: SquashfsWorker, tmp_path: Path
    ) -> None:
        """A member that declares more than the budget is refused by name."""
        tree = ExtractedTree()
        stream = io.BytesIO(make_tar({"big": b"z" * 4096}))
        # The stream itself is bounded first, so a hostile declaring size is
        # caught either by the per-member check or by the stream budget; both
        # mean "over budget" and both must stop the extraction.
        with pytest.raises((ExtractionError, BoundedReadLimitError)) as excinfo:
            worker._collect_tar(stream, tmp_path / "rootfs", tree, budget=1024)
        assert getattr(excinfo.value, "state", EXTRACTION_QUOTA) == EXTRACTION_QUOTA

    def test_stream_that_is_not_a_tar_is_refused(
        self, worker: SquashfsWorker, tmp_path: Path
    ) -> None:
        tree = ExtractedTree()
        with pytest.raises(ExtractionError) as excinfo:
            worker._collect_tar(io.BytesIO(b"not a tar at all"), tmp_path / "rootfs", tree, 1024)
        assert excinfo.value.state == EXTRACTION_CORRUPT

    def test_empty_stream_is_refused(self, worker: SquashfsWorker, tmp_path: Path) -> None:
        tree = ExtractedTree()
        empty_tar = make_tar({})
        with pytest.raises(ExtractionError) as excinfo:
            worker._collect_tar(io.BytesIO(empty_tar), tmp_path / "rootfs", tree, 1 << 20)
        assert excinfo.value.state == "EMPTY_OUTPUT"

    def test_byte_budget_applies_to_the_whole_stream(
        self, worker: SquashfsWorker, tmp_path: Path
    ) -> None:
        payload = make_tar({"a": b"1" * 2048, "b": b"2" * 2048})
        tree = ExtractedTree()
        with pytest.raises(BoundedReadLimitError):
            worker._collect_tar(io.BytesIO(payload), tmp_path / "rootfs", tree, 3000)


class TestScratchLifecycle:
    def test_release_removes_the_tree_including_link_targets(
        self, worker: SquashfsWorker, tmp_path: Path
    ) -> None:
        scratch = tmp_path / "scratch"
        (scratch / "rootfs" / "etc").mkdir(parents=True)
        (scratch / "rootfs" / "etc" / "passwd").write_text("x")
        outside = tmp_path / "outside.txt"
        outside.write_text("keep me")
        (scratch / "rootfs" / "link").symlink_to(outside)

        worker.release(scratch)

        assert not scratch.exists()
        # A link inside the scratch tree must never delete its target.
        assert outside.exists()

    def test_release_of_a_missing_directory_is_harmless(
        self, worker: SquashfsWorker, tmp_path: Path
    ) -> None:
        worker.release(tmp_path / "never-created")


class TestStateMapping:
    @pytest.mark.parametrize(
        ("state", "incomplete"),
        [
            ("OK", False),
            ("TIMEOUT", True),
            ("QUOTA_EXCEEDED", True),
            ("CORRUPT_INPUT", True),
            ("HELPER_FAILED", True),
            ("EMPTY_OUTPUT", True),
            ("NO_ISOLATION", True),
            ("UNAVAILABLE", False),
        ],
    )
    def test_incomplete_states_are_the_documented_ones(self, state: str, incomplete: bool) -> None:
        assert is_incomplete(state) is incomplete
