"""Immutable input binding (2D): the bytes analysed are the bytes hashed."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from iot_hardware_scanner.scanner.input_snapshot import (
    InputBindingError,
    bind_input,
    release_snapshot,
    reverify_source,
)

ORIGINAL = b"firmware bytes v1\n" * 32


@pytest.fixture
def original(tmp_path: Path) -> Path:
    path = tmp_path / "build-output.bin"
    path.write_bytes(ORIGINAL)
    return path


class TestBinding:
    def test_snapshot_copies_and_verifies(self, original: Path, tmp_path: Path) -> None:
        snapshot = bind_input(
            original,
            tmp_path / "private",
            declared_sha256=hashlib.sha256(ORIGINAL).hexdigest(),
            budget_bytes=1024 * 1024,
        )
        assert snapshot.digest_matches
        assert snapshot.snapshot_path.read_bytes() == ORIGINAL
        assert snapshot.size == len(ORIGINAL)
        assert snapshot.immutable

    def test_snapshot_is_read_only(self, original: Path, tmp_path: Path) -> None:
        snapshot = bind_input(
            original,
            tmp_path / "private",
            declared_sha256=hashlib.sha256(ORIGINAL).hexdigest(),
            budget_bytes=1024 * 1024,
        )
        assert snapshot.snapshot_path.stat().st_mode & 0o222 == 0

    def test_replaced_build_output_is_refused(self, original: Path, tmp_path: Path) -> None:
        declared = hashlib.sha256(ORIGINAL).hexdigest()
        # The build rewrote the file between hashing it and analysing it.
        original.write_bytes(b"firmware bytes v2, different\n")

        with pytest.raises(InputBindingError) as excinfo:
            bind_input(
                original,
                tmp_path / "private",
                declared_sha256=declared,
                budget_bytes=1024 * 1024,
            )
        assert declared in str(excinfo.value)
        # No partial snapshot is left behind, and the new bytes are not adopted.
        assert list((tmp_path / "private").iterdir()) == []

    def test_storage_budget_is_enforced(self, original: Path, tmp_path: Path) -> None:
        with pytest.raises(InputBindingError) as excinfo:
            bind_input(
                original,
                tmp_path / "private",
                declared_sha256=hashlib.sha256(ORIGINAL).hexdigest(),
                budget_bytes=16,
            )
        assert "budget" in str(excinfo.value)
        assert list((tmp_path / "private").iterdir()) == []

    def test_insufficient_free_space_is_refused(
        self, original: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import shutil as shutil_module

        monkeypatch.setattr(
            shutil_module,
            "disk_usage",
            lambda _path: type("Usage", (), {"free": 1, "total": 1, "used": 0})(),
        )
        with pytest.raises(InputBindingError) as excinfo:
            bind_input(
                original,
                tmp_path / "private",
                declared_sha256=hashlib.sha256(ORIGINAL).hexdigest(),
                budget_bytes=1024 * 1024,
            )
        assert "free space" in str(excinfo.value)


class TestReverification:
    def test_unchanged_source_is_recorded(self, original: Path, tmp_path: Path) -> None:
        snapshot = bind_input(
            original,
            tmp_path / "private",
            declared_sha256=hashlib.sha256(ORIGINAL).hexdigest(),
            budget_bytes=1024 * 1024,
        )
        snapshot = reverify_source(snapshot)
        assert snapshot.source_reverified
        assert not snapshot.source_changed

    def test_changed_source_keeps_the_snapshot_digest(self, original: Path, tmp_path: Path) -> None:
        declared = hashlib.sha256(ORIGINAL).hexdigest()
        snapshot = bind_input(
            original,
            tmp_path / "private",
            declared_sha256=declared,
            budget_bytes=1024 * 1024,
        )
        original.write_bytes(b"a different build\n")
        snapshot = reverify_source(snapshot)

        assert snapshot.source_changed
        assert snapshot.verified_sha256 == declared
        assert snapshot.snapshot_path.read_bytes() == ORIGINAL

    def test_vanished_source_is_reported_as_changed(self, original: Path, tmp_path: Path) -> None:
        snapshot = bind_input(
            original,
            tmp_path / "private",
            declared_sha256=hashlib.sha256(ORIGINAL).hexdigest(),
            budget_bytes=1024 * 1024,
        )
        original.unlink()
        snapshot = reverify_source(snapshot)
        assert snapshot.source_changed
        assert not snapshot.source_reverified


class TestRelease:
    def test_release_removes_the_snapshot(self, original: Path, tmp_path: Path) -> None:
        snapshot = bind_input(
            original,
            tmp_path / "private",
            declared_sha256=hashlib.sha256(ORIGINAL).hexdigest(),
            budget_bytes=1024 * 1024,
        )
        release_snapshot(snapshot)
        assert not snapshot.snapshot_path.exists()

    def test_release_can_be_kept(self, original: Path, tmp_path: Path) -> None:
        snapshot = bind_input(
            original,
            tmp_path / "private",
            declared_sha256=hashlib.sha256(ORIGINAL).hexdigest(),
            budget_bytes=1024 * 1024,
        )
        release_snapshot(snapshot, keep=True)
        assert snapshot.snapshot_path.exists()
