"""Immutable input binding (slice 2D).

A scan has two moments: the bytes are hashed, and the bytes are analysed.
Between them, a build system may rewrite the file it just produced. If the
scanner reads the file twice and only hashes it the first time, the report
attributes *new* bytes to the *old* digest — a silent, unverifiable result.

The binding is:

1. Stream the input into a private directory belonging to this scan, hashing
   as it goes, under a storage budget.
2. Compare the digest with the one ingest recorded. A mismatch is a hard
   failure, not a warning.
3. Make the private copy read-only, and read only from it for the rest of the
   scan.
4. Re-verify the original path once analysis is finished, and record whether it
   still has the same digest. A changed source is reported; it never changes
   which bytes were analysed.

Either outcome is acceptable to the release gate — the original snapshot stays
in use, or the scan is marked incomplete — but new bytes are never attributed
to the old digest.
"""

from __future__ import annotations

import contextlib
import hashlib
import logging
import os
import shutil
import stat
from pathlib import Path

from iot_hardware_scanner.models import InputSnapshot

logger = logging.getLogger(__name__)

_CHUNK = 1024 * 1024


class InputBindingError(Exception):
    """Raised when the input cannot be bound to a verified private snapshot."""


def _hash_file(path: Path, budget: int) -> tuple[str, int]:
    hasher = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(_CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if total > budget:
                raise InputBindingError(
                    f"{path} exceeds the {budget}-byte snapshot budget while being copied"
                )
            hasher.update(chunk)
    return hasher.hexdigest(), total


def bind_input(
    source: Path,
    destination_dir: Path,
    *,
    declared_sha256: str,
    budget_bytes: int,
    basename: str | None = None,
) -> InputSnapshot:
    """Copy ``source`` into a private, read-only snapshot and verify its digest.

    ``destination_dir`` must be private to this scan. A shortfall in free space
    or a digest mismatch raises :class:`InputBindingError`; the caller records
    the scan as incomplete rather than reading unverified bytes.
    """
    source = Path(source)
    destination_dir = Path(destination_dir)
    destination_dir.mkdir(parents=True, exist_ok=True)

    try:
        free = shutil.disk_usage(str(destination_dir)).free
    except OSError as exc:  # pragma: no cover - platform dependent
        raise InputBindingError(f"cannot measure free space for {destination_dir}: {exc}") from exc
    if free < budget_bytes:
        raise InputBindingError(
            f"insufficient free space for the input snapshot: {free} free, {budget_bytes} required"
        )

    snapshot = destination_dir / (basename or source.name)
    hasher = hashlib.sha256()
    total = 0
    try:
        with source.open("rb") as reader, snapshot.open("wb") as writer:
            while True:
                chunk = reader.read(_CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > budget_bytes:
                    raise InputBindingError(
                        f"{source} exceeds the {budget_bytes}-byte snapshot budget"
                    )
                hasher.update(chunk)
                writer.write(chunk)
    except BaseException as exc:
        # A partial snapshot must never survive: it would be a copy that does not
        # match the digest recorded at ingest.
        snapshot.unlink(missing_ok=True)
        if isinstance(exc, InputBindingError):
            raise
        raise InputBindingError(f"cannot copy {source} into the scan snapshot: {exc}") from exc

    verified = hasher.hexdigest()
    if verified != declared_sha256:
        snapshot.unlink(missing_ok=True)
        raise InputBindingError(
            f"{source} changed between ingest and analysis: ingest recorded "
            f"{declared_sha256}, the snapshot holds {verified}"
        )

    os.chmod(snapshot, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    logger.info("Input bound to snapshot %s (%d bytes, sha256 %s)", snapshot, total, verified)
    return InputSnapshot(
        original_path=source.resolve(),
        snapshot_path=snapshot,
        declared_sha256=declared_sha256,
        verified_sha256=verified,
        size=total,
        budget_bytes=budget_bytes,
        immutable=True,
    )


def reverify_source(snapshot: InputSnapshot) -> InputSnapshot:
    """Re-hash the original path after analysis and record whether it moved.

    Returns the same object so callers can use it inline. A source that changed
    does **not** invalidate the analysis: the snapshot is what was analysed.
    """
    try:
        digest, _ = _hash_file(snapshot.original_path, snapshot.budget_bytes)
    except (OSError, InputBindingError) as exc:
        logger.warning("Cannot re-verify %s: %s", snapshot.original_path, exc)
        snapshot.source_changed = True
        return snapshot
    snapshot.source_reverified = True
    snapshot.source_changed = digest != snapshot.declared_sha256
    if snapshot.source_changed:
        logger.warning(
            "Input %s changed after ingest (%s -> %s); the snapshot was analysed",
            snapshot.original_path,
            snapshot.declared_sha256,
            digest,
        )
    return snapshot


def release_snapshot(snapshot: InputSnapshot, *, keep: bool = False) -> None:
    """Delete the private snapshot unless the operator asked to keep it."""
    if keep:
        return
    with contextlib.suppress(OSError):  # pragma: no cover - best effort
        snapshot.snapshot_path.chmod(stat.S_IWUSR | stat.S_IRUSR)
    try:
        snapshot.snapshot_path.unlink(missing_ok=True)
    except OSError as exc:  # pragma: no cover - best effort
        logger.warning("Could not release snapshot %s: %s", snapshot.snapshot_path, exc)
