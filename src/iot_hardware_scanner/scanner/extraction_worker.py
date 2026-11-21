"""One supported extraction backend, end to end (slice 2A).

The released path is deliberately narrow because it has to be defensible:

1. The gzip wrapper is streamed into bounded private scratch (the slice 2C
   budget applies to *decoded* bytes, not to the wrapper size) and the SquashFS
   v4 superblock is validated by :mod:`iot_hardware_scanner.scanner.image_map`.
2. Upstream ``unsquashfs`` — never a Python binding — decodes the filesystem
   inside a pinned, unprivileged Linux worker: read-only input, private
   size-limited scratch, no network, no capabilities, memory/pid/CPU limits and
   a wall-clock deadline. The container writes nothing to the host: it streams a
   tar to a pipe, which this module parses under entry, byte and path budgets.
3. The worker image digest and the helper version are recorded with the result,
   so a report names exactly which decoder produced the observations.

Why a tar stream instead of a bind-mounted output directory
-----------------------------------------------------------
An untrusted image must not be able to write to the analysis host at all. With
the tree streamed over a pipe there is no host path for a malicious image to
traverse into: every name is validated here before anything is created, and
every byte is counted against a budget. The input is mounted read-only and the
worker's own scratch is a tmpfs that disappears with the container.

Failure states
--------------
Every failure carries a named state (see ``models.EXTRACTION_*``) so the
orchestrator maps it to a stage status without parsing English. A missing
runtime, a missing image, or isolation required but absent is a *dependency*
(exit 5); corrupt input, a timeout, a quota breach, a non-zero helper exit or an
empty tree is *incomplete analysis* (exit 4).

Scratch is released on every failing path, so a retry starts from a clean
directory.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import subprocess
import tarfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.models import (
    EXTRACTION_CORRUPT,
    EXTRACTION_EMPTY,
    EXTRACTION_INCOMPLETE_STATES,
    EXTRACTION_NO_ISOLATION,
    EXTRACTION_NONZERO,
    EXTRACTION_OK,
    EXTRACTION_QUOTA,
    EXTRACTION_TIMEOUT,
    EXTRACTION_UNAVAILABLE,
    ExtractionProvenance,
    ExtractionResult,
)
from iot_hardware_scanner.scanner.bounded_reader import BoundedReadLimitError

logger = logging.getLogger(__name__)

#: Marker the worker prints to stderr before the helper runs.
VERSION_MARKER = "IHS-HELPER-VERSION "
#: Container runtimes, in preference order. Rootless Podman first: it needs no
#: daemon and maps the container user to the invoking user.
RUNTIME_PREFERENCE = ("podman", "docker")
#: Paths inside the worker.
WORKER_INPUT = "/input/root.squashfs"
WORKER_SCRATCH = "/scratch/rootfs"
#: One shell invocation per run: helper version to stderr, tree to stdout.
WORKER_SCRIPT = (
    f'echo "{VERSION_MARKER}$(unsquashfs -version | head -1)" >&2; '
    f"unsquashfs -no-progress -ignore-errors -d {WORKER_SCRATCH} {WORKER_INPUT} >&2; "
    f"status=$?; "
    f"if [ -d {WORKER_SCRATCH} ]; then tar -C {WORKER_SCRATCH} -cf - .; fi; "
    f"exit $status"
)
#: Failures the helper reports that this scanner tolerates: it collects regular
#: files only, and without CAP_MKNOD the helper cannot create device nodes.
_TOLERATED_HELPER_ERRORS = ("character device", "block device", "fifo", "socket")


class ExtractionError(Exception):
    """A failure with a named state the caller maps to a stage status."""

    def __init__(self, state: str, message: str) -> None:
        super().__init__(message)
        self.state = state
        self.message = message


@dataclass
class WorkerRuntime:
    """A detected runtime and the worker image it will run."""

    name: str  # podman | docker | host-process
    image: str
    digest: str | None = None
    isolation: str = "container"

    @property
    def is_container(self) -> bool:
        """Whether this runtime gives the worker its own sandbox."""
        return self.isolation == "container"


@dataclass
class ExtractedTree:
    """What the streamed tar actually produced."""

    entries: list[dict[str, Any]] = field(default_factory=list)
    bytes_written: int = 0
    skipped: dict[str, int] = field(default_factory=dict)
    omissions: list[str] = field(default_factory=list)

    @property
    def file_count(self) -> int:
        """Regular files written to scratch."""
        return sum(1 for entry in self.entries if entry["kind"] == "file")


class SquashfsWorker:
    """Run ``unsquashfs`` in a pinned, unprivileged Linux worker."""

    def __init__(self, config: ScannerConfig) -> None:
        self.config = config
        self._version_cache: str | None = None

    # ──────────────────────────────────────────
    # Runtime selection
    # ──────────────────────────────────────────

    def select_runtime(self) -> WorkerRuntime:
        """Pick a runtime, honouring an explicit operator choice.

        A runtime that is installed but whose daemon is unreachable is not
        treated as present: the caller is told the dependency is missing
        instead of getting an empty filesystem.
        """
        requested = (self.config.extraction_worker or "auto").lower()
        if requested == "none":
            raise ExtractionError(
                EXTRACTION_UNAVAILABLE,
                "image extraction disabled by configuration (extraction_worker = none)",
            )
        if requested == "host-process":
            return self._host_process_runtime()

        candidates = RUNTIME_PREFERENCE if requested == "auto" else (requested,)
        for name in candidates:
            executable = shutil.which(name)
            if executable is None:
                continue
            if not self._runtime_reachable(executable):
                logger.info("%s is installed but its daemon is not reachable", name)
                continue
            digest = self._image_digest(executable)
            if digest is None:
                logger.info("%s cannot see worker image %s", name, self.config.worker_image)
                continue
            return WorkerRuntime(name=name, image=self.config.worker_image, digest=digest)

        if requested in RUNTIME_PREFERENCE:
            raise ExtractionError(
                EXTRACTION_UNAVAILABLE,
                f"extraction worker {requested!r} is not reachable, or worker image "
                f"{self.config.worker_image!r} is not present",
            )
        raise ExtractionError(
            EXTRACTION_UNAVAILABLE,
            "no container runtime (podman or docker) is reachable and worker image "
            f"{self.config.worker_image!r} is not present; image extraction needs a "
            "pinned Linux worker",
        )

    def _host_process_runtime(self) -> WorkerRuntime:
        """Use ``unsquashfs`` directly on this host — only when explicitly allowed."""
        if shutil.which("unsquashfs") is None:
            raise ExtractionError(
                EXTRACTION_UNAVAILABLE, "unsquashfs is not installed on this host"
            )
        if self.config.extraction_require_isolation:
            raise ExtractionError(
                EXTRACTION_NO_ISOLATION,
                "extraction_worker is 'host-process' but isolation is required by "
                "configuration; a host process has no read-only, no-network sandbox",
            )
        if os.uname().sysname != "Linux":
            raise ExtractionError(
                EXTRACTION_NO_ISOLATION,
                "a host-process extraction is only supported on Linux; this host is "
                f"{os.uname().sysname}",
            )
        return WorkerRuntime(name="host-process", image="", digest=None, isolation="host-process")

    @staticmethod
    def _runtime_reachable(executable: str) -> bool:
        try:
            completed = subprocess.run(
                [executable, "info"], capture_output=True, text=True, timeout=60, check=False
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return completed.returncode == 0

    def _image_digest(self, executable: str) -> str | None:
        try:
            completed = subprocess.run(
                [executable, "image", "inspect", "--format", "{{.Id}}", self.config.worker_image],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):  # pragma: no cover - runtime dependent
            return None
        if completed.returncode != 0:
            return None
        lines = completed.stdout.strip().splitlines()
        return lines[-1] if lines else None

    # ──────────────────────────────────────────
    # The run
    # ──────────────────────────────────────────

    def extract(self, squashfs_image: Path, scratch_dir: Path) -> ExtractionResult:
        """Extract one validated SquashFS image into ``scratch_dir``.

        ``scratch_dir`` is private to this scan: it is created here and removed
        on every failing path, so a retry starts from a clean directory. On
        success it is kept, because the later stages read the extracted tree;
        ``--keep-scratch`` keeps it after a failure too, for diagnosis.
        """
        started = time.monotonic()
        scratch_dir = Path(scratch_dir)
        rootfs = scratch_dir / "rootfs"
        budget = self.config.max_extracted_bytes_mb * 1024 * 1024
        provenance = ExtractionProvenance(
            worker=(self.config.extraction_worker or "auto"),
            limits={
                "max_decoded_bytes": self.config.max_decoded_bytes_mb * 1024 * 1024,
                "max_extracted_bytes": budget,
                "max_entries": self.config.max_extracted_entries,
                "timeout_seconds": self.config.extraction_timeout_seconds,
                "memory_mb": self.config.worker_memory_mb,
                "pids": 128,
                "network": "none",
                "capabilities": "none",
            },
        )

        try:
            runtime = self.select_runtime()
        except ExtractionError as exc:
            # No backend to run: a dependency the operator can supply, reported
            # with everything that was still learned about the input.
            return ExtractionResult(
                success=False,
                extraction_dir=scratch_dir,
                root_filesystems=[],
                extraction_errors=[exc.message],
                backend="none",
                state=exc.state,
                provenance=provenance,
            )

        provenance.worker = runtime.name
        provenance.isolation = runtime.isolation
        provenance.worker_image = runtime.image or None
        provenance.worker_digest = runtime.digest

        try:
            scratch_dir.mkdir(parents=True, exist_ok=False)
        except FileExistsError:
            self._release(scratch_dir)
            scratch_dir.mkdir(parents=True, exist_ok=True)

        try:
            tree, helper_version, helper_exit, diagnostics = self._execute(
                runtime, squashfs_image, scratch_dir, rootfs, budget
            )
        except ExtractionError as exc:
            # A backend that ran and failed: incomplete analysis, scratch released.
            self._release(scratch_dir)
            provenance.scratch_released = True
            provenance.durations_seconds = round(time.monotonic() - started, 3)
            provenance.helper_version = self._cached_version(runtime)
            return ExtractionResult(
                success=False,
                extraction_dir=scratch_dir,
                root_filesystems=[],
                extraction_errors=[exc.message],
                backend=runtime.name,
                backend_version=provenance.helper_version,
                worker_digest=runtime.digest,
                state=exc.state,
                provenance=provenance,
            )
        except BaseException:
            self._release(scratch_dir)
            provenance.scratch_released = True
            raise

        provenance.helper_version = helper_version or self._cached_version(runtime)
        provenance.extracted_entries = len(tree.entries)
        provenance.extracted_bytes = tree.bytes_written
        provenance.durations_seconds = round(time.monotonic() - started, 3)
        provenance.helper_argv = self._argv_for(runtime, squashfs_image)

        if tree.file_count == 0:
            self._release(scratch_dir)
            provenance.scratch_released = True
            return ExtractionResult(
                success=False,
                extraction_dir=scratch_dir,
                root_filesystems=[],
                extraction_errors=[
                    "the worker produced no regular files; the payload is not a readable "
                    "SquashFS v4 filesystem"
                ],
                backend=runtime.name,
                backend_version=provenance.helper_version,
                worker_digest=runtime.digest,
                state=EXTRACTION_EMPTY,
                provenance=provenance,
            )

        state = EXTRACTION_OK
        errors: list[str] = []
        if helper_exit != 0:
            failures = [line for line in diagnostics if "failed" in line.lower()]
            tolerated = bool(failures) and all(
                any(token in line.lower() for token in _TOLERATED_HELPER_ERRORS)
                for line in failures
            )
            if tolerated:
                # The eligible population for this scanner is regular files. A
                # container without CAP_MKNOD cannot create /dev/console, and
                # recording that as a *failure* would be dishonest: the tree is
                # complete for everything the scanner reads.
                specials = tree.skipped.get("special", 0)
                if specials:
                    tree.omissions.append(
                        f"{specials} special file(s) were not materialised (device nodes, "
                        "FIFOs, sockets); only regular files are collected"
                    )
                errors.append(
                    f"unsquashfs exited {helper_exit} with special-file errors only; device "
                    "nodes and FIFOs are recorded as metadata and not collected"
                )
            else:
                self._release(scratch_dir)
                provenance.scratch_released = True
                return ExtractionResult(
                    success=False,
                    extraction_dir=scratch_dir,
                    root_filesystems=[],
                    extraction_errors=[
                        f"unsquashfs exited {helper_exit}: "
                        + ("; ".join(diagnostics[:3]) or "no diagnostic")
                    ],
                    backend=runtime.name,
                    backend_version=provenance.helper_version,
                    worker_digest=runtime.digest,
                    state=EXTRACTION_NONZERO,
                    provenance=provenance,
                )

        manifest = scratch_dir / "extract-manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "worker": runtime.name,
                    "worker_image": runtime.image or None,
                    "worker_digest": runtime.digest,
                    "helper_version": provenance.helper_version,
                    "entries": tree.entries,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        if not self.config.keep_scratch:
            provenance.scratch_released = False  # the extracted tree is the product
        return ExtractionResult(
            success=True,
            extraction_dir=scratch_dir,
            root_filesystems=[rootfs],
            file_count=tree.file_count,
            total_size=tree.bytes_written,
            extraction_errors=errors,
            backend=runtime.name,
            backend_version=provenance.helper_version,
            worker_digest=runtime.digest,
            state=state,
            provenance=provenance,
            omissions=list(tree.omissions),
        )

    # ──────────────────────────────────────────
    # Command construction
    # ──────────────────────────────────────────

    def _argv_for(self, runtime: WorkerRuntime, image: Path) -> list[str]:
        """The argv that identifies the decoder, recorded in the report."""
        if not runtime.is_container:
            return ["unsquashfs", "-no-progress", "-ignore-errors", "-d", "<scratch>", str(image)]
        return [
            runtime.name,
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--tmpfs",
            f"/scratch:size={self.config.max_extracted_bytes_mb + 64}m",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--memory",
            f"{self.config.worker_memory_mb}m",
            "--pids-limit",
            "128",
            "-v",
            f"{image}:{WORKER_INPUT}:ro",
            runtime.image,
        ]

    def _command(self, runtime: WorkerRuntime, image: Path, rootfs: Path) -> list[str]:
        """The exact argv for one run."""
        script = WORKER_SCRIPT
        from iot_hardware_scanner import faults

        if faults.enabled(faults.FAULT_EXTRACTION_TIMEOUT):
            script = f'echo "{VERSION_MARKER}$(unsquashfs -version | head -1)" >&2; sleep 3600'
        elif faults.enabled(faults.FAULT_EXTRACTION_NONZERO):
            script = (
                f'echo "{VERSION_MARKER}$(unsquashfs -version | head -1)" >&2; '
                'echo "FATAL ERROR: simulated helper failure" >&2; exit 99'
            )

        if not runtime.is_container:
            return [
                "sh",
                "-c",
                (
                    # Double quotes: the version marker must be expanded by the
                    # shell, and single quotes would ship the literal command.
                    f'echo "{VERSION_MARKER}$(unsquashfs -version | head -1)" >&2; '
                    f"unsquashfs -no-progress -ignore-errors -d {rootfs} {image} >&2"
                ),
            ]
        return [
            runtime.name,
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--tmpfs",
            f"/scratch:size={self.config.max_extracted_bytes_mb + 64}m,mode=1777",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--memory",
            f"{self.config.worker_memory_mb}m",
            "--pids-limit",
            "128",
            "--cpus",
            "2",
            "--entrypoint",
            "sh",
            "-v",
            f"{image}:{WORKER_INPUT}:ro",
            runtime.image,
            "-c",
            script,
        ]

    # ──────────────────────────────────────────
    # Execution and bounded collection
    # ──────────────────────────────────────────

    def _execute(
        self,
        runtime: WorkerRuntime,
        image: Path,
        scratch_dir: Path,
        rootfs: Path,
        budget: int,
    ) -> tuple[ExtractedTree, str | None, int, list[str]]:
        """Run the worker, collect its tree into scratch, and classify the exit."""
        deadline = self.config.extraction_timeout_seconds
        command = self._command(runtime, image, rootfs)
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
        )
        expired = threading.Event()

        def _kill() -> None:
            expired.set()
            process.kill()

        watchdog = threading.Timer(deadline, _kill)
        watchdog.start()
        diagnostics: list[str] = []
        assert process.stdout is not None
        assert process.stderr is not None
        drainer = threading.Thread(
            target=self._drain, args=(process.stderr, diagnostics), daemon=True
        )
        drainer.start()

        tree = ExtractedTree()
        failure: Exception | None = None
        try:
            if runtime.is_container:
                self._collect_tar(process.stdout, rootfs, tree, budget)
            else:
                # A host-process helper writes directly into the scratch tree.
                process.stdout.read()
        except (ExtractionError, BoundedReadLimitError) as exc:
            failure = exc
            process.kill()
        finally:
            try:
                process.wait(timeout=deadline + 30)
            except subprocess.TimeoutExpired:  # pragma: no cover - defensive
                process.kill()
                process.wait()
            watchdog.cancel()
            drainer.join(timeout=10)
            process.stdout.close()
            process.stderr.close()

        helper_version = next(
            (
                line[len(VERSION_MARKER) :]
                for line in diagnostics
                if line.startswith(VERSION_MARKER)
            ),
            None,
        )
        messages = [line for line in diagnostics if not line.startswith(VERSION_MARKER)]

        if expired.is_set():
            raise ExtractionError(
                EXTRACTION_TIMEOUT,
                f"the extraction worker exceeded its {deadline}s deadline and was killed",
            )
        if failure is not None:
            state = getattr(failure, "state", EXTRACTION_QUOTA)
            if state == EXTRACTION_CORRUPT and (process.returncode or 0) != 0:
                # The helper failed and left no usable stream: its exit code is
                # the cause, and the stream is the symptom.
                state = EXTRACTION_NONZERO
                message = f"unsquashfs exited {process.returncode}: " + (
                    "; ".join(messages[:3]) or str(failure)
                )
                raise ExtractionError(state, message) from failure
            raise ExtractionError(state, str(failure)) from failure
        if not runtime.is_container:
            tree = self._walk_tree(rootfs, budget)
        return tree, helper_version, process.returncode or 0, messages

    def _drain(self, stream: IO[bytes], lines: list[str]) -> None:
        """Read the worker's diagnostics, bounded in both lines and bytes."""
        consumed = 0
        try:
            for raw in stream:
                consumed += len(raw)
                if consumed > 256 * 1024:
                    lines.append("worker diagnostics exceeded 256 KiB and were truncated")
                    return
                lines.append(raw.decode("utf-8", "replace").rstrip())
        except (OSError, ValueError):  # pragma: no cover - pipe closed under us
            return

    def _collect_tar(
        self, stdout: IO[bytes], rootfs: Path, tree: ExtractedTree, budget: int
    ) -> None:
        """Parse the streamed tar into ``rootfs`` under entry, path and byte budgets.

        Every member name is validated before anything is created: an absolute
        path, a ``..`` component, or a name that leaves the root is rejected.
        Symbolic links are recorded as metadata and never created, so a link
        cannot be used to read outside the tree.
        """
        max_entries = self.config.max_extracted_entries
        rootfs.mkdir(parents=True, exist_ok=True)
        seen = 0
        with _open_tar(stdout, budget) as archive:
            for member in archive:
                seen += 1
                if seen > max_entries:
                    raise ExtractionError(
                        EXTRACTION_QUOTA,
                        f"the extracted tree exceeds the {max_entries}-entry budget",
                    )
                name = _normalise_member(member.name)
                if not name:
                    continue
                if not _safe_member_name(name):
                    raise ExtractionError(
                        EXTRACTION_CORRUPT,
                        f"the worker returned an unsafe member name: {member.name!r}",
                    )
                if member.isdir():
                    (rootfs / name).mkdir(parents=True, exist_ok=True)
                    continue
                if member.issym():
                    tree.skipped["symlink"] = tree.skipped.get("symlink", 0) + 1
                    tree.entries.append(
                        {
                            "path": name,
                            "kind": "symlink",
                            "link_target": member.linkname,
                            "size": 0,
                            "mode": member.mode,
                            "uid": member.uid,
                            "gid": member.gid,
                            "mtime": int(member.mtime),
                        }
                    )
                    continue
                if member.islnk():
                    tree.skipped["hardlink"] = tree.skipped.get("hardlink", 0) + 1
                    tree.entries.append(
                        {
                            "path": name,
                            "kind": "hardlink",
                            "link_target": _normalise_member(member.linkname),
                            "size": 0,
                            "mode": member.mode,
                            "uid": member.uid,
                            "gid": member.gid,
                            "mtime": int(member.mtime),
                        }
                    )
                    continue
                if not member.isfile():
                    tree.skipped["special"] = tree.skipped.get("special", 0) + 1
                    continue
                if member.size > budget:
                    raise ExtractionError(
                        EXTRACTION_QUOTA,
                        f"{name} declares {member.size} bytes, over the {budget}-byte budget",
                    )
                source = archive.extractfile(member)
                if source is None:  # pragma: no cover - tar guarantees a file object
                    continue
                destination = rootfs / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                written = 0
                with destination.open("wb") as out:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        written += len(chunk)
                        out.write(chunk)
                os.chmod(destination, 0o644)
                tree.bytes_written += written
                tree.entries.append(
                    {
                        "path": name,
                        "kind": "file",
                        "size": written,
                        "sha256": _sha256_of(destination),
                        "mode": member.mode,
                        "uid": member.uid,
                        "gid": member.gid,
                        "mtime": int(member.mtime),
                    }
                )
        if not tree.entries:
            raise ExtractionError(EXTRACTION_EMPTY, "the worker's tree stream contained no entries")
        tree.omissions.extend(
            f"{count} {kind}(s) recorded as metadata only"
            for kind, count in sorted(tree.skipped.items())
            if kind != "special"
        )

    def _walk_tree(self, rootfs: Path, budget: int) -> ExtractedTree:
        """Build the same manifest for a host-process extraction."""
        tree = ExtractedTree()
        inodes: dict[tuple[int, int], str] = {}
        seen = 0
        total = 0
        for entry in sorted(rootfs.rglob("*")):
            seen += 1
            if seen > self.config.max_extracted_entries:
                raise ExtractionError(
                    EXTRACTION_QUOTA,
                    f"the extracted tree exceeds the "
                    f"{self.config.max_extracted_entries}-entry budget",
                )
            relative = str(entry.relative_to(rootfs))
            stat_result = entry.lstat()
            if entry.is_symlink():
                tree.skipped["symlink"] = tree.skipped.get("symlink", 0) + 1
                continue
            if entry.is_dir():
                continue
            if not entry.is_file():
                tree.skipped["special"] = tree.skipped.get("special", 0) + 1
                continue
            total += stat_result.st_size
            if total > budget:
                raise ExtractionError(
                    EXTRACTION_QUOTA, f"the extracted tree exceeds the {budget}-byte budget"
                )
            key = (stat_result.st_dev, stat_result.st_ino)
            if key in inodes:
                tree.skipped["hardlink"] = tree.skipped.get("hardlink", 0) + 1
                tree.entries.append(
                    {
                        "path": relative,
                        "kind": "hardlink",
                        "link_target": inodes[key],
                        "size": 0,
                        "mode": stat_result.st_mode,
                        "uid": stat_result.st_uid,
                        "gid": stat_result.st_gid,
                        "mtime": int(stat_result.st_mtime),
                    }
                )
                continue
            inodes[key] = relative
            tree.entries.append(
                {
                    "path": relative,
                    "kind": "file",
                    "size": stat_result.st_size,
                    "sha256": _sha256_of(entry),
                    "mode": stat_result.st_mode,
                    "uid": stat_result.st_uid,
                    "gid": stat_result.st_gid,
                    "mtime": int(stat_result.st_mtime),
                }
            )
            tree.bytes_written += stat_result.st_size
        return tree

    def _cached_version(self, runtime: WorkerRuntime) -> str | None:
        """Helper version, read once per process from the same pinned image."""
        if self._version_cache is not None:
            return self._version_cache
        if not runtime.is_container:  # pragma: no cover - host path reports its own
            return None
        try:
            completed = subprocess.run(
                [runtime.name, "run", "--rm", "--network", "none", runtime.image, "-version"],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):  # pragma: no cover - runtime dependent
            return None
        if completed.returncode != 0:  # pragma: no cover - runtime dependent
            return None
        self._version_cache = completed.stdout.strip().splitlines()[0]
        return self._version_cache

    # ──────────────────────────────────────────
    # Scratch lifecycle
    # ──────────────────────────────────────────

    @staticmethod
    def _release(scratch_dir: Path) -> None:
        """Delete a scratch directory without following links out of it."""
        root = Path(scratch_dir)
        if not root.exists():
            return
        for entry in root.rglob("*"):
            if entry.is_symlink():
                entry.unlink(missing_ok=True)
        shutil.rmtree(root, ignore_errors=True)

    def release(self, scratch_dir: Path) -> None:
        """Public alias used by callers that need to clean up explicitly."""
        self._release(scratch_dir)


def is_incomplete(state: str) -> bool:
    """Whether an extraction state means the analysis is incomplete."""
    return state in EXTRACTION_INCOMPLETE_STATES


def _normalise_member(name: str) -> str:
    """Strip the leading ``./`` a ``tar -cf .`` stream puts on every member."""
    while name.startswith("./"):
        name = name[2:]
    return "" if name in (".", "") else name


def _safe_member_name(name: str) -> bool:
    """Reject absolute, parent-relative or home-relative member names."""
    if name.startswith(("/", "~", "\\")):
        return False
    parts = [part for part in name.split("/") if part not in ("", ".")]
    return bool(parts) and all(part != ".." for part in parts)


def _sha256_of(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _open_tar(stdout: IO[bytes], budget: int) -> tarfile.TarFile:
    """Open the worker's tree stream as a tar archive, or fail with a state."""
    try:
        # The caller owns the archive through a ``with`` block; the handle is not
        # opened here and closed elsewhere.
        archive: tarfile.TarFile = tarfile.open(  # type: ignore[call-overload]  # noqa: SIM115
            fileobj=_CountingStream(stdout, budget), mode="r|"
        )
        return archive
    except tarfile.TarError as exc:
        raise ExtractionError(
            EXTRACTION_CORRUPT, f"the worker's tree stream is not a valid tar: {exc}"
        ) from exc


class _CountingStream:
    """Wrap the worker pipe so ``tarfile`` cannot outrun the byte budget."""

    def __init__(self, source: IO[bytes], budget: int) -> None:
        self._source = source
        self._budget = budget
        self.consumed = 0

    def read(self, size: int = -1) -> bytes:
        """Read at most ``size`` bytes, raising when the budget is exceeded."""
        chunk = self._source.read(65536 if size < 0 else size)
        if not chunk:
            return b""
        self.consumed += len(chunk)
        if self.consumed > self._budget:
            raise BoundedReadLimitError(
                f"the worker streamed more than its {self._budget}-byte budget"
            )
        return chunk

    def tell(self) -> int:
        """Position in the stream, which tarfile's stream mode requires."""
        return self.consumed


__all__ = [
    "ExtractionError",
    "SquashfsWorker",
    "WorkerRuntime",
    "is_incomplete",
]
