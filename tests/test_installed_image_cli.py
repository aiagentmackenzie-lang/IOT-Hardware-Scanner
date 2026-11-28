"""Milestone B acceptance: inventory one shipped Linux image.

Every case here runs the *installed* command through :class:`Runner` (the wheel,
or the relocated package when no wheel is installed), from a directory that no
checkout is visible in, with the network unused.

The rows are the Milestone B acceptance list, kept current by
`docs/SUPPORT-MATRIX.md` and `tests/test_claim_matrix.py`:

1. the reference image's inventory is recoverable through the CLI;
2. the same image with the worker turned off still identifies the artifact,
   names the dependency, keeps findings and exits 5;
3. a failing backend (corrupt payload, quota breach, timeout) exits 4, releases
   its scratch directory and permits a retry;
4. a staged tree and an image built from it yield the same file findings, with
   the differences stated;
5. a staged tree runs with no extraction prerequisite at all;
6. a build output replaced between ingest and analysis is never attributed to the
   old digest;
7. ``firmware-static`` reaches COMPLETE on the reference image;
8. budgets on a sparse 2 GiB input are measured, not asserted.

Extraction needs the pinned Linux worker, so the rows that depend on it skip
with a stated reason when no container runtime is available. A skip leaves that
capability unqualified; the ``linux-extractor`` CI job is the qualified gate.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import shutil
import subprocess
import sys
import uuid
from functools import lru_cache
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cpio_fixtures
import partition_fixtures
from cpio_fixtures import ODC, build, initramfs
from elf_fixtures import ElfSpec, write_fixture
from harness import Runner, make_tree

WORKER_IMAGE = "ihs-squashfs-worker:4.5.1"
REFERENCE_SHA256 = "8b5aa82659cafd90b26333dd419a0df9ad63c517ad94a2159e970a5bb5b6ff02"
BUSYBOX_SHA256 = "214a261c08545de6aa734442495f722fbe3ba71a0a9083cd010927f3c3ba696c"
OPKG_STATUS_SHA256 = "9442acbaf4ccc25115e770533ffe2b8a10d1c81e92d59b6d32035ba5ee6a3258"


# ──────────────────────────────────────────────
# Environment gates
# ──────────────────────────────────────────────


@lru_cache(maxsize=1)
def _container_runtime() -> tuple[str, str | None] | None:
    """The usable runtime, and the daemon endpoint to point the CLI at."""
    for name in ("podman", "docker"):
        executable = shutil.which(name)
        if executable is None:
            continue
        probe = subprocess.run(
            [executable, "image", "inspect", "--format", "{{.Id}}", WORKER_IMAGE],
            capture_output=True,
            text=True,
            check=False,
        )
        if probe.returncode != 0:
            continue
        host: str | None = None
        context = subprocess.run(
            [executable, "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"],
            capture_output=True,
            text=True,
            check=False,
        )
        if context.returncode == 0 and context.stdout.strip():
            host = context.stdout.strip()
        return name, host
    return None


def _daemon_env() -> dict[str, str]:
    """The daemon endpoint, if the harness's private HOME would hide it."""
    found = _container_runtime()
    if found is None or not found[1]:
        return {}
    return {"DOCKER_HOST": found[1]}


@pytest.fixture(scope="session")
def runtime() -> str:
    found = _container_runtime()
    if found is None:
        pytest.skip(
            f"no container runtime with {WORKER_IMAGE}: image extraction unqualified here "
            "(the linux-extractor CI job is the qualified gate)"
        )
    return found[0]


@lru_cache(maxsize=1)
def _mksquashfs_available() -> bool:
    """Whether the worker image carries the *builder*, for generated fixtures."""
    found = _container_runtime()
    if found is None:
        return False
    probe = subprocess.run(
        [found[0], "run", "--rm", "--entrypoint", "/usr/bin/mksquashfs", WORKER_IMAGE, "-version"],
        capture_output=True,
        text=True,
        check=False,
    )
    return probe.returncode == 0


def _build_squashfs(runtime: str, workdir: Path, source: Path, name: str) -> Path:
    """Build a SquashFS image from a tree, using the pinned worker's tool set."""
    # `-all-root` is what makes the image extractable without a chown the
    # container is not permitted to perform; it is the same recipe
    # `build_image()` uses for the single-image rows.
    subprocess.run(
        [
            runtime,
            "run",
            "--rm",
            "--network",
            "none",
            "-v",
            f"{workdir}:/work",
            "--entrypoint",
            "/usr/bin/mksquashfs",
            WORKER_IMAGE,
            f"/work/{source.name}",
            f"/work/{name}",
            "-noappend",
            "-comp",
            "gzip",
            "-all-root",
            "-quiet",
            "-no-progress",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return workdir / name


@pytest.fixture
def workdir(tmp_path: Path) -> Path:
    """A working directory the container runtime can see.

    On macOS a VM only shares the home directory, and the extractor bind-mounts
    the scan's private snapshot, so scans that use the worker run here.
    """
    base = Path.home() / ".cache" / "ihs-acceptance"
    base.mkdir(parents=True, exist_ok=True)
    directory = base / uuid.uuid4().hex[:12]
    directory.mkdir()
    try:
        yield directory
    finally:
        shutil.rmtree(directory, ignore_errors=True)


# ──────────────────────────────────────────────
# Controlled fixtures
# ──────────────────────────────────────────────

OPKG_STATUS = b"""Package: base-files
Version: 1589~0123456789
Status: install user installed
Architecture: aarch64_generic

Package: busybox
Version: 1.36.1-r2
Status: install user installed
Architecture: aarch64_generic

Package: libc
Version: 1.2.5-r4
Status: install hold installed
Architecture: aarch64_generic
"""


def make_controlled_tree(root: Path) -> Path:
    """A small but complete root tree: accounts, boot, ELF, packages, links."""
    (root / "etc").mkdir(parents=True)
    (root / "bin").mkdir(parents=True)
    (root / "usr" / "lib" / "opkg").mkdir(parents=True)
    (root / "etc" / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/ash\nuser:x:1000:1000:user:/home/user:/bin/ash\n"
    )
    (root / "etc" / "shadow").write_text(
        "root:!$6$salt$hash:19000:0:99999:7:::\nuser:$6$salt$hash:19000:0:99999:7:::\n"
    )
    (root / "etc" / "inittab").write_text(
        "::sysinit:/etc/init.d/rcS\n::respawn:/usr/sbin/sshd -D\n"
    )
    (root / "etc" / "config").mkdir()
    (root / "etc" / "config" / "system").write_text("config system\n\toption hostname 'gw'\n")
    write_fixture(root / "bin" / "busybox", ElfSpec())
    (root / "usr" / "lib" / "opkg" / "status").write_bytes(OPKG_STATUS)
    (root / "bin" / "sh").symlink_to("busybox")
    return root


def build_image(tree: Path, destination: Path, runtime: str) -> Path:
    """Build a gzip-wrapped SquashFS image from ``tree`` using the worker image."""
    staging = destination.parent
    squashfs = staging / "root.squashfs"
    shutil.rmtree(staging / "out", ignore_errors=True)
    (staging / "out").mkdir()
    completed = subprocess.run(
        [
            runtime,
            "run",
            "--rm",
            "--network",
            "none",
            "-v",
            f"{tree}:/src:ro",
            "-v",
            f"{staging / 'out'}:/out",
            "--entrypoint",
            "/usr/bin/mksquashfs",
            WORKER_IMAGE,
            "/src",
            "/out/root.squashfs",
            "-noappend",
            "-comp",
            "gzip",
            "-all-root",
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    shutil.move(str(staging / "out" / "root.squashfs"), squashfs)
    shutil.rmtree(staging / "out", ignore_errors=True)
    destination.write_bytes(gzip.compress(squashfs.read_bytes(), mtime=0))
    return destination


def scan(
    runner: Runner,
    work: Path,
    target: Path,
    *extra: str,
    env: dict[str, str] | None = None,
) -> tuple[int, dict | None, str]:
    """Run one scan, returning ``(exit, document, stdout+stderr)``."""
    out = work / f"report-{uuid.uuid4().hex[:6]}.json"
    arguments = [
        "scan",
        str(target),
        "--offline",
        "--format",
        "json",
        "--out",
        str(out),
        *extra,
    ]
    completed = runner(arguments, cwd=work, env={**_daemon_env(), **(env or {})})
    document = json.loads(out.read_text()) if out.is_file() else None
    return completed.returncode, document, completed.stdout + completed.stderr


def stage(document: dict | None, stage_id: str) -> dict:
    assert document is not None
    return next(item for item in document["stages"] if item["stage"] == stage_id)


def normalised_findings(document: dict) -> list[tuple]:
    """Findings with the root qualifier and volatile text removed."""
    rows = []
    for finding in document["findings"]:
        locations = sorted(
            location.split("/", 1)[-1] if "/" in location else location
            for location in finding["locations"]
        )
        rows.append(
            (
                finding["rule_id"],
                finding["severity"],
                finding["category"],
                tuple(locations),
                finding["critical_qualified"],
            )
        )
    return sorted(rows)


# ──────────────────────────────────────────────
# Row 1 + 7: the shipped image's inventory, and COMPLETE
# ──────────────────────────────────────────────


class TestReferenceImageInventory:
    def test_inventory_is_recoverable_through_the_cli(
        self, runner: Runner, runtime: str, reference_image: Path, workdir: Path
    ) -> None:
        exit_code, document, output = scan(runner, workdir, reference_image)
        assert document is not None, output

        # Row 7: every required stage ran.
        assert document["assessment"]["completion"] == "COMPLETE", document["assessment"][
            "incomplete_reasons"
        ]
        assert document["assessment"]["missing_required_dependencies"] == []

        # Row 1: all 196 installed records, with the exact revision.
        opkg = document["opkg"]
        assert opkg["installed"] == 196
        assert opkg["held"] == 4
        assert opkg["database_sha256"] == OPKG_STATUS_SHA256
        records = {record["name"]: record for record in opkg["records"]}
        busybox = records["busybox"]
        assert busybox["version"] == "1.36.1-r2"
        assert busybox["architecture"] == "aarch64_generic"
        assert busybox["installed"] is True

        # Row 1: the content hash and the AArch64 identity, from the ELF header.
        elf = next(
            record
            for record in document["elf"]["records"]
            if record["locator"].endswith("/bin/busybox")
        )
        assert elf["digest_sha256"] == BUSYBOX_SHA256
        assert (elf["class"], elf["byte_order"]) == ("ELF64", "little")
        assert elf["machine"] == 183
        assert elf["machine_name"] == "AArch64"

        # Row 1: traceable back to the exact inventory entry and byte range.
        evidence = busybox["evidence"]
        assert 0 < evidence["start"] < evidence["end"] <= opkg["byte_length"]
        assert evidence["line"] > 0
        component = next(item for item in document["components"] if item["product"] == "busybox")
        assert "1.36.1-r2" in component["cpe"]
        assert f"{evidence['start']}-{evidence['end']}" in component["evidence"]

        # The artifact is identified, and the extractor names its worker.
        assert document["artifact"]["sha256"] == REFERENCE_SHA256
        assert document["extraction"]["worker_digest"]
        assert "unsquashfs" in document["extraction"]["helper_version"]
        assert document["image_map"]["nodes"][1]["extent_bytes"] == 4_348_264

        # The image's own account database is joined, and it records an empty
        # password field for root with a login shell. That meets the documented
        # critical-evidence rule, so the release image exits 1 -- a fact that was
        # invisible until the filesystem could be opened.
        assert stage(document, "unix_accounts")["status"] == "COMPLETE"
        critical = [f for f in document["findings"] if f["critical_qualified"]]
        assert [f["rule_id"] for f in critical] == ["credential.unix.empty_password"]
        assert critical[0]["locations"] == ["rootfs/etc/shadow:1"]
        assert exit_code == 1, output


# ──────────────────────────────────────────────
# Row 2: the worker is off — useful partial report, exit 5
# ──────────────────────────────────────────────


class TestWorkerOff:
    def test_reference_image_is_identified_and_names_the_dependency(
        self, runner: Runner, reference_image: Path, workdir: Path
    ) -> None:
        exit_code, document, output = scan(runner, workdir, reference_image, "--worker", "none")
        assert document is not None, output

        assert exit_code == 5, output
        assert document["outcome"]["exit_reason"] == "MISSING_REQUIRED_DEPENDENCY"
        assert document["artifact"]["sha256"] == REFERENCE_SHA256
        assert document["assessment"]["missing_required_dependencies"]
        assert any(
            "extraction" in reason for reason in document["assessment"]["incomplete_reasons"]
        )

        extraction = stage(document, "extraction")
        assert extraction["status"] == "UNAVAILABLE"
        assert extraction["dependency"]
        assert stage(document, "root_discovery")["status"] == "UNAVAILABLE"

        # The wrapper was still identified: this is a useful partial report.
        nodes = document["image_map"]["nodes"]
        assert nodes[0]["format"] == "gzip"
        assert nodes[0]["length"] == 4_451_127
        assert nodes[1]["format"] == "squashfs"
        assert nodes[1]["extent_bytes"] == 4_348_264

        # Findings that do not need the filesystem are still reported.
        assert isinstance(document["findings"], list)
        assert document["risk_score"] is None


# ──────────────────────────────────────────────
# Row 3: the backend is present but failing — exit 4, scratch released, retry
# ──────────────────────────────────────────────


class TestFailingBackend:
    def test_corrupt_payload_exits_4_and_a_retry_succeeds(
        self, runner: Runner, runtime: str, workdir: Path
    ) -> None:
        tree = make_controlled_tree(workdir / "tree")
        good = build_image(tree, workdir / "good.img.gz", runtime)

        # Corrupt the filesystem inside a valid gzip wrapper: the helper now has
        # a backend, and that backend fails. The damaged range is inside the
        # extent the superblock declares, not in the wrapper's padding -- the
        # decoder never reads the padding, so corrupting it would prove nothing.
        payload = bytearray(gzip.decompress(good.read_bytes()))
        bytes_used = int.from_bytes(payload[40:48], "little")
        payload[bytes_used - 64 : bytes_used] = b"\xff" * 64
        broken = workdir / "broken.img.gz"
        broken.write_bytes(gzip.compress(bytes(payload), mtime=0))

        exit_code, document, output = scan(runner, workdir, broken)
        assert document is not None, output
        assert exit_code == 4, output
        assert document["outcome"]["exit_reason"] == "INCOMPLETE_ANALYSIS"
        assert document["extraction"]["state"] in (
            "HELPER_FAILED",
            "CORRUPT_INPUT",
            "EMPTY_OUTPUT",
        )
        assert stage(document, "extraction")["status"] == "FAILED"
        assert not document["assessment"]["missing_required_dependencies"]

        # The scratch directory was released: no extracted tree survives anywhere
        # under the scan's output directory.
        assert not list(workdir.rglob("scratch/extract/rootfs"))

        # Retry with the good image: the same command now completes.
        retry_exit, retry, retry_output = scan(runner, workdir, good)
        assert retry is not None, retry_output
        assert retry_exit in (0, 2), retry_output
        assert retry["assessment"]["completion"] == "COMPLETE"
        assert retry["opkg"]["installed"] == 3

    def test_nonzero_helper_exit_exits_4(
        self, runner: Runner, runtime: str, reference_image: Path, workdir: Path
    ) -> None:
        """A helper that exits non-zero after decoding starts is a failure, not a gap."""
        exit_code, document, output = scan(
            runner,
            workdir,
            reference_image,
            env={"IHS_TEST_FAULTS": "extraction-nonzero"},
        )
        assert document is not None, output
        assert exit_code == 4, output
        assert document["extraction"]["state"] == "HELPER_FAILED"
        assert "exited 99" in " ".join(document["extraction"]["errors"])
        assert stage(document, "extraction")["status"] == "FAILED"
        assert not document["assessment"]["missing_required_dependencies"]

    def test_quota_breach_exits_4(
        self, runner: Runner, runtime: str, reference_image: Path, workdir: Path
    ) -> None:
        exit_code, document, output = scan(
            runner,
            workdir,
            reference_image,
            env={"IOT_HARDWARE_SCANNER_MAX_EXTRACTED_BYTES_MB": "1"},
        )
        assert document is not None, output
        assert exit_code == 4, output
        assert document["extraction"]["state"] == "QUOTA_EXCEEDED"
        assert stage(document, "extraction")["status"] == "FAILED"
        assert not list(workdir.rglob("scratch/extract/rootfs"))

    def test_timeout_exits_4_and_releases_scratch(
        self, runner: Runner, runtime: str, reference_image: Path, workdir: Path
    ) -> None:
        exit_code, document, output = scan(
            runner,
            workdir,
            reference_image,
            env={
                "IHS_TEST_FAULTS": "extraction-timeout",
                "IOT_HARDWARE_SCANNER_EXTRACTION_TIMEOUT_SECONDS": "5",
            },
        )
        assert document is not None, output
        assert exit_code == 4, output
        assert document["extraction"]["state"] == "TIMEOUT"
        assert not list(workdir.rglob("scratch/extract/rootfs"))


# ──────────────────────────────────────────────
# Row 4 + 5: tree/image equivalence, and no extraction prerequisite for a tree
# ──────────────────────────────────────────────


class TestTreeAndImage:
    def test_staged_tree_and_image_from_it_agree_on_file_findings(
        self, runner: Runner, runtime: str, workdir: Path
    ) -> None:
        tree = make_controlled_tree(workdir / "tree")
        image = build_image(tree, workdir / "tree.img.gz", runtime)

        tree_exit, tree_doc, tree_output = scan(runner, workdir, tree, "--input-tree")
        image_exit, image_doc, image_output = scan(runner, workdir, image)
        assert tree_doc is not None, tree_output
        assert image_doc is not None, image_output

        assert normalised_findings(tree_doc) == normalised_findings(image_doc)

        # Stated differences, limited to boot/image evidence and coordinates.
        assert tree_doc["artifact"]["kind"] == "tree"
        assert image_doc["artifact"]["kind"] == "file"
        assert tree_doc["image_map"] is None
        assert image_doc["image_map"]["nodes"][0]["format"] == "gzip"
        assert image_doc["inventory"]["boot_evidence"]
        assert tree_doc["inventory"]["boot_evidence"]
        assert image_doc["inventory"]["metadata_source"] == "image"
        assert tree_doc["inventory"]["metadata_source"] == "host"
        assert tree_exit in (0, 2) and image_exit in (0, 2)

    def test_tree_profile_has_no_extraction_prerequisite(
        self, runner: Runner, workdir: Path
    ) -> None:
        tree = make_controlled_tree(workdir / "tree")

        exit_code, document, output = scan(
            runner, workdir, tree, "--input-tree", "--worker", "none"
        )
        assert document is not None, output
        assert exit_code in (0, 2), output
        assert document["assessment"]["completion"] == "COMPLETE"
        assert document["assessment"]["missing_required_dependencies"] == []
        assert document["assessment"]["profile"] == "firmware-tree"
        assert stage(document, "extraction")["status"] == "NOT_APPLICABLE"
        assert stage(document, "extraction")["required"] is False
        assert stage(document, "root_discovery")["required"] is False


# ──────────────────────────────────────────────
# Row 6: replaced build output between ingest and analysis
# ──────────────────────────────────────────────


class TestReplacedBuildOutput:
    def test_new_bytes_are_never_attributed_to_the_old_digest(
        self, runner: Runner, reference_image: Path, workdir: Path
    ) -> None:
        original = workdir / "firmware.img.gz"
        shutil.copy(reference_image, original)
        original_digest = REFERENCE_SHA256

        exit_code, document, output = scan(
            runner,
            workdir,
            original,
            env={"IHS_TEST_FAULTS": "replace-input-after-ingest"},
        )
        assert document is not None, output

        # The scan is marked incomplete ...
        assert exit_code == 4, output
        assert document["assessment"]["completion"] == "INCOMPLETE"
        # ... it still names the artifact it was asked about ...
        assert document["artifact"]["sha256"] == original_digest
        assert any(
            "bound" in reason or "changed" in reason
            for reason in document["assessment"]["incomplete_reasons"]
        )
        # ... and nothing was analysed from the replacement.
        assert document["opkg"] is None
        assert document["elf"]["parsed"] == 0
        assert stage(document, "extraction")["status"] == "UNAVAILABLE"

    def test_the_snapshot_stays_in_use_when_the_source_moves_later(
        self, runner: Runner, runtime: str, reference_image: Path, workdir: Path
    ) -> None:
        """The other documented outcome: the original bytes are what was analysed."""
        original = workdir / "firmware.img.gz"
        shutil.copy(reference_image, original)

        exit_code, document, output = scan(
            runner,
            workdir,
            original,
            env={"IHS_TEST_FAULTS": "replace-input-after-bind"},
        )
        assert document is not None, output

        # The scan completed on the snapshot that was verified at ingest. The
        # image's empty root password field makes the exit 1, not 0: the point
        # here is that the analysed bytes are the original ones.
        assert exit_code == 1, output
        assert document["assessment"]["completion"] == "COMPLETE"
        assert document["artifact"]["sha256"] == REFERENCE_SHA256
        assert document["input_binding"]["source_changed"] is True
        assert document["input_binding"]["verified_sha256"] == REFERENCE_SHA256
        # ... and the inventory is the original image's, not the replacement's.
        assert document["opkg"]["installed"] == 196
        assert any(
            "changed after ingest" in limitation
            for limitation in document["assessment"]["limitations"]
        )


# ──────────────────────────────────────────────
# Row 8: budgets measured on a sparse 2 GiB input
# ──────────────────────────────────────────────

_LAUNCHER = r"""
import json, resource, subprocess, sys, time
argv = json.loads(sys.argv[1])
started = time.monotonic()
completed = subprocess.run(argv)
elapsed = time.monotonic() - started
usage = resource.getrusage(resource.RUSAGE_CHILDREN)
print(json.dumps({
    "exit": completed.returncode,
    "elapsed_seconds": round(elapsed, 2),
    "peak_rss": float(usage.ru_maxrss),
    "peak_rss_units": "KiB" if sys.platform != "darwin" else "bytes",
}))
"""


class TestBudgets:
    def test_peak_rss_elapsed_and_scratch_on_a_sparse_two_gibibyte_input(
        self, runner: Runner, workdir: Path
    ) -> None:
        target = workdir / "sparse-2g.bin"
        with target.open("wb") as handle:
            handle.truncate(2 * 1024 * 1024 * 1024)
        assert target.stat().st_size == 2 * 1024 * 1024 * 1024

        runs: dict[str, dict] = {}
        for label, arguments, env in (
            (
                "sampled",
                ["entropy", str(target), "--format", "json"],
                {},
            ),
            (
                "whole_image",
                ["entropy", str(target), "--format", "json", "--block-size", "16777216"],
                {"IOT_HARDWARE_SCANNER_MAX_ENTROPY_SCAN_SIZE_MB": "4096"},
            ),
        ):
            command = [*runner.argv_prefix, *arguments]
            completed = runner(
                ["--version"], cwd=workdir
            )  # keeps the entrypoint warm and proves it runs
            assert completed.returncode == 0
            measurement = subprocess.run(
                [sys.executable, "-c", _LAUNCHER, json.dumps(command)],
                cwd=str(workdir),
                env={
                    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                    "HOME": str(workdir),
                    "PYTHONPATH": os.environ.get("PYTHONPATH", ""),
                    **env,
                },
                capture_output=True,
                text=True,
                timeout=900,
                check=False,
            )
            assert measurement.returncode == 0, measurement.stderr
            payload = json.loads(measurement.stdout.strip().splitlines()[-1])
            assert payload["exit"] == 0, measurement.stdout[-2000:]
            runs[label] = payload

        scan_exit, document, output = scan(runner, workdir, target, "--worker", "none")
        assert document is not None, output
        assert scan_exit in (4, 5)
        scratch_bytes = sum(
            path.stat().st_size for path in (workdir / "reports").rglob("*") if path.is_file()
        )

        record = {
            "input": {"bytes": 2 * 1024 * 1024 * 1024, "sparse": True},
            "machine": {"platform": sys.platform, "python": sys.version.split()[0]},
            "settings": {
                "max_entropy_scan_size_mb_sampled_run": 256,
                "max_entropy_scan_size_mb_whole_run": 4096,
                "block_size_whole_run": 16 * 1024 * 1024,
            },
            "sampled_run": runs["sampled"],
            "whole_image_run": runs["whole_image"],
            "scan_exit_with_worker_off": scan_exit,
            "scratch_bytes": scratch_bytes,
        }
        (workdir / "budgets.json").write_text(json.dumps(record, indent=2))
        print(json.dumps(record, indent=2))

        # The measurement is the point; this only guards against a regression
        # that would pull the input into memory.
        assert runs["sampled"]["elapsed_seconds"] < 120
        assert runs["whole_image"]["elapsed_seconds"] < 300
        assert scratch_bytes < 64 * 1024 * 1024


# ──────────────────────────────────────────────
# Milestone C rows: typed destinations, honest controls, offline advisories
# ──────────────────────────────────────────────


ADVISORY_SNAPSHOT = {
    "schema": "ihs-advisory-snapshot/1",
    "provider": "nvd",
    "acquired_at": "2026-11-01T00:00:00+00:00",
    "kev": {"source": "cisa-kev-sample", "cves": ["CVE-2024-0001"]},
    "advisories": [
        {
            "cve_id": "CVE-2024-0001",
            "description": "recorded provider response: busybox heap overflow",
            "published": "2024-01-10T00:00:00",
            "last_modified": "2024-02-01T00:00:00",
            "provider_score": 9.8,
            "provider_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "matches": [
                {
                    "cpe": "cpe:2.3:a:busybox:busybox:1.36.1-r2:*:*:*:*:*:*:*",
                    "vulnerable": True,
                }
            ],
        }
    ],
    "lookups": [],
}


class TestReleasedDetectionSemantics:
    def test_the_rule_set_is_identified_and_compiled_once(
        self, runner: Runner, runtime: str, reference_image: Path, workdir: Path
    ) -> None:
        """One compile, one digest, and every destination present."""
        exit_code, document, output = scan(runner, workdir, reference_image)
        assert document is not None, output
        ruleset = document["ruleset"]
        assert ruleset is not None
        assert len(ruleset["digest"]) == 64
        assert ruleset["compile_errors"] == []
        assert len(ruleset["rule_files"]) >= 12
        destinations = {
            destination
            for record in ruleset["rule_files"]
            for destination in record["destinations"]
        }
        assert destinations == {"credential", "service", "crypto", "indicator"}
        assert all(len(record["sha256"]) == 64 for record in ruleset["rule_files"])

        # Every finding names the rule identity and the set it came from.
        for finding in document["findings"]:
            assert finding["destination"] in {
                "credential",
                "service",
                "crypto",
                "indicator",
                "advisory",
            }
            if finding["destination"] in {"credential", "service", "crypto", "indicator"}:
                assert finding["ruleset_digest"] in ("", ruleset["digest"])
        assert exit_code == 1, output

    def test_the_reference_image_raises_no_indicator_noise(
        self, runner: Runner, runtime: str, reference_image: Path, workdir: Path
    ) -> None:
        """The eleven false positives measured in Milestone B are gone.

        The corpus is the negative control: a stock OpenWrt image must not
        produce a C2 domain or malware-signature finding. The one review finding
        that remains is a true observation (DES implementation code in mbedTLS).
        """
        exit_code, document, output = scan(runner, workdir, reference_image)
        assert document is not None, output
        indicators = [f for f in document["findings"] if f["category"] == "c2_indicator"]
        assert indicators == [], [f["rule_id"] for f in indicators]

        critical = [f for f in document["findings"] if f["critical_qualified"]]
        assert [f["rule_id"] for f in critical] == ["credential.unix.empty_password"]
        assert exit_code == 1, output

        # The suppressions are reported as coverage, not silently dropped.
        c2_stage = stage(document, "c2_indicators")
        assert c2_stage["status"] == "COMPLETE"
        assert any("rejected" in omission for omission in c2_stage["omissions"])

    def test_control_8_has_an_evidence_source_on_the_reference_image(
        self, runner: Runner, runtime: str, reference_image: Path, workdir: Path
    ) -> None:
        _exit_code, document, output = scan(runner, workdir, reference_image)
        assert document is not None, output
        crypto = next(c for c in document["controls"] if c["control_id"] == 8)
        assert crypto["status"] == "PERFORMED", crypto["evidence"]
        assert crypto["result"] in ("REVIEW", "FAIL")
        assert crypto["required_source"]
        assert crypto["question"]
        # It is not hardening evidence, and hardening is its own check.
        assert any("not proof" in item or "presence" in item for item in crypto["evidence"])
        hardening = next(c for c in document["controls"] if c["control_id"] == 10)
        assert hardening["control_id"] != crypto["control_id"]

    def test_an_offline_advisory_snapshot_is_assessed(
        self, runner: Runner, runtime: str, reference_image: Path, workdir: Path
    ) -> None:
        snapshot_path = workdir / "advisory.json"
        snapshot_path.write_text(json.dumps(ADVISORY_SNAPSHOT, indent=2))

        exit_code, document, output = scan(
            runner,
            workdir,
            reference_image,
            "--advisory-snapshot",
            str(snapshot_path),
        )
        assert document is not None, output

        advisory = document["advisory"]
        assert advisory is not None
        assert advisory["state"] == "ASSESSED"
        assert advisory["matched"] == 1
        assert advisory["kev_matches"] == 1
        assert advisory["snapshot"]["digest_sha256"]
        assert advisory["snapshot"]["provider"] == "nvd"
        assert advisory["lookups"], "no component was looked up"

        finding = next(f for f in document["findings"] if f["category"] == "advisory")
        assert finding["rule_id"] == "advisory.CVE-2024-0001"
        assert finding["destination"] == "advisory"
        assert any("applicability=cpe-exact" in item for item in finding["evidence"])
        assert any("kev=True" in item for item in finding["evidence"])

        advisory_stage = stage(document, "advisory")
        assert advisory_stage["status"] == "COMPLETE"
        assert advisory_stage["required"] is True
        control_3 = next(c for c in document["controls"] if c["control_id"] == 3)
        assert control_3["status"] == "PERFORMED"
        assert control_3["result"] == "FAIL"
        assert exit_code == 1, output

    def test_without_a_snapshot_advisory_stays_unassessed(
        self, runner: Runner, runtime: str, reference_image: Path, workdir: Path
    ) -> None:
        exit_code, document, output = scan(runner, workdir, reference_image)
        assert document is not None, output
        assert document["advisory"] is None
        advisory_stage = stage(document, "advisory")
        assert advisory_stage["status"] == "SKIPPED"
        assert advisory_stage["required"] is False
        control_3 = next(c for c in document["controls"] if c["control_id"] == 3)
        assert control_3["status"] == "OMITTED"
        assert control_3["result"] == "UNKNOWN"
        assert exit_code == 1, output


# ──────────────────────────────────────────────
# Milestone D — release comparison and declaration reconciliation
# ──────────────────────────────────────────────

#: Environment variables for the frozen OpenWrt declarations. The suite never
#: downloads them: the qualified CI job fetches each one, checks it against the
#: publisher's index, and only then hands it over.
MANIFEST_ENV = "IHS_REFERENCE_MANIFEST"
SBOM_ENV = "IHS_REFERENCE_SBOM"


def scan_to(
    runner: Runner,
    work: Path,
    target: Path,
    out_name: str,
    *extra: str,
    env: dict[str, str] | None = None,
) -> tuple[int, dict | None, Path, str]:
    """Run one scan to a named report, returning the path as well as the document."""
    out = work / out_name
    completed = runner(
        ["scan", str(target), "--offline", "--format", "json", "--out", str(out), *extra],
        cwd=work,
        env={**_daemon_env(), **(env or {})},
    )
    document = json.loads(out.read_text()) if out.is_file() else None
    return completed.returncode, document, out, completed.stdout + completed.stderr


def compare(
    runner: Runner,
    work: Path,
    base_report: Path,
    target_report: Path,
    *declarations: Path,
    out_name: str = "comparison.json",
) -> tuple[int, dict | None, str]:
    """Run the comparison command and return its exit, document and output."""
    out = work / out_name
    arguments = [
        "compare",
        str(base_report),
        str(target_report),
        "--format",
        "json",
        "--out",
        str(out),
    ]
    for declaration in declarations:
        arguments += ["--declaration", str(declaration)]
    completed = runner(arguments, cwd=work, env=_daemon_env())
    document = json.loads(out.read_text()) if out.is_file() else None
    return completed.returncode, document, completed.stdout + completed.stderr


def release_tree(
    root: Path,
    *,
    busybox_version: str,
    locked_root: bool,
    tool_directory: str,
) -> Path:
    """One generated release: accounts, boot, two ELFs and an opkg database."""
    (root / "etc").mkdir(parents=True)
    (root / "bin").mkdir(parents=True)
    (root / "usr" / "lib" / "opkg").mkdir(parents=True)
    (root / tool_directory).mkdir(parents=True, exist_ok=True)
    (root / "etc" / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/ash\nuser:x:1000:1000:user:/home/user:/bin/ash\n"
    )
    root_shadow = "root:!$6$salt$hash:19000:0:99999:7:::" if locked_root else "root::0:0:99999:7:::"
    (root / "etc" / "shadow").write_text(f"{root_shadow}\nuser:$6$salt$hash:19000:0:99999:7:::\n")
    (root / "etc" / "inittab").write_text(
        "::sysinit:/etc/init.d/rcS\n::respawn:/usr/sbin/sshd -D\n"
    )
    status = (
        "Package: base-files\nVersion: 1589~0123456789\n"
        "Status: install user installed\nArchitecture: aarch64_generic\n\n"
        f"Package: busybox\nVersion: {busybox_version}\n"
        "Status: install user installed\nArchitecture: aarch64_generic\n\n"
        "Package: libc\nVersion: 1.2.5-r4\n"
        "Status: install user installed\nArchitecture: aarch64_generic\n"
    )
    (root / "usr" / "lib" / "opkg" / "status").write_text(status)
    write_fixture(root / "bin" / "busybox", ElfSpec())
    # The same bytes in both releases, in a different directory: a component
    # that moved is the same component.
    write_fixture(
        root / tool_directory / "tool",
        ElfSpec(build_id=b"\x01\x02\x03\x04\x05\x06\x07\x08"),
    )
    return root


@pytest.fixture(scope="session")
def generated_pair(runner: Runner, runtime: str) -> tuple[Path, dict, Path, dict]:
    """Two generated release images, scanned through the installed CLI.

    Release A: busybox 1.36.1-r2, an empty root password, the helper at
    ``usr/lib/tool``, scanned with an advisory snapshot.
    Release B: busybox 1.36.1-r3, root locked, the helper at ``usr/bin/tool``,
    scanned without a snapshot — so its advisory question was not asked.
    """
    base = Path.home() / ".cache" / "ihs-acceptance" / f"pair-{uuid.uuid4().hex[:10]}"
    base.mkdir(parents=True)
    try:
        tree_a = release_tree(
            base / "tree-a",
            busybox_version="1.36.1-r2",
            locked_root=False,
            tool_directory="usr/lib",
        )
        tree_b = release_tree(
            base / "tree-b",
            busybox_version="1.36.1-r3",
            locked_root=True,
            tool_directory="usr/bin",
        )
        (base / "a").mkdir()
        (base / "b").mkdir()
        image_a = build_image(tree_a, base / "a" / "release-a.img.gz", runtime)
        image_b = build_image(tree_b, base / "b" / "release-b.img.gz", runtime)
        snapshot = base / "advisory.json"
        snapshot.write_text(json.dumps(ADVISORY_SNAPSHOT, indent=2))

        exit_a, document_a, report_a, output_a = scan_to(
            runner, base, image_a, "release-a.json", "--advisory-snapshot", str(snapshot)
        )
        assert document_a is not None, output_a
        _exit_b, document_b, report_b, output_b = scan_to(runner, base, image_b, "release-b.json")
        assert document_b is not None, output_b
        assert document_a["assessment"]["completion"] == "COMPLETE", output_a
        assert document_b["assessment"]["completion"] == "COMPLETE", output_b
        assert exit_a == 1, output_a  # the empty root password is critical
        yield report_a, document_a, report_b, document_b
    finally:
        shutil.rmtree(base, ignore_errors=True)


class TestTwoReleaseComparison:
    """Slice 5B: what changed between two released images."""

    def test_a_generated_pair_distinguishes_the_change_kinds(
        self, runner: Runner, generated_pair: tuple[Path, dict, Path, dict], workdir: Path
    ) -> None:
        from iot_hardware_scanner.scanner.comparison import COMPARISON_SCHEMA
        from iot_hardware_scanner.scanner.report_document import SCHEMA_VERSION

        report_a, document_a, report_b, document_b = generated_pair
        # Ground truth, read from the two scans themselves.
        base_rules = {finding["rule_id"] for finding in document_a["findings"]}
        target_rules = {finding["rule_id"] for finding in document_b["findings"]}
        assert "credential.unix.empty_password" in base_rules
        assert "advisory.CVE-2024-0001" in base_rules
        assert "credential.unix.empty_password" not in target_rules
        assert document_a["schema_version"] == SCHEMA_VERSION

        exit_code, comparison, output = compare(
            runner, workdir, report_a, report_b, out_name="pair-comparison.json"
        )
        assert comparison is not None, output
        assert exit_code == 2, output
        assert comparison["schema_version"] == COMPARISON_SCHEMA

        # 1. A real package change, from the package records themselves.
        packages = comparison["packages"]
        assert [entry["name"] for entry in packages["changed"]] == ["busybox"]
        assert packages["changed"][0]["base_versions"] == ["1.36.1-r2"]
        assert packages["changed"][0]["target_versions"] == ["1.36.1-r3"]
        assert packages["base_names"] == 3
        assert packages["target_names"] == 3

        # 2. A removed finding, resolved because the detector settled both times.
        findings = comparison["findings"]
        assert [entry["rule_id"] for entry in findings["resolved"]] == [
            "credential.unix.empty_password"
        ]
        assert findings["by_destination"]["credential"]["comparable"] is True

        # 3. A coverage change is never a resolution.
        advisory = findings["by_destination"]["advisory"]
        assert advisory["comparable"] is False
        assert findings["counts"]["indeterminate"] == 1
        assert findings["indeterminate"][0]["rule_id"] == "advisory.CVE-2024-0001"
        coverage = comparison["environment"]["coverage_changes"]
        assert any(
            change["stage"] == "advisory" and change["target"]["status"] == "SKIPPED"
            for change in coverage
        )
        # The instruments are reported before any difference is interpreted.
        assert comparison["environment"]["comparison"]["scanner_version"]["changed"] is False
        assert comparison["comparability"]["status"] == "partial"

        # 4. A relocated identical component is recognised by identity.
        layout = comparison["layout"]
        assert layout["counts"]["relocated"] == 1
        relocated = layout["relocated"][0]
        assert any("usr/lib/tool" in location for location in relocated["base_locations"])
        assert any("usr/bin/tool" in location for location in relocated["target_locations"])
        assert layout["counts"]["new"] == 0
        assert layout["counts"]["removed"] == 0

    def test_the_comparison_renders_without_re_reading_the_images(
        self, runner: Runner, generated_pair: tuple[Path, dict, Path, dict], workdir: Path
    ) -> None:
        report_a, _document_a, report_b, _document_b = generated_pair
        completed = runner(
            ["compare", str(report_a), str(report_b)], cwd=workdir, env=_daemon_env()
        )
        assert completed.returncode == 2, completed.stdout + completed.stderr
        assert "Release comparison" in completed.stdout
        assert "Instruments (read before any difference)" in completed.stdout
        assert "changed busybox: 1.36.1-r2 → 1.36.1-r3" in completed.stdout
        assert "resolved credential.unix.empty_password" in completed.stdout
        assert "indeterminate advisory.CVE-2024-0001" in completed.stdout
        # Indeterminate is stated, never folded into "resolved".
        assert "resolved advisory" not in completed.stdout


class TestDeclarationReconciliation:
    """Slice 5D: the build declaration against the shipped bytes."""

    def test_one_matching_one_mismatch_one_declared_only_one_observed_only(
        self, runner: Runner, generated_pair: tuple[Path, dict, Path, dict], workdir: Path
    ) -> None:
        _report_a, _document_a, report_b, document_b = generated_pair
        declaration = workdir / "release-b.manifest"
        declaration.write_text(
            "base-files - 1589~0123456789\n"  # agreement
            "libc - 1.2.5-r5\n"  # declared version differs from the image
            "ghost-pkg - 1.0-r1\n"  # declared and absent from the image
        )
        exit_code, comparison, output = compare(
            runner, workdir, report_b, report_b, declaration, out_name="declared.json"
        )
        assert comparison is not None, output
        entry = comparison["declarations"][0]
        assert entry["kind"] == "openwrt-target-manifest"
        assert entry["binding"]["status"] == "unclaimed"
        assert entry["scope"]["declared_rows"] == 3
        assert entry["scope"]["observed_rows"] == 3
        assert entry["outcomes"] == {
            "agreement": 1,
            "unresolved-revision": 0,
            "version-conflict": 1,
            "declared-only": 1,
            "observed-only": 1,  # busybox is in the image and not declared
            "unbound": 0,
        }
        # The image itself did not change: the only differences are declaration
        # facts, which is what a declaration-only change is.
        assert comparison["packages"]["counts"]["changed"] == 0
        assert exit_code == 2, output
        # Every observed record keeps its provenance.
        assert (
            entry["observed_provenance"]["database_sha256"]
            == (document_b["opkg"]["database_sha256"])
        )
        assert entry["observed_only"][0]["name"] == "busybox"
        assert entry["observed_only"][0]["evidence"]["start"] >= 0

    def test_a_revision_less_supplier_row_is_unresolved_and_markdown_says_so(
        self, runner: Runner, generated_pair: tuple[Path, dict, Path, dict], workdir: Path
    ) -> None:
        _report_a, _document_a, report_b, document_b = generated_pair
        supplier = workdir / "supplier.cdx.json"
        supplier.write_text(
            json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.4",
                    "version": 1,
                    "components": [{"type": "application", "name": "busybox", "version": "1.36.1"}],
                }
            )
        )
        _exit_code, comparison, output = compare(
            runner, workdir, report_b, report_b, supplier, out_name="supplier.json"
        )
        assert comparison is not None, output
        entry = comparison["declarations"][0]
        assert entry["kind"] == "cyclonedx"
        assert entry["spec_version"] == "1.4"
        assert entry["outcomes"]["unresolved-revision"] == 1
        assert entry["outcomes"]["version-conflict"] == 0
        assert entry["rows"][0]["declared_version"] == "1.36.1"
        assert entry["rows"][0]["observed_version"] == "1.36.1-r3"

        rendered = runner(
            [
                "compare",
                str(report_b),
                str(report_b),
                "--declaration",
                str(supplier),
                "--format",
                "markdown",
            ],
            cwd=workdir,
            env=_daemon_env(),
        )
        # Two packages in the image are not declared at all, and the supplier's
        # BusyBox row stops short of the revision: differences, plus one row that
        # is unresolved rather than a mismatch.
        assert rendered.returncode == 2, rendered.stdout + rendered.stderr
        assert "unresolved-revision" in rendered.stdout
        assert "observed-only" in rendered.stdout
        assert document_b["artifact"]["sha256"]

    def test_a_declaration_for_another_image_resolves_nothing(
        self, runner: Runner, generated_pair: tuple[Path, dict, Path, dict], workdir: Path
    ) -> None:
        _report_a, _document_a, report_b, _document_b = generated_pair
        other = workdir / "other-image.cdx.json"
        other.write_text(
            json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.4",
                    "version": 1,
                    "metadata": {
                        "component": {
                            "type": "firmware",
                            "name": "some other image",
                            "hashes": [{"alg": "SHA-256", "content": "0" * 64}],
                        }
                    },
                    "components": [
                        {"type": "application", "name": "busybox", "version": "1.36.1-r3"},
                        {"type": "application", "name": "libc", "version": "9.9"},
                    ],
                }
            )
        )
        exit_code, comparison, output = compare(
            runner, workdir, report_b, report_b, other, out_name="other-image.json"
        )
        assert comparison is not None, output
        entry = comparison["declarations"][0]
        assert entry["binding"]["status"] == "mismatched"
        assert entry["outcomes"]["unbound"] == 2
        assert entry["outcomes"]["agreement"] == 0
        assert entry["outcomes"]["version-conflict"] == 0
        assert entry["observed_only"] == []
        # Only the binding is reported; nothing was resolved from it.
        assert exit_code == 4, output


@pytest.fixture(scope="session")
def reference_declarations() -> tuple[Path, Path]:
    """The frozen OpenWrt manifest and supplier SBOM, if the operator staged them."""
    manifest = os.environ.get(MANIFEST_ENV)
    sbom = os.environ.get(SBOM_ENV)
    if not manifest or not sbom:
        pytest.skip(
            f"{MANIFEST_ENV}/{SBOM_ENV} not set: declaration reconciliation on the "
            "published image unverified"
        )
    for path in (manifest, sbom):
        if not Path(path).is_file():
            pytest.skip(f"declaration not found at {path}")
    return Path(manifest), Path(sbom)


@pytest.fixture(scope="session")
def reference_scan(runner: Runner, runtime: str) -> dict:
    """One scan of the pinned image, shared by the milestone D rows."""
    configured = os.environ.get("IHS_REFERENCE_IMAGE")
    if not configured or not Path(configured).is_file():
        pytest.skip("IHS_REFERENCE_IMAGE not set: reference-image checks unverified")
    base = Path.home() / ".cache" / "ihs-acceptance" / f"reference-d-{uuid.uuid4().hex[:8]}"
    base.mkdir(parents=True)
    try:
        exit_code, document, report, output = scan_to(
            runner, base, Path(configured), "reference.json"
        )
        assert document is not None, output
        assert document["assessment"]["completion"] == "COMPLETE", output
        yield {"document": document, "report": report, "exit": exit_code, "dir": base}
    finally:
        shutil.rmtree(base, ignore_errors=True)


class TestReferenceDeclarationReconciliation:
    """The published OpenWrt case: 196 image records against 124 declared rows."""

    def test_the_real_comparison_keeps_every_record_and_the_72_image_only_rows(
        self,
        runner: Runner,
        reference_scan: dict,
        reference_declarations: tuple[Path, Path],
        workdir: Path,
    ) -> None:
        manifest, supplier = reference_declarations
        document = reference_scan["document"]
        exit_code, comparison, output = compare(
            runner,
            workdir,
            reference_scan["report"],
            reference_scan["report"],
            manifest,
            supplier,
            out_name="openwrt-declaration.json",
        )
        assert comparison is not None, output
        # The image did not change; the supplier declaration does not agree with
        # the opkg names, so the comparison reports differences, not a clean run.
        assert exit_code == 2, output

        # Every image record is preserved, and the package identity is the record.
        assert len(document["opkg"]["records"]) == 196
        assert comparison["packages"]["base_names"] == 196
        assert comparison["packages"]["target_names"] == 196

        by_kind = {entry["kind"]: entry for entry in comparison["declarations"]}
        target_manifest = by_kind["openwrt-target-manifest"]
        assert target_manifest["scope"]["declared_rows"] == 124
        assert len(target_manifest["rows"]) == 124
        assert target_manifest["outcomes"]["agreement"] == 124
        assert target_manifest["outcomes"]["observed-only"] == 72
        assert target_manifest["outcomes"]["declared-only"] == 0
        assert target_manifest["outcomes"]["version-conflict"] == 0
        assert len(target_manifest["observed_only"]) == 72
        assert target_manifest["scope"]["observed_rows"] == 196
        assert target_manifest["observed_provenance"]["installed"] == 196
        assert target_manifest["observed_provenance"]["database_sha256"] == (
            "9442acbaf4ccc25115e770533ffe2b8a10d1c81e92d59b6d32035ba5ee6a3258"
        )
        # Proximity and release name cannot bind it: neither document names the
        # image digest, so both bindings are recorded as unverified.
        assert target_manifest["binding"]["status"] == "unclaimed"

        supplier_entry = by_kind["cyclonedx"]
        assert supplier_entry["spec_version"] == "1.4"
        assert supplier_entry["scope"]["declared_rows"] == 124
        # BusyBox is declared as 1.36.1 while the image records 1.36.1-r2: one
        # row unresolved at revision granularity, never a mismatch.
        busybox = next(row for row in supplier_entry["rows"] if row["name"] == "busybox")
        assert busybox["state"] == "unresolved-revision"
        assert busybox["declared_version"] == "1.36.1"
        assert busybox["observed_version"] == "1.36.1-r2"
        assert supplier_entry["outcomes"]["version-conflict"] == 0
        assert supplier_entry["binding"]["status"] == "unclaimed"
        assert target_manifest["digest_sha256"] == (
            "e5951c2355950b187ed154dd6f46547e3cac240937094502dd8b66afcc65fbff"
        )
        assert supplier_entry["digest_sha256"] == (
            "50ca09d781aeb7bda85eed0069d0853c0cde506f5e450667374283d6c296a068"
        )


class TestCycloneDXExport:
    """Slice 5A: the portable inventory, validated offline."""

    def test_the_reference_inventory_exports_and_validates(
        self, runner: Runner, reference_scan: dict, workdir: Path
    ) -> None:
        from iot_hardware_scanner.scanner.sbom_export import (
            CYCLONEDX_SPEC_VERSION,
            validate_sbom,
        )

        destination = workdir / "reference.cdx.json"
        completed = runner(
            [
                "sbom",
                str(reference_scan["report"]),
                "--out",
                str(destination),
                "--validate",
            ],
            cwd=workdir,
            env=_daemon_env(),
        )
        assert completed.returncode == 0, completed.stdout + completed.stderr
        payload = json.loads(destination.read_text())
        assert payload["bomFormat"] == "CycloneDX"
        assert payload["specVersion"] == CYCLONEDX_SPEC_VERSION
        validate_sbom(payload)

        document = reference_scan["document"]
        firmware = payload["metadata"]["component"]
        assert firmware["hashes"] == [{"alg": "SHA-256", "content": document["artifact"]["sha256"]}]
        assert len(payload["components"]) == len(document["components"]) == 196
        records = {component["evidence"]: component for component in document["components"]}
        for component in payload["components"]:
            properties = {item["name"]: item["value"] for item in component["properties"]}
            assert properties["ihs:firmware-sha256"] == document["artifact"]["sha256"]
            assert properties["ihs:cpe-basis"] in ("nist-mapped", "opkg-package-name")
            original = records[properties["ihs:evidence"]]
            assert component["bom-ref"].startswith("urn:ihs:component:")
            # The version is verbatim, and the CPE name is complete CPE 2.3.
            # A reserved character in a component is escaped, as the grammar
            # requires, so the escaped form is what the name carries.
            from iot_hardware_scanner.intelligence.cpe_builder import escape_component

            assert component["version"] == original["version"]
            assert component["cpe"].count(":") == 12
            assert component["cpe"].startswith("cpe:2.3:a:")
            assert escape_component(original["version"]) in component["cpe"]


# ──────────────────────────────────────────────
# Slice 3A, part 2: a disk image with two root filesystems
# ──────────────────────────────────────────────


class TestPartitionedImage:
    """The plan's 3A acceptance row, through the installed CLI.

    Two distinct root filesystems inside one GPT image, built by the pinned
    worker's own ``mksquashfs``; both must appear in the report, every partition
    range must be inside the image, and the same relative path in each root must
    stay distinguishable because it is qualified by its root id.
    """

    def test_two_roots_in_one_disk_are_mapped_and_distinguishable(
        self, runtime: str, workdir: Path, runner: Runner
    ) -> None:
        if not _mksquashfs_available():
            pytest.skip(
                f"the {WORKER_IMAGE} image carries no mksquashfs: a generated disk image "
                "cannot be built here"
            )

        # Two trees with the same relative path and different account state:
        # A is locked, B has an empty password on a login shell.
        tree_a = make_tree(workdir / "tree-a", "root:*:19000:0:99999:7:::\n")
        tree_b = make_tree(workdir / "tree-b", "root::19000:0:99999:7:::\n")
        image_a = _build_squashfs(runtime, workdir, tree_a, "a.squashfs")
        image_b = _build_squashfs(runtime, workdir, tree_b, "b.squashfs")

        first_lba = partition_fixtures.BASE_LBA
        second_lba = first_lba + (image_a.stat().st_size // 512) + 16
        disk_sectors = second_lba + (image_b.stat().st_size // 512) + 16
        disk = bytearray(
            partition_fixtures.gpt_image(
                [
                    (
                        first_lba,
                        image_a.stat().st_size // 512 + 1,
                        partition_fixtures.LINUX_GUID,
                        "rootfs-a",
                    ),
                    (
                        second_lba,
                        image_b.stat().st_size // 512 + 1,
                        partition_fixtures.LINUX_GUID,
                        "rootfs-b",
                    ),
                ],
                sectors=disk_sectors,
            )
        )
        for path, lba in ((image_a, first_lba), (image_b, second_lba)):
            start = lba * 512
            payload = path.read_bytes()
            disk[start : start + len(payload)] = payload
        disk_path = workdir / "two-roots.img"
        disk_path.write_bytes(bytes(disk))

        result = runner(
            ["scan", str(disk_path), "--offline", "--format", "json", "--out", "disk.json"],
            cwd=workdir,
            env=_daemon_env(),
        )
        document = json.loads((workdir / "disk.json").read_text())

        # 1. Both partitions are in the map, with byte coordinates in the image.
        nodes = document["image_map"]["nodes"]
        partitions = [node for node in nodes if node["format"] == "partition"]
        assert [node["artifact_id"] for node in partitions] == ["p1", "p2"]
        assert [node["details"]["label"] for node in partitions] == ["rootfs-a", "rootfs-b"]
        assert partitions[0]["coordinate_system"] == "container-bytes"
        assert partitions[0]["offset"] == first_lba * 512
        assert len({node["offset"] for node in partitions}) == 2
        for node in partitions:
            assert node["offset"] + node["length"] <= disk_path.stat().st_size
            assert node["details"]["content"] == "squashfs"

        # 2. Both roots were enumerated, and each is attributed to its partition.
        roots = document["inventory"]["roots"]
        assert len(roots) == 2
        assert {root["artifact_id"] for root in roots} == {"p1", "p2"}
        assert len({root["root_id"] for root in roots}) == 2

        # 3. The same relative path stays distinguishable: the empty-password
        #    finding names the root it was found in, not a bare etc/shadow.
        b_root = next(root for root in roots if root["artifact_id"] == "p2")
        empty = [
            f for f in document["findings"] if f["rule_id"] == "credential.unix.empty_password"
        ]
        assert empty, document["outcome"]
        assert all(
            location.startswith(f"{b_root['root_id']}/") for location in empty[0]["locations"]
        ), empty[0]["locations"]
        assert document["assessment"]["completion"] == "COMPLETE"
        assert result.returncode == 1


# ──────────────────────────────────────────────
# 3A part 3 — an initramfs is a filesystem nobody mounted
# ──────────────────────────────────────────────


class TestCpioInitramfs:
    """A CPIO initramfs, decoded in-process, through the installed CLI.

    None of these rows need a container runtime, and that is the claim: an
    initramfs is a sequence of headers, so the scanner can enumerate it on any
    host. A row that skipped here would leave the slice unqualified, which is
    why no case below is gated on ``runtime``.
    """

    def test_an_initramfs_is_decoded_in_process_and_enumerated(
        self, workdir: Path, runner: Runner
    ) -> None:
        image = workdir / "initramfs.cpio"
        image.write_bytes(initramfs(shadow=b"root::19000:0:99999:7:::\n"))
        result = runner(
            ["scan", str(image), "--offline", "--format", "json", "--out", "initramfs.json"],
            cwd=workdir,
        )
        document = json.loads((workdir / "initramfs.json").read_text())

        # 1. The label came from the bytes, not from the suffix.
        assert document["artifact"]["file_type_source"] == "magic-bytes"
        assert "CPIO" in document["artifact"]["file_type"]

        # 2. The container is mapped, and every member is a byte range in it.
        root = document["image_map"]["nodes"][0]
        assert root["format"] == "cpio"
        assert root["details"]["cpio_format"] == "newc"
        assert root["extent_bytes"] == image.stat().st_size
        members = document["image_map"]["nodes"][1:]
        assert {node["locator"] for node in members} >= {"etc/passwd", "etc/shadow", "bin/sh"}
        shadow_node = next(node for node in members if node["locator"] == "etc/shadow")
        assert shadow_node["coordinate_system"] == "container-bytes"
        assert (
            shadow_node["digest_sha256"]
            == hashlib.sha256(b"root::19000:0:99999:7:::\n").hexdigest()
        )

        # 3. No worker ran, and the document says which decoder did.
        extraction = document["extraction"]
        assert extraction["state"] == "OK"
        assert extraction["backend"] == "in-process"
        assert "worker" not in extraction
        stage = next(s for s in document["stages"] if s["stage"] == "extraction")
        assert "in-process newc decoder" in stage["reason"]
        assert "no worker" in stage["reason"]

        # 4. The filesystem was enumerated with archive-derived metadata, and the
        #    empty root password is a critical finding, not a 0-byte file.
        roots = document["inventory"]["roots"]
        assert len(roots) == 1
        assert roots[0]["metadata_source"] == "image"
        # Four regular names on disk, but ``bin/sh`` and ``bin/busybox.sh`` are one
        # inode: the inventory reconciles them, which is what "a hard link is one
        # file, however many names point at it" means.
        assert roots[0]["files"] == 3
        critical = [f for f in document["findings"] if f["critical_qualified"]]
        assert [f["rule_id"] for f in critical] == ["credential.unix.empty_password"]
        assert document["assessment"]["completion"] == "COMPLETE"
        assert result.returncode == 1

    def test_a_gzip_wrapped_initramfs_is_the_same_filesystem(
        self, workdir: Path, runner: Runner
    ) -> None:
        plain = initramfs(shadow=b"root::19000:0:99999:7:::\n")
        image = workdir / "initramfs.cpio.gz"
        image.write_bytes(gzip.compress(plain))

        result = runner(
            ["scan", str(image), "--offline", "--format", "json", "--out", "wrapped.json"],
            cwd=workdir,
        )
        document = json.loads((workdir / "wrapped.json").read_text())

        nodes = document["image_map"]["nodes"]
        assert [node["format"] for node in nodes[:2]] == ["gzip", "cpio"]
        assert nodes[1]["parent_id"] == nodes[0]["artifact_id"]
        assert nodes[1]["details"]["cpio_format"] == "newc"
        assert document["extraction"]["backend"] == "in-process"
        assert [f["rule_id"] for f in document["findings"] if f["critical_qualified"]] == [
            "credential.unix.empty_password"
        ]
        assert result.returncode == 1

    def test_the_odc_layout_is_not_read_as_newc(self, workdir: Path, runner: Runner) -> None:
        """Octal fields and no padding: a newc reader would produce garbage."""
        image = workdir / "initramfs.odc"
        image.write_bytes(initramfs(archive_format=ODC, shadow=b"root::19000:0:99999:7:::\n"))

        result = runner(
            ["scan", str(image), "--offline", "--format", "json", "--out", "odc.json"],
            cwd=workdir,
        )
        document = json.loads((workdir / "odc.json").read_text())

        root = document["image_map"]["nodes"][0]
        assert root["details"]["cpio_format"] == "odc"
        assert {node["locator"] for node in document["image_map"]["nodes"][1:]} >= {
            "etc/passwd",
            "etc/shadow",
        }
        assert [f["rule_id"] for f in document["findings"] if f["critical_qualified"]] == [
            "credential.unix.empty_password"
        ]
        assert result.returncode == 1

    def test_a_zero_length_hardlink_member_does_not_weaken_the_finding(
        self, workdir: Path, runner: Runner
    ) -> None:
        """The bytes live in one member of the group; every name carries them.

        A reader that takes ``filesize == 0`` literally reports a 0-byte
        ``/etc/shadow`` and misses the empty password. This is the row that
        proves the group is resolved.
        """
        image = workdir / "linked.cpio"
        image.write_bytes(
            build(
                [
                    cpio_fixtures.Member(name="etc", mode=cpio_fixtures.S_IFDIR | 0o755),
                    cpio_fixtures.Member(
                        name="etc/passwd", data=b"root:x:0:0:root:/root:/bin/sh\n"
                    ),
                    # The name a scan looks for is the *empty* member of the group.
                    *cpio_fixtures.hardlink_pair(
                        "var/lib/shadow",
                        "etc/shadow",
                        b"root::19000:0:99999:7:::\n",
                        ino=77,
                    ),
                ]
            )
        )

        result = runner(
            ["scan", str(image), "--offline", "--format", "json", "--out", "linked.json"],
            cwd=workdir,
        )
        document = json.loads((workdir / "linked.json").read_text())

        nodes = {node["locator"]: node for node in document["image_map"]["nodes"][1:]}
        assert nodes["etc/shadow"]["digest_sha256"] == nodes["var/lib/shadow"]["digest_sha256"]
        assert nodes["etc/shadow"]["length"] == len(b"root::19000:0:99999:7:::\n")

        finding = next(
            f for f in document["findings"] if f["rule_id"] == "credential.unix.empty_password"
        )
        assert any("etc/shadow" in location for location in finding["locations"]), finding[
            "locations"
        ]
        assert result.returncode == 1

    def test_a_truncated_archive_is_exit_4_and_no_traceback(
        self, workdir: Path, runner: Runner
    ) -> None:
        image = workdir / "truncated.cpio"
        payload = initramfs()
        image.write_bytes(payload[: len(payload) // 2])

        result = runner(
            ["scan", str(image), "--offline", "--format", "json", "--out", "truncated.json"],
            cwd=workdir,
        )
        document = json.loads((workdir / "truncated.json").read_text())

        assert result.returncode == 4
        assert "Traceback" not in result.stderr
        stage = next(s for s in document["stages"] if s["stage"] == "extraction")
        assert stage["status"] == "FAILED"
        assert "CPIO archive is not decodable" in stage["reason"]
        assert document["assessment"]["completion"] != "COMPLETE"
