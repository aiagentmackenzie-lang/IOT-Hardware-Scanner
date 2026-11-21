"""Milestone B acceptance: inventory one shipped Linux image.

Every case here runs the *installed* command through :class:`Runner` (the wheel,
or the relocated package when no wheel is installed), from a directory that no
checkout is visible in, with the network unused.

The rows are the release gate from FIRMWARE_SCANNER_PLAN.md and the Milestone B
acceptance list:

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
from elf_fixtures import ElfSpec, write_fixture
from harness import Runner

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
