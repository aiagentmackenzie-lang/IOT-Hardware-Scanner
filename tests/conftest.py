"""Shared test fixtures for IoT Hardware Scanner."""

import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from claims import claimed_outcomes
from harness import PACKAGE_SRC, Runner, build_runner
from run_recorder import RECORDER

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.models import FirmwareSizeCategory, ScanContext

# ──────────────────────────────────────────────
# Run-wide outcome record and the skip gate
# ──────────────────────────────────────────────
#
# ``--fail-on-skips`` is the enforcement for a qualified CI job. It replaces
# grepping the pytest log for "N skipped", which was a proxy that could drift
# from the run: the flag sees every skip pytest itself saw, and prints the node
# id with the reason that made the capability unqualified.


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--fail-on-skips",
        action="store_true",
        default=False,
        dest="fail_on_skips",
        help=(
            "fail the process if any test skips, naming the node id and the "
            "reason (used by every qualified CI job)"
        ),
    )


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    """Feed the shared recorder used by the claim-matrix check."""
    RECORDER.record(report)


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Decide the run's claim verdict, then the skip gate.

    This runs after every module, which is the only place a claim can be checked
    against what actually ran: pytest executes modules in file order, so a test
    inside the claim module cannot see a failure in a module it has not reached.

    * A claimed test that failed leaves its row unqualified -- the process fails.
    * A claimed test that skipped is reported; with ``--fail-on-skips`` it also
      fails the process.
    * ``--fail-on-skips`` fails on any skip, claimed or not, naming node and
      reason.
    """
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    write = reporter.write_line if reporter is not None else print
    strict = bool(session.config.getoption("fail_on_skips"))
    unqualified = False

    try:
        failed_claims, skipped_claims = claimed_outcomes(RECORDER.outcomes)
    except Exception as exc:  # a broken matrix is reported by its own test
        write(
            f"CLAIM MATRIX: docs/SUPPORT-MATRIX.md could not be read: {type(exc).__name__}: {exc}"
        )
        failed_claims, skipped_claims = [], []

    if failed_claims:
        write("")
        write("CLAIM MATRIX: a claimed test did not pass; its row is unqualified")
        for claim, outcome in failed_claims:
            write(
                f"  CLAIM line {claim.line}: `{claim.text}` -> {outcome.nodeid}: "
                f"{outcome.reason or 'failed'}"
            )
        unqualified = True

    if skipped_claims:
        write("")
        write(
            "CLAIM MATRIX: claimed node(s) did not run to completion, so the row is unverified here"
        )
        for claim, outcome in skipped_claims:
            write(
                f"  UNVERIFIED line {claim.line}: `{claim.text}` -> {outcome.nodeid}: "
                f"{outcome.reason or 'skipped'}"
            )
        unqualified = unqualified or strict

    if strict and RECORDER.skipped:
        write("")
        write(
            "FAIL-ON-SKIPS: a skip leaves the capability claimed for that node "
            "unqualified; the run fails"
        )
        for outcome in RECORDER.skipped:
            write(f"  SKIPPED {outcome.nodeid}")
            write(f"          reason: {outcome.reason}")
        unqualified = True

    if unqualified:
        # The exit status is the process result: automation must not be able to
        # read an unqualified claim or a skip as a pass.
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


@pytest.fixture
def config() -> ScannerConfig:
    """Default scanner config for testing."""
    return ScannerConfig()


@pytest.fixture
def temp_dir() -> Path:
    """Create a temporary directory for test outputs."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def output_config(temp_dir: Path) -> ScannerConfig:
    """Scanner config with a temporary output directory."""
    return ScannerConfig(output_dir=temp_dir / "reports")


@pytest.fixture
def small_firmware(temp_dir: Path) -> Path:
    """Create a small test firmware file (~1KB)."""
    firmware = temp_dir / "test_firmware.bin"
    firmware.write_bytes(os.urandom(1024))
    return firmware


@pytest.fixture
def medium_firmware(temp_dir: Path) -> Path:
    """Create a medium test firmware file (~100KB)."""
    firmware = temp_dir / "medium_firmware.bin"
    firmware.write_bytes(os.urandom(100 * 1024))
    return firmware


@pytest.fixture
def empty_firmware(temp_dir: Path) -> Path:
    """Create an empty firmware file."""
    firmware = temp_dir / "empty.bin"
    firmware.write_bytes(b"")
    return firmware


@pytest.fixture
def large_firmware_name(temp_dir: Path) -> Path:
    """Return a path for a firmware file that exceeds size limits.

    We don't actually create a large file — just test the size check
    with a very low max_file_size_mb.
    """
    firmware = temp_dir / "large.bin"
    firmware.write_bytes(os.urandom(2048))  # 2KB file
    return firmware


@pytest.fixture
def sample_scan_context(temp_dir: Path) -> ScanContext:
    """Create a sample ScanContext for testing later phases."""
    return ScanContext(
        scan_id="test-scan-001",
        firmware_path=temp_dir / "test.bin",
        output_dir=temp_dir / "output",
        file_hash_sha256="a" * 64,
        file_hash_md5="b" * 32,
        file_size=1024,
        file_type="ELF 32-bit LSB executable, MIPS",
        firmware_name="test",
        size_category=FirmwareSizeCategory.SMALL,
        started_at=datetime.now(timezone.utc),
    )


# ──────────────────────────────────────────────
# Installed-CLI harness (milestone A/B acceptance)
# ──────────────────────────────────────────────


@pytest.fixture(scope="session")
def runner(tmp_path_factory: pytest.TempPathFactory) -> Runner:
    """Run the scanner from outside the checkout, in wheel mode when available."""
    import shutil

    if os.environ.get("IHS_INSTALLED_CLI"):
        return build_runner(Path())
    site = tmp_path_factory.mktemp("relocated-site")
    shutil.copytree(PACKAGE_SRC, site / "iot_hardware_scanner")
    return build_runner(site)


# ──────────────────────────────────────────────
# Milestone A fixtures — deterministic, no network
# ──────────────────────────────────────────────

#: Digest of the pinned OpenWrt reference image, recorded in the plan.
OPENWRT_SHA256 = "8b5aa82659cafd90b26333dd419a0df9ad63c517ad94a2159e970a5bb5b6ff02"


@pytest.fixture
def blank_image(temp_dir: Path) -> Path:
    """4,096 zero bytes: a valid but opaque artifact."""
    path = temp_dir / "blank.bin"
    path.write_bytes(b"\x00" * 4096)
    return path


@pytest.fixture
def opaque_image(temp_dir: Path) -> Path:
    """An opaque blob carrying a non-placeholder password assignment."""
    path = temp_dir / "opaque.bin"
    body = b'# device config\nssid=HomeNet\npassword="Xk9#mQ2vLp7!zR4"\n'
    path.write_bytes(body + b"\x00" * (4096 - len(body)))
    return path


@pytest.fixture
def fixture_tree(temp_dir: Path) -> Path:
    """A deterministic, minimal staged root tree.

    Contents, by design:
      etc/passwd   root (UID 0, login shell) and user (UID 1000)
      etc/shadow   root locked, user SHA-512
      etc/inittab  one configured sshd respawn and one commented telnetd
      etc/config/system  no secrets
      usr/bin/suid_helper  SUID bit set
    """
    root = temp_dir / "tree"
    (root / "etc" / "config").mkdir(parents=True)
    (root / "usr" / "bin").mkdir(parents=True)
    (root / "etc" / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/ash\nuser:x:1000:1000:user:/home/user:/bin/ash\n"
    )
    (root / "etc" / "shadow").write_text(
        "root:!$6$salt$hash:19000:0:99999:7:::\nuser:$6$salt$hash:19000:0:99999:7:::\n"
    )
    (root / "etc" / "inittab").write_text(
        "::sysinit:/etc/init.d/rcS\n"
        "::respawn:/usr/sbin/sshd -D\n"
        "#::respawn:/usr/sbin/telnetd -l /bin/sh\n"
    )
    (root / "etc" / "config" / "system").write_text("config system\n\toption hostname 'router'\n")
    helper = root / "usr" / "bin" / "suid_helper"
    helper.write_bytes(b"\x7fELF" + b"\x00" * 60)
    helper.chmod(0o4755)
    return root


@pytest.fixture
def legacy_v1_document() -> dict:
    """A v1 report: one credential finding and a historical aggregate grade."""
    return {
        "scan_id": "legacy-001",
        "scan_date": "2025-01-01T00:00:00+00:00",
        "firmware": {
            "name": "legacy_fw",
            "path": "legacy.bin",
            "sha256": "a" * 64,
            "md5": "b" * 32,
            "size": 1024,
            "file_type": "ELF",
        },
        "entropy": None,
        "credentials": {
            "total": 1,
            "by_severity": {"HIGH": 1},
            "findings": [
                {
                    "severity": "HIGH",
                    "category": "password",
                    "matched_pattern": "unix_shadow_parse",
                    "file_path": "etc/config/system",
                    "line_number": 12,
                    "masked_value": "root:****",
                    "is_default": False,
                    "is_placeholder": False,
                }
            ],
        },
        "cve": {"total": 0, "findings": []},
        "c2_malware": {"total": 0, "findings": []},
        "risk_score": {
            "total_score": 88.0,
            "risk_level": "MEDIUM",
            "control_scores": [],
            "weighted_breakdown": {},
            "executive_summary": "legacy",
            "owasp_iot_mapping": {},
        },
        "sbom": {"total": 0, "components": []},
    }


@pytest.fixture
def legacy_v1_report(temp_dir: Path, legacy_v1_document: dict) -> Path:
    """The v1 document written to disk."""
    import json

    path = temp_dir / "legacy.json"
    path.write_text(json.dumps(legacy_v1_document, indent=2))
    return path


@pytest.fixture
def reference_image() -> Path:
    """The pinned OpenWrt ARM64 image, if the operator staged one.

    Set ``IHS_REFERENCE_IMAGE`` to a checksum-verified copy. The suite never
    downloads it: fetching is a separate operation from scanning.
    """
    import os

    configured = os.environ.get("IHS_REFERENCE_IMAGE")
    if not configured:
        pytest.skip("IHS_REFERENCE_IMAGE not set: reference-image checks unverified")
    path = Path(configured)
    if not path.is_file():
        pytest.skip(f"reference image not found at {path}")
    return path
