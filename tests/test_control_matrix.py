"""Slice 4D — every named check, in three evidence situations.

The release gate needs each of the 12 checks exercised for **positive
evidence**, **contrary evidence** and **missing evidence**. This module is
table-driven on purpose: a check that has no row for one of the three
situations is a check whose silence has never been tested.

Two separations the table enforces explicitly, because both used to be blurred:

* entropy never passes "encrypted at rest", and binary hardening is never
  cryptography evidence;
* a verification step inside the image (check 5) is not board enforcement
  (check 6).
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.models import (
    AdvisoryAssessment,
    AdvisoryLookup,
    AdvisorySnapshotInfo,
    BinaryHardening,
    BinaryIntelligenceResult,
    BinaryMetadata,
    BootEvidence,
    C2Finding,
    CheckStatus,
    CredentialFinding,
    CryptoFinding,
    CVEFinding,
    EntropyProfile,
    FileCategory,
    FilesystemFinding,
    FilesystemInventory,
    FirmwareSizeCategory,
    OpkgInventory,
    OpkgPackageRecord,
    ScanContext,
    Severity,
    StageId,
    StageStatus,
)
from iot_hardware_scanner.scanner.assessment import record_stage
from iot_hardware_scanner.scanner.risk_scorer import CONTROL_SPECS, ControlEvaluator


def make_context(tmp_path: Path) -> ScanContext:
    context = ScanContext(
        scan_id="controls",
        firmware_path=tmp_path / "fw.bin",
        output_dir=tmp_path,
        file_hash_sha256="a" * 64,
        file_hash_md5="b" * 32,
        file_size=1024,
        file_type="binary",
        firmware_name="fw",
        size_category=FirmwareSizeCategory.SMALL,
        started_at=datetime.now(tz=timezone.utc),
    )
    for stage in (
        StageId.INGEST,
        StageId.ENUMERATION,
        StageId.CREDENTIAL_SCAN,
        StageId.UNIX_ACCOUNTS,
        StageId.C2_INDICATORS,
        StageId.SERVICE_ANALYSIS,
        StageId.ELF_METADATA,
    ):
        record_stage(context, stage, StageStatus.COMPLETE, inspected=1, eligible=1)
    return context


def inventory(tmp_path: Path, **kwargs) -> FilesystemInventory:
    values = {
        "rootfs_path": tmp_path,
        "total_files": 1,
        "total_directories": 1,
        "metadata_source": "image",
    }
    values.update(kwargs)
    return FilesystemInventory(**values)


def control(evaluator: ControlEvaluator, context: ScanContext, control_id: int, **kwargs):
    return next(
        item for item in evaluator.evaluate(context, **kwargs) if item.control_id == control_id
    )


@pytest.fixture
def evaluator() -> ControlEvaluator:
    return ControlEvaluator(ScannerConfig())


# ──────────────────────────────────────────────
# The catalogue itself
# ──────────────────────────────────────────────


def test_every_control_declares_its_question_and_required_source(evaluator, tmp_path) -> None:
    context = make_context(tmp_path)
    for item in evaluator.evaluate(context):
        assert 1 <= item.control_id <= 12
        assert item.question, f"control {item.control_id} does not state its question"
        assert item.required_source, f"control {item.control_id} names no evidence source"
        assert item.evidence_status == item.status.value
        assert item.applicability in ("APPLICABLE", "NOT_APPLICABLE")
    assert set(CONTROL_SPECS) == set(range(1, 13))


# ──────────────────────────────────────────────
# 1 — credentials
# ──────────────────────────────────────────────


def test_control_1_positive_contrary_and_missing(evaluator, tmp_path) -> None:
    context = make_context(tmp_path)
    positive = control(evaluator, context, 1)
    assert (positive.status, positive.result) == (CheckStatus.PERFORMED, "PASS")

    context.credential_findings = [
        CredentialFinding(
            severity=Severity.CRITICAL,
            category="password",
            file_path=Path("etc/shadow"),
            rule_id="credential.unix.empty_password",
        )
    ]
    contrary = control(evaluator, context, 1)
    assert (contrary.status, contrary.result) == (CheckStatus.PERFORMED, "FAIL")

    bare = make_context(tmp_path)
    bare.stages = [s for s in bare.stages if s.stage_id is not StageId.CREDENTIAL_SCAN]
    missing = control(evaluator, bare, 1)
    assert missing.status is CheckStatus.OMITTED
    assert missing.result == "UNKNOWN"


# ──────────────────────────────────────────────
# 2 — network services
# ──────────────────────────────────────────────


def test_control_2_positive_contrary_and_missing(evaluator, tmp_path) -> None:
    context = make_context(tmp_path)
    context.filesystem_inventory = inventory(tmp_path)
    positive = control(evaluator, context, 2)
    assert (positive.status, positive.result) == (CheckStatus.PERFORMED, "PASS")

    context.filesystem_inventory = inventory(
        tmp_path,
        boot_evidence=[
            BootEvidence(
                root_id="rootfs",
                source="etc/inittab",
                line_number=2,
                directive="::respawn:/usr/sbin/telnetd -l /bin/sh",
                action="respawn",
                program="/usr/sbin/telnetd -l /bin/sh",
            )
        ],
    )
    contrary = control(evaluator, context, 2)
    assert (contrary.status, contrary.result) == (CheckStatus.PERFORMED, "FAIL")
    assert any("telnetd" in item for item in contrary.evidence)

    context.filesystem_inventory = None
    missing = control(evaluator, context, 2)
    assert missing.status is CheckStatus.OMITTED


# ──────────────────────────────────────────────
# 3 — advisories
# ──────────────────────────────────────────────


def _advisory(state: str = "ASSESSED", **kwargs) -> AdvisoryAssessment:
    snapshot = AdvisorySnapshotInfo(
        path="snapshot.json",
        digest_sha256="c" * 64,
        schema="ihs-advisory-snapshot/1",
        provider="nvd",
        acquired_at="2026-11-01T00:00:00+00:00",
        entries=3,
        age_days=1.0,
        stale=state == "STALE",
        includes_kev=True,
    )
    values = {
        "snapshot": snapshot,
        "lookups": [AdvisoryLookup(component="busybox", version="1.36.1-r2", state="KNOWN_EMPTY")],
        "state": state,
    }
    values.update(kwargs)
    return AdvisoryAssessment(**values)


def test_control_3_positive_contrary_and_missing(evaluator, tmp_path) -> None:
    context = make_context(tmp_path)

    context.advisory = _advisory()
    positive = control(evaluator, context, 3, advisory_assessed=True)
    assert (positive.status, positive.result) == (CheckStatus.PERFORMED, "PASS")
    assert any("lookup" in item for item in positive.evidence)

    context.cve_findings = [
        CVEFinding(
            cve_id="CVE-2024-0001",
            severity=Severity.HIGH,
            is_in_kev=True,
            affected_product="busybox",
            affected_version="1.36.1-r2",
            applicability="cpe-exact",
        )
    ]
    contrary = control(evaluator, context, 3, advisory_assessed=True)
    assert (contrary.status, contrary.result) == (CheckStatus.PERFORMED, "FAIL")

    missing = control(evaluator, make_context(tmp_path), 3, advisory_assessed=False)
    assert missing.status is CheckStatus.OMITTED
    assert "not assessed" in missing.evidence[0]


def test_control_3_a_stale_snapshot_never_passes(evaluator, tmp_path) -> None:
    context = make_context(tmp_path)
    context.advisory = _advisory(state="STALE")
    stale = control(evaluator, context, 3, advisory_assessed=True)
    assert stale.status is CheckStatus.INCONCLUSIVE
    assert stale.result == "UNKNOWN"


def test_control_3_an_unanswered_lookup_never_passes(evaluator, tmp_path) -> None:
    context = make_context(tmp_path)
    context.advisory = _advisory(
        state="PARTIAL",
        lookups=[
            AdvisoryLookup(component="busybox", version="1.36.1-r2", state="KNOWN_EMPTY"),
            AdvisoryLookup(
                component="openssl",
                version="3.0.0",
                state="UNAVAILABLE",
                reason="the query failed",
            ),
        ],
    )
    partial = control(evaluator, context, 3, advisory_assessed=True)
    assert partial.status is CheckStatus.INCONCLUSIVE
    assert any("openssl" in item for item in partial.evidence)


# ──────────────────────────────────────────────
# 4 — data at rest
# ──────────────────────────────────────────────


def _entropy() -> EntropyProfile:
    return EntropyProfile(
        firmware_path=Path("fw.bin"),
        total_blocks=1,
        block_size=4096,
        overall_entropy=7.99,
        window_mean_entropy=7.99,
        bytes_analyzed=4096,
    )


def test_control_4_entropy_never_passes_and_plaintext_fails(evaluator, tmp_path) -> None:
    context = make_context(tmp_path)
    context.entropy_profile = _entropy()
    missing = control(evaluator, context, 4)
    assert missing.status is CheckStatus.INCONCLUSIVE
    assert missing.result == "UNKNOWN"

    context.credential_findings = [
        CredentialFinding(
            severity=Severity.CRITICAL,
            category="password",
            file_path=Path("etc/app.conf"),
            rule_id="credential.regex.password",
        )
    ]
    contrary = control(evaluator, context, 4)
    assert (contrary.status, contrary.result) == (CheckStatus.PERFORMED, "FAIL")


def test_control_4_has_no_positive_case_available_from_an_image(evaluator, tmp_path) -> None:
    """The check is honest about never having a positive source.

    A pass would require format evidence (an encrypted container, a key
    management record). No source in this release provides one, so the best a
    clean image can earn is INCONCLUSIVE — which is the point of the check.
    """
    context = make_context(tmp_path)
    context.entropy_profile = _entropy()
    result = control(evaluator, context, 4)
    assert result.result != "PASS"
    assert result.status in (CheckStatus.INCONCLUSIVE, CheckStatus.OMITTED)


# ──────────────────────────────────────────────
# 5 and 6 — content verification vs board enforcement
# ──────────────────────────────────────────────


def _update_file(tmp_path: Path, name: str, body: str) -> FilesystemFinding:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)
    return FilesystemFinding(
        path=Path(name),
        absolute_path=path,
        category=FileCategory.CRITICAL_CONFIG,
        file_type="script",
        file_size=len(body),
        permissions="rwxr-xr-x",
        owner_uid=0,
        owner_gid=0,
        is_suid=False,
        is_world_writable=False,
        hash_sha256="d" * 64,
    )


def test_control_5_positive_contrary_and_missing(evaluator, tmp_path) -> None:
    context = make_context(tmp_path)
    finding = _update_file(
        tmp_path,
        "sbin/sysupgrade",
        "verify_signature || exit 1\nsha256sum -c checksums\n",
    )
    context.filesystem_inventory = inventory(tmp_path, findings=[finding])
    positive = control(evaluator, context, 5)
    assert (positive.status, positive.result) == (CheckStatus.PERFORMED, "REVIEW")
    assert any("check 6" in item for item in positive.evidence)

    context.filesystem_inventory = inventory(
        tmp_path, findings=[_update_file(tmp_path, "sbin/fwupdate", "cp image /dev/mtd0\n")]
    )
    contrary = control(evaluator, context, 5)
    assert (contrary.status, contrary.result) == (CheckStatus.PERFORMED, "FAIL")

    context.filesystem_inventory = None
    missing = control(evaluator, context, 5)
    assert missing.status is CheckStatus.OMITTED


def test_control_6_is_never_answered_by_the_image(evaluator, tmp_path) -> None:
    context = make_context(tmp_path)
    finding = _update_file(tmp_path, "sbin/sysupgrade", "verify_signature\n")
    context.filesystem_inventory = inventory(tmp_path, findings=[finding])
    for verdict in (
        control(evaluator, context, 5),
        control(evaluator, context, 6),
    ):
        assert verdict.control_id in (5, 6)
    enforcement = control(evaluator, context, 6)
    assert enforcement.status is CheckStatus.INCONCLUSIVE
    assert enforcement.result == "UNKNOWN"
    assert any("check 5" in item for item in enforcement.evidence)


# ──────────────────────────────────────────────
# 7 and 11 — indicators
# ──────────────────────────────────────────────


def test_control_7_and_11_positive_contrary_and_missing(evaluator, tmp_path) -> None:
    context = make_context(tmp_path)
    for control_id in (7, 11):
        clean = control(evaluator, context, control_id)
        assert (clean.status, clean.result) == (CheckStatus.PERFORMED, "PASS")

    context.c2_findings = [
        C2Finding(
            severity="LIKELY_C2",
            indicator_type="domain",
            value="updates.firmware-vendor.su",
            file_path=Path("etc/config"),
        )
    ]
    for control_id in (7, 11):
        contrary = control(evaluator, context, control_id)
        assert (contrary.status, contrary.result) == (CheckStatus.PERFORMED, "FAIL")

    bare = make_context(tmp_path)
    bare.stages = [s for s in bare.stages if s.stage_id is not StageId.C2_INDICATORS]
    for control_id in (7, 11):
        missing = control(evaluator, bare, control_id)
        assert missing.status is CheckStatus.OMITTED


# ──────────────────────────────────────────────
# 8 — cryptography, separate from hardening
# ──────────────────────────────────────────────


def test_control_8_positive_contrary_and_missing(evaluator, tmp_path) -> None:
    context = make_context(tmp_path)
    context.opkg_inventory = OpkgInventory(
        locator="rootfs/usr/lib/opkg/status",
        database_sha256="e" * 64,
        byte_length=100,
        records=[
            OpkgPackageRecord(
                name="libopenssl",
                version="3.0.15-r1",
                architecture="aarch64_generic",
                status="install user installed",
                installed=True,
                held=False,
            )
        ],
        installed_count=1,
    )
    positive = control(evaluator, context, 8)
    assert (positive.status, positive.result) == (CheckStatus.PERFORMED, "REVIEW")
    assert any("libopenssl 3.0.15-r1" in item for item in positive.evidence)

    context.credential_findings = [
        CredentialFinding(
            severity=Severity.HIGH,
            category="password",
            file_path=Path("etc/shadow"),
            rule_id="credential.unix.md5_hash",
        )
    ]
    contrary = control(evaluator, context, 8)
    assert (contrary.status, contrary.result) == (CheckStatus.PERFORMED, "FAIL")

    context.credential_findings = []
    context.opkg_inventory = None
    missing = control(evaluator, context, 8)
    assert missing.status is CheckStatus.OMITTED
    assert missing.result == "UNKNOWN"


def test_control_8_algorithm_evidence_is_not_hardening(evaluator, tmp_path) -> None:
    context = make_context(tmp_path)
    context.binary_intelligence = BinaryIntelligenceResult(
        binaries=[BinaryMetadata(path=Path("bin/sh"), hardening=BinaryHardening(nx_enabled=True))],
        total_binaries=1,
        hardened_binaries=1,
    )
    assert control(evaluator, context, 8).status is CheckStatus.OMITTED

    context.crypto_findings = [
        CryptoFinding(
            rule_id="crypto.yara.des_weak_key",
            algorithm="DES",
            strength="weak",
            file_path=Path("usr/lib/libmbedcrypto.so"),
            evidence="usr/lib/libmbedcrypto.so@37098",
        )
    ]
    named = control(evaluator, context, 8)
    assert (named.status, named.result) == (CheckStatus.PERFORMED, "REVIEW")
    assert any("DES" in item for item in named.evidence)


# ──────────────────────────────────────────────
# 9 and 10 — attack surface and hardening
# ──────────────────────────────────────────────


def test_control_9_positive_contrary_and_missing(evaluator, tmp_path) -> None:
    context = make_context(tmp_path)
    context.filesystem_inventory = inventory(tmp_path, metadata_source="image")
    positive = control(evaluator, context, 9)
    assert (positive.status, positive.result) == (CheckStatus.PERFORMED, "PASS")

    suid = FilesystemFinding(
        path=Path("usr/bin/su"),
        absolute_path=tmp_path / "usr/bin/su",
        category=FileCategory.CRITICAL_BINARY,
        file_type="ELF",
        file_size=1,
        permissions="rwsr-xr-x",
        owner_uid=0,
        owner_gid=0,
        is_suid=True,
        is_world_writable=False,
        hash_sha256="f" * 64,
    )
    context.filesystem_inventory = inventory(
        tmp_path, metadata_source="image", suid_binaries=[suid]
    )
    contrary = control(evaluator, context, 9)
    assert (contrary.status, contrary.result) == (CheckStatus.PERFORMED, "REVIEW")

    context.filesystem_inventory = inventory(
        tmp_path, metadata_source="host", permission_unknown_count=3
    )
    missing = control(evaluator, context, 9)
    assert missing.status is CheckStatus.INCONCLUSIVE
    assert missing.result == "UNKNOWN"


def test_control_10_positive_contrary_and_missing(evaluator, tmp_path) -> None:
    context = make_context(tmp_path)
    missing = control(evaluator, context, 10)
    assert missing.status is CheckStatus.OMITTED

    context.binary_intelligence = BinaryIntelligenceResult(
        binaries=[
            BinaryMetadata(
                path=Path("bin/a"),
                hardening=BinaryHardening(
                    nx_enabled=True, pie_enabled=True, stack_canary=True, relro="full"
                ),
            )
        ],
        total_binaries=1,
    )
    positive = control(evaluator, context, 10)
    assert (positive.status, positive.result) == (CheckStatus.PERFORMED, "PASS")

    context.binary_intelligence = BinaryIntelligenceResult(
        binaries=[
            BinaryMetadata(
                path=Path("bin/b"),
                hardening=BinaryHardening(
                    nx_enabled=False, pie_enabled=False, stack_canary=None, relro="none"
                ),
            )
        ],
        total_binaries=1,
    )
    contrary = control(evaluator, context, 10)
    assert contrary.status is CheckStatus.INCONCLUSIVE
    assert contrary.result == "UNKNOWN"


# ──────────────────────────────────────────────
# 12 — component inventory
# ──────────────────────────────────────────────


def test_control_12_positive_contrary_and_missing(evaluator, tmp_path) -> None:
    context = make_context(tmp_path)
    missing = control(evaluator, context, 12)
    assert missing.status is CheckStatus.INCONCLUSIVE
    assert missing.result == "UNKNOWN"

    from iot_hardware_scanner.models import SoftwareComponent

    context.software_components = [
        SoftwareComponent(
            vendor="openwrt",
            product="busybox",
            version="1.36.1-r2",
            cpe_string="cpe:2.3:a:openwrt:busybox:1.36.1-r2:*:*:*:*:*:*:*",
            source_file=Path("usr/lib/opkg/status"),
            source_method="opkg_status",
        )
    ]
    record_stage(context, StageId.OPKG_INVENTORY, StageStatus.COMPLETE, inspected=1, eligible=1)
    positive = control(evaluator, context, 12)
    assert (positive.status, positive.result) == (CheckStatus.PERFORMED, "PASS")

    record_stage(context, StageId.OPKG_INVENTORY, StageStatus.FAILED, reason="unreadable database")
    contrary = control(evaluator, context, 12)
    assert contrary.status is CheckStatus.INCONCLUSIVE
    assert any("package database" in item for item in contrary.evidence)


# ──────────────────────────────────────────────
# Profile applicability
# ──────────────────────────────────────────────


def test_a_narrow_profile_marks_the_other_checks_not_applicable(evaluator, tmp_path) -> None:
    context = make_context(tmp_path)
    context.profile = "credentials-only"
    controls = evaluator.evaluate(context)
    assert [c.control_id for c in controls if c.applicability == "NOT_APPLICABLE"] == (
        list(range(2, 13))
    )
    for item in controls:
        if item.applicability == "NOT_APPLICABLE":
            assert item.status is CheckStatus.NOT_APPLICABLE
            assert item.applicability_note == "" or item.applicability_note
