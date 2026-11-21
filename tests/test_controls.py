"""Named-check tests: one question at a time, with its evidence status.

The retired 0-100 grade is gone, so these tests assert only what each check
observed. Every case is table-driven over the three evidence situations the
plan requires: positive evidence, contrary evidence, and missing evidence.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.models import (
    BootEvidence,
    C2Finding,
    CheckStatus,
    CredentialFinding,
    CVEFinding,
    EntropyProfile,
    FileCategory,
    FilesystemFinding,
    FilesystemInventory,
    FirmwareSizeCategory,
    ScanContext,
    Severity,
    StageId,
    StageStatus,
)
from iot_hardware_scanner.scanner.assessment import record_stage
from iot_hardware_scanner.scanner.risk_scorer import (
    CONTROLS,
    OWASP_IOT_MAP,
    ControlEvaluator,
)


@pytest.fixture
def evaluator() -> ControlEvaluator:
    return ControlEvaluator(ScannerConfig())


@pytest.fixture
def context(tmp_path: Path) -> ScanContext:
    ctx = ScanContext(
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
    record_stage(ctx, StageId.INGEST, StageStatus.COMPLETE, inspected=1, eligible=1)
    # A completed run of the two detectors these checks read evidence from.
    record_stage(ctx, StageId.CREDENTIAL_SCAN, StageStatus.COMPLETE, inspected=1, eligible=1)
    record_stage(ctx, StageId.C2_INDICATORS, StageStatus.COMPLETE, inspected=1, eligible=1)
    return ctx


def by_id(controls, control_id: int):
    return next(c for c in controls if c.control_id == control_id)


def inventory(tmp_path: Path, **kwargs) -> FilesystemInventory:
    inv = FilesystemInventory(rootfs_path=tmp_path, total_files=1, total_directories=1)
    for key, value in kwargs.items():
        setattr(inv, key, value)
    return inv


class TestControlCatalogue:
    def test_twelve_controls_keep_their_names(self) -> None:
        assert [c[0] for c in CONTROLS] == list(range(1, 13))
        assert CONTROLS[0][1] == "No default/hardcoded credentials"

    def test_evaluator_returns_every_control_once(self, evaluator, context) -> None:
        controls = evaluator.evaluate(context)
        assert [c.control_id for c in controls] == list(range(1, 13))

    def test_no_control_carries_points(self, evaluator, context) -> None:
        controls = evaluator.evaluate(context)
        assert not any(hasattr(c, "points") for c in controls)

    def test_owasp_map_references_known_controls(self) -> None:
        for control_ids in OWASP_IOT_MAP.values():
            assert all(1 <= cid <= 12 for cid in control_ids)


class TestControl1Credentials:
    def test_positive_evidence_passes_with_evidence(self, evaluator, context) -> None:
        control = by_id(evaluator.evaluate(context), 1)
        assert control.status is CheckStatus.PERFORMED
        assert control.result == "PASS"
        assert control.evidence

    def test_contrary_evidence_fails(self, evaluator, context) -> None:
        context.credential_findings = [
            CredentialFinding(
                severity=Severity.CRITICAL,
                category="password",
                file_path=Path("etc/config"),
                rule_id="credential.regex.password",
            )
        ]
        control = by_id(evaluator.evaluate(context), 1)
        assert control.result == "FAIL"

    def test_missing_evidence_is_omitted(self, evaluator, tmp_path: Path) -> None:
        bare = ScanContext(
            scan_id="x",
            firmware_path=tmp_path / "fw.bin",
            output_dir=tmp_path,
            file_hash_sha256="",
            file_hash_md5="",
            file_size=0,
            file_type="",
            firmware_name="fw",
            size_category=FirmwareSizeCategory.SMALL,
            started_at=datetime.now(tz=timezone.utc),
        )
        control = by_id(evaluator.evaluate(bare), 1)
        assert control.status is CheckStatus.OMITTED


class TestControl2Services:
    def test_configured_startup_is_reported_with_its_source(
        self, evaluator, context, tmp_path
    ) -> None:
        context.filesystem_inventory = inventory(
            tmp_path,
            boot_evidence=[
                BootEvidence(
                    root_id="rootfs",
                    source="etc/inittab",
                    line_number=2,
                    directive="::respawn:/usr/sbin/sshd -D",
                    action="respawn",
                    program="/usr/sbin/sshd -D",
                    configured=True,
                )
            ],
        )
        control = by_id(evaluator.evaluate(context), 2)
        # Configured is not listening: the check cannot conclude.
        assert control.status is CheckStatus.INCONCLUSIVE
        assert any("etc/inittab:2" in item for item in control.evidence)

    def test_commented_entry_does_not_establish_startup(self, evaluator, context, tmp_path) -> None:
        context.filesystem_inventory = inventory(
            tmp_path,
            boot_evidence=[
                BootEvidence(
                    root_id="rootfs",
                    source="etc/inittab",
                    line_number=3,
                    directive="#::respawn:/usr/sbin/telnetd -l /bin/sh",
                    action="respawn",
                    program="/usr/sbin/telnetd -l /bin/sh",
                    configured=False,
                )
            ],
        )
        control = by_id(evaluator.evaluate(context), 2)
        assert control.result == "PASS"
        assert not any("telnetd" in item for item in control.evidence)

    def test_configured_insecure_service_fails(self, evaluator, context, tmp_path) -> None:
        context.filesystem_inventory = inventory(
            tmp_path,
            boot_evidence=[
                BootEvidence(
                    root_id="rootfs",
                    source="etc/inittab",
                    line_number=4,
                    directive="::respawn:/usr/sbin/telnetd -l /bin/sh",
                    action="respawn",
                    program="/usr/sbin/telnetd -l /bin/sh",
                    configured=True,
                )
            ],
        )
        control = by_id(evaluator.evaluate(context), 2)
        assert control.result == "FAIL"
        assert any("etc/inittab:4" in item for item in control.evidence)

    def test_no_inventory_is_omitted_not_passed(self, evaluator, context) -> None:
        control = by_id(evaluator.evaluate(context), 2)
        assert control.status is CheckStatus.OMITTED
        assert control.result == "UNKNOWN"


class TestControl3Advisories:
    def test_unassessed_without_a_snapshot(self, evaluator, context) -> None:
        control = by_id(evaluator.evaluate(context, advisory_assessed=False), 3)
        assert control.status is CheckStatus.OMITTED
        assert "not assessed" in control.evidence[0]

    def test_assessed_clean_passes(self, evaluator, context) -> None:
        control = by_id(evaluator.evaluate(context, advisory_assessed=True), 3)
        assert control.result == "PASS"

    def test_kev_hit_fails(self, evaluator, context) -> None:
        context.cve_findings = [
            CVEFinding(
                cve_id="CVE-2024-0001",
                severity=Severity.CRITICAL,
                is_in_kev=True,
                affected_product="busybox",
                affected_version="1.36.1",
            )
        ]
        control = by_id(evaluator.evaluate(context, advisory_assessed=True), 3)
        assert control.result == "FAIL"


class TestControl4DataAtRest:
    def _entropy(self) -> EntropyProfile:
        return EntropyProfile(
            firmware_path=Path("fw.bin"),
            total_blocks=1,
            block_size=4096,
            overall_entropy=7.99,
            window_mean_entropy=7.99,
            bytes_analyzed=4096,
        )

    def test_high_entropy_never_passes_this_control(self, evaluator, context) -> None:
        context.entropy_profile = self._entropy()
        control = by_id(evaluator.evaluate(context), 4)
        assert control.result != "PASS"
        assert control.status is CheckStatus.INCONCLUSIVE
        assert any("not evidence of encryption" in item for item in control.evidence)

    def test_plaintext_password_fails(self, evaluator, context) -> None:
        context.credential_findings = [
            CredentialFinding(
                severity=Severity.CRITICAL,
                category="password",
                file_path=Path("etc/config"),
                rule_id="credential.regex.password",
            )
        ]
        control = by_id(evaluator.evaluate(context), 4)
        assert control.result == "FAIL"

    def test_locked_account_is_not_plaintext_evidence(self, evaluator, context) -> None:
        context.credential_findings = [
            CredentialFinding(
                severity=Severity.INFO,
                category="account",
                file_path=Path("etc/passwd"),
                rule_id="credential.unix.uid0_account",
            )
        ]
        control = by_id(evaluator.evaluate(context), 4)
        assert control.result != "FAIL"

    def test_no_evidence_is_unknown_not_pass(self, evaluator, context) -> None:
        control = by_id(evaluator.evaluate(context), 4)
        assert control.result == "UNKNOWN"
        assert control.status is CheckStatus.INCONCLUSIVE


class TestControl6SecureBoot:
    def test_static_image_cannot_pass_secure_boot(self, evaluator, context) -> None:
        control = by_id(evaluator.evaluate(context), 6)
        assert control.result == "UNKNOWN"
        assert control.status is CheckStatus.INCONCLUSIVE


class TestControl8Crypto:
    def test_md5_hash_fails(self, evaluator, context) -> None:
        context.credential_findings = [
            CredentialFinding(
                severity=Severity.HIGH,
                category="password",
                file_path=Path("etc/shadow"),
                rule_id="credential.unix.md5_hash",
            )
        ]
        control = by_id(evaluator.evaluate(context), 8)
        assert control.result == "FAIL"

    def test_hardening_is_not_crypto_evidence(self, evaluator, context) -> None:
        from iot_hardware_scanner.models import (
            BinaryHardening,
            BinaryIntelligenceResult,
            BinaryMetadata,
        )

        context.binary_intelligence = BinaryIntelligenceResult(
            binaries=[
                BinaryMetadata(path=Path("bin/sh"), hardening=BinaryHardening(nx_enabled=True))
            ],
            total_binaries=1,
            hardened_binaries=1,
        )
        control = by_id(evaluator.evaluate(context), 8)
        assert control.status is CheckStatus.OMITTED


class TestControl10Hardening:
    def test_no_binaries_means_no_verdict(self, evaluator, context) -> None:
        control = by_id(evaluator.evaluate(context), 10)
        assert control.status is CheckStatus.OMITTED
        assert control.result == "UNKNOWN"

    def test_unknown_hardening_cannot_earn_credit(self, evaluator, context) -> None:
        from iot_hardware_scanner.models import BinaryIntelligenceResult, BinaryMetadata

        context.binary_intelligence = BinaryIntelligenceResult(
            binaries=[BinaryMetadata(path=Path("bin/sh"))],
            total_binaries=1,
            hardened_binaries=0,
        )
        control = by_id(evaluator.evaluate(context), 10)
        assert control.result == "UNKNOWN"


class TestControl9AttackSurface:
    def test_suid_files_are_reviewed(self, evaluator, context, tmp_path) -> None:
        finding = FilesystemFinding(
            path=Path("usr/bin/su"),
            absolute_path=tmp_path / "su",
            category=FileCategory.CRITICAL_BINARY,
            file_type="ELF",
            file_size=10,
            permissions="rwsr-xr-x",
            owner_uid=0,
            owner_gid=0,
            is_suid=True,
            is_world_writable=False,
            hash_sha256="",
        )
        context.filesystem_inventory = inventory(tmp_path, suid_binaries=[finding])
        control = by_id(evaluator.evaluate(context), 9)
        assert control.result == "REVIEW"
        assert control.status is CheckStatus.PERFORMED

    def test_clear_tree_passes_with_image_metadata(self, evaluator, context, tmp_path) -> None:
        """A clean result requires permission bits that came from the image."""
        context.filesystem_inventory = inventory(tmp_path, metadata_source="image")
        control = by_id(evaluator.evaluate(context), 9)
        assert control.result == "PASS"
        assert control.evidence

    def test_host_derived_permissions_cannot_pass(self, evaluator, context, tmp_path) -> None:
        """A staged tree's host metadata cannot establish a clean permission state."""
        context.filesystem_inventory = inventory(
            tmp_path, metadata_source="host", permission_unknown_count=3
        )
        control = by_id(evaluator.evaluate(context), 9)
        assert control.result == "UNKNOWN"
        assert control.status is CheckStatus.INCONCLUSIVE
        assert any("host-derived" in item for item in control.evidence)


class TestControl12Inventory:
    def test_no_components_is_unknown(self, evaluator, context) -> None:
        control = by_id(evaluator.evaluate(context), 12)
        assert control.result == "UNKNOWN"

    def test_components_pass(self, evaluator, context) -> None:
        from iot_hardware_scanner.models import SoftwareComponent

        context.software_components = [
            SoftwareComponent(
                vendor="busybox",
                product="busybox",
                version="1.36.1-r2",
                cpe_string="cpe:2.3:a:busybox:busybox:1.36.1-r2:*:*:*:*:*:*:*",
                source_file=Path("usr/lib/opkg/status"),
                source_method="package_manifest",
            )
        ]
        control = by_id(evaluator.evaluate(context), 12)
        assert control.result == "PASS"


class TestC2Controls:
    def test_suspicious_indicator_is_review(self, evaluator, context) -> None:
        context.c2_findings = [
            C2Finding(
                severity="SUSPICIOUS",
                indicator_type="domain",
                value="example.tk",
                file_path=Path("etc/config"),
            )
        ]
        assert by_id(evaluator.evaluate(context), 7).result == "REVIEW"
        assert by_id(evaluator.evaluate(context), 11).result == "REVIEW"

    def test_likely_c2_fails(self, evaluator, context) -> None:
        context.c2_findings = [
            C2Finding(
                severity="LIKELY_C2",
                indicator_type="domain",
                value="c2.example",
                file_path=Path("bin/x"),
            )
        ]
        assert by_id(evaluator.evaluate(context), 7).result == "FAIL"
        assert by_id(evaluator.evaluate(context), 11).result == "FAIL"

    def test_clean_sweep_passes(self, evaluator, context) -> None:
        assert by_id(evaluator.evaluate(context), 7).result == "PASS"
        assert by_id(evaluator.evaluate(context), 11).result == "PASS"


class TestProfileApplicability:
    def test_credentials_profile_marks_other_checks_not_applicable(
        self, evaluator, context
    ) -> None:
        context.profile = "credentials-only"
        record_stage(
            context, StageId.CREDENTIAL_SCAN, StageStatus.COMPLETE, inspected=1, eligible=1
        )
        controls = evaluator.evaluate(context)
        assert by_id(controls, 1).status is CheckStatus.PERFORMED
        others = [c for c in controls if c.control_id != 1]
        assert all(c.status is CheckStatus.NOT_APPLICABLE for c in others)
        assert all(c.applicability == "NOT_APPLICABLE" for c in others)

    def test_firmware_profile_assesses_every_check(self, evaluator, context) -> None:
        controls = evaluator.evaluate(context)
        assert all(c.status is not CheckStatus.NOT_APPLICABLE for c in controls)
        assert all(c.applicability == "APPLICABLE" for c in controls)
