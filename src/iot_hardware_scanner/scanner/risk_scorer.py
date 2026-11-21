"""Named security checks — one question at a time, with its evidence status.

The 12 control names are kept for continuity with earlier reports, but the
aggregate 0-100 grade is retired: there is no calibrated relationship between
the old weights and real device risk, and several of the questions cannot be
answered from a static image at all.

Rules this module enforces:

* No check returns PASS without positive evidence. Missing evidence yields
  INCONCLUSIVE, NOT_APPLICABLE or OMITTED with a reason — never a silent pass.
* An entropy measurement never establishes encryption, readability or a pass.
* A binary being present is not a service being configured or listening.
* A locked password field describes one authentication method, not the
  absence of every way to log in.

Legacy ``ControlScore``/``RiskScore`` objects are only ever produced when
replaying a v1 report that already contains them.
"""

from __future__ import annotations

import logging
from typing import ClassVar

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.models import (
    BinaryHardening,
    CheckStatus,
    ControlResult,
    ScanContext,
    Severity,
    StageId,
    StageStatus,
)

logger = logging.getLogger(__name__)

# ── Control names, kept stable for continuity ──
CONTROLS: list[tuple[int, str]] = [
    (1, "No default/hardcoded credentials"),
    (2, "No unnecessary network services"),
    (3, "No outdated/vulnerable components"),
    (4, "Encrypted data at rest"),
    (5, "Secure firmware update mechanism"),
    (6, "Secure boot/integrity verification"),
    (7, "No backdoor interfaces"),
    (8, "Strong cryptography used"),
    (9, "Minimal attack surface"),
    (10, "Binary hardening present"),
    (11, "No C2/malware indicators"),
    (12, "Accurate component inventory (SBOM)"),
]

#: OWASP IoT Top 10 mapping. Values are the control ids that inform each item.
OWASP_IOT_MAP: dict[str, list[int]] = {
    "I1 - Weak/Default Passwords": [1],
    "I2 - Insecure Network Services": [2, 9],
    "I3 - Insecure Ecosystem Interfaces": [5, 12],
    "I4 - Lack of Secure Update Mechanism": [5],
    "I5 - Use of Insecure/Outdated Components": [3],
    "I6 - Insufficient Privacy Protection": [4],
    "I7 - Insecure Data Transfer/Storage": [4],
    "I8 - Lack of Device Management": [6, 10],
    "I9 - Insecure Default Settings": [1, 9],
    "I10 - Lack of Physical Hardening": [6],
}

#: Programs whose configured startup is a genuine exposure concern.
DANGEROUS_SERVICES = frozenset({"telnetd", "ftpd", "rshd", "rlogind", "tftpd"})


class ControlEvaluator:
    """Evaluate each control independently and record why it reached a verdict."""

    def __init__(self, config: ScannerConfig) -> None:
        self.config = config

    #: Controls a profile actually asks about. Everything else is reported as
    #: not applicable rather than quietly "omitted", so a narrow run cannot be
    #: read as a broad one.
    PROFILE_CONTROLS: ClassVar[dict[str, frozenset[int]]] = {
        "firmware-static": frozenset(range(1, 13)),
        "firmware-tree": frozenset(range(1, 13)),
        "credentials-only": frozenset({1}),
    }

    def evaluate(
        self, context: ScanContext, advisory_assessed: bool = False
    ) -> list[ControlResult]:
        """Return one :class:`ControlResult` per control, in stable id order."""
        in_scope = self.PROFILE_CONTROLS.get(context.profile, frozenset(range(1, 13)))
        results: list[ControlResult] = []
        for control_id, name in CONTROLS:
            if control_id not in in_scope:
                results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=name,
                        status=CheckStatus.NOT_APPLICABLE,
                        result="NOT_APPLICABLE",
                        evidence=[
                            f"not part of the {context.profile} profile; "
                            "select another profile to assess it"
                        ],
                    )
                )
                continue
            method = getattr(self, self._EVALUATORS[control_id])
            result = method(context, advisory_assessed)
            result.control_id = control_id
            result.control_name = name
            results.append(result)
        return results

    # ── Control 1: credentials ──
    def _eval_credentials(self, context: ScanContext, advisory_assessed: bool) -> ControlResult:
        findings = context.credential_findings
        if not findings:
            if not _stage_completed(context, StageId.CREDENTIAL_SCAN):
                return _omitted(
                    "Credential scanning did not run to completion",
                    "Run the credential stage or supply a scanned artifact.",
                    StageId.CREDENTIAL_SCAN,
                )
            return ControlResult(
                control_id=1,
                control_name="",
                status=CheckStatus.PERFORMED,
                result="PASS",
                evidence=["Credential scan completed with no findings"],
                source_stage=StageId.CREDENTIAL_SCAN,
            )

        critical = sum(1 for f in findings if f.severity is Severity.CRITICAL)
        high = sum(1 for f in findings if f.severity is Severity.HIGH)
        evidence = []
        if critical:
            evidence.append(f"{critical} CRITICAL credential finding(s)")
        if high:
            evidence.append(f"{high} HIGH credential finding(s)")
        evidence.append(f"{len(findings)} credential finding(s) in total")

        return ControlResult(
            control_id=1,
            control_name="",
            status=CheckStatus.PERFORMED,
            result="FAIL" if critical else "REVIEW",
            evidence=evidence,
            remediation=(
                "Remove hardcoded and default credentials from the image; "
                "provision secrets at manufacture or first boot."
            ),
            source_stage=StageId.CREDENTIAL_SCAN,
        )

    # ── Control 2: network services ──
    def _eval_services(self, context: ScanContext, advisory_assessed: bool) -> ControlResult:
        inventory = context.filesystem_inventory
        if inventory is None:
            return _omitted(
                "No filesystem inventory — no startup directives could be read",
                "Extract the root filesystem and re-run the service check.",
                StageId.SERVICE_ANALYSIS,
            )

        configured = [e for e in inventory.boot_evidence if e.configured]
        if configured:
            names = sorted({_program_name(e.program) for e in configured})
            dangerous = sorted(set(names) & DANGEROUS_SERVICES)
            evidence = [f"{e.source}:{e.line_number} — {e.action} {e.program}" for e in configured]
            if dangerous:
                return ControlResult(
                    control_id=2,
                    control_name="",
                    status=CheckStatus.PERFORMED,
                    result="FAIL",
                    evidence=[
                        f"Configured insecure service(s): {', '.join(dangerous)}",
                        *evidence,
                    ],
                    remediation=(
                        "Remove telnet/ftp/rsh startup entries; use SSH with key authentication."
                    ),
                    source_stage=StageId.SERVICE_ANALYSIS,
                )
            return ControlResult(
                control_id=2,
                control_name="",
                status=CheckStatus.INCONCLUSIVE,
                result="REVIEW",
                evidence=[
                    *evidence,
                    "A configured startup entry is not a listening socket; "
                    "exposed services require device evidence.",
                ],
                remediation=(
                    "Confirm on the device which configured services actually "
                    "listen, and on which interfaces."
                ),
                source_stage=StageId.SERVICE_ANALYSIS,
            )

        return ControlResult(
            control_id=2,
            control_name="",
            status=CheckStatus.PERFORMED,
            result="PASS",
            evidence=[
                "No startup directive configuring a network service was found in "
                "the enumerated boot paths"
            ],
            source_stage=StageId.SERVICE_ANALYSIS,
        )

    # ── Control 3: outdated components ──
    def _eval_components(self, context: ScanContext, advisory_assessed: bool) -> ControlResult:
        if not advisory_assessed:
            return _omitted(
                "No advisory snapshot was applied — applicability was not assessed",
                "Supply a local intelligence snapshot and request advisory assessment.",
                StageId.ADVISORY,
            )
        if not context.cve_findings:
            return ControlResult(
                control_id=3,
                control_name="",
                status=CheckStatus.PERFORMED,
                result="PASS",
                evidence=["Advisory assessment ran with no applicable matches"],
                source_stage=StageId.ADVISORY,
            )

        kev = [f for f in context.cve_findings if f.is_in_kev]
        critical = [f for f in context.cve_findings if f.severity is Severity.CRITICAL]
        evidence = [f"{len(context.cve_findings)} applicable advisory finding(s)"]
        if kev:
            evidence.append(f"{len(kev)} listed in CISA KEV")
        return ControlResult(
            control_id=3,
            control_name="",
            status=CheckStatus.PERFORMED,
            result="FAIL" if kev or critical else "REVIEW",
            evidence=evidence,
            remediation="Update the affected components before shipping.",
            source_stage=StageId.ADVISORY,
        )

    # ── Control 4: data at rest ──
    def _eval_data_at_rest(self, context: ScanContext, advisory_assessed: bool) -> ControlResult:
        evidence: list[str] = []
        if context.entropy_profile is not None:
            evidence.append(
                "Entropy observation: "
                f"{context.entropy_profile.overall_entropy:.2f} bits/byte "
                "(byte distribution only — not evidence of encryption)"
            )

        # Only a plaintext secret in the artifact is evidence about plaintext
        # at rest. A locked or hashed shadow entry is not.
        plaintext = [
            f
            for f in context.credential_findings
            if f.rule_id.startswith("credential.regex.") and f.category == "password"
        ]
        if plaintext:
            return ControlResult(
                control_id=4,
                control_name="",
                status=CheckStatus.PERFORMED,
                result="FAIL",
                evidence=[
                    *evidence,
                    f"{len(plaintext)} plaintext password value(s) stored in the artifact",
                ],
                remediation="Do not ship plaintext secrets; derive or provision them.",
                source_stage=StageId.CREDENTIAL_SCAN,
            )

        return ControlResult(
            control_id=4,
            control_name="",
            status=CheckStatus.INCONCLUSIVE,
            result="UNKNOWN",
            evidence=[
                *evidence,
                "No format evidence identifies encrypted storage; at-rest "
                "encryption is not established by entropy.",
            ],
            remediation=(
                "Provide evidence of the storage format (encrypted container, "
                "key management) to assess this control."
            ),
            source_stage=StageId.ENTROPY,
        )

    # ── Control 5: update mechanism ──
    def _eval_update(self, context: ScanContext, advisory_assessed: bool) -> ControlResult:
        inventory = context.filesystem_inventory
        if inventory is None:
            return _omitted(
                "No filesystem inventory — update mechanism not inspected",
                "Extract the root filesystem and re-run.",
                StageId.ENUMERATION,
            )

        update_files = [
            f
            for f in inventory.findings
            if any(
                kw in str(f.path).lower()
                for kw in ("update", "upgrade", "firmware", "ota", "sysupgrade")
            )
        ]
        if not update_files:
            return ControlResult(
                control_id=5,
                control_name="",
                status=CheckStatus.INCONCLUSIVE,
                result="UNKNOWN",
                evidence=["No update-related files were found in the inventory"],
                remediation="Document the update mechanism and its verification step.",
                source_stage=StageId.ENUMERATION,
            )

        verifying: list[str] = []
        for entry in update_files:
            try:
                content = entry.absolute_path.read_text(errors="ignore").lower()
            except (OSError, PermissionError):
                continue
            if any(kw in content for kw in ("verify", "signature", "gpg", "sha256sum", "checksum")):
                verifying.append(str(entry.path))

        if verifying:
            return ControlResult(
                control_id=5,
                control_name="",
                status=CheckStatus.PERFORMED,
                result="REVIEW",
                evidence=[
                    f"{len(update_files)} update-related file(s); verification string "
                    f"present in {', '.join(verifying[:3])}"
                ],
                remediation=(
                    "A verification string is not proof the check runs; confirm "
                    "signed updates on the device."
                ),
                source_stage=StageId.ENUMERATION,
            )

        return ControlResult(
            control_id=5,
            control_name="",
            status=CheckStatus.PERFORMED,
            result="FAIL",
            evidence=[f"{len(update_files)} update-related file(s), none verifying a signature"],
            remediation="Implement signed firmware updates with cryptographic verification.",
            source_stage=StageId.ENUMERATION,
        )

    # ── Control 6: secure boot ──
    def _eval_secure_boot(self, context: ScanContext, advisory_assessed: bool) -> ControlResult:
        return ControlResult(
            control_id=6,
            control_name="",
            status=CheckStatus.INCONCLUSIVE,
            result="UNKNOWN",
            evidence=[
                "Boot enforcement happens on the device; a static image cannot "
                "establish that a verified boot chain runs or cannot be bypassed."
            ],
            remediation="Provide boot log or fuse/OTP state from the device.",
            source_stage=StageId.ENUMERATION,
        )

    # ── Control 7: backdoors ──
    def _eval_backdoors(self, context: ScanContext, advisory_assessed: bool) -> ControlResult:
        if not _stage_completed(context, StageId.C2_INDICATORS):
            return _omitted(
                "Indicator detection did not run to completion",
                "Run the C2 indicator stage.",
                StageId.C2_INDICATORS,
            )
        likely = [f for f in context.c2_findings if f.severity == "LIKELY_C2"]
        suspicious = [f for f in context.c2_findings if f.severity == "SUSPICIOUS"]
        if likely:
            return ControlResult(
                control_id=7,
                control_name="",
                status=CheckStatus.PERFORMED,
                result="FAIL",
                evidence=[f"{len(likely)} indicator(s) scored LIKELY_C2"],
                remediation="Investigate and remove the indicator; treat the image as suspect.",
                source_stage=StageId.C2_INDICATORS,
            )
        if suspicious:
            return ControlResult(
                control_id=7,
                control_name="",
                status=CheckStatus.PERFORMED,
                result="REVIEW",
                evidence=[f"{len(suspicious)} indicator(s) scored SUSPICIOUS"],
                remediation="Review each indicator; heuristic scores are not proof.",
                source_stage=StageId.C2_INDICATORS,
            )
        return ControlResult(
            control_id=7,
            control_name="",
            status=CheckStatus.PERFORMED,
            result="PASS",
            evidence=["No indicator exceeded the review threshold"],
            source_stage=StageId.C2_INDICATORS,
        )

    # ── Control 8: cryptography ──
    def _eval_crypto(self, context: ScanContext, advisory_assessed: bool) -> ControlResult:
        weak = [
            f
            for f in context.credential_findings
            if f.category == "password" and f.rule_id == "credential.unix.md5_hash"
        ]
        if weak:
            return ControlResult(
                control_id=8,
                control_name="",
                status=CheckStatus.PERFORMED,
                result="FAIL",
                evidence=[f"{len(weak)} account(s) use an MD5 password hash"],
                remediation="Re-hash account credentials with SHA-512 or bcrypt.",
                source_stage=StageId.UNIX_ACCOUNTS,
            )
        return _omitted(
            "No evidence source identifies cryptographic algorithms in this release",
            "Qualify a crypto-algorithm detector before claiming this control.",
            StageId.ELF_METADATA,
        )

    # ── Control 9: attack surface ──
    def _eval_attack_surface(self, context: ScanContext, advisory_assessed: bool) -> ControlResult:
        inventory = context.filesystem_inventory
        if inventory is None:
            return _omitted(
                "No filesystem inventory — permissions not inspected",
                "Extract the root filesystem and re-run.",
                StageId.ENUMERATION,
            )
        suid = len(inventory.suid_binaries)
        world_writable = len(inventory.world_writable_files)
        if suid or world_writable:
            return ControlResult(
                control_id=9,
                control_name="",
                status=CheckStatus.PERFORMED,
                result="REVIEW",
                evidence=[
                    f"{suid} SUID binary/binaries",
                    f"{world_writable} world-writable file(s)",
                ],
                remediation="Audit SUID binaries and fix world-writable permissions.",
                source_stage=StageId.ENUMERATION,
            )
        if inventory.metadata_source != "image" and inventory.metadata_source != "declared":
            # Nothing was observed, and the bits that were read describe this
            # host's copy of the tree, not the shipped image. "No SUID binary"
            # is therefore not an observation about the device.
            return ControlResult(
                control_id=9,
                control_name="",
                status=CheckStatus.INCONCLUSIVE,
                result="UNKNOWN",
                evidence=[
                    f"Permission bits are {inventory.metadata_source}-derived "
                    f"({inventory.permission_unknown_count} entr(ies) unknown); a clean "
                    "result cannot be claimed from them."
                ],
                remediation=(
                    "Supply a build manifest with declared modes/ownership, or extract "
                    "the shipped image so its own metadata is available."
                ),
                source_stage=StageId.ENUMERATION,
            )
        return ControlResult(
            control_id=9,
            control_name="",
            status=CheckStatus.PERFORMED,
            result="PASS",
            evidence=["No SUID binaries or world-writable files in the enumerated tree"],
            source_stage=StageId.ENUMERATION,
        )

    # ── Control 10: binary hardening ──
    def _eval_hardening(self, context: ScanContext, advisory_assessed: bool) -> ControlResult:
        bi = context.binary_intelligence
        if bi is None or bi.total_binaries == 0:
            return _omitted(
                "No binaries were analyzed — hardening was not assessed",
                "Analyze the target ELF binaries.",
                StageId.ELF_METADATA,
            )
        # "Hardened" here means *positive* evidence: an NX stack and PIE (or a
        # shared library, for which PIE is not applicable) read from the file's
        # own program headers. A missing symbol table cannot earn credit.
        evidenced = [b for b in bi.binaries if _has_positive_hardening(b.hardening)]
        unknown = sum(
            1
            for b in bi.binaries
            if b.hardening.nx_enabled is None
            or b.hardening.stack_canary is None
            or b.hardening.pie_enabled is None
        )
        evidence = [
            f"{len(evidenced)}/{bi.total_binaries} binaries show positive hardening evidence"
        ]
        if unknown:
            evidence.append(
                f"{unknown} binary/binaries have at least one unknown hardening property "
                "(no symbol table, or no program header that supports a verdict)"
            )
        if not evidenced:
            return ControlResult(
                control_id=10,
                control_name="",
                status=CheckStatus.INCONCLUSIVE,
                result="UNKNOWN",
                evidence=evidence,
                remediation="Build with an NX stack and PIE, then re-scan the image.",
                source_stage=StageId.ELF_METADATA,
            )
        if len(evidenced) < bi.total_binaries:
            return ControlResult(
                control_id=10,
                control_name="",
                status=CheckStatus.PERFORMED,
                result="REVIEW",
                evidence=evidence,
                remediation=(
                    "Enable NX, stack canaries, full RELRO and PIE for every shipped binary."
                ),
                source_stage=StageId.ELF_METADATA,
            )
        return ControlResult(
            control_id=10,
            control_name="",
            status=CheckStatus.PERFORMED if not unknown else CheckStatus.INCONCLUSIVE,
            result="PASS" if not unknown else "REVIEW",
            evidence=evidence,
            remediation="",
            source_stage=StageId.ELF_METADATA,
        )

    # ── Control 11: C2 / malware ──
    def _eval_c2(self, context: ScanContext, advisory_assessed: bool) -> ControlResult:
        if not _stage_completed(context, StageId.C2_INDICATORS):
            return _omitted(
                "Indicator detection did not run to completion",
                "Run the C2 indicator stage.",
                StageId.C2_INDICATORS,
            )
        if not context.c2_findings:
            return ControlResult(
                control_id=11,
                control_name="",
                status=CheckStatus.PERFORMED,
                result="PASS",
                evidence=["No C2 or malware indicator was observed"],
                source_stage=StageId.C2_INDICATORS,
            )
        likely = sum(1 for f in context.c2_findings if f.severity == "LIKELY_C2")
        return ControlResult(
            control_id=11,
            control_name="",
            status=CheckStatus.PERFORMED,
            result="FAIL" if likely else "REVIEW",
            evidence=[f"{len(context.c2_findings)} indicator(s), {likely} LIKELY_C2"],
            remediation="Investigate the indicators; heuristic scores are not proof of compromise.",
            source_stage=StageId.C2_INDICATORS,
        )

    # ── Control 12: inventory ──
    def _eval_inventory(self, context: ScanContext, advisory_assessed: bool) -> ControlResult:
        components = context.software_components
        if not components:
            return ControlResult(
                control_id=12,
                control_name="",
                status=CheckStatus.INCONCLUSIVE,
                result="UNKNOWN",
                evidence=["No software components were recovered from the artifact"],
                remediation=(
                    "Read the installed package database and ELF metadata to build "
                    "a component inventory."
                ),
                source_stage=StageId.OPKG_INVENTORY,
            )
        recorded = [c for c in components if c.confidence != "candidate"]
        candidates = len(components) - len(recorded)
        evidence = [f"{len(recorded)} recorded component(s) recovered"]
        if candidates:
            evidence.append(
                f"{candidates} component(s) are banner candidates only, not installed records"
            )
        inventory_stage = next(
            (s for s in context.stages if s.stage_id is StageId.OPKG_INVENTORY), None
        )
        if inventory_stage is not None and inventory_stage.status is not StageStatus.COMPLETE:
            return ControlResult(
                control_id=12,
                control_name="",
                status=CheckStatus.INCONCLUSIVE,
                result="UNKNOWN",
                evidence=[
                    *evidence,
                    f"the installed-package database was not read: {inventory_stage.reason}",
                ],
                remediation=(
                    "Read the image's own package database; a banner-derived list does "
                    "not establish what is installed."
                ),
                source_stage=StageId.OPKG_INVENTORY,
            )
        return ControlResult(
            control_id=12,
            control_name="",
            status=CheckStatus.PERFORMED,
            result="PASS" if not candidates else "REVIEW",
            evidence=evidence,
            source_stage=StageId.OPKG_INVENTORY,
        )

    _EVALUATORS: ClassVar[dict[int, str]] = {
        1: "_eval_credentials",
        2: "_eval_services",
        3: "_eval_components",
        4: "_eval_data_at_rest",
        5: "_eval_update",
        6: "_eval_secure_boot",
        7: "_eval_backdoors",
        8: "_eval_crypto",
        9: "_eval_attack_surface",
        10: "_eval_hardening",
        11: "_eval_c2",
        12: "_eval_inventory",
    }


def _stage_completed(context: ScanContext, stage_id: StageId) -> bool:
    """Whether a stage ran to completion, so its silence means something."""
    return any(s.stage_id is stage_id and s.status is StageStatus.COMPLETE for s in context.stages)


def _omitted(reason: str, remediation: str, stage: StageId) -> ControlResult:
    """A check that did not run, with the reason stated rather than implied."""
    return ControlResult(
        control_id=0,
        control_name="",
        status=CheckStatus.OMITTED,
        result="UNKNOWN",
        evidence=[reason],
        remediation=remediation,
        source_stage=stage,
    )


def _has_positive_hardening(hardening: BinaryHardening) -> bool:
    """Whether the structures support a hardening claim, positively."""
    if hardening.nx_enabled is not True:
        return False
    return bool(hardening.pie_enabled is not False)


def _program_name(program: str) -> str:
    """Basename of a startup program, ignoring arguments."""
    return program.split()[0].rsplit("/", 1)[-1].lower()


def summarize_controls(controls: list[ControlResult]) -> dict[str, int]:
    """Counts of performed / inconclusive / not-applicable / omitted checks."""
    counts = {status.value: 0 for status in CheckStatus}
    for control in controls:
        counts[control.status.value] = counts.get(control.status.value, 0) + 1
    return counts
