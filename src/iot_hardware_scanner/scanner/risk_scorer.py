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
from pathlib import Path
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
from iot_hardware_scanner.scanner.fit_dtb import selected_configuration

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

#: Packages whose presence and version identify the shipped TLS implementation.
TLS_PACKAGE_NAMES = frozenset(
    {
        "libopenssl",
        "openssl-util",
        "libopenssl-conf",
        "libustream-openssl",
        "libustream-mbedtls",
        "libustream-wolfssl",
        "libmbedtls",
        "libwolfssl",
        "libgnutls",
        "libnettle",
        "libcyassl",
        "libmbedcrypto",
    }
)

#: What each check asks, and which source can answer it. A check is only
#: reported as PERFORMED when its required source actually produced evidence;
#: a missing source is OMITTED or INCONCLUSIVE with the reason, never a pass.
CONTROL_SPECS: dict[int, dict[str, str]] = {
    1: {
        "question": "Does the artifact contain a default or hardcoded credential?",
        "required_source": (
            "the credential rule set and the account databases, with placeholder, "
            "documentation and reachability semantics applied"
        ),
    },
    2: {
        "question": "Does the artifact configure a network service, and is it listening?",
        "required_source": (
            "startup directives with their source line (configured); a socket table "
            "from the device (listening) — the second is not available from an image"
        ),
    },
    3: {
        "question": "Does an applicable advisory affect a component this artifact ships?",
        "required_source": "a local advisory snapshot, applied to observed product and version",
    },
    4: {
        "question": "Is data stored in the artifact encrypted at rest?",
        "required_source": (
            "format evidence (an encrypted container, a key-management record); byte "
            "distribution is an observation and never a verdict"
        ),
    },
    5: {
        "question": "Does shipped content contain a signature or digest verification step?",
        "required_source": "the update-path files in the enumerated image, read bounded",
    },
    6: {
        "question": "Does the board enforce that verified content at boot?",
        "required_source": (
            "boot log, fuse/OTP state or secure-boot configuration from the device; a "
            "static image cannot answer this"
        ),
    },
    7: {
        "question": "Does the artifact contain a backdoor interface?",
        "required_source": (
            "the indicator rule set and the domain/IP sweep, after reachability rules"
        ),
    },
    8: {
        "question": "Does the artifact use a strong cryptographic algorithm?",
        "required_source": (
            "algorithm identifiers in shipped binaries, account hash algorithms and the "
            "TLS implementation recorded by the package database — not binary hardening"
        ),
    },
    9: {
        "question": "Is the attack surface minimal (no SUID or world-writable files)?",
        "required_source": "permission bits from the image or a declared build manifest",
    },
    10: {
        "question": "Do shipped binaries carry positive hardening evidence?",
        "required_source": (
            "program headers: NX stack, PIE, RELRO; a missing symbol table is unknown"
        ),
    },
    11: {
        "question": "Does the artifact carry a C2 or malware indicator?",
        "required_source": (
            "the indicator rule set and the heuristic sweep, with typed destinations"
        ),
    },
    12: {
        "question": "Does the artifact carry an accurate component inventory?",
        "required_source": "the image's own installed-package database and read ELF metadata",
    },
}


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
        # A boot manifest is asked exactly two questions: does the shipped
        # content carry a verification step, and does the board enforce it?
        "firmware-boot": frozenset({5, 6}),
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
            spec = CONTROL_SPECS[control_id]
            result.question = spec["question"]
            result.required_source = spec["required_source"]
            if result.status is CheckStatus.NOT_APPLICABLE:
                result.applicability = "NOT_APPLICABLE"
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
        """Applicability from the local snapshot, with each lookup's state.

        A clean result is only a pass when **every** lookup settled as an empty
        or matched answer against a current snapshot. An unavailable, partial or
        stale lookup is a stated gap: the check answers INCONCLUSIVE and names
        which component's question went unanswered.
        """
        if not advisory_assessed:
            return _omitted(
                "No advisory snapshot was applied — applicability was not assessed",
                "Supply a local snapshot with --advisory-snapshot to assess it offline.",
                StageId.ADVISORY,
            )

        advisory = context.advisory
        findings = context.cve_findings
        stale = advisory is not None and (
            advisory.state == "STALE" or (advisory.snapshot is not None and advisory.snapshot.stale)
        )
        evidence: list[str] = []
        if advisory is not None:
            evidence.append(
                f"{len(advisory.lookups)} component lookup(s) against {advisory.state.lower()} "
                f"snapshot data"
                + (
                    f" from {advisory.snapshot.provider} acquired {advisory.snapshot.acquired_at}"
                    if advisory.snapshot is not None
                    else ""
                )
            )
            if advisory.keyword_candidates_rejected:
                evidence.append(
                    f"{advisory.keyword_candidates_rejected} keyword candidate(s) were rejected "
                    "because the advisory did not name the shipped product and version"
                )

        kev = [finding for finding in findings if finding.is_in_kev]
        critical = [finding for finding in findings if finding.severity is Severity.CRITICAL]
        if findings:
            evidence.append(f"{len(findings)} applicable advisory finding(s)")
            if kev:
                evidence.append(
                    f"{len(kev)} listed in CISA KEV: "
                    + ", ".join(sorted({finding.cve_id for finding in kev}))
                )
            if stale:
                evidence.append(
                    "The snapshot this matched is older than the configured age, so the "
                    "match itself may no longer hold; refresh it before acting."
                )
            return ControlResult(
                control_id=3,
                control_name="",
                status=CheckStatus.INCONCLUSIVE if stale else CheckStatus.PERFORMED,
                result="FAIL" if kev or critical else "REVIEW",
                evidence=evidence,
                remediation="Refresh the snapshot, then update the affected components.",
                source_stage=StageId.ADVISORY,
            )

        if advisory is None:
            return ControlResult(
                control_id=3,
                control_name="",
                status=CheckStatus.PERFORMED,
                result="PASS",
                evidence=["Advisory assessment ran with no applicable matches"],
                source_stage=StageId.ADVISORY,
            )

        if advisory.state == "STALE" or advisory.snapshot is None or advisory.snapshot.stale:
            return ControlResult(
                control_id=3,
                control_name="",
                status=CheckStatus.INCONCLUSIVE,
                result="UNKNOWN",
                evidence=[
                    *evidence,
                    "The snapshot is older than the configured age, so a clean result "
                    "from it is not a statement about the current advisory picture.",
                ],
                remediation="Refresh the advisory snapshot in a separate operation and re-run.",
                source_stage=StageId.ADVISORY,
            )

        if not advisory.complete:
            gaps = [
                f"{lookup.component} {lookup.version}: {lookup.state.lower()}"
                + (f" — {lookup.reason}" if lookup.reason else "")
                for lookup in advisory.lookups
                if lookup.state not in ("MATCHED", "KNOWN_EMPTY")
            ]
            return ControlResult(
                control_id=3,
                control_name="",
                status=CheckStatus.INCONCLUSIVE,
                result="UNKNOWN",
                evidence=[
                    *evidence,
                    "Not every component's advisory question was answered: " + "; ".join(gaps),
                ],
                remediation=(
                    "Refresh the snapshot so every queried component has a settled lookup."
                ),
                source_stage=StageId.ADVISORY,
            )

        return ControlResult(
            control_id=3,
            control_name="",
            status=CheckStatus.PERFORMED,
            result="PASS",
            evidence=[
                *evidence,
                "Every component's advisory lookup settled with no applicable match.",
            ],
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

    # ── Control 5: signed-content verification ──
    def _eval_update(self, context: ScanContext, advisory_assessed: bool) -> ControlResult:
        """Content verification only. Whether the board enforces it is control 6.

        The evidence is what the shipped files contain, read through the bounded
        reader: an update path plus a verification step (a signature check, a
        digest comparison, a verification program). That is a statement about
        content, not about a running updater.
        """
        if context.boot is not None:
            return self._eval_boot_update(context)

        inventory = context.filesystem_inventory
        if inventory is None:
            return _omitted(
                "No filesystem inventory — no update path could be read",
                "Extract the root filesystem and re-run the service check.",
                StageId.ENUMERATION,
            )

        update_files = [
            finding
            for finding in inventory.findings
            if any(
                keyword in str(finding.path).lower()
                for keyword in ("update", "upgrade", "firmware", "ota", "sysupgrade")
            )
        ]
        if not update_files:
            return ControlResult(
                control_id=5,
                control_name="",
                status=CheckStatus.INCONCLUSIVE,
                result="UNKNOWN",
                evidence=[
                    "No update-related file was found in the enumerated image, so the "
                    "update mechanism could not be inspected."
                ],
                remediation=(
                    "Document the update mechanism and the verification step it performs."
                ),
                source_stage=StageId.ENUMERATION,
            )

        verifiers: list[str] = []
        for entry in update_files:
            text = _read_text_bounded(entry.absolute_path, self.config)
            if not text:
                continue
            lowered = text.lower()
            if any(
                keyword in lowered
                for keyword in ("verify", "signature", "gpg", "sha256sum", "checksum", "ed25519")
            ):
                verifiers.append(str(entry.path))

        if verifiers:
            return ControlResult(
                control_id=5,
                control_name="",
                status=CheckStatus.PERFORMED,
                result="REVIEW",
                evidence=[
                    f"{len(update_files)} update-related file(s); a verification step is "
                    f"present in {', '.join(sorted(verifiers)[:3])}",
                    "Content verification in a shipped script is not proof that the device "
                    "runs it, or that the public key is pinned. Board enforcement is check 6.",
                ],
                remediation=(
                    "Confirm on the device that the updater verifies a signature against a "
                    "pinned key and refuses unsigned content."
                ),
                source_stage=StageId.ENUMERATION,
            )

        return ControlResult(
            control_id=5,
            control_name="",
            status=CheckStatus.PERFORMED,
            result="FAIL",
            evidence=[
                f"{len(update_files)} update-related file(s), and none of them contains a "
                "signature, digest or checksum verification step"
            ],
            remediation="Implement signed firmware updates and verify the signature on the device.",
            source_stage=StageId.ENUMERATION,
        )

    def _eval_boot_update(self, context: ScanContext) -> ControlResult:
        """Check 5 for a boot manifest: a positive source, kept in its place.

        An FIT can carry a real verification step: declared payload digests and
        a signature over the selected configuration. That is positive content
        evidence, so this is the one place check 5 can be PERFORMED without a
        filesystem. It still does not claim the board runs the check.
        """
        artifacts = context.boot.artifacts if context.boot else []
        selected = [(artifact, selected_configuration(artifact)) for artifact in artifacts]
        payloads = [p for artifact in artifacts for p in artifact.referenced_payloads]
        matches = [p for p in payloads if p.integrity == "match"]
        mismatches = [p for p in payloads if p.integrity == "mismatch"]
        out_of_bounds = [p for p in payloads if p.integrity == "out-of-bounds"]
        undeclared = [p for p in payloads if p.integrity == "undeclared"]
        signed_selected = [
            config
            for _artifact, config in selected
            if config is not None and config.signature.present
        ]
        verified_selected = [
            config for config in signed_selected if config.signature.verified is True
        ]

        evidence = [
            f"{len(payloads)} referenced payload(s): {len(matches)} digest match, "
            f"{len(mismatches)} mismatch, {len(out_of_bounds)} out of bounds, "
            f"{len(undeclared)} undeclared",
            f"{len(signed_selected)} signature(s) on the selected configuration, "
            f"{len(verified_selected)} verified with an operator-supplied key",
        ]

        if mismatches or out_of_bounds:
            for payload in mismatches + out_of_bounds:
                evidence.append(
                    f"{payload.node}: declared {payload.digest_declared or 'nothing'}, "
                    f"observed {payload.digest_observed or 'unreadable'} "
                    f"({payload.integrity})"
                )
            return ControlResult(
                control_id=5,
                control_name="",
                status=CheckStatus.PERFORMED,
                result="FAIL",
                evidence=[
                    *evidence,
                    "A declared digest does not match the bytes it covers, so the "
                    "verification step the manifest declares would reject this payload.",
                ],
                remediation=(
                    "Rebuild the FIT so each payload digest matches its declared hash, "
                    "or correct the declaration; then confirm on the device that the "
                    "bootloader enforces it."
                ),
                source_stage=StageId.BOOT_ANALYSIS,
            )

        if verified_selected:
            config = verified_selected[0]
            evidence.append(
                f"configuration {config.name!r} is signed over "
                f"{', '.join(config.signature.signed_nodes)} and verifies with the "
                f"supplied key (algo {config.signature.algo})"
            )
        elif signed_selected:
            config = signed_selected[0]
            evidence.append(
                f"configuration {config.name!r} carries a signature that was not "
                f"verified: {config.signature.reason}"
            )
        elif matches:
            evidence.append(
                "Declared payload digests match, but no signature covers the selected "
                "configuration; this is integrity, not authenticity."
            )

        if verified_selected or signed_selected or matches:
            return ControlResult(
                control_id=5,
                control_name="",
                status=CheckStatus.PERFORMED,
                result="REVIEW",
                evidence=[
                    *evidence,
                    "The manifest declares a verification step and the content evidence "
                    "supports it. Whether the device runs it, and whether the key is "
                    "pinned in hardware, is check 6 and is unknown.",
                ],
                remediation=(
                    "Confirm on the device that the bootloader verifies this "
                    "configuration against a pinned key and refuses unverified content."
                ),
                source_stage=StageId.BOOT_ANALYSIS,
            )

        if not payloads and not signed_selected:
            return ControlResult(
                control_id=5,
                control_name="",
                status=CheckStatus.INCONCLUSIVE,
                result="UNKNOWN",
                evidence=[
                    *evidence,
                    "The artifact declares no payload digest and no signature over a "
                    "selected configuration, so no verification step was observed.",
                ],
                remediation="Ship a manifest that declares payload digests or a signature.",
                source_stage=StageId.BOOT_ANALYSIS,
            )

        return ControlResult(
            control_id=5,
            control_name="",
            status=CheckStatus.PERFORMED,
            result="FAIL",
            evidence=[
                *evidence,
                "Referenced payloads declare no digest and no selected configuration "
                "carries a signature.",
            ],
            remediation="Add payload digests and a signature over the selected configuration.",
            source_stage=StageId.BOOT_ANALYSIS,
        )

    # ── Control 6: secure boot / board enforcement ──
    def _eval_secure_boot(self, context: ScanContext, advisory_assessed: bool) -> ControlResult:
        """Enforcement, not content: the question a static image cannot answer.

        Check 5 reports whether shipped content verifies a signature. This check
        asks whether the board refuses unverified content at boot, which needs
        boot logs, fuse/OTP state or secure-boot configuration from the device.
        """
        if context.boot is not None:
            evidence = []
            for artifact in context.boot.artifacts:
                config = selected_configuration(artifact)
                if config is None:
                    evidence.append(
                        f"{artifact.locator}: no default configuration is declared, so "
                        "even the intended boot target is unknown"
                    )
                    continue
                signature = config.signature
                verification = (
                    "true"
                    if signature.verified is True
                    else "false"
                    if signature.verified is False
                    else "unverified"
                )
                evidence.append(
                    f"{artifact.locator}: declares default configuration {config.name!r} "
                    f"(kernel {config.kernel!r}, fdt {config.fdt!r}); signature "
                    f"{'present' if signature.present else 'absent'}, verification "
                    f"{verification}"
                )
            evidence.extend(
                [
                    "A declared configuration is intent, not enforcement. No boot log, "
                    "fuse/OTP state or secure-boot configuration was supplied, so this "
                    "check cannot pass or fail.",
                    "The artifact's own signature verification is reported separately as "
                    "check 5; it says nothing about the board refusing unverified content.",
                ]
            )
            return ControlResult(
                control_id=6,
                control_name="",
                status=CheckStatus.INCONCLUSIVE,
                result="UNKNOWN",
                evidence=evidence,
                remediation=(
                    "Provide a boot log and the fuse/OTP state from the device, or an "
                    "authorised report of the secure-boot configuration."
                ),
                source_stage=StageId.BOOT_ANALYSIS,
            )
        return ControlResult(
            control_id=6,
            control_name="",
            status=CheckStatus.INCONCLUSIVE,
            result="UNKNOWN",
            evidence=[
                "Boot enforcement happens on the device; a static image cannot establish "
                "that a verified boot chain runs or that it cannot be bypassed.",
                "Signed-content verification inside the image is reported separately as "
                "check 5; it says nothing about enforcement.",
            ],
            remediation="Provide a boot log and the fuse/OTP state from the device.",
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
        """Algorithm evidence, kept apart from binary hardening (check 10).

        Three sources can answer part of this question, and each is named:

        * an account hash algorithm read from the joined ``/etc/shadow`` records;
        * an algorithm identifier next to a structural constant in a shipped
          binary (the ``crypto`` destination of the rule set) — evidence that an
          implementation is *present*, not that it is reachable or in use;
        * the TLS implementation and version recorded by the package database.

        A weak account hash is contrary evidence and fails the check. Presence
        of a weak algorithm in library code is a review: the image ships it, and
        a static scan cannot say whether anything calls it. Missing every source
        leaves the check omitted, never passed.
        """
        weak_accounts = [
            finding
            for finding in context.credential_findings
            if finding.rule_id == "credential.unix.md5_hash"
        ]
        weak_code = list(context.crypto_findings)
        tls_libraries = _tls_libraries(context)

        evidence: list[str] = []
        if weak_accounts:
            evidence.append(
                f"{len(weak_accounts)} account(s) store an MD5 password hash: "
                + ", ".join(sorted({str(item.file_path) for item in weak_accounts}))
            )
        elif _stage_completed(context, StageId.UNIX_ACCOUNTS):
            evidence.append("The account database was joined and no account stores an MD5 hash.")
        if weak_code:
            evidence.append(
                f"{len(weak_code)} weak-algorithm implementation(s) are present in shipped "
                "binaries: "
                + ", ".join(sorted({f"{item.algorithm} in {item.file_path}" for item in weak_code}))
            )
        if tls_libraries:
            evidence.append(
                "The package database records "
                + ", ".join(
                    f"{record.name} {record.version}"
                    for record in sorted(tls_libraries, key=lambda r: r.name)
                )
            )

        if weak_accounts:
            return ControlResult(
                control_id=8,
                control_name="",
                status=CheckStatus.PERFORMED,
                result="FAIL",
                evidence=evidence,
                remediation="Re-hash account credentials with SHA-512 or bcrypt.",
                source_stage=StageId.UNIX_ACCOUNTS,
            )

        if weak_code or tls_libraries:
            return ControlResult(
                control_id=8,
                control_name="",
                status=CheckStatus.PERFORMED,
                result="REVIEW",
                evidence=[
                    *evidence,
                    "No account uses a broken hash, but an implementation being present is "
                    "not proof of the algorithms in use. Cipher suites, key sizes and "
                    "protocol versions need a configuration or runtime source.",
                ],
                remediation=(
                    "Disable weak ciphers in the shipped configuration and provide the TLS "
                    "configuration as evidence."
                ),
                source_stage=StageId.OPKG_INVENTORY if tls_libraries else StageId.C2_INDICATORS,
            )

        return _omitted(
            "No evidence source identified a cryptographic algorithm in this artifact "
            "(no account database, no algorithm identifier in a parsed binary, no TLS "
            "package record)",
            "Extract the image, or supply the package database, so an algorithm can be named.",
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
        installed_records = (
            context.opkg_inventory.installed_count if context.opkg_inventory is not None else None
        )
        evidence = [f"{len(recorded)} recorded component(s) recovered"]
        if installed_records is not None:
            evidence.append(
                f"{len(recorded)} of {installed_records} installed-package record(s) "
                "carry a component with its own evidence range"
            )
        by_basis: dict[str, int] = {}
        for component in components:
            by_basis[component.cpe_basis or "unrecorded"] = (
                by_basis.get(component.cpe_basis or "unrecorded", 0) + 1
            )
        if by_basis:
            evidence.append(
                "naming basis: "
                + ", ".join(f"{name} {count}" for name, count in sorted(by_basis.items()))
            )
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


def _tls_libraries(context: ScanContext) -> list:
    """Package records that identify the shipped TLS implementation."""
    inventory = context.opkg_inventory
    if inventory is None:
        return []
    return [
        record
        for record in inventory.records
        if record.installed and record.name.lower() in TLS_PACKAGE_NAMES
    ]


def _read_text_bounded(path: Path, config: ScannerConfig, budget_bytes: int | None = None) -> str:
    """Read a file for inspection without ever reading an arbitrary amount."""
    from iot_hardware_scanner.scanner.bounded_reader import open_bounded

    budget = budget_bytes or config.max_scan_file_size_mb * 1024 * 1024
    try:
        text, _truncated = open_bounded(path).read_text_bounded(budget, encoding="utf-8")
    except (OSError, ValueError):
        return ""
    return text


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
