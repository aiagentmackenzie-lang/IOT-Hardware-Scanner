"""Risk Scorer — Phase 7a.

Evaluates 12 security controls and computes a numerical risk score
based on findings from all prior scan phases.

SDR §13.1 — Risk Scoring Model
"""

from __future__ import annotations

import logging
from typing import ClassVar

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.models import (
    ControlScore,
    RiskLevel,
    RiskScore,
    ScanContext,
)

logger = logging.getLogger(__name__)

# ── SDR §13.1 — 12 security controls ──
# (control_id, control_name, max_points)
CONTROLS: list[tuple[int, str, float]] = [
    (1, "No default/hardcoded credentials", 10),
    (2, "No unnecessary network services", 10),
    (3, "No outdated/vulnerable components", 10),
    (4, "Encrypted data at rest", 10),
    (5, "Secure firmware update mechanism", 10),
    (6, "Secure boot/integrity verification", 8),
    (7, "No backdoor interfaces", 10),
    (8, "Strong cryptography used", 8),
    (9, "Minimal attack surface", 8),
    (10, "Binary hardening present", 8),
    (11, "No C2/malware indicators", 5),
    (12, "Accurate component inventory (SBOM)", 3),
]

# ── OWASP IoT Top 10 mapping ──
_OWASP_IOT_MAP: dict[str, list[int]] = {
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


class RiskScorer:
    """Compute numerical risk score from all findings.

    Each control is evaluated independently:
    - PASS (full points): No findings for this control
    - PARTIAL (50% points): Some findings, mitigated
    - FAIL (0 points): Findings indicate control is absent

    Total possible: 100 points → mapped to LOW/MEDIUM/HIGH/CRITICAL
    """

    def __init__(self, config: ScannerConfig) -> None:
        self.config = config

    def score(self, context: ScanContext) -> RiskScore:
        """Compute risk score from all scan findings."""
        control_scores: list[ControlScore] = []
        total = 0.0
        max_total = sum(c[2] for c in CONTROLS)

        for ctrl_id, ctrl_name, max_pts in CONTROLS:
            result, points, evidence, remediation = self._evaluate_control(
                ctrl_id, context
            )
            control_scores.append(
                ControlScore(
                    control_id=ctrl_id,
                    control_name=ctrl_name,
                    result=result,
                    points=points,
                    max_points=max_pts,
                    evidence=evidence,
                    remediation=remediation,
                )
            )
            total += points

        # Determine risk level (SDR §13.1)
        if total >= 90:
            level = RiskLevel.LOW
        elif total >= 70:
            level = RiskLevel.MEDIUM
        elif total >= 50:
            level = RiskLevel.HIGH
        else:
            level = RiskLevel.CRITICAL

        # Weighted breakdown
        breakdown = self._compute_breakdown(control_scores)

        # Executive summary
        failed = [c.control_name for c in control_scores if c.result == "FAIL"]
        partial = [c.control_name for c in control_scores if c.result == "PARTIAL"]
        summary = f"Risk Score: {total:.0f}/{max_total:.0f} ({level.value}). "
        if failed:
            summary += f"Failed controls: {', '.join(failed)}. "
        if partial:
            summary += f"Partial: {', '.join(partial)}. "
        if not failed and not partial:
            summary += "All controls passed."

        # OWASP IoT Top 10 mapping
        owasp_mapping = self._compute_owasp_mapping(control_scores)

        return RiskScore(
            total_score=total,
            risk_level=level,
            control_scores=control_scores,
            weighted_breakdown=breakdown,
            executive_summary=summary,
            owasp_iot_mapping=owasp_mapping,
        )

    # ──────────────────────────────────────────
    # Control evaluation
    # ──────────────────────────────────────────

    def _evaluate_control(
        self, ctrl_id: int, context: ScanContext
    ) -> tuple[str, float, list[str], str]:
        """Evaluate a single security control.

        Returns:
            (result, points, evidence, remediation)
        """
        evaluator = self._EVALUATORS.get(ctrl_id)
        if evaluator:
            method = getattr(self, evaluator)
            return method(context)
        # Unknown control → PASS with max points
        max_pts = next((c[2] for c in CONTROLS if c[0] == ctrl_id), 10)
        return "PASS", max_pts, [], ""

    def _eval_no_default_credentials(
        self, context: ScanContext
    ) -> tuple[str, float, list[str], str]:
        """Control 1: No default/hardcoded credentials (OWASP I1)."""
        if not context.credential_findings:
            return "PASS", 10.0, [], ""

        critical = sum(
            1 for f in context.credential_findings if f.severity.value == "CRITICAL"
        )
        high = sum(
            1 for f in context.credential_findings if f.severity.value == "HIGH"
        )
        medium = sum(
            1 for f in context.credential_findings if f.severity.value == "MEDIUM"
        )

        evidence: list[str] = []
        if critical:
            evidence.append(f"{critical} CRITICAL credential findings")
        if high:
            evidence.append(f"{high} HIGH credential findings")
        if medium:
            evidence.append(f"{medium} MEDIUM credential findings")

        if critical > 0:
            return (
                "FAIL",
                0.0,
                evidence,
                "Remove all hardcoded and default credentials. "
                "Implement proper credential management.",
            )
        if high > 0:
            return (
                "PARTIAL",
                5.0,
                evidence,
                "Review and remove high-severity credential exposures.",
            )
        # Only medium/low → partial
        return (
            "PARTIAL",
            7.0,
            evidence,
            "Review remaining credential findings for hardening.",
        )

    def _eval_no_unnecessary_services(
        self, context: ScanContext
    ) -> tuple[str, float, list[str], str]:
        """Control 2: No unnecessary network services (OWASP I2)."""
        inv = context.filesystem_inventory
        if not inv:
            return "PASS", 10.0, [], ""

        network_svcs = inv.network_services
        init_scripts = inv.init_scripts

        # Check for dangerous services: telnet, ftp, rsh
        dangerous_found: list[str] = []
        for svc in network_svcs:
            name_lower = str(svc.path).lower()
            if any(d in name_lower for d in ("telnet", "ftp", "rsh", "rlogin")):
                dangerous_found.append(str(svc.path))

        evidence: list[str] = []
        if dangerous_found:
            evidence.append(f"Dangerous services: {', '.join(dangerous_found[:5])}")
        if network_svcs:
            evidence.append(f"{len(network_svcs)} network services detected")
        if init_scripts:
            evidence.append(f"{len(init_scripts)} init scripts")

        if dangerous_found:
            return (
                "FAIL",
                0.0,
                evidence,
                "Remove insecure services (telnetd, ftpd, rshd). "
                "Use SSH with key-based auth instead.",
            )
        if len(network_svcs) > 10:
            return (
                "PARTIAL",
                5.0,
                evidence,
                "Reduce network attack surface by disabling "
                "unnecessary services.",
            )
        return "PASS", 10.0, evidence, ""

    def _eval_no_outdated_components(
        self, context: ScanContext
    ) -> tuple[str, float, list[str], str]:
        """Control 3: No outdated/vulnerable components (OWASP I5)."""
        if not context.cve_findings:
            return "PASS", 10.0, [], ""

        critical_cves = sum(
            1 for f in context.cve_findings if f.severity.value == "CRITICAL"
        )
        high_cves = sum(
            1 for f in context.cve_findings if f.severity.value == "HIGH"
        )
        kev_count = sum(1 for f in context.cve_findings if f.is_in_kev)

        evidence: list[str] = []
        if critical_cves:
            evidence.append(f"{critical_cves} CRITICAL CVEs")
        if high_cves:
            evidence.append(f"{high_cves} HIGH CVEs")
        if kev_count:
            evidence.append(f"{kev_count} in CISA KEV catalog")

        if kev_count > 0 or critical_cves > 0:
            return (
                "FAIL",
                0.0,
                evidence,
                "Update components with known exploited vulnerabilities. "
                "Prioritize CISA KEV catalog entries.",
            )
        if high_cves > 0:
            return (
                "PARTIAL",
                5.0,
                evidence,
                "Update components with high-severity CVEs.",
            )
        return (
            "PARTIAL",
            7.0,
            evidence,
            "Review remaining CVEs and plan component updates.",
        )

    def _eval_encrypted_data_at_rest(
        self, context: ScanContext
    ) -> tuple[str, float, list[str], str]:
        """Control 4: Encrypted data at rest (OWASP I7)."""
        # Check for plaintext passwords and sensitive data
        plaintext_creds = [
            f
            for f in context.credential_findings
            if f.severity.value in ("CRITICAL", "HIGH")
            and not f.is_placeholder
            and f.category in ("password", "connection_string")
        ]

        evidence: list[str] = []
        if plaintext_creds:
            evidence.append(
                f"{len(plaintext_creds)} plaintext credential findings"
            )

        if len(plaintext_creds) > 3:
            return (
                "FAIL",
                0.0,
                evidence,
                "Encrypt sensitive data at rest. "
                "Remove plaintext credentials from firmware.",
            )
        if plaintext_creds:
            return (
                "PARTIAL",
                5.0,
                evidence,
                "Encrypt or hash remaining plaintext credentials.",
            )
        return "PASS", 10.0, [], ""

    def _eval_secure_update(
        self, context: ScanContext
    ) -> tuple[str, float, list[str], str]:
        """Control 5: Secure firmware update mechanism (OWASP I4)."""
        inv = context.filesystem_inventory
        if not inv:
            return "PASS", 10.0, ["No filesystem inventory available"], ""

        # Check for firmware update scripts/services
        update_related = [
            ff
            for ff in inv.findings
            if any(
                kw in str(ff.path).lower()
                for kw in ("update", "upgrade", "firmware", "ota", "sysupgrade")
            )
        ]

        # Check for signature verification in update scripts
        has_sig_check = False
        for ff in update_related:
            try:
                content = ff.absolute_path.read_text(errors="ignore")
                if any(
                    kw in content.lower()
                    for kw in ("verify", "signature", "gpg", "sha256sum", "checksum")
                ):
                    has_sig_check = True
                    break
            except (OSError, PermissionError):
                continue

        evidence: list[str] = []
        if update_related:
            evidence.append(f"{len(update_related)} update-related files found")
        if has_sig_check:
            evidence.append("Signature verification detected")
        else:
            evidence.append("No signature verification detected")

        if not update_related:
            return "PASS", 10.0, evidence, ""
        if not has_sig_check:
            return (
                "FAIL",
                0.0,
                evidence,
                "Implement signed firmware updates with "
                "cryptographic verification.",
            )
        return "PASS", 10.0, evidence, ""

    def _eval_secure_boot(
        self, context: ScanContext
    ) -> tuple[str, float, list[str], str]:
        """Control 6: Secure boot/integrity verification (ISVS V4.1)."""
        # If firmware has encrypted regions → good (indicates protection)
        # If no encrypted regions and no signature checks → fail
        entropy = context.entropy_profile
        evidence: list[str] = []

        if entropy:
            if entropy.has_encrypted_regions:
                evidence.append("Encrypted regions detected (positive)")
            else:
                evidence.append("No encrypted regions detected")
            if entropy.firmware_partially_readable:
                evidence.append("Firmware is partially readable")
        else:
            evidence.append("No entropy profile available")

        if entropy and not entropy.has_encrypted_regions and entropy.firmware_partially_readable:
            return (
                "PARTIAL",
                4.0,
                evidence,
                "Implement secure boot with firmware encryption "
                "and integrity verification.",
            )
        return "PASS", 8.0, evidence, ""

    def _eval_no_backdoor_interfaces(
        self, context: ScanContext
    ) -> tuple[str, float, list[str], str]:
        """Control 7: No backdoor interfaces (ISTG-FW-SCRT-003)."""
        # C2 findings with LIKELY_C2 severity
        c2_likely = [f for f in context.c2_findings if f.severity == "LIKELY_C2"]
        c2_suspicious = [f for f in context.c2_findings if f.severity == "SUSPICIOUS"]

        # Backdoor service indicators from YARA
        backdoor_findings = [
            f for f in context.c2_findings if f.indicator_type == "backdoor_service"
        ]

        evidence: list[str] = []
        if c2_likely:
            evidence.append(f"{len(c2_likely)} LIKELY_C2 findings")
        if c2_suspicious:
            evidence.append(f"{len(c2_suspicious)} SUSPICIOUS findings")
        if backdoor_findings:
            evidence.append(f"{len(backdoor_findings)} backdoor service detections")

        if c2_likely or backdoor_findings:
            return (
                "FAIL",
                0.0,
                evidence,
                "Remove backdoor services and C2 indicators. "
                "Investigate and eliminate unauthorized access paths.",
            )
        if c2_suspicious:
            return (
                "PARTIAL",
                5.0,
                evidence,
                "Investigate suspicious indicators for potential "
                "backdoor access.",
            )
        return "PASS", 10.0, evidence, ""

    def _eval_strong_crypto(
        self, context: ScanContext
    ) -> tuple[str, float, list[str], str]:
        """Control 8: Strong cryptography used (ISTG-FW-CRYPT-001)."""
        # Check binary intelligence for weak crypto
        bi = context.binary_intelligence
        evidence: list[str] = []

        if bi:
            total = bi.total_binaries
            unhardened = bi.unhardened_binaries
            evidence.append(f"{total} binaries, {unhardened} unhardened")
            if unhardened > total * 0.5 and total > 0:
                return (
                    "FAIL",
                    0.0,
                    evidence,
                    "Most binaries lack hardening. "
                    "Enable NX, stack canaries, RELRO, PIE.",
                )
            if unhardened > 0:
                return (
                    "PARTIAL",
                    4.0,
                    evidence,
                    "Enable binary hardening for all compiled binaries.",
                )
        else:
            evidence.append("No binary intelligence available")

        # Check for weak crypto in credential findings
        weak_crypto_creds = [
            f
            for f in context.credential_findings
            if f.category == "password" and f.matched_pattern and "md5" in f.matched_pattern.lower()
        ]
        if weak_crypto_creds:
            evidence.append(f"{len(weak_crypto_creds)} MD5-related findings")
            return (
                "PARTIAL",
                4.0,
                evidence,
                "Replace weak cryptographic hashes (MD5) with SHA-256+.",
            )

        return "PASS", 8.0, evidence, ""

    def _eval_minimal_attack_surface(
        self, context: ScanContext
    ) -> tuple[str, float, list[str], str]:
        """Control 9: Minimal attack surface (ISVS V3.2)."""
        inv = context.filesystem_inventory
        if not inv:
            return "PASS", 8.0, [], ""

        suid = len(inv.suid_binaries)
        world_writable = len(inv.world_writable_files)

        evidence: list[str] = []
        if suid:
            evidence.append(f"{suid} SUID binaries")
        if world_writable:
            evidence.append(f"{world_writable} world-writable files")

        if suid > 5 or world_writable > 10:
            return (
                "FAIL",
                0.0,
                evidence,
                "Reduce attack surface: audit SUID binaries, "
                "fix world-writable permissions.",
            )
        if suid > 0 or world_writable > 0:
            return (
                "PARTIAL",
                4.0,
                evidence,
                "Review SUID binaries and world-writable files.",
            )
        return "PASS", 8.0, evidence, ""

    def _eval_binary_hardening(
        self, context: ScanContext
    ) -> tuple[str, float, list[str], str]:
        """Control 10: Binary hardening present (FSTM Stage 5)."""
        bi = context.binary_intelligence
        if not bi or bi.total_binaries == 0:
            return "PASS", 8.0, ["No binaries analyzed"], ""

        hardened = bi.hardened_binaries
        total = bi.total_binaries

        # Calculate hardening ratio
        ratio = hardened / total if total > 0 else 1.0
        evidence = [f"{hardened}/{total} binaries hardened ({ratio:.0%})"]

        if ratio < 0.3:
            return (
                "FAIL",
                0.0,
                evidence,
                "Enable NX, stack canaries, full RELRO, and PIE "
                "for all compiled binaries.",
            )
        if ratio < 0.7:
            return (
                "PARTIAL",
                4.0,
                evidence,
                "Increase binary hardening coverage. "
                "Compile with -fstack-protector-strong, -D_FORTIFY_SOURCE=2.",
            )
        return "PASS", 8.0, evidence, ""

    def _eval_no_c2_malware(
        self, context: ScanContext
    ) -> tuple[str, float, list[str], str]:
        """Control 11: No C2/malware indicators (MITRE ATT&CK ICS)."""
        c2_count = len(context.c2_findings)
        if c2_count == 0:
            return "PASS", 5.0, [], ""

        c2_likely = sum(1 for f in context.c2_findings if f.severity == "LIKELY_C2")
        evidence = [f"{c2_count} C2/malware findings ({c2_likely} LIKELY_C2)"]

        if c2_likely > 0:
            return (
                "FAIL",
                0.0,
                evidence,
                "Investigate and remove C2 indicators. "
                "Potential malware compromise detected.",
            )
        if c2_count > 3:
            return (
                "PARTIAL",
                2.0,
                evidence,
                "Review suspicious indicators for potential compromise.",
            )
        return (
            "PARTIAL",
            3.0,
            evidence,
            "Review flagged indicators for false positives.",
        )

    def _eval_sbom_inventory(
        self, context: ScanContext
    ) -> tuple[str, float, list[str], str]:
        """Control 12: Accurate component inventory (ISVS V1.1.1)."""
        components = context.software_components
        if not components:
            return (
                "PARTIAL",
                1.0,
                ["No software components detected"],
                "Improve component detection. "
                "Generate SBOM with CycloneDX format.",
            )

        evidence = [f"{len(components)} components identified"]
        # Check version coverage
        with_version = sum(1 for c in components if c.version and c.version != "unknown")
        if with_version < len(components) * 0.8:
            evidence.append(
                f"Version coverage: {with_version}/{len(components)}"
            )
            return (
                "PARTIAL",
                2.0,
                evidence,
                "Improve version detection coverage. "
                "Many components have unknown versions.",
            )
        return "PASS", 3.0, evidence, ""

    # ── Evaluator dispatch ──
    _EVALUATORS: ClassVar[dict[int, str]] = {
        1: "_eval_no_default_credentials",
        2: "_eval_no_unnecessary_services",
        3: "_eval_no_outdated_components",
        4: "_eval_encrypted_data_at_rest",
        5: "_eval_secure_update",
        6: "_eval_secure_boot",
        7: "_eval_no_backdoor_interfaces",
        8: "_eval_strong_crypto",
        9: "_eval_minimal_attack_surface",
        10: "_eval_binary_hardening",
        11: "_eval_no_c2_malware",
        12: "_eval_sbom_inventory",
    }

    # ──────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────

    @staticmethod
    def _compute_breakdown(
        control_scores: list[ControlScore],
    ) -> dict[str, float]:
        """Compute weighted breakdown by control category."""
        categories: dict[str, float] = {
            "credentials": 0.0,
            "network": 0.0,
            "components": 0.0,
            "encryption": 0.0,
            "hardening": 0.0,
            "c2_malware": 0.0,
        }
        category_map = {
            1: "credentials",
            2: "network",
            3: "components",
            4: "encryption",
            5: "encryption",
            6: "encryption",
            7: "c2_malware",
            8: "hardening",
            9: "network",
            10: "hardening",
            11: "c2_malware",
            12: "components",
        }
        for cs in control_scores:
            cat = category_map.get(cs.control_id, "other")
            categories[cat] = categories.get(cat, 0.0) + cs.points
        return categories

    @staticmethod
    def _compute_owasp_mapping(
        control_scores: list[ControlScore],
    ) -> dict[str, int]:
        """Map OWASP IoT Top 10 items to finding counts."""
        fail_ids = {cs.control_id for cs in control_scores if cs.result == "FAIL"}
        partial_ids = {cs.control_id for cs in control_scores if cs.result == "PARTIAL"}

        mapping: dict[str, int] = {}
        for owasp_item, ctrl_ids in _OWASP_IOT_MAP.items():
            # 0 = pass, 1 = partial, 2 = fail
            if any(cid in fail_ids for cid in ctrl_ids):
                mapping[owasp_item] = 2
            elif any(cid in partial_ids for cid in ctrl_ids):
                mapping[owasp_item] = 1
            else:
                mapping[owasp_item] = 0
        return mapping
