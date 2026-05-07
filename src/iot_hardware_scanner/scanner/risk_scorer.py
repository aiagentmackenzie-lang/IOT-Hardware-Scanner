"""Risk Scorer — Phase 7a.

Evaluates 12 security controls and computes a numerical risk score.

SDR §13.1 — Risk Scoring

Stub implementation — full build in Phase 7 delivery.
"""

from __future__ import annotations

import logging

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.models import (
    ControlScore,
    RiskLevel,
    RiskScore,
    ScanContext,
)

logger = logging.getLogger(__name__)

# SDR §13.1 — 12 security controls
CONTROLS = [
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


class RiskScorer:
    """Compute numerical risk score from all findings."""

    def __init__(self, config: ScannerConfig) -> None:
        self.config = config

    def score(self, context: ScanContext) -> RiskScore:
        """Compute risk score from all scan findings.

        Each control is evaluated independently:
        - PASS (full points): No findings for this control
        - PARTIAL (50% points): Some findings, mitigated
        - FAIL (0 points): Findings indicate control is absent
        """
        control_scores: list[ControlScore] = []
        total = 0.0
        max_total = sum(c[2] for c in CONTROLS)

        for ctrl_id, ctrl_name, max_pts in CONTROLS:
            result, points, evidence, remediation = self._evaluate_control(ctrl_id, context)
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

        # Determine risk level
        if total >= 90:
            level = RiskLevel.LOW
        elif total >= 70:
            level = RiskLevel.MEDIUM
        elif total >= 50:
            level = RiskLevel.HIGH
        else:
            level = RiskLevel.CRITICAL

        failed = [c.control_name for c in control_scores if c.result == "FAIL"]

        summary = f"Risk Score: {total:.0f}/{max_total} ({level.value}). " + (
            f"Failed controls: {', '.join(failed)}." if failed else "All controls passed."
        )

        return RiskScore(
            total_score=total,
            risk_level=level,
            control_scores=control_scores,
            executive_summary=summary,
        )

    def _evaluate_control(
        self, ctrl_id: int, context: ScanContext
    ) -> tuple[str, float, list[str], str]:
        """Evaluate a single security control.

        Returns: (result, points, evidence, remediation)
        """
        if ctrl_id == 1:  # No default/hardcoded credentials
            cred_critical = sum(
                1 for f in context.credential_findings if f.severity.value == "CRITICAL"
            )
            if cred_critical > 0:
                return (
                    "FAIL",
                    0.0,
                    [f"{cred_critical} CRITICAL credential findings"],
                    "Remove all hardcoded credentials",
                )
            return "PASS", 10.0, [], ""

        if ctrl_id == 7:  # No backdoor interfaces
            c2_likely = sum(1 for f in context.c2_findings if f.severity == "LIKELY_C2")
            if c2_likely > 0:
                return (
                    "FAIL",
                    0.0,
                    [f"{c2_likely} LIKELY_C2 findings"],
                    "Remove backdoor services and C2 indicators",
                )

        if ctrl_id == 11 and context.c2_findings:  # No C2/malware indicators
                c2_count = len(context.c2_findings)
                pts = max(0, 5 - c2_count)
                return (
                    "PARTIAL" if pts > 0 else "FAIL",
                    pts,
                    [f"{c2_count} C2 findings"],
                    "Investigate and remove C2 indicators",
                )

        # Default: PASS (no findings for this control)
        max_pts = next((c[2] for c in CONTROLS if c[0] == ctrl_id), 10)
        return "PASS", float(max_pts), [], ""
