"""Assessment completion and the process exit contract.

This module is the single place that answers two questions:

1. Did the requested work actually happen? (:func:`build_assessment`)
2. What should the process exit with? (:func:`decide_exit`)

The CLI, the JSON writer and the terminal summary all read these answers from
here, so a saved report and the process status can never disagree.

Precedence, highest first (see FIRMWARE_SCANNER_PLAN.md, "What a successful
result means"):

===  ===========================================================
 3   invalid input or configuration
 6   internal error, or an output that could not be delivered
 1   a critical finding that meets its documented evidence rule
 5   a required dependency or snapshot is missing
 4   analysis incomplete (unsupported input, extraction failure, limit hit)
 2   report delivered with a review or non-critical finding
 0   report delivered, all required work complete, no findings
===  ===========================================================
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from iot_hardware_scanner.models import (
    Assessment,
    C2Finding,
    Completion,
    ControlResult,
    CredentialFinding,
    CVEFinding,
    ReportFinding,
    ScanContext,
    Severity,
    StageId,
    StageResult,
    StageStatus,
)

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# Profiles
# ──────────────────────────────────────────────

PROFILE_FIRMWARE = "firmware-static"
PROFILE_FIRMWARE_TREE = "firmware-tree"
PROFILE_CREDENTIALS = "credentials-only"
PROFILE_VERSION = "3.0"

#: Stages a profile must finish before it may report a complete assessment.
#:
#: The firmware profile names every question the released product claims to
#: answer about a shipped Linux image. Until extraction, enumeration, ELF
#: metadata and opkg inventory can run, that profile cannot complete -- which
#: is the honest result for an image whose root filesystem was never opened.
REQUIRED_STAGES: dict[str, tuple[StageId, ...]] = {
    PROFILE_FIRMWARE: (
        StageId.INGEST,
        StageId.EXTRACTION,
        StageId.ROOT_DISCOVERY,
        StageId.ENUMERATION,
        StageId.ENTROPY,
        StageId.BINARY_INVENTORY,
        StageId.ELF_METADATA,
        StageId.OPKG_INVENTORY,
        StageId.CREDENTIAL_SCAN,
        StageId.UNIX_ACCOUNTS,
        StageId.SERVICE_ANALYSIS,
        StageId.C2_INDICATORS,
        StageId.RISK_CONTROLS,
    ),
    #: A staged tree is already an enumerable root. This profile has **no**
    #: extraction prerequisite at all: there is no container to decode and no
    #: byte stream to measure entropy on, so neither is required.
    PROFILE_FIRMWARE_TREE: (
        StageId.INGEST,
        StageId.ENUMERATION,
        StageId.BINARY_INVENTORY,
        StageId.ELF_METADATA,
        StageId.OPKG_INVENTORY,
        StageId.CREDENTIAL_SCAN,
        StageId.UNIX_ACCOUNTS,
        StageId.SERVICE_ANALYSIS,
        StageId.C2_INDICATORS,
        StageId.RISK_CONTROLS,
    ),
    PROFILE_CREDENTIALS: (
        StageId.INGEST,
        StageId.ENUMERATION,
        StageId.CREDENTIAL_SCAN,
        StageId.UNIX_ACCOUNTS,
        StageId.RISK_CONTROLS,
    ),
}

#: Stages that never block completion, with the reason they are not requested.
OPTIONAL_STAGES: dict[str, tuple[StageId, ...]] = {
    PROFILE_FIRMWARE: (StageId.ADVISORY,),
    PROFILE_FIRMWARE_TREE: (
        StageId.EXTRACTION,
        StageId.ROOT_DISCOVERY,
        StageId.ENTROPY,
        StageId.ADVISORY,
    ),
    PROFILE_CREDENTIALS: (
        StageId.CREDENTIAL_SCAN,
        StageId.ADVISORY,
    ),
}

# ──────────────────────────────────────────────
# Documented critical-evidence rules
# ──────────────────────────────────────────────
#
# Only rules listed here may produce exit 1. Each entry states the observation
# that is sufficient, and each has both a positive and a lookalike-negative
# fixture in tests/test_exit_contract.py. Every other detection -- however
# severe its raw label -- is a review finding and exits 2.

CRITICAL_RULE_EVIDENCE: dict[str, str] = {
    "credential.regex.password": (
        "A password-category assignment whose value is quoted, not a known "
        "placeholder, not in a documentation path, and whose Shannon entropy "
        "meets the configured floor. Locations: artifact path plus line."
    ),
    "credential.unix.empty_password": (
        "An /etc/shadow entry with an empty password field, joined by root and "
        "username to an /etc/passwd entry whose shell is a login shell. "
        "Locations: both files plus the account name."
    ),
}


def finding_is_critical(rule_id: str, severity: Severity) -> bool:
    """Whether a finding meets a documented critical-evidence rule."""
    return severity is Severity.CRITICAL and rule_id in CRITICAL_RULE_EVIDENCE


# ──────────────────────────────────────────────
# Finding normalization
# ──────────────────────────────────────────────

_C2_SEVERITY = {
    "LIKELY_C2": Severity.HIGH,
    "SUSPICIOUS": Severity.MEDIUM,
    "INFORMATIONAL": Severity.INFO,
}


def _location(file_path: object, line_number: int | None, offset: int | None) -> str:
    text = str(file_path)
    if line_number is not None:
        return f"{text}:{line_number}"
    if offset is not None:
        return f"{text}@{offset}"
    return text


def _credential_to_finding(finding: CredentialFinding) -> ReportFinding:
    rule_id = finding.rule_id or f"credential.{finding.category}"
    return ReportFinding(
        rule_id=rule_id,
        severity=finding.severity,
        title=f"{finding.category.replace('_', ' ').title()} finding",
        description=(
            f"{finding.context or finding.matched_pattern} "
            f"(value {finding.masked_value or 'redacted'})"
        ).strip(),
        category=finding.category,
        locations=[_location(finding.file_path, finding.line_number, finding.offset)],
        evidence=[finding.masked_value] if finding.masked_value else [],
        critical_qualified=finding_is_critical(rule_id, finding.severity),
    )


def _c2_to_finding(finding: C2Finding) -> ReportFinding:
    rule_id = f"c2.{finding.indicator_type}"
    severity = _C2_SEVERITY.get(finding.severity, Severity.INFO)
    return ReportFinding(
        rule_id=rule_id,
        severity=severity,
        title=f"C2 indicator ({finding.indicator_type})",
        description=finding.description or f"{finding.indicator_type} indicator",
        category="c2_indicator",
        locations=[_location(finding.file_path, None, None)],
        evidence=[f"score={finding.suspicion_score:.0f}"],
        critical_qualified=finding_is_critical(rule_id, severity),
    )


def _cve_to_finding(finding: CVEFinding) -> ReportFinding:
    rule_id = f"advisory.{finding.cve_id}"
    return ReportFinding(
        rule_id=rule_id,
        severity=finding.severity,
        title=f"{finding.cve_id} in {finding.affected_product or 'component'}",
        description=finding.description,
        category="advisory",
        locations=[
            f"{finding.affected_product} {finding.affected_version}".strip(),
        ],
        evidence=[f"kev={finding.is_in_kev}"],
        critical_qualified=finding_is_critical(rule_id, finding.severity),
    )


def collect_findings(context: ScanContext) -> list[ReportFinding]:
    """Normalize every detector result into one list of findings.

    Order is stable: it derives from the detector lists, not from filesystem
    enumeration order or dict iteration.
    """
    findings: list[ReportFinding] = []
    findings.extend(_credential_to_finding(f) for f in context.credential_findings)
    findings.extend(_c2_to_finding(f) for f in context.c2_findings)
    findings.extend(_cve_to_finding(f) for f in context.cve_findings)

    findings.sort(key=lambda f: (f.category, f.rule_id, tuple(f.locations), f.severity.value))
    return findings


# ──────────────────────────────────────────────
# Stage bookkeeping
# ──────────────────────────────────────────────


def record_stage(
    context: ScanContext,
    stage_id: StageId,
    status: StageStatus,
    *,
    reason: str = "",
    inspected: int | None = None,
    eligible: int | None = None,
    omissions: list[str] | None = None,
    dependency: str | None = None,
) -> StageResult:
    """Record (or replace) one stage result on the context."""
    result = StageResult(
        stage_id=stage_id,
        status=status,
        required=False,
        reason=reason,
        inspected=inspected,
        eligible=eligible,
        omissions=list(omissions or []),
        dependency=dependency,
    )
    context.stages = [s for s in context.stages if s.stage_id != stage_id]
    context.stages.append(result)
    return result


def _required(profile: str, stage_id: StageId) -> bool:
    return stage_id in REQUIRED_STAGES.get(profile, ())


def build_assessment(
    context: ScanContext,
    controls: list[ControlResult] | None = None,
    limitations: list[str] | None = None,
) -> Assessment:
    """Derive assessment completion from the stages that actually ran."""
    profile = context.profile or PROFILE_FIRMWARE
    required = REQUIRED_STAGES.get(profile, ())
    stages = sorted(context.stages, key=lambda s: s.stage_id.value)

    missing_deps: list[str] = []
    reasons: list[str] = []
    incomplete = False

    for stage in stages:
        stage.required = stage.stage_id in required
        if not stage.required:
            continue
        if stage.status is StageStatus.COMPLETE or stage.status is StageStatus.NOT_APPLICABLE:
            continue
        incomplete = True
        label = f"{stage.stage_id.value}: {stage.status.value.lower()}"
        if stage.reason:
            label = f"{label} — {stage.reason}"
        reasons.append(label)
        if stage.dependency:
            missing_deps.append(stage.dependency)

    # A required stage with no record at all is an omission, not a pass.
    recorded = {s.stage_id for s in stages}
    for stage_id in required:
        if stage_id not in recorded:
            incomplete = True
            reasons.append(f"{stage_id.value}: omitted — stage never ran")

    assessment = Assessment(
        profile=profile,
        profile_version=context.profile_version,
        completion=Completion.INCOMPLETE if incomplete else Completion.COMPLETE,
        stages=stages,
        controls=list(controls or []),
        incomplete_reasons=reasons,
        missing_required_dependencies=missing_deps,
        limitations=list(limitations or []),
        started_at=context.started_at,
        completed_at=context.completed_at or datetime.now(tz=timezone.utc),
    )
    context.assessment = assessment
    return assessment


# ──────────────────────────────────────────────
# Exit decision
# ──────────────────────────────────────────────


@dataclass
class ExitDecision:
    """The outcome the process must report, with machine-readable reasons."""

    exit_code: int
    summary: str
    reasons: list[str] = field(default_factory=list)
    critical_findings: list[ReportFinding] = field(default_factory=list)
    reportable_findings: list[ReportFinding] = field(default_factory=list)

    @property
    def exit_reason(self) -> str:
        """Stable identifier for the applied precedence row."""
        return {
            0: "COMPLETE_NO_FINDINGS",
            1: "CRITICAL_FINDING",
            2: "REPORTABLE_FINDING",
            3: "INVALID_INPUT",
            4: "INCOMPLETE_ANALYSIS",
            5: "MISSING_REQUIRED_DEPENDENCY",
            6: "OUTPUT_FAILURE",
        }.get(self.exit_code, "UNKNOWN")


def decide_exit(
    findings: list[ReportFinding],
    assessment: Assessment | None,
    *,
    output_error: str | None = None,
) -> ExitDecision:
    """Apply the precedence table to a delivered report.

    ``output_error`` is set when the requested output could not be written; it
    outranks any finding, because a finding nobody can read is not a result.
    """
    critical = [f for f in findings if f.critical_qualified]
    reportable = [f for f in findings if not f.critical_qualified]

    if output_error:
        return ExitDecision(
            exit_code=6,
            summary=f"Report not delivered: {output_error}",
            reasons=[output_error],
            critical_findings=critical,
            reportable_findings=reportable,
        )

    if critical:
        reasons = [f"{f.rule_id}: {', '.join(f.locations)}" for f in critical]
        if assessment is not None and assessment.completion is not Completion.COMPLETE:
            reasons.extend(f"incomplete: {r}" for r in assessment.incomplete_reasons)
        return ExitDecision(
            exit_code=1,
            summary=(f"{len(critical)} critical finding(s) meeting a documented evidence rule"),
            reasons=reasons,
            critical_findings=critical,
            reportable_findings=reportable,
        )

    if assessment is None:
        return ExitDecision(
            exit_code=4,
            summary="No assessment was recorded — analysis is incomplete",
            reasons=["assessment missing"],
            reportable_findings=reportable,
        )

    if assessment.missing_required_dependencies:
        return ExitDecision(
            exit_code=5,
            summary="A required dependency is missing",
            reasons=list(assessment.missing_required_dependencies)
            + list(assessment.incomplete_reasons),
            reportable_findings=reportable,
        )

    if assessment.completion is not Completion.COMPLETE:
        return ExitDecision(
            exit_code=4,
            summary="Analysis incomplete",
            reasons=list(assessment.incomplete_reasons),
            reportable_findings=reportable,
        )

    if reportable:
        return ExitDecision(
            exit_code=2,
            summary=f"{len(reportable)} review finding(s); required checks completed",
            reasons=[f"{f.rule_id}: {', '.join(f.locations)}" for f in reportable],
            reportable_findings=reportable,
        )

    return ExitDecision(
        exit_code=0,
        summary="All required checks completed; no findings",
    )
