"""The versioned report document and every renderer.

One document is the single source for JSON, Markdown, HTML and terminal
output. Renderers read the document, never the live ``ScanContext``, so what is
written to disk and what is printed can never disagree, and replay renders the
same facts the original scan recorded.

Schema 2 (this release)
----------------------
``schema_version`` is 2. New scans never carry an aggregate security grade.
Assessment completion, per-stage coverage, named checks and findings are
separate top-level sections. ``risk_score`` is present only when replaying a v1
document that actually contained one, in which case it is labelled with its
legacy method and the assessment completeness is ``UNKNOWN``.

Reading an unversioned (v1) document
------------------------------------
:func:`load_document` upgrades v1 in place of guessing: findings are lifted out
of ``credentials``/``cve``/``c2_malware``, the historical grade is kept under
``legacy_grade``, and coverage is recorded as unknown rather than assumed
complete.
"""

from __future__ import annotations

import html
import json
import logging
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from iot_hardware_scanner.models import (
    Completion,
    ControlResult,
    ScanContext,
    StageResult,
)

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 2
TOOL_NAME = "iot-hardware-scanner"

_EXTENSIONS = {"json": ".json", "markdown": ".md", "html": ".html", "terminal": ".txt"}


class ReportWriteError(Exception):
    """Raised when the requested report destination cannot be written."""


# ──────────────────────────────────────────────
# Building the document from a scan
# ──────────────────────────────────────────────


def _stage_to_dict(stage: StageResult) -> dict[str, Any]:
    return {
        "stage": stage.stage_id.value,
        "status": stage.status.value,
        "required": stage.required,
        "reason": stage.reason,
        "inspected": stage.inspected,
        "eligible": stage.eligible,
        "omissions": stage.omissions,
        "dependency": stage.dependency,
    }


def _control_to_dict(control: ControlResult) -> dict[str, Any]:
    return {
        "control_id": control.control_id,
        "control_name": control.control_name,
        "status": control.status.value,
        "applicability": control.applicability,
        "result": control.result,
        "evidence": control.evidence,
        "remediation": control.remediation,
        "source_stage": control.source_stage.value if control.source_stage else None,
    }


def build_document(context: ScanContext, version: str) -> dict[str, Any]:
    """Build the schema-2 report document for a completed scan."""
    from iot_hardware_scanner.scanner.assessment import collect_findings

    assessment = context.assessment
    findings = collect_findings(context)

    document: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": version},
        "scan_id": context.scan_id,
        "scan_date": context.started_at.isoformat() if context.started_at else None,
        "report_generated": datetime.now(tz=timezone.utc).isoformat(),
        "artifact": {
            "kind": context.input_kind.value,
            "name": context.firmware_name,
            "path": str(context.firmware_path),
            "size": context.file_size,
            "sha256": context.file_hash_sha256,
            "md5": context.file_hash_md5,
            "file_type": context.file_type,
            "size_category": context.size_category.value,
            "manifest_entries": context.input_manifest_entries,
        },
        "assessment": _assessment_section(context),
        "stages": [_stage_to_dict(s) for s in (assessment.stages if assessment else [])],
        "controls": [_control_to_dict(c) for c in context.controls],
        "findings": [_finding_to_dict(f) for f in findings],
        "inventory": _inventory_section(context),
        "entropy": _entropy_section(context),
        "components": _components_section(context),
        "data_sources": _data_sources_section(),
        "risk_score": None,
    }
    return document


def _data_sources_section() -> list[dict[str, Any]]:
    """Record which bundled data backed this run, with digests."""
    from iot_hardware_scanner import resources

    try:
        return resources.describe_loaded()
    except Exception as exc:  # a missing install resource is a real finding
        return [{"name": "<unavailable>", "error": str(exc)}]


def _assessment_section(context: ScanContext) -> dict[str, Any]:
    assessment = context.assessment
    if assessment is None:
        return {
            "profile": context.profile,
            "profile_version": context.profile_version,
            "completion": Completion.UNKNOWN.value,
            "coverage": "UNKNOWN",
            "incomplete_reasons": ["no assessment was recorded for this scan"],
        }
    counts = assessment.check_counts
    return {
        "profile": assessment.profile,
        "profile_version": assessment.profile_version,
        "completion": assessment.completion.value,
        "coverage": "RECORDED",
        "incomplete_reasons": assessment.incomplete_reasons,
        "missing_required_dependencies": assessment.missing_required_dependencies,
        "limitations": assessment.limitations,
        "check_counts": counts,
        "started_at": assessment.started_at.isoformat() if assessment.started_at else None,
        "completed_at": assessment.completed_at.isoformat() if assessment.completed_at else None,
    }


def _finding_to_dict(finding: Any) -> dict[str, Any]:
    return {
        "rule_id": finding.rule_id,
        "severity": finding.severity.value,
        "title": finding.title,
        "description": finding.description,
        "category": finding.category,
        "locations": finding.locations,
        "evidence": finding.evidence,
        "remediation": finding.remediation,
        "critical_qualified": finding.critical_qualified,
    }


def _inventory_section(context: ScanContext) -> dict[str, Any] | None:
    inventory = context.filesystem_inventory
    if inventory is None:
        return None
    return {
        "files": inventory.total_files,
        "directories": inventory.total_directories,
        "bytes": inventory.total_size,
        "metadata_source": inventory.metadata_source,
        "suid_binaries": [str(f.path) for f in inventory.suid_binaries],
        "world_writable_files": [str(f.path) for f in inventory.world_writable_files],
        "boot_evidence": [
            {
                "root_id": e.root_id,
                "source": e.source,
                "line": e.line_number,
                "action": e.action,
                "program": e.program,
                "configured": e.configured,
                "directive": e.directive,
            }
            for e in inventory.boot_evidence
        ],
    }


def _entropy_section(context: ScanContext) -> dict[str, Any] | None:
    profile = context.entropy_profile
    if profile is None:
        return None
    return {
        "units": profile.units,
        "overall_entropy": profile.overall_entropy,
        "window_mean_entropy": profile.window_mean_entropy,
        "bytes_analyzed": profile.bytes_analyzed,
        "sampled": profile.bytes_sampled,
        "block_size": profile.block_size,
        "total_blocks": profile.total_blocks,
        "regions": [
            {
                "start": r.start_offset,
                "end": r.end_offset,
                "size": r.size,
                "avg_entropy": r.avg_entropy,
                "classification": r.classification,
            }
            for r in profile.regions
        ],
        "notes": [
            "Entropy describes byte distribution only. It does not establish "
            "encryption, readability, or any control verdict.",
        ],
    }


def _components_section(context: ScanContext) -> list[dict[str, Any]]:
    return [
        {
            "vendor": c.vendor,
            "product": c.product,
            "version": c.version,
            "cpe": c.cpe_string,
            "source_file": str(c.source_file),
            "source_method": c.source_method,
            "architecture": c.architecture,
        }
        for c in context.software_components
    ]


# ──────────────────────────────────────────────
# Loading / upgrading
# ──────────────────────────────────────────────


def load_document(data: dict[str, Any]) -> dict[str, Any]:
    """Return a schema-2 document, upgrading a v1 document if necessary."""
    if not isinstance(data, dict):
        raise ValueError("report document must be a JSON object")

    raw_version = data.get("schema_version")
    if raw_version == 2:
        document = dict(data)
        document.setdefault("findings", [])
        document.setdefault("controls", [])
        document.setdefault("stages", [])
        document.setdefault("components", [])
        document.setdefault("assessment", {})
        document.setdefault("risk_score", None)
        return document

    return _upgrade_v1(data)


def _upgrade_v1(data: dict[str, Any]) -> dict[str, Any]:
    """Convert an unversioned v1 document without inventing facts."""
    firmware = data.get("firmware") or {}
    findings: list[dict[str, Any]] = []

    for entry in (data.get("credentials") or {}).get("findings", []):
        findings.append(
            {
                "rule_id": entry.get("matched_pattern") or "credential.v1",
                "severity": entry.get("severity", "INFO"),
                "title": f"{(entry.get('category') or 'credential').title()} finding",
                "description": entry.get("context", ""),
                "category": entry.get("category", "credential"),
                "locations": [
                    f"{entry.get('file_path', '')}"
                    + (f":{entry['line_number']}" if entry.get("line_number") else "")
                ],
                "evidence": [],
                "remediation": None,
                "critical_qualified": False,
            }
        )
    for entry in (data.get("cve") or {}).get("findings", []):
        findings.append(
            {
                "rule_id": f"advisory.{entry.get('cve_id', 'unknown')}",
                "severity": entry.get("severity", "INFO"),
                "title": entry.get("cve_id", "advisory"),
                "description": entry.get("description", ""),
                "category": "advisory",
                "locations": [entry.get("affected_product", "")],
                "evidence": [],
                "remediation": None,
                "critical_qualified": False,
            }
        )
    for entry in (data.get("c2_malware") or {}).get("findings", []):
        findings.append(
            {
                "rule_id": f"c2.{entry.get('indicator_type', 'indicator')}",
                "severity": entry.get("severity", "INFO"),
                "title": "C2 indicator",
                "description": entry.get("description", ""),
                "category": "c2_indicator",
                "locations": [entry.get("file_path", "")],
                "evidence": [],
                "remediation": None,
                "critical_qualified": False,
            }
        )

    legacy_grade = None
    if data.get("risk_score"):
        risk = data["risk_score"]
        legacy_grade = {
            "method": "v1-12-control-weighted",
            "total_score": risk.get("total_score"),
            "risk_level": risk.get("risk_level"),
            "executive_summary": risk.get("executive_summary", ""),
            "control_scores": risk.get("control_scores", []),
            "owasp_iot_mapping": risk.get("owasp_iot_mapping", {}),
        }

    return {
        "schema_version": SCHEMA_VERSION,
        "schema_note": "upgraded from an unversioned (v1) report",
        "tool": data.get("tool") or {"name": TOOL_NAME, "version": "1.x"},
        "scan_id": data.get("scan_id"),
        "scan_date": data.get("scan_date"),
        "report_generated": datetime.now(tz=timezone.utc).isoformat(),
        "artifact": {
            "kind": "file",
            "name": firmware.get("name"),
            "path": firmware.get("path"),
            "size": firmware.get("size"),
            "sha256": firmware.get("sha256"),
            "md5": firmware.get("md5"),
            "file_type": firmware.get("file_type"),
            "size_category": firmware.get("size_category"),
            "manifest_entries": None,
        },
        "assessment": {
            "profile": "v1-legacy",
            "profile_version": "1.x",
            "completion": Completion.UNKNOWN.value,
            "coverage": "UNKNOWN",
            "incomplete_reasons": [
                "This document was produced by a version that did not record "
                "stage coverage; what ran and what was omitted is unknown."
            ],
            "missing_required_dependencies": [],
            "limitations": ["Historical report replayed for rendering. Nothing was re-analysed."],
            "check_counts": {},
            "started_at": None,
            "completed_at": None,
        },
        "stages": [],
        "controls": [],
        "findings": findings,
        "inventory": None,
        "entropy": data.get("entropy"),
        "components": (data.get("sbom") or {}).get("components", []),
        "risk_score": legacy_grade,
        "legacy_grade": legacy_grade,
    }


# ──────────────────────────────────────────────
# Rendering — JSON
# ──────────────────────────────────────────────


def render_json(document: dict[str, Any]) -> str:
    """Serialize the document exactly as stored."""
    return json.dumps(document, indent=2, default=str)


# ──────────────────────────────────────────────
# Rendering — shared helpers
# ──────────────────────────────────────────────


def _completion_line(document: dict[str, Any]) -> str:
    assessment = document.get("assessment") or {}
    completion = assessment.get("completion", "UNKNOWN")
    if completion == Completion.COMPLETE.value:
        return "Assessment: COMPLETE — every required stage ran"
    if completion == Completion.INCOMPLETE.value:
        count = len(assessment.get("incomplete_reasons") or [])
        return f"Assessment: INCOMPLETE — {count} required stage(s) did not finish (listed below)"
    return "Assessment: UNKNOWN — this document does not record which stages ran (legacy report)"


def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        key = str(finding.get("severity", "INFO"))
        counts[key] = counts.get(key, 0) + 1
    return counts


# ──────────────────────────────────────────────
# Rendering — terminal
# ──────────────────────────────────────────────


def render_terminal(document: dict[str, Any]) -> str:
    """Plain-text summary suitable for a terminal or CI log."""
    artifact = document.get("artifact") or {}
    assessment = document.get("assessment") or {}
    findings = document.get("findings") or []
    controls = document.get("controls") or []

    lines = [
        f"Artifact: {artifact.get('name')} ({artifact.get('kind', 'file')})",
        f"  size:    {artifact.get('size')} bytes",
        f"  sha256:  {artifact.get('sha256')}",
        f"  profile: {assessment.get('profile')} v{assessment.get('profile_version')}",
        _completion_line(document),
    ]

    missing = assessment.get("missing_required_dependencies") or []
    if missing:
        lines.append("Missing required dependencies:")
        lines.extend(f"  - {item}" for item in missing)

    reasons = [
        r
        for r in (assessment.get("incomplete_reasons") or [])
        if not any(dep in r for dep in missing)
    ]
    if reasons and assessment.get("completion") == Completion.INCOMPLETE.value:
        lines.append("Incomplete work:")
        lines.extend(f"  - {item}" for item in reasons)

    counts = _severity_counts(findings)
    if findings:
        summary = ", ".join(f"{k} {v}" for k, v in sorted(counts.items()))
        lines.append(f"Findings: {len(findings)} ({summary})")
        for finding in findings:
            locations = ", ".join(finding.get("locations") or [])
            qualified = "critical" if finding.get("critical_qualified") else "review"
            lines.append(
                f"  [{finding.get('severity')}/{qualified}] {finding.get('rule_id')} — {locations}"
            )
    else:
        lines.append("Findings: none reported")

    if controls:
        performed = sum(1 for c in controls if c.get("status") == "PERFORMED")
        inconclusive = sum(1 for c in controls if c.get("status") == "INCONCLUSIVE")
        omitted = sum(1 for c in controls if c.get("status") == "OMITTED")
        not_applicable = sum(1 for c in controls if c.get("status") == "NOT_APPLICABLE")
        lines.append(
            f"Checks: {performed} performed, {inconclusive} inconclusive, "
            f"{omitted} omitted, {not_applicable} not applicable "
            f"(of {len(controls)})"
        )

    legacy = document.get("legacy_grade") or document.get("risk_score")
    if legacy:
        lines.append(
            f"Legacy grade (v1 method, not comparable to a v2 assessment): "
            f"{legacy.get('total_score')}/100 {legacy.get('risk_level')}"
        )

    entropy = document.get("entropy")
    if entropy:
        scope = "sampled" if entropy.get("sampled") else "whole input"
        lines.append(
            f"Entropy: {entropy.get('overall_entropy')} bits/byte "
            f"over {entropy.get('bytes_analyzed')} bytes ({scope})"
        )

    return "\n".join(lines)


# ──────────────────────────────────────────────
# Rendering — Markdown
# ──────────────────────────────────────────────


def render_markdown(document: dict[str, Any]) -> str:
    """Human-readable Markdown built from the document."""
    artifact = document.get("artifact") or {}
    assessment = document.get("assessment") or {}
    findings = document.get("findings") or []
    controls = document.get("controls") or []
    stages = document.get("stages") or []

    lines = [f"# IoT Hardware Scanner — {artifact.get('name')}", ""]
    lines.append(f"**Scan ID:** {document.get('scan_id')}")
    lines.append(f"**Scan date:** {document.get('scan_date')}")
    lines.append(f"**Artifact kind:** {artifact.get('kind')}")
    lines.append(f"**SHA-256:** `{artifact.get('sha256')}`")
    lines.append(f"**Size:** {artifact.get('size')} bytes")
    lines.append(f"**File type:** {artifact.get('file_type')}")
    lines.append(f"**Profile:** {assessment.get('profile')} v{assessment.get('profile_version')}")
    lines.append("")

    lines += ["## Assessment", "", f"**Completion:** {assessment.get('completion', 'UNKNOWN')}"]
    if (assessment.get("coverage") or "").upper() == "UNKNOWN":
        lines.append("")
        lines.append(
            "> Coverage unknown: this document does not record which stages ran. "
            "No grade is implied by its absence."
        )
    for reason in assessment.get("incomplete_reasons") or []:
        lines.append(f"- Incomplete: {reason}")
    for item in assessment.get("missing_required_dependencies") or []:
        lines.append(f"- Missing dependency: {item}")
    for limitation in assessment.get("limitations") or []:
        lines.append(f"- Limitation: {limitation}")
    counts = assessment.get("check_counts") or {}
    if counts:
        lines.append(
            "- Checks: " + ", ".join(f"{v} {k.lower()}" for k, v in sorted(counts.items()))
        )
    lines.append("")

    if stages:
        lines += [
            "## Stage coverage",
            "",
            "| Stage | Status | Required | Inspected | Eligible | Reason |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for stage in stages:
            lines.append(
                f"| {stage.get('stage')} | {stage.get('status')} | "
                f"{'yes' if stage.get('required') else 'no'} | "
                f"{_count(stage.get('inspected'))} | {_count(stage.get('eligible'))} | "
                f"{_md_cell(stage.get('reason') or '')} |"
            )
        lines.append("")

    lines += ["## Findings", ""]
    if not findings:
        lines.append("None reported.")
    else:
        lines += [
            "| Severity | Rule | Locations | Review/critical |",
            "| --- | --- | --- | --- |",
        ]
        for finding in findings:
            lines.append(
                f"| {finding.get('severity')} | `{finding.get('rule_id')}` | "
                f"{_md_cell(', '.join(finding.get('locations') or []))} | "
                f"{'critical' if finding.get('critical_qualified') else 'review'} |"
            )
    lines.append("")

    if controls:
        lines += [
            "## Named checks",
            "",
            "| # | Check | Status | Result | Evidence |",
            "| --- | --- | --- | --- | --- |",
        ]
        for control in controls:
            evidence = "; ".join(control.get("evidence") or []) or "—"
            lines.append(
                f"| {control.get('control_id')} | {_md_cell(control.get('control_name', ''))} | "
                f"{control.get('status')} | {control.get('result')} | {_md_cell(evidence)} |"
            )
        lines.append("")

    inventory = document.get("inventory")
    if inventory:
        lines += ["## Inventory", ""]
        lines.append(f"- Files: {inventory.get('files')}")
        lines.append(f"- Directories: {inventory.get('directories')}")
        lines.append(f"- Bytes: {inventory.get('bytes')}")
        lines.append(f"- Metadata source: {inventory.get('metadata_source')}")
        boot = inventory.get("boot_evidence") or []
        if boot:
            lines.append("")
            lines += [
                "| Root | Source | Line | Action | Program | Configured |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
            for entry in boot:
                lines.append(
                    f"| {entry.get('root_id')} | {_md_cell(entry.get('source', ''))} | "
                    f"{entry.get('line')} | {entry.get('action')} | "
                    f"{_md_cell(entry.get('program', ''))} | "
                    f"{'yes' if entry.get('configured') else 'no (commented)'} |"
                )
        lines.append("")

    entropy = document.get("entropy")
    if entropy:
        scope = "sampled" if entropy.get("sampled") else "whole input"
        lines += [
            "## Entropy",
            "",
            f"- Whole-input entropy: {entropy.get('overall_entropy')} bits/byte "
            f"over {entropy.get('bytes_analyzed')} bytes ({scope})",
            f"- Mean of windows: {entropy.get('window_mean_entropy')} bits/byte",
            f"- Window size: {entropy.get('block_size')} bytes",
        ]
        for note in entropy.get("notes") or []:
            lines.append(f"- {note}")
        lines.append("")

    components = document.get("components") or []
    if components:
        lines += [
            "## Components",
            "",
            "| Vendor | Product | Version | Source | Method |",
            "| --- | --- | --- | --- | --- |",
        ]
        for component in components:
            lines.append(
                f"| {_md_cell(component.get('vendor', ''))} | "
                f"{_md_cell(component.get('product', ''))} | "
                f"{_md_cell(component.get('version', ''))} | "
                f"{_md_cell(component.get('source_file', ''))} | "
                f"{component.get('source_method')} |"
            )
        lines.append("")

    legacy = document.get("legacy_grade") or document.get("risk_score")
    if legacy:
        lines += [
            "## Legacy grade (not comparable)",
            "",
            f"- Method: {legacy.get('method')}",
            f"- Historical score: {legacy.get('total_score')}/100 {legacy.get('risk_level')}",
            "",
            "> This grade comes from the retired 12-control weighted method. It is "
            "rendered for continuity only and does not describe this or any new "
            "scan.",
            "",
        ]

    return "\n".join(lines)


def _count(value: Any) -> str:
    return "unknown" if value is None else str(value)


def _md_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


# ──────────────────────────────────────────────
# Rendering — HTML
# ──────────────────────────────────────────────

_CSS = """
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
       max-width: 960px; margin: 2rem auto; padding: 0 1rem; background: #1a1a2e; color: #e0e0e0; }
h1 { color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: .5rem; }
h2 { color: #7c4dff; margin-top: 2rem; }
table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
th, td { border: 1px solid #333; padding: .5rem .75rem; text-align: left; vertical-align: top; }
th { background: #16213e; color: #00d4ff; }
tr:nth-child(even) { background: #0f3460; }
code { background: #16213e; padding: .1rem .3rem; border-radius: 3px; }
.badge { display: inline-block; padding: .25rem .75rem; border-radius: 4px; font-weight: bold; }
.badge.COMPLETE { background: #2e7d32; color: #fff; }
.badge.INCOMPLETE { background: #c62828; color: #fff; }
.badge.UNKNOWN { background: #616161; color: #fff; }
.note { border-left: 4px solid #7c4dff; padding: .5rem 1rem; background: #16213e; }
"""


def render_html(document: dict[str, Any]) -> str:
    """Standalone HTML, built from the document with every value escaped.

    Nothing here reads a neighbouring Markdown file, and no firmware-derived
    string is interpolated without escaping.
    """
    artifact = document.get("artifact") or {}
    assessment = document.get("assessment") or {}
    completion = str(assessment.get("completion", "UNKNOWN"))
    title = f"IoT Hardware Scanner — {artifact.get('name')}"

    parts: list[str] = []
    parts.append(f"<h1>{html.escape(title)}</h1>")
    parts.append(
        "<table>"
        f"<tr><th>Scan ID</th><td>{html.escape(str(document.get('scan_id')))}</td></tr>"
        f"<tr><th>Scan date</th><td>{html.escape(str(document.get('scan_date')))}</td></tr>"
        f"<tr><th>Artifact</th><td>{html.escape(str(artifact.get('kind')))} "
        f"({html.escape(str(artifact.get('size')))} bytes)</td></tr>"
        f"<tr><th>SHA-256</th><td><code>{html.escape(str(artifact.get('sha256')))}</code></td></tr>"
        f"<tr><th>Profile</th><td>{html.escape(str(assessment.get('profile')))} "
        f"v{html.escape(str(assessment.get('profile_version')))}</td></tr>"
        "</table>"
    )

    parts.append("<h2>Assessment</h2>")
    parts.append(
        f'<p><span class="badge {html.escape(completion)}">{html.escape(completion)}</span></p>'
    )
    if str(assessment.get("coverage", "")).upper() == "UNKNOWN":
        parts.append(
            '<p class="note">Coverage unknown: this document does not record which '
            "stages ran. No grade is implied by its absence.</p>"
        )
    reasons = assessment.get("incomplete_reasons") or []
    if reasons:
        parts.append("<ul>")
        parts.extend(f"<li>{html.escape(str(r))}</li>" for r in reasons)
        parts.append("</ul>")

    stages = document.get("stages") or []
    if stages:
        parts.append("<h2>Stage coverage</h2><table>")
        parts.append(
            "<tr><th>Stage</th><th>Status</th><th>Required</th><th>Inspected</th>"
            "<th>Eligible</th><th>Reason</th></tr>"
        )
        for stage in stages:
            parts.append(
                "<tr>"
                f"<td>{html.escape(str(stage.get('stage')))}</td>"
                f"<td>{html.escape(str(stage.get('status')))}</td>"
                f"<td>{'yes' if stage.get('required') else 'no'}</td>"
                f"<td>{html.escape(_count(stage.get('inspected')))}</td>"
                f"<td>{html.escape(_count(stage.get('eligible')))}</td>"
                f"<td>{html.escape(str(stage.get('reason') or ''))}</td>"
                "</tr>"
            )
        parts.append("</table>")

    findings = document.get("findings") or []
    parts.append("<h2>Findings</h2>")
    if not findings:
        parts.append("<p>None reported.</p>")
    else:
        parts.append(
            "<table><tr><th>Severity</th><th>Rule</th><th>Locations</th><th>Kind</th></tr>"
        )
        for finding in findings:
            kind = "critical" if finding.get("critical_qualified") else "review"
            parts.append(
                "<tr>"
                f"<td>{html.escape(str(finding.get('severity')))}</td>"
                f"<td><code>{html.escape(str(finding.get('rule_id')))}</code></td>"
                f"<td>{html.escape(', '.join(finding.get('locations') or []))}</td>"
                f"<td>{kind}</td>"
                "</tr>"
            )
        parts.append("</table>")

    controls = document.get("controls") or []
    if controls:
        parts.append("<h2>Named checks</h2><table>")
        parts.append(
            "<tr><th>#</th><th>Check</th><th>Status</th><th>Result</th><th>Evidence</th></tr>"
        )
        for control in controls:
            evidence = "; ".join(control.get("evidence") or [])
            parts.append(
                "<tr>"
                f"<td>{html.escape(str(control.get('control_id')))}</td>"
                f"<td>{html.escape(str(control.get('control_name')))}</td>"
                f"<td>{html.escape(str(control.get('status')))}</td>"
                f"<td>{html.escape(str(control.get('result')))}</td>"
                f"<td>{html.escape(evidence)}</td>"
                "</tr>"
            )
        parts.append("</table>")

    inventory = document.get("inventory")
    if inventory:
        parts.append("<h2>Inventory</h2><table>")
        parts.append(f"<tr><th>Files</th><td>{html.escape(str(inventory.get('files')))}</td></tr>")
        parts.append(
            f"<tr><th>Directories</th><td>{html.escape(str(inventory.get('directories')))}</td></tr>"
        )
        parts.append(
            f"<tr><th>Metadata source</th><td>"
            f"{html.escape(str(inventory.get('metadata_source')))}</td></tr>"
        )
        parts.append("</table>")
        boot = inventory.get("boot_evidence") or []
        if boot:
            parts.append("<h3>Configured startup evidence</h3><table>")
            parts.append(
                "<tr><th>Root</th><th>Source</th><th>Line</th><th>Action</th>"
                "<th>Program</th><th>Configured</th></tr>"
            )
            for entry in boot:
                parts.append(
                    "<tr>"
                    f"<td>{html.escape(str(entry.get('root_id')))}</td>"
                    f"<td>{html.escape(str(entry.get('source')))}</td>"
                    f"<td>{html.escape(str(entry.get('line')))}</td>"
                    f"<td>{html.escape(str(entry.get('action')))}</td>"
                    f"<td>{html.escape(str(entry.get('program')))}</td>"
                    f"<td>{'yes' if entry.get('configured') else 'no (commented)'}</td>"
                    "</tr>"
                )
            parts.append("</table>")

    entropy = document.get("entropy")
    if entropy:
        scope = "sampled" if entropy.get("sampled") else "whole input"
        parts.append("<h2>Entropy</h2>")
        parts.append(
            f"<p>{html.escape(str(entropy.get('overall_entropy')))} bits/byte over "
            f"{html.escape(str(entropy.get('bytes_analyzed')))} bytes ({scope})</p>"
        )
        parts.append("<ul>")
        parts.extend(f"<li>{html.escape(str(note))}</li>" for note in entropy.get("notes") or [])
        parts.append("</ul>")

    legacy = document.get("legacy_grade") or document.get("risk_score")
    if legacy:
        parts.append("<h2>Legacy grade (not comparable)</h2>")
        parts.append(
            "<table>"
            f"<tr><th>Method</th><td>{html.escape(str(legacy.get('method')))}</td></tr>"
            f"<tr><th>Historical score</th><td>"
            f"{html.escape(str(legacy.get('total_score')))}/100 "
            f"{html.escape(str(legacy.get('risk_level')))}</td></tr>"
            "</table>"
        )
        parts.append(
            '<p class="note">This grade comes from the retired 12-control weighted '
            "method. It is rendered for continuity only.</p>"
        )

    body = "\n".join(parts)
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n<head>\n<meta charset="UTF-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
        f"<title>{html.escape(title)}</title>\n<style>{_CSS}</style>\n"
        f"</head>\n<body>\n{body}\n</body>\n</html>\n"
    )


RENDERERS = {
    "json": render_json,
    "markdown": render_markdown,
    "html": render_html,
    "terminal": render_terminal,
}


def render(document: dict[str, Any], fmt: str) -> str:
    """Render the document in ``fmt``."""
    try:
        renderer = RENDERERS[fmt]
    except KeyError as exc:  # pragma: no cover - guarded by config validation
        raise ValueError(f"unsupported report format: {fmt}") from exc
    return renderer(document)


# ──────────────────────────────────────────────
# Writing
# ──────────────────────────────────────────────


def write_atomic(destination: Path, content: str) -> Path:
    """Write ``content`` to exactly ``destination``, atomically.

    The temporary file is created in the destination directory so ``os.replace``
    is a same-filesystem rename. A failure leaves no partial report behind and
    raises :class:`ReportWriteError`; callers must not announce success before
    this returns.
    """
    destination = Path(destination)
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=str(destination.parent),
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            tmp_path = Path(handle.name)
            try:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            except BaseException:
                handle.close()
                tmp_path.unlink(missing_ok=True)
                raise
        try:
            os.replace(tmp_path, destination)
        except BaseException:
            tmp_path.unlink(missing_ok=True)
            raise
    except OSError as exc:
        raise ReportWriteError(f"cannot write {destination}: {exc}") from exc
    return destination


def default_filename(fmt: str) -> str:
    """The conventional filename for a format."""
    return f"report{_EXTENSIONS.get(fmt, '.txt')}"
