"""Report Generator — Phase 7b.

Generates reports in JSON, Markdown, HTML, and terminal formats.

SDR §13.2 — Report Generation
"""

from __future__ import annotations

import contextlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.models import ScanContext

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generate multi-format reports from scan results.

    Supports JSON, Markdown, HTML, and terminal output.
    """

    def __init__(self, config: ScannerConfig) -> None:
        self.config = config

    def generate(self, context: ScanContext) -> dict[str, Path]:
        """Generate reports in all configured formats.

        Returns:
            Dict mapping format name to output file path.
        """
        paths: dict[str, Path] = {}

        for fmt in self.config.report_formats:
            if fmt == "json":
                path = self._generate_json(context)
                if path:
                    paths["json"] = path
            elif fmt == "markdown":
                path = self._generate_markdown(context)
                if path:
                    paths["markdown"] = path
            elif fmt == "terminal":
                # Terminal output already rendered during scan
                pass
            elif fmt == "html":
                path = self._generate_html(context)
                if path:
                    paths["html"] = path

        return paths

    # ──────────────────────────────────────────
    # JSON Report
    # ──────────────────────────────────────────

    def _generate_json(self, context: ScanContext) -> Path | None:
        """Generate comprehensive JSON report."""
        report: dict = {
            "scan_id": context.scan_id,
            "scan_date": context.started_at.isoformat(),
            "report_generated": datetime.now(tz=timezone.utc).isoformat(),
            "firmware": self._firmware_section(context),
            "entropy": self._entropy_section(context),
            "credentials": self._credentials_section(context),
            "cve": self._cve_section(context),
            "c2_malware": self._c2_section(context),
            "risk_score": self._risk_section(context),
            "sbom": self._sbom_section(context),
        }

        output_path = context.output_dir / "report.json"
        try:
            output_path.write_text(json.dumps(report, indent=2, default=str))
            logger.info("JSON report: %s", output_path)
            return output_path
        except (OSError, PermissionError) as exc:
            logger.error("Cannot write JSON report: %s", exc)
            return None

    # ──────────────────────────────────────────
    # Markdown Report
    # ──────────────────────────────────────────

    def _generate_markdown(self, context: ScanContext) -> Path | None:
        """Generate detailed Markdown report."""
        lines: list[str] = []

        # Header
        lines.append(f"# IoT Hardware Scanner — {context.firmware_name}")
        lines.append("")
        lines.append(f"**Scan ID:** {context.scan_id}")
        lines.append(f"**Date:** {context.started_at.isoformat()}")
        lines.append(f"**SHA-256:** `{context.file_hash_sha256}`")
        lines.append(f"**MD5:** `{context.file_hash_md5}`")
        lines.append(f"**File Type:** {context.file_type}")
        size_cat = context.size_category
        size_cat_str = size_cat.value if hasattr(size_cat, "value") else str(size_cat)
        lines.append(
            f"**Size:** {context.file_size:,} bytes "
            f"({size_cat_str})"
        )
        lines.append("")

        # Executive Summary
        if context.risk_score:
            rs = context.risk_score
            lines.append("## Executive Summary")
            lines.append("")
            lines.append(
                f"**Risk Score:** {rs.total_score:.0f}/100 "
                f"— **{rs.risk_level.value}**"
            )
            lines.append("")
            lines.append(rs.executive_summary)
            lines.append("")

        # Risk Scorecard
        if context.risk_score:
            lines.append(self._md_risk_scorecard(context))

        # OWASP Mapping
        if context.risk_score and context.risk_score.owasp_iot_mapping:
            lines.append(self._md_owasp_mapping(context))

        # Extraction
        if context.extraction_result:
            lines.append(self._md_extraction(context))

        # Entropy
        if context.entropy_profile:
            lines.append(self._md_entropy(context))

        # Credentials
        if context.credential_findings:
            lines.append(self._md_credentials(context))

        # CVEs
        if context.cve_findings:
            lines.append(self._md_cves(context))

        # C2/Malware
        if context.c2_findings:
            lines.append(self._md_c2(context))

        # SBOM
        if context.software_components:
            lines.append(self._md_sbom(context))

        output_path = context.output_dir / "report.md"
        try:
            output_path.write_text("\n".join(lines))
            logger.info("Markdown report: %s", output_path)
            return output_path
        except (OSError, PermissionError) as exc:
            logger.error("Cannot write Markdown report: %s", exc)
            return None

    # ──────────────────────────────────────────
    # HTML Report
    # ──────────────────────────────────────────

    def _generate_html(self, context: ScanContext) -> Path | None:
        """Generate styled HTML report."""
        md_content = ""
        md_path = context.output_dir / "report.md"
        if md_path.exists():
            with contextlib.suppress(OSError, PermissionError):
                md_content = md_path.read_text()

        # If markdown not available, generate inline
        if not md_content:
            self._generate_markdown(context)
            if md_path.exists():
                try:
                    md_content = md_path.read_text()
                except (OSError, PermissionError):
                    md_content = "Report generation failed."

        # Simple Markdown-to-HTML conversion for basic formatting
        html_body = self._md_to_html(md_content)

        risk_color = "#4caf50"  # green
        if context.risk_score:
            level = context.risk_score.risk_level.value
            risk_color = {
                "LOW": "#4caf50",
                "MEDIUM": "#ff9800",
                "HIGH": "#f44336",
                "CRITICAL": "#9c27b0",
            }.get(level, "#4caf50")

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IoT Hardware Scanner — {context.firmware_name}</title>
<style>
body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    max-width: 960px;
    margin: 2rem auto;
    padding: 0 1rem;
    background: #1a1a2e;
    color: #e0e0e0;
}}
h1 {{ color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: 0.5rem; }}
h2 {{ color: #7c4dff; margin-top: 2rem; }}
h3 {{ color: #b388ff; }}
table {{
    width: 100%;
    border-collapse: collapse;
    margin: 1rem 0;
}}
th, td {{
    border: 1px solid #333;
    padding: 0.5rem 0.75rem;
    text-align: left;
}}
th {{ background: #16213e; color: #00d4ff; }}
tr:nth-child(even) {{ background: #0f3460; }}
code {{ background: #16213e; padding: 0.15rem 0.3rem; border-radius: 3px; }}
.CRITICAL {{ color: #ff5252; font-weight: bold; }}
.HIGH {{ color: #ff9800; font-weight: bold; }}
.MEDIUM {{ color: #ffd740; }}
.LOW {{ color: #69f0ae; }}
.PASS {{ color: #69f0ae; }}
.PARTIAL {{ color: #ffd740; }}
.FAIL {{ color: #ff5252; }}
.risk-badge {{
    display: inline-block;
    padding: 0.5rem 1.5rem;
    border-radius: 6px;
    font-size: 1.2rem;
    font-weight: bold;
    background: {risk_color};
    color: white;
}}
</style>
</head>
<body>
{html_body}
</body>
</html>"""

        output_path = context.output_dir / "report.html"
        try:
            output_path.write_text(html)
            logger.info("HTML report: %s", output_path)
            return output_path
        except (OSError, PermissionError) as exc:
            logger.error("Cannot write HTML report: %s", exc)
            return None

    # ──────────────────────────────────────────
    # JSON section builders
    # ──────────────────────────────────────────

    @staticmethod
    def _firmware_section(context: ScanContext) -> dict:
        size_cat = context.size_category
        size_cat_str = size_cat.value if hasattr(size_cat, "value") else str(size_cat)
        return {
            "name": context.firmware_name,
            "path": str(context.firmware_path),
            "size": context.file_size,
            "sha256": context.file_hash_sha256,
            "md5": context.file_hash_md5,
            "file_type": context.file_type,
            "size_category": size_cat_str,
        }

    @staticmethod
    def _entropy_section(context: ScanContext) -> dict | None:
        if not context.entropy_profile:
            return None
        ep = context.entropy_profile
        return {
            "overall_entropy": ep.overall_entropy,
            "total_blocks": ep.total_blocks,
            "block_size": ep.block_size,
            "has_encrypted_regions": ep.has_encrypted_regions,
            "has_compressed_regions": ep.has_compressed_regions,
            "regions": [
                {
                    "start": r.start_offset,
                    "end": r.end_offset,
                    "size": r.size,
                    "avg_entropy": round(r.avg_entropy, 4),
                    "classification": r.classification,
                }
                for r in ep.regions
            ],
        }

    @staticmethod
    def _credentials_section(context: ScanContext) -> dict:
        if not context.credential_findings:
            return {"total": 0, "findings": []}
        by_severity: dict[str, int] = {}
        for f in context.credential_findings:
            by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1
        return {
            "total": len(context.credential_findings),
            "by_severity": by_severity,
            "findings": [
                {
                    "severity": f.severity.value,
                    "category": f.category,
                    "file_path": str(f.file_path),
                    "line_number": f.line_number,
                    "masked_value": f.masked_value,
                    "is_default": f.is_default,
                    "is_placeholder": f.is_placeholder,
                }
                for f in context.credential_findings
            ],
        }

    @staticmethod
    def _cve_section(context: ScanContext) -> dict:
        if not context.cve_findings:
            return {"total": 0, "findings": []}
        by_severity: dict[str, int] = {}
        kev_count = 0
        for f in context.cve_findings:
            by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1
            if f.is_in_kev:
                kev_count += 1
        return {
            "total": len(context.cve_findings),
            "by_severity": by_severity,
            "kev_count": kev_count,
            "findings": [
                {
                    "cve_id": f.cve_id,
                    "severity": f.severity.value,
                    "cvss_v3_score": f.cvss_v3_score,
                    "affected_product": f.affected_product,
                    "affected_version": f.affected_version,
                    "is_in_kev": f.is_in_kev,
                    "description": f.description[:200] if f.description else "",
                }
                for f in context.cve_findings
            ],
        }

    @staticmethod
    def _c2_section(context: ScanContext) -> dict:
        if not context.c2_findings:
            return {"total": 0, "findings": []}
        by_type: dict[str, int] = {}
        for f in context.c2_findings:
            by_type[f.indicator_type] = by_type.get(f.indicator_type, 0) + 1
        return {
            "total": len(context.c2_findings),
            "by_type": by_type,
            "findings": [
                {
                    "severity": f.severity,
                    "indicator_type": f.indicator_type,
                    "value": f.value,
                    "file_path": str(f.file_path),
                    "suspicion_score": f.suspicion_score,
                    "score_breakdown": f.score_breakdown,
                    "threat_intel_match": f.threat_intel_match,
                    "mitre_attack": f.mitre_attack,
                    "description": f.description[:200] if f.description else "",
                }
                for f in context.c2_findings
            ],
        }

    @staticmethod
    def _risk_section(context: ScanContext) -> dict | None:
        if not context.risk_score:
            return None
        rs = context.risk_score
        return {
            "total_score": rs.total_score,
            "risk_level": rs.risk_level.value,
            "executive_summary": rs.executive_summary,
            "control_scores": [
                {
                    "control_id": cs.control_id,
                    "control_name": cs.control_name,
                    "result": cs.result,
                    "points": cs.points,
                    "max_points": cs.max_points,
                    "evidence": cs.evidence,
                    "remediation": cs.remediation,
                }
                for cs in rs.control_scores
            ],
            "weighted_breakdown": rs.weighted_breakdown,
            "owasp_iot_mapping": rs.owasp_iot_mapping,
        }

    @staticmethod
    def _sbom_section(context: ScanContext) -> dict:
        if not context.software_components:
            return {"total": 0, "components": []}
        return {
            "total": len(context.software_components),
            "components": [
                {
                    "vendor": c.vendor,
                    "product": c.product,
                    "version": c.version,
                    "cpe": c.cpe_string,
                    "source_file": str(c.source_file),
                    "source_method": c.source_method,
                }
                for c in context.software_components
            ],
        }

    # ──────────────────────────────────────────
    # Markdown section builders
    # ──────────────────────────────────────────

    @staticmethod
    def _md_risk_scorecard(context: ScanContext) -> str:
        """Generate risk scorecard as Markdown table."""
        rs = context.risk_score
        if rs is None:
            return ""
        lines = [
            "## Risk Scorecard",
            "",
            "| # | Control | Result | Score | Evidence |",
            "|---|---------|--------|-------|----------|",
        ]
        for cs in rs.control_scores:
            ev = "; ".join(cs.evidence[:2]) if cs.evidence else "—"
            lines.append(
                f"| {cs.control_id} | {cs.control_name} "
                f"| {cs.result} "
                f"| {cs.points:.0f}/{cs.max_points:.0f} "
                f"| {ev} |"
            )
        lines.append("")
        if rs.weighted_breakdown:
            lines.append("### Breakdown by Category")
            lines.append("")
            lines.append("| Category | Score |")
            lines.append("|----------|-------|")
            for cat, score in rs.weighted_breakdown.items():
                lines.append(f"| {cat} | {score:.0f} |")
            lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _md_owasp_mapping(context: ScanContext) -> str:
        """Generate OWASP IoT Top 10 mapping as Markdown."""
        rs = context.risk_score
        if rs is None:
            return ""
        lines = [
            "## OWASP IoT Top 10 Mapping",
            "",
            "| OWASP Item | Status |",
            "|------------|--------|",
        ]
        for item, status in rs.owasp_iot_mapping.items():
            label = {0: "✅ PASS", 1: "⚠️ PARTIAL", 2: "❌ FAIL"}.get(
                status, "—"
            )
            lines.append(f"| {item} | {label} |")
        lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _md_extraction(context: ScanContext) -> str:
        """Generate extraction summary as Markdown."""
        er = context.extraction_result
        if er is None:
            return ""
        lines = [
            "## Extraction Summary",
            "",
            f"- **Success:** {er.success}",
            f"- **Files extracted:** {er.file_count}",
            f"- **Root filesystems:** {len(er.root_filesystems)}",
        ]
        if er.signatures_detected:
            lines.append(f"- **Signatures:** {len(er.signatures_detected)}")
        lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _md_entropy(context: ScanContext) -> str:
        """Generate entropy profile as Markdown."""
        ep = context.entropy_profile
        if ep is None:
            return ""
        lines = [
            "## Entropy Profile",
            "",
            f"- **Overall entropy:** {ep.overall_entropy:.4f}",
            f"- **Blocks:** {ep.total_blocks} (block size: {ep.block_size})",
            f"- **Encrypted regions:** {'Yes' if ep.has_encrypted_regions else 'No'}",
            f"- **Compressed regions:** {'Yes' if ep.has_compressed_regions else 'No'}",
        ]
        if ep.regions:
            lines.append("")
            lines.append("| Start | End | Classification | Avg Entropy |")
            lines.append("|-------|-----|----------------|-------------|")
            for r in ep.regions[:20]:
                lines.append(
                    f"| {r.start_offset} | {r.end_offset} "
                    f"| {r.classification} | {r.avg_entropy:.4f} |"
                )
        lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _md_credentials(context: ScanContext) -> str:
        """Generate credential findings as Markdown table."""
        lines = [
            "## Credential Findings",
            "",
            f"**Total:** {len(context.credential_findings)}",
            "",
            "| Severity | Category | File | Line | Default |",
            "|----------|----------|------|------|---------|",
        ]
        for f in context.credential_findings:
            lines.append(
                f"| {f.severity.value} | {f.category} "
                f"| `{f.file_path}` | {f.line_number or '—'} "
                f"| {'Yes' if f.is_default else 'No'} |"
            )
        lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _md_cves(context: ScanContext) -> str:
        """Generate CVE findings as Markdown."""
        lines = [
            "## CVE Findings",
            "",
            f"**Total:** {len(context.cve_findings)}",
            f"**CISA KEV:** {sum(1 for f in context.cve_findings if f.is_in_kev)}",
            "",
        ]
        for f in context.cve_findings:
            kev_tag = " ⚠️**KEV**" if f.is_in_kev else ""
            lines.append(
                f"- **{f.cve_id}** ({f.severity.value}, "
                f"CVSS: {f.cvss_v3_score or 'N/A'}){kev_tag}: "
                f"{f.affected_product}"
            )
        lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _md_c2(context: ScanContext) -> str:
        """Generate C2/malware findings as Markdown."""
        lines = [
            "## C2 / Malware Indicators",
            "",
            f"**Total:** {len(context.c2_findings)}",
            "",
            "| Severity | Type | Value | Score |",
            "|----------|------|-------|-------|",
        ]
        for f in context.c2_findings:
            lines.append(
                f"| {f.severity} | {f.indicator_type} "
                f"| `{f.value}` | {f.suspicion_score:.0f} |"
            )
        lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _md_sbom(context: ScanContext) -> str:
        """Generate SBOM as Markdown."""
        lines = [
            "## Software Bill of Materials (SBOM)",
            "",
            f"**Components:** {len(context.software_components)}",
            "",
            "| Vendor | Product | Version | CPE |",
            "|--------|---------|---------|-----|",
        ]
        for c in context.software_components:
            lines.append(
                f"| {c.vendor} | {c.product} "
                f"| {c.version} | `{c.cpe_string}` |"
            )
        lines.append("")
        return "\n".join(lines)

    # ──────────────────────────────────────────
    # Simple Markdown → HTML converter
    # ──────────────────────────────────────────

    @staticmethod
    def _md_to_html(md: str) -> str:
        """Convert basic Markdown to HTML for report rendering."""
        import re

        lines = md.split("\n")
        html_lines: list[str] = []
        in_table = False
        in_code_block = False

        for line in lines:
            # Code fences
            if line.startswith("```"):
                if in_code_block:
                    html_lines.append("</code></pre>")
                    in_code_block = False
                else:
                    html_lines.append("<pre><code>")
                    in_code_block = True
                continue
            if in_code_block:
                html_lines.append(line)
                continue

            # Headings
            if line.startswith("# "):
                html_lines.append(f"<h1>{line[2:]}</h1>")
            elif line.startswith("## "):
                html_lines.append(f"<h2>{line[3:]}</h2>")
            elif line.startswith("### "):
                html_lines.append(f"<h3>{line[4:]}</h3>")
            elif line.startswith("---"):
                html_lines.append("<hr>")
            # Table rows
            elif line.startswith("|") and "|" in line[1:]:
                cells = [c.strip() for c in line.split("|")[1:-1]]
                if not in_table:
                    html_lines.append("<table>")
                    in_table = True
                    # Header row
                    row = "".join(f"<th>{c}</th>" for c in cells)
                    html_lines.append(f"<tr>{row}</tr>")
                else:
                    # Check if separator row
                    if all(set(c.strip()) <= {"-", ":"} for c in cells if c.strip()):
                        continue  # skip separator
                    row = "".join(f"<td>{c}</td>" for c in cells)
                    html_lines.append(f"<tr>{row}</tr>")
            elif not line.startswith("|") and in_table:
                html_lines.append("</table>")
                in_table = False
                if line.strip():
                    html_lines.append(f"<p>{line}</p>")
            elif line.startswith("- "):
                content = line[2:]
                html_lines.append(f"<li>{content}</li>")
            elif line.strip():
                # Inline formatting
                content = re.sub(
                    r"`([^`]+)`", r"<code>\1</code>", line
                )
                content = re.sub(
                    r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", content
                )
                html_lines.append(f"<p>{content}</p>")

        if in_table:
            html_lines.append("</table>")

        return "\n".join(html_lines)
