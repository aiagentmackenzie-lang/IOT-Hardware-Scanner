"""Report Generator — Phase 7b.

Generates reports in JSON, Markdown, HTML, and terminal formats.

SDR §13.2 — Report Generation

Stub implementation — full build in Phase 7 delivery.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.models import ScanContext

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generate multi-format reports from scan results."""

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
                paths["json"] = path
            elif fmt == "markdown":
                path = self._generate_markdown(context)
                paths["markdown"] = path
            elif fmt == "terminal":
                # Terminal output already rendered during scan
                pass
            elif fmt == "html":
                path = self._generate_html(context)
                paths["html"] = path

        return paths

    def _generate_json(self, context: ScanContext) -> Path:
        """Generate JSON report."""
        report = {
            "scan_id": context.scan_id,
            "firmware": {
                "name": context.firmware_name,
                "path": str(context.firmware_path),
                "size": context.file_size,
                "sha256": context.file_hash_sha256,
                "md5": context.file_hash_md5,
                "file_type": context.file_type,
                "size_category": context.size_category.value,
            },
            "started_at": context.started_at.isoformat(),
            "credential_findings": [
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
            "cve_findings": [
                {
                    "cve_id": f.cve_id,
                    "severity": f.severity.value,
                    "cvss_v3_score": f.cvss_v3_score,
                    "affected_product": f.affected_product,
                    "is_in_kev": f.is_in_kev,
                }
                for f in context.cve_findings
            ],
            "c2_findings": [
                {
                    "severity": f.severity,
                    "indicator_type": f.indicator_type,
                    "value": f.value,
                    "suspicion_score": f.suspicion_score,
                }
                for f in context.c2_findings
            ],
            "risk_score": {
                "total": context.risk_score.total_score,
                "level": context.risk_score.risk_level.value,
                "summary": context.risk_score.executive_summary,
            }
            if context.risk_score
            else None,
        }

        output_path = context.output_dir / "report.json"
        output_path.write_text(json.dumps(report, indent=2, default=str))
        logger.info("JSON report: %s", output_path)
        return output_path

    def _generate_markdown(self, context: ScanContext) -> Path:
        """Generate Markdown report."""
        lines = [
            f"# IoT Hardware Scanner — {context.firmware_name}",
            "",
            f"**Scan ID:** {context.scan_id}",
            f"**Date:** {context.started_at.isoformat()}",
            f"**SHA-256:** `{context.file_hash_sha256}`",
            f"**File Type:** {context.file_type}",
            f"**Size:** {context.file_size:,} bytes ({context.size_category.value})",
            "",
        ]

        if context.risk_score:
            lines.extend(
                [
                    "## Risk Score",
                    "",
                    f"**Score:** {context.risk_score.total_score:.0f}/100 "
                    f"— **{context.risk_score.risk_level.value}**",
                    "",
                    context.risk_score.executive_summary,
                    "",
                ]
            )

        if context.credential_findings:
            lines.extend(
                [
                    "## Credential Findings",
                    "",
                    f"Total: {len(context.credential_findings)}",
                    "",
                    "| Severity | Category | File | Line |",
                    "|----------|----------|------|------|",
                ]
            )
            for f in context.credential_findings:
                lines.append(
                    f"| {f.severity.value} | {f.category} "
                    f"| `{f.file_path}` | {f.line_number or '-'} |"
                )
            lines.append("")

        if context.cve_findings:
            lines.extend(
                [
                    "## CVE Findings",
                    "",
                    f"Total: {len(context.cve_findings)}",
                    "",
                ]
            )
            for f in context.cve_findings:
                lines.append(f"- **{f.cve_id}** ({f.severity.value}): {f.affected_product}")
            lines.append("")

        if context.c2_findings:
            lines.extend(
                [
                    "## C2 / Malware Indicators",
                    "",
                    f"Total: {len(context.c2_findings)}",
                    "",
                ]
            )
            for f in context.c2_findings:
                lines.append(f"- **{f.severity}**: {f.value} (score: {f.suspicion_score})")
            lines.append("")

        output_path = context.output_dir / "report.md"
        output_path.write_text("\n".join(lines))
        logger.info("Markdown report: %s", output_path)
        return output_path

    def _generate_html(self, context: ScanContext) -> Path:
        """Generate HTML report (stub — template-based in Phase 7)."""
        md_path = self._generate_markdown(context)
        # Simple HTML wrapper
        md_content = md_path.read_text()
        html = f"""<!DOCTYPE html>
<html>
<head><title>IoT Hardware Scanner — {context.firmware_name}</title></head>
<body>
<pre>{md_content}</pre>
</body>
</html>"""
        output_path = context.output_dir / "report.html"
        output_path.write_text(html)
        logger.info("HTML report: %s", output_path)
        return output_path
