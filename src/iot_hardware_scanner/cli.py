"""Click CLI entry point for IoT Hardware Scanner.

Provides the `iot-hardware-scanner` command with subcommands:
  scan     — Full pipeline scan
  extract  — Firmware extraction only
  entropy  — Entropy analysis only
  report   — Generate report from previous scan
  version  — Show version
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import click
from rich.console import Console

from iot_hardware_scanner import __version__
from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.exceptions import ScannerError
from iot_hardware_scanner.models import FirmwareSizeCategory, ScanContext

console = Console()


def _build_config(
    output: Path | None,
    verbose: bool,
    nvd_api_key: str | None,
    yara_rules: Path | None,
    offline: bool,
    max_size: int | None,
) -> ScannerConfig:
    """Build ScannerConfig from CLI flags."""
    kwargs: dict = {}
    if output:
        kwargs["output_dir"] = output
    if verbose:
        kwargs["verbose"] = True
    if nvd_api_key:
        kwargs["nvd_api_key"] = nvd_api_key
    if yara_rules:
        kwargs["yara_rules_dirs"] = [yara_rules]
    if offline:
        kwargs["offline_mode"] = True
    if max_size is not None:
        kwargs["max_file_size_mb"] = max_size
    return ScannerConfig(**kwargs)


@click.group()
@click.version_option(version=__version__, prog_name="iot-hardware-scanner")
def main() -> None:
    """IoT Hardware Scanner — Firmware Security Analysis Platform."""
    pass


@main.command()
@click.argument("firmware", type=click.Path(exists=False))
@click.option("--output", "-o", type=click.Path(), default=None, help="Output directory")
@click.option(
    "--format",
    "report_format",
    type=click.Choice(["json", "markdown", "html", "terminal"], case_sensitive=False),
    default="terminal",
    help="Report format",
)
@click.option("--out", "report_file", type=click.Path(), default=None, help="Report output file")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option("--nvd-api-key", envvar="NVD_API_KEY", default=None, help="NVD API key")
@click.option("--yara-rules", type=click.Path(), default=None, help="Custom YARA rules dir")
@click.option("--creds", is_flag=True, help="Run credential scan only (skip other phases)")
@click.option("--offline", is_flag=True, help="Disable network requests")
@click.option("--max-size", type=int, default=None, help="Max firmware size in MB")
def scan(
    firmware: str,
    output: str | None,
    report_format: str,
    report_file: str | None,
    verbose: bool,
    nvd_api_key: str | None,
    yara_rules: str | None,
    creds: bool,
    offline: bool,
    max_size: int | None,
) -> None:
    """Run full firmware security scan."""
    from iot_hardware_scanner.orchestrator import Orchestrator

    config = _build_config(
        output=Path(output) if output else None,
        verbose=verbose,
        nvd_api_key=nvd_api_key,
        yara_rules=Path(yara_rules) if yara_rules else None,
        offline=offline,
        max_size=max_size,
    )
    config.report_formats = [report_format]

    firmware_path = Path(firmware)
    orchestrator = Orchestrator(config, creds_only=creds)

    try:
        context = orchestrator.run(firmware_path)
    except ScannerError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        sys.exit(exc.exit_code)

    # Print summary to terminal
    _print_scan_summary(context)

    if report_file:
        console.print(f"\n[green]Report saved:[/green] {report_file}")

    # Exit with CRITICAL findings code if any found
    if context.credential_findings or context.cve_findings or context.c2_findings:
        has_critical = any(
            f.severity == "CRITICAL" for f in context.credential_findings + context.cve_findings
        )
        sys.exit(1 if has_critical else 0)


@main.command()
@click.argument("firmware", type=click.Path(exists=False))
@click.option("--output", "-o", type=click.Path(), default=None, help="Extraction output dir")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def extract(firmware: str, output: str | None, verbose: bool) -> None:
    """Extract firmware filesystem only (no analysis)."""
    from iot_hardware_scanner.scanner.firmware_extractor import FirmwareExtractor
    from iot_hardware_scanner.scanner.firmware_ingest import FirmwareIngest

    config = ScannerConfig(verbose=verbose)
    if output:
        config.output_dir = Path(output)

    firmware_path = Path(firmware)
    try:
        ingest = FirmwareIngest(config)
        context = ingest.ingest(firmware_path)
        console.print(f"[green]✓[/green] Firmware ingested: {context.firmware_name}")

        extractor = FirmwareExtractor(config)
        result = extractor.extract(context.firmware_path, context.output_dir)
        if result.success:
            console.print(f"[green]✓[/green] Extracted to: {result.extraction_dir}")
            console.print(f"  Filesystems: {len(result.root_filesystems)}")
            console.print(f"  Files: {result.file_count}")
        else:
            console.print("[red]✗[/red] Extraction failed")
            for err in result.extraction_errors:
                console.print(f"  [red]![/red] {err}")
    except ScannerError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        sys.exit(exc.exit_code)


@main.command()
@click.argument("firmware", type=click.Path(exists=False))
@click.option("--block-size", type=int, default=None, help="Entropy block size")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def entropy(firmware: str, block_size: int | None, verbose: bool) -> None:
    """Run entropy analysis only."""
    from iot_hardware_scanner.scanner.entropy_analyzer import EntropyAnalyzer
    from iot_hardware_scanner.scanner.firmware_ingest import FirmwareIngest

    config = ScannerConfig(verbose=verbose)
    if block_size:
        config.entropy_block_size = block_size

    firmware_path = Path(firmware)
    try:
        ingest = FirmwareIngest(config)
        context = ingest.ingest(firmware_path)
        console.print(f"[green]✓[/green] Firmware ingested: {context.firmware_name}")

        data = firmware_path.read_bytes()
        analyzer = EntropyAnalyzer(config)
        profile = analyzer.analyze(data, block_size=block_size)
        console.print(f"Overall entropy: {profile.overall_entropy:.4f}")
        console.print(f"Blocks analyzed: {profile.total_blocks}")
        console.print(f"Encrypted regions: {'Yes' if profile.has_encrypted_regions else 'No'}")
        console.print(f"Compressed regions: {'Yes' if profile.has_compressed_regions else 'No'}")
    except ScannerError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        sys.exit(exc.exit_code)


@main.command()
@click.argument("scan_file", type=click.Path(exists=True))
@click.option(
    "--format",
    "report_format",
    type=click.Choice(["json", "markdown", "html", "terminal"], case_sensitive=False),
    default="markdown",
    help="Report format",
)
@click.option("--out", "report_file", type=click.Path(), default=None, help="Output file")
def report(scan_file: str, report_format: str, report_file: str | None) -> None:
    """Generate report from a previous scan JSON file."""
    import json

    scan_path = Path(scan_file)
    if not scan_path.exists():
        console.print(f"[red]Error:[/red] File not found: {scan_file}")
        sys.exit(3)

    try:
        data = json.loads(scan_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        console.print(f"[red]Error:[/red] Cannot read scan file: {exc}")
        sys.exit(6)

    # Reconstruct ScanContext from JSON
    from iot_hardware_scanner.scanner.report_generator import ReportGenerator

    config = ScannerConfig(report_formats=[report_format])

    # Build a minimal ScanContext from the JSON data
    firmware_data = data.get("firmware", {})
    context = ScanContext(
        scan_id=data.get("scan_id", "unknown"),
        firmware_path=Path(firmware_data.get("path", ".")),
        output_dir=scan_path.parent,
        file_hash_sha256=firmware_data.get("sha256", ""),
        file_hash_md5=firmware_data.get("md5", ""),
        file_size=firmware_data.get("size", 0),
        file_type=firmware_data.get("file_type", "unknown"),
        firmware_name=firmware_data.get("name", scan_path.stem),
        size_category=FirmwareSizeCategory.MEDIUM,
        started_at=datetime.fromisoformat(
            data.get("scan_date", datetime.now(timezone.utc).isoformat())
        )
        if data.get("scan_date")
        else datetime.now(timezone.utc),
    )

    # Populate from JSON
    if data.get("risk_score"):
        from iot_hardware_scanner.models import ControlScore, RiskLevel, RiskScore

        rs = data["risk_score"]
        control_scores = [
            ControlScore(
                control_id=cs["control_id"],
                control_name=cs["control_name"],
                result=cs["result"],
                points=cs["points"],
                max_points=cs["max_points"],
                evidence=cs.get("evidence", []),
                remediation=cs.get("remediation", ""),
            )
            for cs in rs.get("control_scores", [])
        ]
        context.risk_score = RiskScore(
            total_score=rs["total_score"],
            risk_level=RiskLevel(rs["risk_level"]),
            control_scores=control_scores,
            weighted_breakdown=rs.get("weighted_breakdown", {}),
            executive_summary=rs.get("executive_summary", ""),
            owasp_iot_mapping=rs.get("owasp_iot_mapping", {}),
        )

    # Set output file for report generator
    if report_file:
        context.output_dir = Path(report_file).parent
        context.output_dir.mkdir(parents=True, exist_ok=True)

    config.report_formats = [report_format]
    generator = ReportGenerator(config)
    paths = generator.generate(context)

    if report_format == "terminal":
        console.print("[green]Report rendered to terminal[/green]")
    elif paths:
        for fmt, path in paths.items():
            output_path = Path(report_file) if report_file else path
            if report_file and fmt in paths:
                # Copy to desired output file
                import shutil
                shutil.copy2(str(paths[fmt]), str(output_path))
                console.print(f"[green]Report saved:[/green] {output_path}")
            else:
                console.print(f"[green]Report saved:[/green] {path}")
    else:
        console.print("[yellow]No report generated[/yellow]")


def _print_scan_summary(context: ScanContext) -> None:
    """Print a terminal summary of the scan results."""

    console.print()
    console.rule("[bold]IoT Hardware Scanner — Scan Complete[/bold]")
    console.print(f"  Target: [cyan]{context.firmware_name}[/cyan] ({context.file_size:,} bytes)")
    console.print(f"  SHA-256: [dim]{context.file_hash_sha256[:16]}...[/dim]")
    console.print(f"  Scan ID: [dim]{context.scan_id}[/dim]")

    if context.credential_findings:
        cred_critical = sum(1 for f in context.credential_findings if f.severity == "CRITICAL")
        cred_high = sum(1 for f in context.credential_findings if f.severity == "HIGH")
        console.print(
            f"  Credentials: [red]{cred_critical} CRITICAL[/red], "
            f"[yellow]{cred_high} HIGH[/yellow], "
            f"{len(context.credential_findings)} total"
        )

    if context.cve_findings:
        cve_critical = sum(1 for f in context.cve_findings if f.severity == "CRITICAL")
        console.print(
            f"  CVEs: [red]{cve_critical} CRITICAL[/red], {len(context.cve_findings)} total"
        )

    if context.c2_findings:
        c2_likely = sum(1 for f in context.c2_findings if f.severity == "LIKELY_C2")
        console.print(
            f"  C2 Indicators: [red]{c2_likely} LIKELY_C2[/red], {len(context.c2_findings)} total"
        )

    if context.risk_score:
        score = context.risk_score.total_score
        level = context.risk_score.risk_level
        color = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "red", "CRITICAL": "bold red"}.get(
            level, "white"
        )
        console.print(f"  Risk Score: [{color}]{score:.0f}/100 — {level}[/{color}]")

    console.print(f"  Output: [dim]{context.output_dir}[/dim]")
    console.rule()


if __name__ == "__main__":
    main()
