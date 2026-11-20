"""Click CLI entry point for IoT Hardware Scanner.

Subcommands:
  scan     — run the pipeline for a profile
  extract  — extraction only
  entropy  — byte-distribution measurement only
  report   — replay a saved report document into another format
  version  — print the version

Exit status is decided in exactly one place,
:func:`iot_hardware_scanner.scanner.assessment.decide_exit`, and the same
decision is written into the saved report. ``report`` is the one exception: a
replay only reports whether rendering worked, because the saved assessment
already holds the scan's own result.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

import click
from rich.console import Console

from iot_hardware_scanner import __version__
from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.exceptions import ConfigError, ScannerError
from iot_hardware_scanner.models import (
    FirmwareSizeCategory,
    ScanContext,
    Severity,
)
from iot_hardware_scanner.scanner.assessment import (
    PROFILE_CREDENTIALS,
    PROFILE_FIRMWARE,
    collect_findings,
    decide_exit,
)
from iot_hardware_scanner.scanner.report_document import (
    ReportWriteError,
    default_filename,
    load_document,
    render,
    write_atomic,
)

console = Console()

_EXIT_MEANINGS = {
    0: "complete, no findings",
    1: "critical finding (documented evidence rule)",
    2: "review finding(s)",
    3: "invalid input or configuration",
    4: "analysis incomplete",
    5: "required dependency missing",
    6: "internal error or report could not be written",
}


# ──────────────────────────────────────────────
# Configuration resolution
# ──────────────────────────────────────────────


def _cli_overrides(ctx: click.Context, names: dict[str, str]) -> dict[str, object]:
    """Collect only the values the operator actually supplied on the command line."""
    overrides: dict[str, object] = {}
    for option, field in names.items():
        if ctx.get_parameter_source(option) is not click.core.ParameterSource.COMMANDLINE:
            continue
        value = ctx.params.get(option)
        if value is None:
            continue
        if field == "report_formats":
            overrides[field] = [value]
        elif field == "yara_rules_dirs":
            overrides[field] = [Path(value)]
        else:
            overrides[field] = value
    return overrides


def _build_config(ctx: click.Context, names: dict[str, str]) -> ScannerConfig:
    """Resolve configuration: explicit CLI > environment > file > defaults."""
    config_file = ctx.params.get("config_file")
    try:
        return ScannerConfig.resolve(
            config_file=Path(config_file) if config_file else None,
            cli_overrides=_cli_overrides(ctx, names),
        )
    except (ConfigError, ValueError) as exc:
        console.print(f"[red]Configuration error:[/red] {exc}")
        sys.exit(3)


# ──────────────────────────────────────────────
# Root group
# ──────────────────────────────────────────────


@click.group()
@click.version_option(version=__version__, prog_name="iot-hardware-scanner")
@click.option("--verbose", "-v", is_flag=True, help="Verbose logging")
def main(verbose: bool) -> None:
    """IoT Hardware Scanner — firmware security analysis."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )


# ──────────────────────────────────────────────
# scan
# ──────────────────────────────────────────────


@main.command()
@click.argument("firmware", type=click.Path(exists=False))
@click.option("--output", "-o", type=click.Path(), default=None, help="Output directory")
@click.option(
    "--format",
    "report_format",
    type=click.Choice(["json", "markdown", "html", "terminal"], case_sensitive=False),
    default="terminal",
    help="Report format for the saved report (default: terminal only)",
)
@click.option(
    "--out", "report_file", type=click.Path(), default=None, help="Exact report file path"
)
@click.option(
    "--profile",
    type=click.Choice([PROFILE_FIRMWARE, PROFILE_CREDENTIALS], case_sensitive=False),
    default=None,
    help="Assessment profile (default: firmware-static; --creds selects credentials-only)",
)
@click.option("--creds", is_flag=True, help="Credential-only profile (narrower required set)")
@click.option(
    "--config", "config_file", type=click.Path(), default=None, help="YAML/TOML config file"
)
@click.option(
    "--offline/--online",
    default=None,
    help="Disable network access (default: offline)",
)
@click.option("--nvd-api-key", default=None, help="NVD API key for online refresh")
@click.option(
    "--yara-rules", type=click.Path(), default=None, help="Additional YARA rules directory"
)
@click.option("--max-size", type=int, default=None, help="Maximum input size in MB")
@click.pass_context
def scan(
    ctx: click.Context,
    firmware: str,
    output: str | None,
    report_format: str,
    report_file: str | None,
    profile: str | None,
    creds: bool,
    config_file: str | None,
    offline: bool | None,
    nvd_api_key: str | None,
    yara_rules: str | None,
    max_size: int | None,
) -> None:
    """Run the analysis pipeline and save a report."""
    from iot_hardware_scanner.orchestrator import Orchestrator
    from iot_hardware_scanner.scanner.report_generator import ReportGenerator

    config = _build_config(
        ctx,
        {
            "output": "output_dir",
            "report_format": "report_formats",
            "offline": "offline_mode",
            "nvd_api_key": "nvd_api_key",
            "yara_rules": "yara_rules_dirs",
            "max_size": "max_file_size_mb",
        },
    )
    # Normalise CLI-shaped values after the precedence merge.
    if output:
        config.output_dir = Path(output)
    if nvd_api_key:
        config.nvd_api_key = nvd_api_key
    if yara_rules:
        config.yara_rules_dirs = [*config.yara_rules_dirs, Path(yara_rules)]
    if max_size is not None:
        config.max_file_size_mb = max_size

    selected_profile = profile or (PROFILE_CREDENTIALS if creds else PROFILE_FIRMWARE)

    try:
        orchestrator = Orchestrator(config, profile=selected_profile)
        context = orchestrator.run(Path(firmware))
    except ScannerError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        sys.exit(exc.exit_code)

    generator = ReportGenerator(config)
    document = generator.document(context)
    findings = collect_findings(context)

    # The decision is part of the saved document, so CI can read the outcome
    # from the same file it archives.
    decision = decide_exit(findings, context.assessment)
    document["outcome"] = {
        "exit_code": decision.exit_code,
        "exit_reason": decision.exit_reason,
        "summary": decision.summary,
        "reasons": decision.reasons,
    }

    # ── Deliver the report ──
    output_error: str | None = None
    written: Path | None = None
    destination: Path | None = None
    if report_file:
        destination = Path(report_file)
    elif report_format != "terminal":
        destination = context.output_dir / default_filename(report_format)

    if destination is not None:
        try:
            written = write_atomic(destination, render(document, report_format))
        except ReportWriteError as exc:
            output_error = str(exc)
            decision = decide_exit(findings, context.assessment, output_error=output_error)

    if output_error:
        # Never print a success line for a report that does not exist.
        console.print(f"[red]Report not written:[/red] {output_error}")
    elif written is not None:
        console.print(f"[green]Report written:[/green] {written}")

    console.print()
    console.print(render(document, "terminal"), markup=False, highlight=False)
    console.print()
    console.print(
        f"Exit {decision.exit_code} — {decision.summary}",
        markup=False,
        highlight=False,
    )

    sys.exit(decision.exit_code)


# ──────────────────────────────────────────────
# extract
# ──────────────────────────────────────────────


@main.command()
@click.argument("firmware", type=click.Path(exists=False))
@click.option("--output", "-o", type=click.Path(), default=None, help="Extraction output directory")
@click.option(
    "--config", "config_file", type=click.Path(), default=None, help="YAML/TOML config file"
)
@click.pass_context
def extract(ctx: click.Context, firmware: str, output: str | None, config_file: str | None) -> None:
    """Extract a firmware image's filesystems (no analysis)."""
    from iot_hardware_scanner.scanner.firmware_extractor import FirmwareExtractor
    from iot_hardware_scanner.scanner.firmware_ingest import FirmwareIngest

    config = _build_config(ctx, {"output": "output_dir"})
    if output:
        config.output_dir = Path(output)

    try:
        context = FirmwareIngest(config).ingest(Path(firmware))
    except ScannerError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        sys.exit(exc.exit_code)

    console.print(f"[green]✓[/green] Ingested: {context.firmware_name}")
    result = FirmwareExtractor(config).extract(context.firmware_path, context.output_dir)
    if result.success:
        console.print(f"[green]✓[/green] Extracted to: {result.extraction_dir}")
        console.print(f"  Root filesystems: {len(result.root_filesystems)}")
        console.print(f"  Files: {result.file_count}")
        sys.exit(0)

    console.print(f"[red]✗[/red] Extraction unavailable ({result.backend})")
    for error in result.extraction_errors:
        console.print(f"  [red]![/red] {error}")
    sys.exit(4)


# ──────────────────────────────────────────────
# entropy
# ──────────────────────────────────────────────


@main.command()
@click.argument("firmware", type=click.Path(exists=False))
@click.option("--block-size", type=int, default=None, help="Window size in bytes")
@click.option("--format", "report_format", type=click.Choice(["text", "json"]), default="text")
@click.pass_context
def entropy(ctx: click.Context, firmware: str, block_size: int | None, report_format: str) -> None:
    """Measure byte-distribution entropy (bits/byte, 0.0-8.0)."""
    from iot_hardware_scanner.scanner.entropy_analyzer import EntropyAnalyzer
    from iot_hardware_scanner.scanner.firmware_ingest import FirmwareIngest

    config = _build_config(ctx, {})
    try:
        EntropyAnalyzer.validate_block_size(block_size)
        context = FirmwareIngest(config).ingest(Path(firmware))
        profile = EntropyAnalyzer(config).analyze_file(context.firmware_path, block_size=block_size)
    except ValueError as exc:
        console.print(f"[red]Configuration error:[/red] {exc}")
        sys.exit(3)
    except ScannerError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        sys.exit(exc.exit_code)

    scope = "sampled" if profile.bytes_sampled else "whole input"
    if report_format == "json":
        console.print(
            json.dumps(
                {
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
                },
                indent=2,
            ),
            markup=False,
            highlight=False,
        )
        return

    console.print(
        f"Whole-input entropy: {profile.overall_entropy:.4f} bits/byte "
        f"over {profile.bytes_analyzed:,} bytes ({scope})",
        markup=False,
    )
    console.print(
        f"Mean of windows:     {profile.window_mean_entropy:.4f} bits/byte "
        f"({profile.total_blocks} window(s) of {profile.block_size} bytes)"
    )
    console.print(
        "Entropy describes byte distribution only; it does not establish encryption or readability."
    )


# ──────────────────────────────────────────────
# report (replay)
# ──────────────────────────────────────────────


@main.command()
@click.argument("scan_file", type=click.Path(exists=True))
@click.option(
    "--format",
    "report_format",
    type=click.Choice(["json", "markdown", "html", "terminal"], case_sensitive=False),
    default="markdown",
    help="Output format",
)
@click.option(
    "--out", "report_file", type=click.Path(), default=None, help="Exact output file path"
)
def report(scan_file: str, report_format: str, report_file: str | None) -> None:
    """Render a saved report document again, without re-analysing anything."""
    scan_path = Path(scan_file)
    try:
        data = json.loads(scan_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        console.print(f"[red]Error:[/red] cannot read {scan_path}: {exc}")
        sys.exit(3)

    try:
        document = load_document(data)
        content = render(document, report_format)
    except (ValueError, KeyError, TypeError) as exc:
        console.print(f"[red]Error:[/red] unrecognised report document: {exc}")
        sys.exit(3)

    if report_format == "terminal" and not report_file:
        console.print(content, markup=False, highlight=False)
        sys.exit(0)

    destination = Path(report_file) if report_file else Path.cwd() / default_filename(report_format)
    try:
        written = write_atomic(destination, content)
    except ReportWriteError as exc:
        console.print(f"[red]Report not written:[/red] {exc}")
        sys.exit(6)

    console.print(f"[green]Report written:[/green] {written}")
    if document.get("assessment", {}).get("completion") == "UNKNOWN":
        console.print(
            "Note: this is a replayed legacy document; its coverage is unknown and "
            "its historical grade is shown as legacy.",
            markup=False,
        )
    sys.exit(0)


# ──────────────────────────────────────────────
# Helpers retained for programmatic callers
# ──────────────────────────────────────────────


def _severity_of(value: str) -> Severity:
    """Map a string to a Severity, defaulting to INFO."""
    try:
        return Severity(value)
    except ValueError:
        return Severity.INFO


def _context_from_document(document: dict) -> ScanContext:
    """Rebuild a minimal context from a document (used by tests and tools).

    This never re-runs analysis; it only gives callers a context-shaped object
    for the fields the document records.
    """
    artifact = document.get("artifact") or {}
    return ScanContext(
        scan_id=document.get("scan_id") or "unknown",
        firmware_path=Path(artifact.get("path") or "."),
        output_dir=Path.cwd(),
        file_hash_sha256=artifact.get("sha256") or "",
        file_hash_md5=artifact.get("md5") or "",
        file_size=int(artifact.get("size") or 0),
        file_type=artifact.get("file_type") or "unknown",
        firmware_name=artifact.get("name") or "unknown",
        size_category=FirmwareSizeCategory.SMALL,
        started_at=datetime.now(tz=timezone.utc),
    )


if __name__ == "__main__":
    main()
