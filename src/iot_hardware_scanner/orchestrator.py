"""Pipeline orchestrator — coordinates all scanner phases.

The Orchestrator is the single entry point for running a full scan.
It creates the ScanContext at ingestion and threads it through
each phase sequentially, collecting results along the way.

SDR §5 — Architecture Overview
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.exceptions import ScannerError
from iot_hardware_scanner.models import ScanContext
from iot_hardware_scanner.scanner.firmware_ingest import FirmwareIngest

logger = logging.getLogger(__name__)
console = Console()


class Orchestrator:
    """Coordinate the full firmware analysis pipeline.

    Phase execution order follows SDR §5 dependency graph:
      1. Ingest      — validate, hash, identify firmware
      2. Extract     — binwalk extraction + filesystem mapping
      3. Entropy     — Shannon entropy analysis + binary intelligence
      4. Credentials — YARA + regex credential detection
      5. CVE         — NVD vulnerability correlation
      6. C2          — Command & control indicator detection
      7. Risk/Report — scoring + multi-format report generation
    """

    def __init__(self, config: ScannerConfig | None = None, creds_only: bool = False) -> None:
        self.config = config or ScannerConfig()
        self.creds_only = creds_only

    def run(self, firmware_path: Path) -> ScanContext:
        """Execute the full scan pipeline.

        Args:
            firmware_path: Path to firmware image.

        Returns:
            Fully populated ScanContext with all findings.

        Raises:
            ScannerError: Any phase-specific error.
        """
        # ── Phase 1: Ingest ──
        context = self._phase_ingest(firmware_path)

        # ── Phase 2: Extract + Filesystem ──
        context = self._phase_extract(context)
        context = self._phase_filesystem(context)

        # ── Phase 3: Entropy + Binary Intelligence ──
        if not self.creds_only:
            context = self._phase_entropy(context)
            context = self._phase_binary_intelligence(context)

        # ── Phase 4: Credentials ──
        context = self._phase_credentials(context)

        # ── Phase 5: CVE ──
        if not self.creds_only:
            context = self._phase_cve(context)

        # ── Phase 6: C2 Detection ──
        if not self.creds_only:
            context = self._phase_c2(context)

        # ── Phase 7: Risk Score + Report ──
        if not self.creds_only:
            context = self._phase_risk(context)
            context = self._phase_report(context)

        context.completed_at = datetime.now(timezone.utc)
        return context

    # ──────────────────────────────────────────
    # Phase implementations
    # ──────────────────────────────────────────

    def _phase_ingest(self, firmware_path: Path) -> ScanContext:
        """Phase 1: Firmware ingestion and validation."""
        console.print("[bold]═══ Phase 1: Ingest ═══[/bold]")
        ingest = FirmwareIngest(self.config)
        context = ingest.ingest(firmware_path)
        console.print("  [green]✓[/green] File validated")
        console.print(f"  [green]✓[/green] SHA-256: {context.file_hash_sha256[:32]}...")
        console.print(f"  [green]✓[/green] Type: {context.file_type}")
        console.print(
            f"  [green]✓[/green] Size: {context.file_size:,} bytes ({context.size_category.value})"
        )
        return context

    def _phase_extract(self, context: ScanContext) -> ScanContext:
        """Phase 2a: Firmware extraction."""
        console.print("[bold]═══ Phase 2: Extraction ═══[/bold]")
        try:
            from iot_hardware_scanner.scanner.firmware_extractor import FirmwareExtractor

            extractor = FirmwareExtractor(self.config)
            result = extractor.extract(context.firmware_path, context.output_dir)
            context.extraction_result = result
            if result.success:
                context.extracted_rootfs = (
                    result.root_filesystems[0] if result.root_filesystems else None
                )
                console.print(
                    f"  [green]✓[/green] {len(result.signatures_detected)} signatures detected"
                )
                console.print(
                    f"  [green]✓[/green] Filesystem extracted ({result.file_count} files)"
                )
            else:
                console.print(
                    "  [yellow]![/yellow] Extraction failed — continuing with raw binary analysis"
                )
                for err in result.extraction_errors:
                    console.print(f"  [yellow]![/yellow] {err}")
        except ImportError:
            console.print(
                "  [yellow]![/yellow] FirmwareExtractor not available — skipping extraction"
            )
            logger.warning("FirmwareExtractor module not available")
        except ScannerError as exc:
            console.print(f"  [yellow]![/yellow] Extraction error: {exc} — continuing")
            logger.warning("Extraction error: %s", exc)
        return context

    def _phase_filesystem(self, context: ScanContext) -> ScanContext:
        """Phase 2b: Filesystem scanning."""
        console.print("[bold]═══ Phase 2b: Filesystem ═══[/bold]")
        if context.extracted_rootfs and context.extracted_rootfs.exists():
            try:
                from iot_hardware_scanner.models import FileCategory, FilesystemInventory
                from iot_hardware_scanner.scanner.filesystem_scanner import FilesystemScanner

                scanner = FilesystemScanner(self.config)
                root_filesystems = (
                    context.extraction_result.root_filesystems
                    if context.extraction_result
                    else [context.extracted_rootfs]
                )

                merged = FilesystemInventory(
                    rootfs_path=context.extracted_rootfs,
                    findings=[],
                    categories={cat: [] for cat in FileCategory},
                )
                for rootfs in root_filesystems:
                    inv = scanner.scan(rootfs)
                    merged.total_files += inv.total_files
                    merged.total_directories += inv.total_directories
                    merged.total_size += inv.total_size
                    merged.findings.extend(inv.findings)
                    for cat, items in inv.categories.items():
                        merged.categories.setdefault(cat, []).extend(items)
                    merged.suid_binaries.extend(inv.suid_binaries)
                    merged.world_writable_files.extend(inv.world_writable_files)
                    merged.shadow_files.extend(inv.shadow_files)
                    merged.ssl_cert_files.extend(inv.ssl_cert_files)
                    merged.init_scripts.extend(inv.init_scripts)
                    merged.network_services.extend(inv.network_services)

                context.filesystem_inventory = merged
                console.print(
                    f"  [green]✓[/green] {merged.total_files} files,"
                    f" {merged.total_directories} directories"
                    f" ({len(root_filesystems)} root filesystem(s))"
                )
            except ImportError:
                console.print("  [yellow]![/yellow] FilesystemScanner not available")
                logger.warning("FilesystemScanner module not available")
        else:
            console.print("  [yellow]![/yellow] No extracted filesystem — skipping filesystem scan")
        return context

    def _phase_entropy(self, context: ScanContext) -> ScanContext:
        """Phase 3a: Entropy analysis."""
        console.print("[bold]═══ Phase 3: Entropy ═══[/bold]")
        try:
            from iot_hardware_scanner.scanner.entropy_analyzer import EntropyAnalyzer

            analyzer = EntropyAnalyzer(self.config)
            profile = analyzer.analyze_file(context.firmware_path)
            context.entropy_profile = profile
            console.print(f"  [green]✓[/green] Overall entropy: {profile.overall_entropy:.4f}")
            if profile.has_encrypted_regions:
                console.print("  [yellow]![/yellow] Encrypted regions detected")
            if profile.has_compressed_regions:
                console.print("  [green]✓[/green] Compressed regions detected (normal)")
        except ImportError:
            console.print("  [yellow]![/yellow] EntropyAnalyzer not available")
            logger.warning("EntropyAnalyzer module not available")
        return context

    def _phase_binary_intelligence(self, context: ScanContext) -> ScanContext:
        """Phase 3b: Binary intelligence extraction."""
        console.print("[bold]═══ Phase 3b: Binary Intelligence ═══[/bold]")
        try:
            from iot_hardware_scanner.scanner.binary_intelligence import BinaryIntelligence

            bi = BinaryIntelligence(self.config)
            result = bi.analyze(context)
            context.binary_intelligence = result
            console.print(f"  [green]✓[/green] {result.total_binaries} binaries analyzed")
        except ImportError:
            console.print("  [yellow]![/yellow] BinaryIntelligence not available")
            logger.warning("BinaryIntelligence module not available")
        return context

    def _phase_credentials(self, context: ScanContext) -> ScanContext:
        """Phase 4: Credential and secret detection."""
        console.print("[bold]═══ Phase 4: Credentials ═══[/bold]")
        try:
            from iot_hardware_scanner.scanner.credential_scanner import CredentialScanner

            scanner = CredentialScanner(self.config)
            # Will scan filesystem inventory when available, or raw paths
            findings = (
                scanner.scan_inventory(context.filesystem_inventory)
                if context.filesystem_inventory
                else []
            )
            context.credential_findings = findings
            if findings:
                crit = sum(1 for f in findings if f.severity.value == "CRITICAL")
                high = sum(1 for f in findings if f.severity.value == "HIGH")
                console.print(
                    f"  [red]![/red] {crit} CRITICAL, {high} HIGH, {len(findings)} total findings"
                )
            else:
                console.print("  [green]✓[/green] No credential findings")
        except ImportError:
            console.print("  [yellow]![/yellow] CredentialScanner not available")
            logger.warning("CredentialScanner module not available")
        return context

    def _phase_cve(self, context: ScanContext) -> ScanContext:
        """Phase 5: CVE matching."""
        console.print("[bold]═══ Phase 5: CVE ═══[/bold]")
        try:
            from iot_hardware_scanner.scanner.cve_scanner import CVEScanner

            scanner = CVEScanner(self.config)
            components = context.software_components or []
            findings = scanner.scan_all(components) if components else []
            context.cve_findings = findings
            if findings:
                kev = sum(1 for f in findings if f.is_in_kev)
                console.print(f"  [red]![/red] {len(findings)} CVEs found ({kev} in CISA KEV)")
            else:
                console.print("  [green]✓[/green] No CVE findings")
        except ImportError:
            console.print("  [yellow]![/yellow] CVEScanner not available")
            logger.warning("CVEScanner module not available")
        return context

    def _phase_c2(self, context: ScanContext) -> ScanContext:
        """Phase 6: C2 and malicious indicator detection."""
        console.print("[bold]═══ Phase 6: C2 & Malware ═══[/bold]")
        try:
            from iot_hardware_scanner.scanner.c2_detector import C2Detector

            detector = C2Detector(self.config)
            inventory = context.filesystem_inventory
            if inventory:
                domain_findings = detector.detect_domains(inventory)
                ip_findings = detector.detect_ips(inventory)
                malware_findings = detector.detect_malware_signatures(inventory)
                context.c2_findings = domain_findings + ip_findings + malware_findings
            if context.c2_findings:
                likely = sum(1 for f in context.c2_findings if f.severity == "LIKELY_C2")
                console.print(
                    f"  [red]![/red] {likely} LIKELY_C2, {len(context.c2_findings)} total"
                )
            else:
                console.print("  [green]✓[/green] No C2 indicators")
        except ImportError:
            console.print("  [yellow]![/yellow] C2Detector not available")
            logger.warning("C2Detector module not available")
        return context

    def _phase_risk(self, context: ScanContext) -> ScanContext:
        """Phase 7a: Risk scoring."""
        console.print("[bold]═══ Phase 7: Risk Score ═══[/bold]")
        try:
            from iot_hardware_scanner.scanner.risk_scorer import RiskScorer

            scorer = RiskScorer(self.config)
            context.risk_score = scorer.score(context)
            score = context.risk_score
            console.print(f"  Risk Score: {score.total_score:.0f}/100 — {score.risk_level.value}")
        except ImportError:
            console.print("  [yellow]![/yellow] RiskScorer not available")
            logger.warning("RiskScorer module not available")
        return context

    def _phase_report(self, context: ScanContext) -> ScanContext:
        """Phase 7b: Report generation."""
        console.print("[bold]═══ Phase 7b: Report ═══[/bold]")
        try:
            from iot_hardware_scanner.scanner.report_generator import ReportGenerator

            generator = ReportGenerator(self.config)
            paths = generator.generate(context)
            for fmt, path in paths.items():
                console.print(f"  [green]✓[/green] {fmt} report: {path}")
        except ImportError:
            console.print("  [yellow]![/yellow] ReportGenerator not available")
            logger.warning("ReportGenerator module not available")
        return context
