"""Pipeline orchestrator — coordinates all scanner phases.

The Orchestrator is the single entry point for running a scan. It creates the
ScanContext at ingestion and threads it through each phase, recording what each
stage actually did on the context. Completion and the process exit status are
then derived by :mod:`iot_hardware_scanner.scanner.assessment`.

Design rules this module follows:

* Every stage records a status, a reason and inspected/eligible counts. A stage
  that did not run says so; it never silently contributes zero findings.
* Findings already collected survive a later stage failure.
* ``completed_at`` is set before the assessment is built and the report is
  rendered, so the saved document and the assessment agree.
* A new scan never produces an aggregate security grade.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.exceptions import BinwalkNotFoundError, ScannerError
from iot_hardware_scanner.models import (
    ControlResult,
    FileCategory,
    InputKind,
    ScanContext,
    StageId,
    StageStatus,
)
from iot_hardware_scanner.scanner.assessment import (
    PROFILE_CREDENTIALS,
    PROFILE_FIRMWARE,
    PROFILE_VERSION,
    build_assessment,
    record_stage,
)
from iot_hardware_scanner.scanner.firmware_ingest import FirmwareIngest

logger = logging.getLogger(__name__)
console = Console()


class Orchestrator:
    """Coordinate the firmware analysis pipeline for one profile.

    Phase execution order:
      1. Ingest      — validate, hash, identify the artifact
      2. Extract     — extraction + root discovery (firmware profile)
      3. Filesystem  — bounded enumeration, categorization, boot evidence
      4. Entropy     — byte-distribution measurement
      5. Binaries    — binary metadata and version strings
      6. Credentials — YARA + regex + Unix account parsing
      7. CVE         — advisory matching against a local snapshot
      8. C2          — indicator detection
      9. Controls    — named checks with evidence status
    """

    def __init__(
        self,
        config: ScannerConfig | None = None,
        creds_only: bool = False,
        profile: str | None = None,
    ) -> None:
        self.config = config or ScannerConfig()
        if profile is None:
            profile = PROFILE_CREDENTIALS if creds_only else PROFILE_FIRMWARE
        self.profile = profile

    # ──────────────────────────────────────────
    # Entry point
    # ──────────────────────────────────────────

    def run(self, input_path: Path) -> ScanContext:
        """Execute the scan pipeline for the selected profile."""
        input_path = Path(input_path)
        if self.profile == PROFILE_CREDENTIALS and input_path.is_dir():
            context = self._ingest_tree(input_path)
        else:
            context = self._phase_ingest(input_path)

        context.profile = self.profile
        context.profile_version = PROFILE_VERSION

        if self.profile == PROFILE_CREDENTIALS:
            if context.input_kind is InputKind.FILE:
                # The artifact is the population: one unit was inspected.
                record_stage(
                    context,
                    StageId.ENUMERATION,
                    StageStatus.COMPLETE,
                    reason="single artifact treated as one inspectable unit",
                    inspected=1,
                    eligible=1,
                )
            context = self._phase_credentials(context)
            context = self._phase_unix(context)
            context = self._phase_controls(context, advisory_assessed=False)
        else:
            context = self._phase_extract(context)
            context = self._phase_filesystem(context)
            context = self._phase_entropy(context)
            context = self._phase_binary_intelligence(context)
            context = self._phase_credentials(context)
            context = self._phase_unix(context)
            context = self._phase_advisory(context)
            context = self._phase_c2(context)
            context = self._phase_controls(
                context, advisory_assessed=self._advisory_assessed(context)
            )

        context.completed_at = datetime.now(timezone.utc)
        build_assessment(context, controls=context.controls, limitations=self._limitations(context))
        return context

    # ──────────────────────────────────────────
    # Phase implementations
    # ──────────────────────────────────────────

    def _ingest_tree(self, tree_path: Path) -> ScanContext:
        console.print("[bold]═══ Phase 1: Ingest (staged tree) ═══[/bold]")
        ingest = FirmwareIngest(self.config)
        context = ingest.ingest_tree(tree_path)
        record_stage(
            context,
            StageId.INGEST,
            StageStatus.COMPLETE,
            reason="Input path validated and catalogued",
            inspected=1,
            eligible=1,
        )
        record_stage(
            context,
            StageId.ENUMERATION,
            StageStatus.COMPLETE,
            reason="Staged tree walked directly; metadata is host-derived",
            inspected=context.input_manifest_entries,
            eligible=context.input_manifest_entries,
        )
        console.print(
            f"  [green]✓[/green] {context.input_manifest_entries} files, "
            f"tree digest {context.file_hash_sha256[:16]}…"
        )
        return context

    def _phase_ingest(self, input_path: Path) -> ScanContext:
        """Phase 1: Artifact ingestion and validation."""
        console.print("[bold]═══ Phase 1: Ingest ═══[/bold]")
        ingest = FirmwareIngest(self.config)
        context = ingest.ingest(input_path)
        record_stage(
            context,
            StageId.INGEST,
            StageStatus.COMPLETE,
            reason="Input file validated and catalogued",
            inspected=1,
            eligible=1,
        )
        console.print("  [green]✓[/green] File validated")
        console.print(f"  [green]✓[/green] SHA-256: {context.file_hash_sha256[:32]}...")
        console.print(f"  [green]✓[/green] Type: {context.file_type}")
        console.print(
            f"  [green]✓[/green] Size: {context.file_size:,} bytes ({context.size_category.value})"
        )
        return context

    def _phase_extract(self, context: ScanContext) -> ScanContext:
        """Phase 2a: Firmware extraction and root discovery."""
        console.print("[bold]═══ Phase 2: Extraction ═══[/bold]")
        try:
            from iot_hardware_scanner.scanner.firmware_extractor import FirmwareExtractor

            extractor = FirmwareExtractor(self.config)
            result = extractor.extract(context.firmware_path, context.output_dir)
            context.extraction_result = result
        except ImportError as exc:
            record_stage(
                context,
                StageId.EXTRACTION,
                StageStatus.UNAVAILABLE,
                reason=f"extraction backend not available: {exc}",
                dependency="extraction backend (binwalk / SquashFS helper) is not installed",
            )
            record_stage(
                context,
                StageId.ROOT_DISCOVERY,
                StageStatus.UNAVAILABLE,
                reason="no extraction backend, so no root filesystem was reached",
            )
            console.print("  [yellow]![/yellow] Extraction backend unavailable")
            return context
        except BinwalkNotFoundError as exc:
            record_stage(
                context,
                StageId.EXTRACTION,
                StageStatus.UNAVAILABLE,
                reason=str(exc),
                dependency="extraction backend (binwalk / SquashFS helper) is not installed",
            )
            record_stage(
                context,
                StageId.ROOT_DISCOVERY,
                StageStatus.UNAVAILABLE,
                reason="no extraction backend, so no root filesystem was reached",
            )
            console.print(f"  [yellow]![/yellow] {exc}")
            return context
        except ScannerError as exc:
            record_stage(
                context,
                StageId.EXTRACTION,
                StageStatus.FAILED,
                reason=str(exc),
            )
            record_stage(
                context,
                StageId.ROOT_DISCOVERY,
                StageStatus.UNAVAILABLE,
                reason="extraction failed, so no root filesystem was reached",
            )
            console.print(f"  [yellow]![/yellow] Extraction failed: {exc}")
            return context

        if result.success and result.root_filesystems:
            context.extracted_rootfs = result.root_filesystems[0]
            record_stage(
                context,
                StageId.EXTRACTION,
                StageStatus.COMPLETE,
                reason=f"backend {result.backend}",
                inspected=result.file_count,
                eligible=result.file_count,
            )
            record_stage(
                context,
                StageId.ROOT_DISCOVERY,
                StageStatus.COMPLETE,
                reason=f"{len(result.root_filesystems)} root filesystem(s) located",
                inspected=len(result.root_filesystems),
                eligible=len(result.root_filesystems),
            )
            console.print(
                f"  [green]✓[/green] Filesystem extracted ({result.file_count} files, "
                f"{len(result.root_filesystems)} root(s))"
            )
            return context

        # Extraction did not succeed: the eligible population is unknown, not 0.
        reason = "; ".join(result.extraction_errors) or "extraction produced no root"
        record_stage(
            context,
            StageId.EXTRACTION,
            StageStatus.UNAVAILABLE,
            reason=reason,
            omissions=["filesystem never enumerated"],
        )
        record_stage(
            context,
            StageId.ROOT_DISCOVERY,
            StageStatus.UNAVAILABLE,
            reason="extraction produced no accessible root filesystem",
        )
        console.print(f"  [yellow]![/yellow] Extraction unavailable — {reason}")
        return context

    def _phase_filesystem(self, context: ScanContext) -> ScanContext:
        """Phase 2b: Bounded filesystem enumeration."""
        console.print("[bold]═══ Phase 2b: Filesystem ═══[/bold]")
        if not (context.extracted_rootfs and context.extracted_rootfs.exists()):
            record_stage(
                context,
                StageId.ENUMERATION,
                StageStatus.UNAVAILABLE,
                reason="no extracted root filesystem to enumerate",
                omissions=["file inventory", "boot evidence"],
            )
            record_stage(
                context,
                StageId.SERVICE_ANALYSIS,
                StageStatus.UNAVAILABLE,
                reason="no enumerated filesystem, so no boot path could be read",
                omissions=["configured startup directives"],
            )
            console.print("  [yellow]![/yellow] No extracted filesystem — enumeration did not run")
            return context

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
            inventory = scanner.scan(rootfs)
            merged.total_files += inventory.total_files
            merged.total_directories += inventory.total_directories
            merged.total_size += inventory.total_size
            merged.findings.extend(inventory.findings)
            for cat, items in inventory.categories.items():
                merged.categories.setdefault(cat, []).extend(items)
            merged.suid_binaries.extend(inventory.suid_binaries)
            merged.world_writable_files.extend(inventory.world_writable_files)
            merged.shadow_files.extend(inventory.shadow_files)
            merged.ssl_cert_files.extend(inventory.ssl_cert_files)
            merged.init_scripts.extend(inventory.init_scripts)
            merged.network_services.extend(inventory.network_services)
            merged.boot_evidence.extend(scanner.collect_boot_evidence(rootfs))

        context.filesystem_inventory = merged
        record_stage(
            context,
            StageId.ENUMERATION,
            StageStatus.COMPLETE,
            reason=f"{len(root_filesystems)} root filesystem(s)",
            inspected=merged.total_files,
            eligible=merged.total_files,
        )
        record_stage(
            context,
            StageId.SERVICE_ANALYSIS,
            StageStatus.COMPLETE,
            reason=(
                f"{len(merged.boot_evidence)} configured startup directive(s) parsed "
                "from init paths"
            ),
            inspected=len(root_filesystems),
            eligible=len(root_filesystems),
        )
        console.print(
            f"  [green]✓[/green] {merged.total_files} files,"
            f" {merged.total_directories} directories"
            f" ({len(root_filesystems)} root filesystem(s))"
        )
        return context

    def _phase_entropy(self, context: ScanContext) -> ScanContext:
        """Phase 3a: Byte-distribution measurement."""
        console.print("[bold]═══ Phase 3: Entropy ═══[/bold]")
        try:
            from iot_hardware_scanner.scanner.entropy_analyzer import EntropyAnalyzer

            analyzer = EntropyAnalyzer(self.config)
            profile = analyzer.analyze_file(context.firmware_path)
            context.entropy_profile = profile
        except ScannerError as exc:
            record_stage(context, StageId.ENTROPY, StageStatus.FAILED, reason=str(exc))
            console.print(f"  [yellow]![/yellow] Entropy failed: {exc}")
            return context

        scope = "sampled" if profile.bytes_sampled else "whole input"
        record_stage(
            context,
            StageId.ENTROPY,
            StageStatus.COMPLETE if not profile.bytes_sampled else StageStatus.PARTIAL,
            reason=f"{profile.bytes_analyzed:,} bytes analysed ({scope})",
            inspected=profile.bytes_analyzed,
            eligible=context.file_size,
            omissions=[] if not profile.bytes_sampled else ["unread regions"],
        )
        console.print(
            f"  [green]✓[/green] {profile.overall_entropy:.4f} bits/byte "
            f"over {profile.bytes_analyzed:,} bytes ({scope})"
        )
        return context

    def _phase_binary_intelligence(self, context: ScanContext) -> ScanContext:
        """Phase 3b: Binary metadata and version strings."""
        console.print("[bold]═══ Phase 3b: Binary Intelligence ═══[/bold]")
        from iot_hardware_scanner.scanner.binary_intelligence import BinaryIntelligence

        inventory = context.filesystem_inventory
        eligible = (
            len(inventory.categories.get(FileCategory.CRITICAL_BINARY, []))
            if inventory is not None
            else None
        )

        bi = BinaryIntelligence(self.config)
        try:
            result = bi.analyze(context)
        except Exception as exc:  # stage isolation is deliberate
            record_stage(context, StageId.BINARY_INVENTORY, StageStatus.FAILED, reason=str(exc))
            logger.warning("Binary intelligence failed: %s", exc)
            return context

        context.binary_intelligence = result
        record_stage(
            context,
            StageId.BINARY_INVENTORY,
            StageStatus.COMPLETE if eligible is not None else StageStatus.UNAVAILABLE,
            reason=(
                "binaries selected from the enumerated inventory"
                if eligible is not None
                else "no enumerated inventory; binaries were never selected"
            ),
            inspected=result.total_binaries,
            eligible=eligible,
        )
        record_stage(
            context,
            StageId.ELF_METADATA,
            StageStatus.UNAVAILABLE,
            reason="native ELF header parsing is not implemented in this release",
        )
        record_stage(
            context,
            StageId.OPKG_INVENTORY,
            StageStatus.UNAVAILABLE,
            reason="installed-package record parsing is not implemented in this release",
        )
        console.print(f"  [green]✓[/green] {result.total_binaries} binaries analyzed")
        return context

    def _phase_credentials(self, context: ScanContext) -> ScanContext:
        """Phase 4: Credential and secret detection."""
        console.print("[bold]═══ Phase 4: Credentials ═══[/bold]")
        from iot_hardware_scanner.scanner.credential_scanner import CredentialScanner

        scanner = CredentialScanner(self.config)
        scanned_categories = {
            FileCategory.CRITICAL_CREDENTIAL,
            FileCategory.CRITICAL_CONFIG,
            FileCategory.HIGH_API_KEY,
            FileCategory.HIGH_CRYPTO,
            FileCategory.HIGH_DATABASE,
        }

        if context.filesystem_inventory is not None:
            eligible = sum(
                len(context.filesystem_inventory.categories.get(cat, []))
                for cat in scanned_categories
            )
            findings = scanner.scan_inventory(context.filesystem_inventory)
            inspected = eligible
        else:
            # No inventory: the artifact itself is still an inspectable unit,
            # so secrets embedded in an opaque image are not silently missed.
            findings = scanner.scan_artifact(context.firmware_path, context.input_kind)
            inspected = 1
            eligible = 1

        context.credential_findings = findings
        record_stage(
            context,
            StageId.CREDENTIAL_SCAN,
            StageStatus.COMPLETE if eligible is not None else StageStatus.UNAVAILABLE,
            reason=(
                "inventory-scoped scan"
                if context.filesystem_inventory is not None
                else "artifact-scoped scan (no root filesystem was enumerated)"
            ),
            inspected=inspected,
            eligible=eligible,
        )

        if findings:
            critical = sum(1 for f in findings if f.severity.value == "CRITICAL")
            high = sum(1 for f in findings if f.severity.value == "HIGH")
            console.print(
                f"  [red]![/red] {critical} CRITICAL, {high} HIGH, {len(findings)} total findings"
            )
        else:
            console.print("  [green]✓[/green] No credential findings")
        return context

    def _phase_unix(self, context: ScanContext) -> ScanContext:
        """Phase 4b: Unix account records, joined by filesystem and username."""
        from iot_hardware_scanner.scanner.credential_scanner import CredentialScanner

        inventory = context.filesystem_inventory
        if inventory is None and context.input_kind is InputKind.FILE:
            record_stage(
                context,
                StageId.UNIX_ACCOUNTS,
                StageStatus.NOT_APPLICABLE,
                reason="no /etc/passwd or /etc/shadow was accessible in a single artifact",
            )
            return context

        scanner = CredentialScanner(self.config)
        findings = scanner.scan_unix_accounts(inventory, context.firmware_path)
        known = {f.raw_value_hash for f in context.credential_findings if f.raw_value_hash}
        added = [f for f in findings if not (f.raw_value_hash and f.raw_value_hash in known)]
        context.credential_findings = context.credential_findings + added

        pairs = getattr(scanner, "last_account_pairs", 0)
        record_stage(
            context,
            StageId.UNIX_ACCOUNTS,
            StageStatus.COMPLETE if pairs else StageStatus.NOT_APPLICABLE,
            reason=(
                f"{pairs} passwd/shadow pair(s) parsed"
                if pairs
                else "no account database was found in the inspected artifact"
            ),
            inspected=pairs,
            eligible=pairs,
        )
        return context

    def _phase_advisory(self, context: ScanContext) -> ScanContext:
        """Phase 5: Advisory assessment (not implemented in this release).

        The stage is recorded as SKIPPED with a reason, never as "no
        advisories": a report must not imply that an image was checked against
        an advisory source when it was not.
        """
        console.print("[bold]═══ Phase 5: Advisory ═══[/bold]")
        record_stage(
            context,
            StageId.ADVISORY,
            StageStatus.SKIPPED,
            reason=(
                "advisory assessment is not implemented in this release; "
                "advisory applicability was not assessed"
            ),
        )
        console.print(
            "  [yellow]![/yellow] Advisory assessment not implemented — applicability not assessed"
        )
        return context

    @staticmethod
    def _advisory_assessed(context: ScanContext) -> bool:
        stage = next((s for s in context.stages if s.stage_id is StageId.ADVISORY), None)
        return stage is not None and stage.status is StageStatus.COMPLETE

    def _phase_c2(self, context: ScanContext) -> ScanContext:
        """Phase 6: C2 and malicious indicator detection."""
        console.print("[bold]═══ Phase 6: C2 & Malware ═══[/bold]")
        from iot_hardware_scanner.scanner.c2_detector import C2Detector

        detector = C2Detector(self.config)
        inventory = context.filesystem_inventory

        if inventory is not None:
            findings = (
                detector.detect_domains(inventory)
                + detector.detect_ips(inventory)
                + detector.detect_malware_signatures(inventory)
            )
            record_stage(
                context,
                StageId.C2_INDICATORS,
                StageStatus.COMPLETE,
                reason="indicator sweep over the enumerated inventory",
                inspected=len(inventory.findings),
                eligible=len(inventory.findings),
            )
        else:
            findings = detector.detect_artifact(context.firmware_path)
            record_stage(
                context,
                StageId.C2_INDICATORS,
                StageStatus.COMPLETE,
                reason="artifact-scoped indicator sweep (no enumerated inventory)",
                inspected=1,
                eligible=1,
            )

        context.c2_findings = findings
        if findings:
            likely = sum(1 for f in findings if f.severity == "LIKELY_C2")
            console.print(f"  [red]![/red] {likely} LIKELY_C2, {len(findings)} total")
        else:
            console.print("  [green]✓[/green] No C2 indicators")
        return context

    def _phase_controls(self, context: ScanContext, advisory_assessed: bool) -> ScanContext:
        """Phase 7: Named checks with evidence status (no aggregate grade)."""
        from iot_hardware_scanner.scanner.risk_scorer import ControlEvaluator

        evaluator = ControlEvaluator(self.config)
        controls: list[ControlResult] = evaluator.evaluate(context, advisory_assessed)
        context.controls = controls
        record_stage(
            context,
            StageId.RISK_CONTROLS,
            StageStatus.COMPLETE,
            reason=f"{len(controls)} named checks evaluated",
            inspected=len(controls),
            eligible=len(controls),
        )
        performed = sum(1 for c in controls if c.status.value == "PERFORMED")
        console.print(f"  [green]✓[/green] {performed}/{len(controls)} checks performed")
        return context

    # ──────────────────────────────────────────
    # Reporting helpers
    # ──────────────────────────────────────────

    @staticmethod
    def _limitations(context: ScanContext) -> list[str]:
        limitations = [
            "Static analysis only: no runtime behaviour, network exposure or "
            "physical boot enforcement is established.",
        ]
        from iot_hardware_scanner import resources

        try:
            loaded = resources.describe_loaded()
        except Exception:  # pragma: no cover - packaging failure path
            loaded = []
        for entry in loaded:
            if entry.get("sample"):
                limitations.append(
                    f"data/{entry['name']} is a bundled sample "
                    f"({entry.get('sample_note')}); conclusions that depend on it "
                    "are indicative, not current."
                )
        if context.input_kind is InputKind.TREE:
            limitations.append(
                "Staged-tree metadata (ownership, permissions) is host-derived and "
                "may differ from the build's declared values."
            )
        return limitations
