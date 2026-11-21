"""Pipeline orchestrator — coordinates all scanner phases.

The Orchestrator is the single entry point for running a scan. It creates the
ScanContext, binds every later read to the bytes that were hashed, and threads
the context through each phase, recording what each stage actually did.
Completion and the process exit status are then derived by
:mod:`iot_hardware_scanner.scanner.assessment`.

Design rules this module follows:

* Every stage records a status, a reason and inspected/eligible counts. A stage
  that did not run says so; it never silently contributes zero findings.
* **A missing external backend is a dependency (exit 5). A backend that ran and
  failed is incomplete analysis (exit 4).** The distinction is carried by
  ``StageResult.dependency`` and nothing else.
* Findings already collected survive a later stage failure.
* A file input is analysed from a private read-only snapshot, never from the
  path an external build might rewrite underneath the scan.
* ``completed_at`` is set before the assessment is built and the report is
  rendered, so the saved document and the assessment agree.
* A new scan never produces an aggregate security grade.
"""

from __future__ import annotations

import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.exceptions import InputKindError, ScannerError
from iot_hardware_scanner.models import (
    EXTRACTION_UNAVAILABLE,
    ArtifactNode,
    ControlResult,
    FileCategory,
    FilesystemInventory,
    InputKind,
    ScanContext,
    StageId,
    StageStatus,
)
from iot_hardware_scanner.scanner.assessment import (
    PROFILE_CREDENTIALS,
    PROFILE_FIRMWARE,
    PROFILE_FIRMWARE_TREE,
    PROFILE_VERSION,
    build_assessment,
    record_stage,
)
from iot_hardware_scanner.scanner.firmware_ingest import FirmwareIngest
from iot_hardware_scanner.scanner.input_snapshot import (
    InputBindingError,
    bind_input,
    release_snapshot,
    reverify_source,
)

logger = logging.getLogger(__name__)
console = Console()

#: Name of the extraction backend the operator can install.
EXTRACTION_DEPENDENCY = (
    "image extraction worker (rootless podman or docker with the pinned unsquashfs image)"
)


class Orchestrator:
    """Coordinate the firmware analysis pipeline for one profile."""

    def __init__(
        self,
        config: ScannerConfig | None = None,
        creds_only: bool = False,
        profile: str | None = None,
        *,
        input_tree: bool = False,
        build_manifest: Path | None = None,
    ) -> None:
        self.config = config or ScannerConfig()
        self.input_tree = input_tree
        self.build_manifest = build_manifest
        if profile is None:
            if creds_only:
                profile = PROFILE_CREDENTIALS
            elif input_tree:
                profile = PROFILE_FIRMWARE_TREE
            else:
                profile = PROFILE_FIRMWARE
        self.profile = profile

    # ──────────────────────────────────────────
    # Entry point
    # ──────────────────────────────────────────

    def run(self, input_path: Path) -> ScanContext:
        """Execute the scan pipeline for the selected profile."""
        input_path = Path(input_path)
        if self.profile == PROFILE_FIRMWARE and input_path.is_dir():
            raise InputKindError(
                f"{input_path} is a directory. The firmware-static profile needs an "
                "image; use --input-tree for a staged root tree."
            )

        if self.profile in (PROFILE_FIRMWARE_TREE,) or (
            self.profile == PROFILE_CREDENTIALS and input_path.is_dir()
        ):
            context = self._ingest_tree(input_path)
        else:
            context = self._phase_ingest(input_path)

        context.profile = self.profile
        context.profile_version = PROFILE_VERSION

        if self.profile == PROFILE_CREDENTIALS:
            context = self._run_credentials_profile(context)
        else:
            context = self._run_firmware_profile(context)

        if context.input_snapshot is not None:
            context.input_snapshot = reverify_source(context.input_snapshot)

        context.completed_at = datetime.now(timezone.utc)
        build_assessment(context, controls=context.controls, limitations=self._limitations(context))
        return context

    # ──────────────────────────────────────────
    # Profiles
    # ──────────────────────────────────────────

    def _run_credentials_profile(self, context: ScanContext) -> ScanContext:
        if context.input_kind is InputKind.TREE:
            record_stage(
                context,
                StageId.ENUMERATION,
                StageStatus.COMPLETE,
                reason="each regular file in the staged tree was scanned as one unit",
                inspected=context.input_manifest_entries,
                eligible=context.input_manifest_entries,
            )
        elif context.input_kind is InputKind.FILE:
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
        return self._phase_controls(context, advisory_assessed=False)

    def _run_firmware_profile(self, context: ScanContext) -> ScanContext:
        if context.input_kind is InputKind.TREE:
            # No container was decoded, so extraction is not part of this
            # profile's required set. It is still recorded, because "no
            # extraction prerequisite" has to be visible, not merely absent.
            record_stage(
                context,
                StageId.EXTRACTION,
                StageStatus.NOT_APPLICABLE,
                reason="a staged tree is already an enumerable root; no container was decoded",
            )
            record_stage(
                context,
                StageId.ROOT_DISCOVERY,
                StageStatus.NOT_APPLICABLE,
                reason="the tree root is the filesystem root; no discovery was needed",
            )
            context = self._phase_tree_filesystem(context)
            record_stage(
                context,
                StageId.ENTROPY,
                StageStatus.NOT_APPLICABLE,
                reason=(
                    "a staged tree has no single byte stream; entropy is measured on an "
                    "artifact, not on a directory"
                ),
            )
        else:
            context = self._phase_extract(context)
            context = self._phase_filesystem(context)
            context = self._phase_entropy(context)

        context = self._phase_binary_intelligence(context)
        context = self._phase_opkg(context)
        context = self._phase_credentials(context)
        context = self._phase_unix(context)
        context = self._phase_advisory(context)
        context = self._phase_c2(context)
        return self._phase_controls(context, advisory_assessed=self._advisory_assessed(context))

    # ──────────────────────────────────────────
    # Phase 1: ingest and input binding
    # ──────────────────────────────────────────

    def _ingest_tree(self, tree_path: Path) -> ScanContext:
        console.print("[bold]═══ Phase 1: Ingest (staged tree) ═══[/bold]")
        ingest = FirmwareIngest(self.config)
        context = ingest.ingest_tree(tree_path, build_manifest=self.build_manifest)
        record_stage(
            context,
            StageId.INGEST,
            StageStatus.COMPLETE if not context.tree_changes else StageStatus.PARTIAL,
            reason=(
                "deterministic per-entry manifest; metadata is host-derived "
                "unless a build manifest declares it"
                if not context.tree_changes
                else "the tree changed while it was being catalogued"
            ),
            inspected=context.input_manifest_entries,
            eligible=context.input_manifest_entries,
            omissions=list(context.tree_changes),
        )
        declared = context.declared_manifest
        console.print(
            f"  [green]✓[/green] {context.input_manifest_entries} file(s), "
            f"tree digest {context.file_hash_sha256[:16]}…"
            + (f", {declared.entry_count} declared entr(ies)" if declared else "")
        )
        return context

    def _phase_ingest(self, input_path: Path) -> ScanContext:
        """Phase 1: artifact ingestion, then binding to a private snapshot."""
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

        from iot_hardware_scanner import faults

        if faults.enabled(faults.FAULT_REPLACE_INPUT):
            faults.replace_input(context.firmware_path, "replaced after ingest")
            console.print("  [yellow]![/yellow] injected fault: input replaced after ingest")

        # Slice 2D: every later read is bound to these bytes.
        try:
            context.input_snapshot = bind_input(
                context.firmware_path,
                context.output_dir / "input",
                declared_sha256=context.file_hash_sha256,
                budget_bytes=self.config.snapshot_budget_mb * 1024 * 1024,
            )
        except InputBindingError as exc:
            # The scan is marked incomplete and stops here: the bytes that were
            # hashed are not the bytes on disk, so nothing may be attributed to
            # the recorded digest.
            context.input_binding_error = str(exc)
            record_stage(
                context,
                StageId.INGEST,
                StageStatus.FAILED,
                reason=f"input could not be bound to a verified snapshot: {exc}",
                inspected=1,
                eligible=1,
                omissions=["no analysis was performed on unverified bytes"],
            )
            console.print(f"  [red]✗[/red] {exc}")
            return context
        if faults.enabled(faults.FAULT_REPLACE_AFTER_BIND):
            faults.replace_input(context.firmware_path, "replaced after binding")
            console.print("  [yellow]![/yellow] injected fault: input replaced after binding")

        console.print(
            "  [green]✓[/green] Bound to private snapshot "
            f"{context.input_snapshot.snapshot_path.name}"
        )
        return context

    @staticmethod
    def _read_path(context: ScanContext) -> Path:
        """The bytes every later stage reads: the verified snapshot if present."""
        if context.input_snapshot is not None:
            return context.input_snapshot.snapshot_path
        return context.firmware_path

    # ──────────────────────────────────────────
    # Phase 2a: extraction and the image map
    # ──────────────────────────────────────────

    def _phase_extract(self, context: ScanContext) -> ScanContext:
        """Phase 2a: decode the wrapper, validate the filesystem, run the worker."""
        console.print("[bold]═══ Phase 2: Extraction ═══[/bold]")
        from iot_hardware_scanner.scanner.extraction_worker import (
            ExtractionError,
            SquashfsWorker,
        )
        from iot_hardware_scanner.scanner.image_map import ImageMapBuilder, ImageMapError

        if context.input_binding_error:
            record_stage(
                context,
                StageId.EXTRACTION,
                StageStatus.UNAVAILABLE,
                reason=(
                    "no analysis was performed: the input could not be bound to the bytes "
                    "that were hashed at ingest"
                ),
                omissions=["filesystem never enumerated"],
            )
            record_stage(
                context,
                StageId.ROOT_DISCOVERY,
                StageStatus.UNAVAILABLE,
                reason="extraction did not run because the input was not bound",
            )
            console.print("  [yellow]![/yellow] Extraction skipped: input not bound")
            return context

        scratch = context.output_dir / "scratch"
        source = self._read_path(context)
        builder = ImageMapBuilder()
        reader = None
        try:
            from iot_hardware_scanner.scanner.bounded_reader import open_bounded

            reader = open_bounded(source)
            image_map = builder.start(reader, context.file_hash_sha256, context.firmware_name)
            context.image_map = image_map

            if image_map.nodes[0].format == "gzip":
                decoded = scratch / "decoded" / "root.squashfs"
                _path, child = builder.decompress_gzip(
                    reader,
                    decoded,
                    max_decoded_bytes=self.config.max_decoded_bytes_mb * 1024 * 1024,
                )
                console.print(
                    f"  [green]✓[/green] gzip wrapper: {reader.size:,} bytes on the wire -> "
                    f"{child.expanded_bytes:,} decoded bytes"
                )
                console.print(
                    f"  [green]✓[/green] {child.format} v{child.details['superblock']['version']} "
                    f"declares {child.extent_bytes:,} bytes used "
                    f"({child.details['superblock']['compression']})"
                )
                squashfs_path = decoded
                parent_id = child.artifact_id
            else:
                # An unwrapped image: validate the superblock where it starts.
                superblock = builder.parse_squashfs(reader)
                node = image_map.add(
                    ArtifactNode(
                        artifact_id="a1",
                        parent_id=image_map.root_artifact_id,
                        digest_sha256=context.file_hash_sha256,
                        format="squashfs",
                        coordinate_system="container-bytes",
                        offset=superblock.offset,
                        length=superblock.bytes_used,
                        decoder="unsquashfs",
                        depth=1,
                        locator=context.firmware_name,
                        extent_bytes=superblock.bytes_used,
                        details={"superblock": superblock.as_dict()},
                    )
                )
                squashfs_path = source
                parent_id = node.artifact_id
                console.print(
                    f"  [green]✓[/green] {superblock.magic} v{superblock.version_major}."
                    f"{superblock.version_minor} at offset {superblock.offset}, "
                    f"{superblock.bytes_used:,} bytes used"
                )
        except ImageMapError as exc:
            record_stage(
                context,
                StageId.EXTRACTION,
                StageStatus.FAILED,
                reason=f"the input container is not decodable: {exc}",
                omissions=["filesystem never enumerated"],
            )
            record_stage(
                context,
                StageId.ROOT_DISCOVERY,
                StageStatus.UNAVAILABLE,
                reason="the container was rejected before a filesystem was reached",
            )
            console.print(f"  [red]✗[/red] {exc}")
            return context
        finally:
            del reader

        worker = SquashfsWorker(self.config)
        try:
            result = worker.extract(squashfs_path, scratch / "extract")
        except ExtractionError as exc:
            if exc.state == EXTRACTION_UNAVAILABLE:
                record_stage(
                    context,
                    StageId.EXTRACTION,
                    StageStatus.UNAVAILABLE,
                    reason=exc.message,
                    dependency=EXTRACTION_DEPENDENCY,
                    omissions=["filesystem never enumerated"],
                )
                record_stage(
                    context,
                    StageId.ROOT_DISCOVERY,
                    StageStatus.UNAVAILABLE,
                    reason="no extraction backend, so no root filesystem was reached",
                )
                console.print(f"  [yellow]![/yellow] Extraction unavailable — {exc.message}")
                return context
            record_stage(
                context,
                StageId.EXTRACTION,
                StageStatus.FAILED,
                reason=exc.message,
                omissions=["filesystem never enumerated"],
            )
            record_stage(
                context,
                StageId.ROOT_DISCOVERY,
                StageStatus.UNAVAILABLE,
                reason="extraction failed, so no root filesystem was reached",
            )
            console.print(f"  [yellow]![/yellow] Extraction failed ({exc.state}): {exc.message}")
            return context

        context.extraction_result = result
        context.extraction_provenance = result.provenance
        if result.provenance is not None:
            image_map.nodes[-1].decoder_version = result.provenance.helper_version

        if not result.success or not result.root_filesystems:
            detail = "; ".join(result.extraction_errors) or "no root filesystem was produced"
            if result.state == EXTRACTION_UNAVAILABLE:
                # A backend the operator could install: exit 5, not 4.
                record_stage(
                    context,
                    StageId.EXTRACTION,
                    StageStatus.UNAVAILABLE,
                    reason=detail,
                    dependency=EXTRACTION_DEPENDENCY,
                    omissions=["filesystem never enumerated"],
                )
                record_stage(
                    context,
                    StageId.ROOT_DISCOVERY,
                    StageStatus.UNAVAILABLE,
                    reason="no extraction backend, so no root filesystem was reached",
                )
                console.print(f"  [yellow]![/yellow] Extraction unavailable — {detail}")
                return context
            record_stage(
                context,
                StageId.EXTRACTION,
                StageStatus.FAILED,
                reason=f"{result.state}: {detail}",
                omissions=["filesystem never enumerated"],
            )
            record_stage(
                context,
                StageId.ROOT_DISCOVERY,
                StageStatus.UNAVAILABLE,
                reason="extraction produced no accessible root filesystem",
            )
            console.print(f"  [red]✗[/red] Extraction failed — {detail}")
            return context

        context.extracted_rootfs = result.root_filesystems[0]
        record_stage(
            context,
            StageId.EXTRACTION,
            StageStatus.COMPLETE,
            reason=(
                f"{result.backend} worker"
                + (f" {result.backend_version}" if result.backend_version else "")
                + (
                    f", image {result.worker_digest[:19]}…"
                    if result.worker_digest
                    else ", image unpinned"
                )
            ),
            inspected=result.file_count,
            eligible=result.file_count,
            omissions=list(result.omissions),
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
            f"{len(result.root_filesystems)} root(s), {result.total_size:,} bytes)"
        )
        context.image_rootfs_artifact_id = parent_id
        return context

    # ──────────────────────────────────────────
    # Phase 2b: enumeration
    # ──────────────────────────────────────────

    def _phase_filesystem(self, context: ScanContext) -> ScanContext:
        """Phase 2b: bounded enumeration with image-derived metadata."""
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

        from iot_hardware_scanner.scanner.filesystem_scanner import FilesystemScanner

        scanner = FilesystemScanner(self.config)
        roots = (
            context.extraction_result.root_filesystems
            if context.extraction_result
            else [context.extracted_rootfs]
        )
        metadata = _extract_manifest_metadata(context.extraction_result)

        merged = FilesystemInventory(
            rootfs_path=context.extracted_rootfs,
            findings=[],
            categories={cat: [] for cat in FileCategory},
            metadata_source="image" if metadata else "host",
        )
        for index, rootfs in enumerate(roots):
            inventory = scanner.scan(
                rootfs,
                root_id=f"rootfs{index + 1}" if len(roots) > 1 else "rootfs",
                metadata=metadata,
                metadata_source="image" if metadata else "host",
            )
            _merge_inventory(merged, inventory)
            merged.boot_evidence.extend(
                scanner.collect_boot_evidence(
                    rootfs, root_id=f"rootfs{index + 1}" if len(roots) > 1 else "rootfs"
                )
            )

        context.filesystem_inventory = merged
        self._record_enumeration(context, merged)
        return context

    def _phase_tree_filesystem(self, context: ScanContext) -> ScanContext:
        """Phase 2b for a staged tree: enumerate the tree directly."""
        console.print("[bold]═══ Phase 2b: Filesystem (staged tree) ═══[/bold]")
        from iot_hardware_scanner.scanner.filesystem_scanner import FilesystemScanner

        scanner = FilesystemScanner(self.config)
        metadata, source = _tree_metadata(context)
        inventory = scanner.scan(
            context.firmware_path,
            root_id="tree",
            metadata=metadata,
            metadata_source=source,
            artifact_id=context.image_map.root_artifact_id if context.image_map else None,
        )
        inventory.boot_evidence = scanner.collect_boot_evidence(
            context.firmware_path, root_id="tree"
        )
        context.filesystem_inventory = inventory
        self._record_enumeration(context, inventory)
        return context

    def _record_enumeration(self, context: ScanContext, merged: FilesystemInventory) -> None:
        record_stage(
            context,
            StageId.ENUMERATION,
            StageStatus.COMPLETE,
            reason=(f"{len(merged.roots)} root(s); metadata from {merged.metadata_source}"),
            inspected=merged.total_files,
            eligible=merged.total_files,
            omissions=list(
                dict.fromkeys(omission for root in merged.roots for omission in root.omissions)
            ),
        )
        record_stage(
            context,
            StageId.SERVICE_ANALYSIS,
            StageStatus.COMPLETE,
            reason=(
                f"{len(merged.boot_evidence)} configured startup directive(s) parsed from "
                "inittab, init.d and rc.local"
            ),
            inspected=len(merged.roots),
            eligible=len(merged.roots),
        )
        console.print(
            f"  [green]✓[/green] {merged.total_files} files, {merged.total_directories} "
            f"directories ({len(merged.roots)} root(s), metadata from {merged.metadata_source})"
        )

    # ──────────────────────────────────────────
    # Phase 3a: entropy
    # ──────────────────────────────────────────

    def _phase_entropy(self, context: ScanContext) -> ScanContext:
        """Phase 3a: byte-distribution measurement over the bound bytes."""
        console.print("[bold]═══ Phase 3: Entropy ═══[/bold]")
        try:
            from iot_hardware_scanner.scanner.entropy_analyzer import EntropyAnalyzer

            analyzer = EntropyAnalyzer(self.config)
            profile = analyzer.analyze_file(self._read_path(context))
            context.entropy_profile = profile
        except (ScannerError, ValueError) as exc:
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
            f"  [green]✓[/green] {profile.overall_entropy:.4f} bits/byte over "
            f"{profile.bytes_analyzed:,} bytes ({scope})"
        )
        return context

    # ──────────────────────────────────────────
    # Phase 3b: ELF metadata
    # ──────────────────────────────────────────

    def _phase_binary_intelligence(self, context: ScanContext) -> ScanContext:
        """Phase 3b: ELF metadata from the files' own structures."""
        console.print("[bold]═══ Phase 3b: Binary Intelligence ═══[/bold]")
        from iot_hardware_scanner.scanner.binary_intelligence import BinaryIntelligence

        inventory = context.filesystem_inventory
        eligible = (
            sum(1 for finding in inventory.findings if finding.format == "elf")
            if inventory is not None
            else 1
        )

        bi = BinaryIntelligence(self.config)
        try:
            result = bi.analyze(context)
        except Exception as exc:  # stage isolation is deliberate
            record_stage(context, StageId.BINARY_INVENTORY, StageStatus.FAILED, reason=str(exc))
            record_stage(context, StageId.ELF_METADATA, StageStatus.FAILED, reason=str(exc))
            logger.warning("Binary intelligence failed: %s", exc)
            return context

        context.binary_intelligence = result
        inventory_status = (
            StageStatus.COMPLETE if inventory is not None else StageStatus.UNAVAILABLE
        )
        record_stage(
            context,
            StageId.BINARY_INVENTORY,
            inventory_status,
            reason=(
                "binaries selected from header signatures in the enumerated inventory"
                if inventory is not None
                else "no enumerated inventory; binaries were never selected"
            ),
            inspected=result.total_binaries,
            eligible=eligible,
        )
        if result.rejected:
            elf_status = StageStatus.PARTIAL if result.total_binaries else StageStatus.FAILED
            elf_reason = f"{len(result.rejected)} of {eligible} ELF file(s) could not be parsed"
        else:
            elf_status = (
                StageStatus.COMPLETE if inventory is not None else StageStatus.NOT_APPLICABLE
            )
            elf_reason = (
                f"{len(context.elf_metadata)} ELF file(s) parsed from their own headers"
                if inventory is not None
                else "no filesystem was enumerated, so no ELF population exists"
            )
        record_stage(
            context,
            StageId.ELF_METADATA,
            elf_status,
            reason=elf_reason,
            inspected=len(context.elf_metadata),
            eligible=eligible if inventory is not None else None,
            omissions=[f"{item['path']}: {item['reason']}" for item in result.rejected],
        )
        console.print(
            f"  [green]✓[/green] {result.total_binaries} ELF file(s) parsed, "
            f"{result.hardened_binaries} with hardening evidence"
        )
        return context

    # ──────────────────────────────────────────
    # Phase 3c: installed packages
    # ──────────────────────────────────────────

    def _phase_opkg(self, context: ScanContext) -> ScanContext:
        """Phase 3c: read the installed-package database verbatim."""
        console.print("[bold]═══ Phase 3c: Package inventory ═══[/bold]")
        from iot_hardware_scanner.scanner.opkg_inventory import read_opkg_status

        inventory = context.filesystem_inventory
        if inventory is None:
            record_stage(
                context,
                StageId.OPKG_INVENTORY,
                StageStatus.NOT_APPLICABLE,
                reason="no filesystem was enumerated, so there was no package database to read",
            )
            return context

        candidates = [
            finding
            for finding in inventory.findings
            if str(finding.path).endswith("usr/lib/opkg/status")
            or str(finding.path).endswith("var/lib/opkg/status")
        ]
        if not candidates:
            record_stage(
                context,
                StageId.OPKG_INVENTORY,
                StageStatus.NOT_APPLICABLE,
                reason=(
                    "the enumerated filesystem contains no opkg status database; this is "
                    "not an OpenWrt-style image, or the database is elsewhere"
                ),
            )
            console.print("  [yellow]![/yellow] No opkg database in this filesystem")
            return context

        finding = sorted(candidates, key=lambda f: str(f.path))[0]
        locator = str(finding.path)
        try:
            parsed = read_opkg_status(
                finding.absolute_path,
                locator=locator,
                budget=self.config.max_scan_file_size_mb * 1024 * 1024,
            )
        except (OSError, ValueError) as exc:
            record_stage(
                context,
                StageId.OPKG_INVENTORY,
                StageStatus.FAILED,
                reason=f"{locator} could not be parsed: {exc}",
            )
            console.print(f"  [red]✗[/red] {exc}")
            return context

        context.opkg_inventory = parsed
        context.software_components = _package_components(parsed, finding)
        record_stage(
            context,
            StageId.OPKG_INVENTORY,
            StageStatus.COMPLETE,
            reason=f"{parsed.installed_count} installed record(s) read from {locator}",
            inspected=parsed.installed_count,
            eligible=parsed.installed_count,
            omissions=(
                [f"{parsed.unparsed_stanzas} stanza(s) had no Package field"]
                if parsed.unparsed_stanzas
                else []
            ),
        )
        console.print(
            f"  [green]✓[/green] {parsed.installed_count} installed package(s), "
            f"{parsed.held_count} held"
        )
        return context

    # ──────────────────────────────────────────
    # Phase 4: detectors
    # ──────────────────────────────────────────

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

        artifacts_scanned = 0
        if context.filesystem_inventory is not None:
            eligible = sum(
                len(context.filesystem_inventory.categories.get(cat, []))
                for cat in scanned_categories
            )
            findings = scanner.scan_inventory(context.filesystem_inventory)
            inspected = eligible
        else:
            findings = scanner.scan_artifact(self._read_path(context), context.input_kind)
            inspected = 1
            eligible = 1
            artifacts_scanned = 1

        context.credential_findings = findings
        record_stage(
            context,
            StageId.CREDENTIAL_SCAN,
            StageStatus.COMPLETE,
            reason=(
                "inventory-scoped scan"
                if context.filesystem_inventory is not None
                else f"artifact-scoped bound read ({artifacts_scanned} artifact unit)"
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
        """Phase 4b: Unix account records, joined by root ID and username."""
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
                f"{pairs} passwd/shadow pair(s) parsed and joined"
                if pairs
                else "no account database was found in the inspected artifact"
            ),
            inspected=pairs,
            eligible=pairs,
        )
        return context

    def _phase_advisory(self, context: ScanContext) -> ScanContext:
        """Phase 5: Advisory assessment (not implemented in this release)."""
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
            findings = detector.detect_artifact(self._read_path(context))
            record_stage(
                context,
                StageId.C2_INDICATORS,
                StageStatus.COMPLETE,
                reason="artifact-scoped indicator sweep over bounded windows",
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

    def _limitations(self, context: ScanContext) -> list[str]:
        limitations = [
            "Static analysis only: no runtime behaviour, network exposure or "
            "physical boot enforcement is established.",
            "Installed-package records describe the package database; they do not "
            "prove every package-owned file is present or intact.",
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
            metadata_source = (
                context.filesystem_inventory.metadata_source
                if context.filesystem_inventory
                else "host"
            )
            limitations.append(
                f"Staged-tree metadata (ownership, permissions) is {metadata_source}-derived"
                + (
                    " and may differ from the build's declared values."
                    if metadata_source == "host"
                    else " and is taken from the supplied build manifest."
                )
            )
        if context.input_snapshot is not None:
            limitations.append(
                "All analysis reads came from a private read-only snapshot of the input, "
                "verified against the digest recorded at ingest."
            )
            if context.input_snapshot.source_changed:
                limitations.append(
                    "The input path changed after ingest; the snapshot that was analysed "
                    "still holds the digest recorded in this report."
                )
        if context.tree_changes:
            limitations.append(
                "The staged tree changed while it was being catalogued: "
                + "; ".join(context.tree_changes)
            )
        if context.extraction_provenance is not None:
            limits = context.extraction_provenance.limits
            limitations.append(
                "Extraction ran in a "
                f"{context.extraction_provenance.isolation} worker "
                f"({context.extraction_provenance.worker}"
                + (
                    f" image {context.extraction_provenance.worker_digest}"
                    if context.extraction_provenance.worker_digest
                    else ""
                )
                + f"); budgets: {limits.get('max_decoded_bytes')} decoded bytes, "
                f"{limits.get('max_extracted_bytes')} extracted bytes, "
                f"{limits.get('max_entries')} entries, {limits.get('timeout_seconds')}s."
            )
        return limitations


# ──────────────────────────────────────────────
# Inventory helpers
# ──────────────────────────────────────────────


def _merge_inventory(merged: FilesystemInventory, inventory: FilesystemInventory) -> None:
    """Fold one root's inventory into the scan-wide one without losing identity."""
    merged.total_files += inventory.total_files
    merged.total_directories += inventory.total_directories
    merged.total_size += inventory.total_size
    merged.permission_unknown_count += inventory.permission_unknown_count
    merged.findings.extend(inventory.findings)
    merged.roots.extend(inventory.roots)
    for category, items in inventory.categories.items():
        merged.categories.setdefault(category, []).extend(items)
    merged.suid_binaries.extend(inventory.suid_binaries)
    merged.world_writable_files.extend(inventory.world_writable_files)
    merged.shadow_files.extend(inventory.shadow_files)
    merged.ssl_cert_files.extend(inventory.ssl_cert_files)
    merged.init_scripts.extend(inventory.init_scripts)
    merged.network_services.extend(inventory.network_services)


def _extract_manifest_metadata(
    result: object | None,
) -> dict[str, dict]:
    """Read the extractor's manifest so file metadata comes from the image."""
    if result is None:
        return {}
    scratch = getattr(result, "extraction_dir", None)
    if scratch is None:
        return {}
    manifest = Path(scratch) / "extract-manifest.json"
    if not manifest.is_file():
        return {}
    import json

    try:
        payload = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError):  # pragma: no cover - extractor writes it
        return {}
    entries = payload.get("entries") or []
    return {
        str(entry["path"]): entry
        for entry in entries
        if isinstance(entry, dict) and entry.get("path")
    }


def _tree_metadata(context: ScanContext) -> tuple[dict[str, dict], str]:
    """Metadata for a staged tree: declared if a manifest supplied it, else host."""
    declared = context.declared_manifest
    if declared is None:
        return {}, "host"
    entries: dict[str, dict] = {}
    for path, values in declared.entries.items():
        entries[path] = {**values, "kind": values.get("kind", "file")}
    return entries, "declared"


def _package_components(parsed: object, finding: object) -> list:
    """Installed packages as component records, with their evidence range."""
    from iot_hardware_scanner.intelligence.cpe_builder import cpe_name, lookup
    from iot_hardware_scanner.models import SoftwareComponent

    components: list[SoftwareComponent] = []
    for record in getattr(parsed, "records", []):
        if not record.installed:
            continue
        mapping = lookup(record.name)
        if mapping is None:
            continue
        vendor, product = mapping
        components.append(
            SoftwareComponent(
                vendor=vendor,
                product=product,
                version=record.version,
                cpe_string=cpe_name(vendor, product, record.version),
                source_file=Path(getattr(finding, "path", "usr/lib/opkg/status")),
                source_method="opkg_status",
                architecture=record.architecture or None,
                evidence=(
                    f"{parsed_locator(parsed)}:{record.evidence_start}-{record.evidence_end} "
                    f"(line {record.evidence_line})"
                ),
                digest_sha256=getattr(parsed, "database_sha256", ""),
                confidence="recorded",
                occurrences=[
                    f"{parsed_locator(parsed)}:{record.evidence_start}-{record.evidence_end}"
                ],
            )
        )
    return components


def parsed_locator(parsed: object) -> str:
    """Locator of a parsed package database."""
    return str(getattr(parsed, "locator", "usr/lib/opkg/status"))


def cleanup_scratch(context: ScanContext, *, keep: bool = False) -> None:
    """Release the transient copies a scan made, unless the operator keeps them.

    The decoded wrapper (a second copy of an already-large payload) and the
    private input snapshot are deleted; the extracted filesystem is kept,
    because it is the evidence the report describes and it lives in the
    operator's own output directory.
    """
    if keep:
        return
    decoded = context.output_dir / "scratch" / "decoded"
    if decoded.exists():
        shutil.rmtree(decoded, ignore_errors=True)
    if context.input_snapshot is not None:
        release_snapshot(context.input_snapshot)
