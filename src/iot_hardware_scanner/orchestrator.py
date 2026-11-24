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
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.exceptions import InputKindError, ScannerError
from iot_hardware_scanner.models import (
    EXTRACTION_CORRUPT,
    EXTRACTION_OK,
    EXTRACTION_UNAVAILABLE,
    ArtifactNode,
    BootAnalysis,
    ControlResult,
    ExtractionProvenance,
    ExtractionResult,
    FileCategory,
    FilesystemInventory,
    ImageMap,
    InputKind,
    McuAnalysis,
    ScanContext,
    StageId,
    StageStatus,
)
from iot_hardware_scanner.scanner.analysis_cache import AnalysisCache
from iot_hardware_scanner.scanner.assessment import (
    PROFILE_BOOT,
    PROFILE_CREDENTIALS,
    PROFILE_FIRMWARE,
    PROFILE_FIRMWARE_TREE,
    PROFILE_MCU,
    PROFILE_VERSION,
    build_assessment,
    record_stage,
)
from iot_hardware_scanner.scanner.bounded_reader import open_bounded
from iot_hardware_scanner.scanner.firmware_ingest import FirmwareIngest
from iot_hardware_scanner.scanner.fit_dtb import (
    FitDtbError,
    TrustAnchor,
    TrustAnchorError,
    analyse_boot,
    load_trust_anchor,
    looks_like_fdt,
)
from iot_hardware_scanner.scanner.input_snapshot import (
    InputBindingError,
    bind_input,
    release_snapshot,
    reverify_source,
)
from iot_hardware_scanner.scanner.mcu_image import (
    McuFormatError,
    analyse_mcu,
    format_hint,
    identify_mcu_format,
)
from iot_hardware_scanner.yara.yara_engine import YaraEngine

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
        advisory_snapshot: Path | None = None,
        trust_anchors: list[Path] | None = None,
    ) -> None:
        self.config = config or ScannerConfig()
        self.input_tree = input_tree
        #: The one compiled rule set this run uses. Built on first need and
        #: shared by every detector, so the rule set is compiled once and the
        #: report carries one digest.
        self._rule_engine: YaraEngine | None = None
        self.build_manifest = build_manifest
        #: A local advisory snapshot makes advisory assessment a requested stage
        #: for this run. None keeps it unassessed, which the report states.
        self.advisory_snapshot = advisory_snapshot or (
            self.config.advisory_snapshot if config is not None else None
        )
        #: Operator-supplied trust anchors (slice 3D). Never read from inside
        #: the artifact: an embedded key is not a trust decision.
        self.trust_anchor_paths = list(trust_anchors or [])
        if profile is None:
            if creds_only:
                profile = PROFILE_CREDENTIALS
            elif input_tree:
                profile = PROFILE_FIRMWARE_TREE
            else:
                profile = PROFILE_FIRMWARE
        self.profile = profile
        #: Slice 5C: an optional content-addressed cache of deterministic
        #: parser outputs. One instance is shared by every consumer so the
        #: report carries one set of hit/miss counts.
        self._analysis_cache: AnalysisCache | None = (
            AnalysisCache(
                self.config.analysis_cache_dir,
                max_entries=self.config.analysis_cache_max_entries,
                max_bytes=self.config.analysis_cache_max_mb * 1024 * 1024,
            )
            if self.config.analysis_cache_dir is not None
            else None
        )

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

        # Slice 3D: an FDT/FIT is not a root filesystem. Recognise it by its
        # own magic and select the profile that means what it says, rather than
        # running the firmware profile and failing at extraction.
        if self.profile == PROFILE_BOOT and context.input_kind is InputKind.FILE:
            context.input_kind = InputKind.BOOT
        elif self.profile == PROFILE_MCU and context.input_kind is InputKind.FILE:
            context.input_kind = InputKind.MCU
        elif (
            self.profile == PROFILE_FIRMWARE
            and context.input_kind is InputKind.FILE
            and context.input_binding_error is None
        ):
            head = open_bounded(self._read_path(context)).read_head(4096)
            if looks_like_fdt(head):
                self.profile = PROFILE_BOOT
                context.input_kind = InputKind.BOOT
                console.print(
                    "  [green]✓[/green] Recognised a flattened device tree or FIT; "
                    "selected the firmware-boot profile"
                )
            elif identify_mcu_format(head):
                # A bare-metal encoding is not a SquashFS image: selecting the
                # profile that means what it says beats failing at extraction.
                self.profile = PROFILE_MCU
                context.input_kind = InputKind.MCU
                console.print(
                    "  [green]✓[/green] Recognised a bare-metal image "
                    f"({identify_mcu_format(head)}); selected the firmware-mcu profile"
                )

        context.profile = self.profile
        context.profile_version = PROFILE_VERSION

        self._phase_rules(context)

        if self.profile == PROFILE_CREDENTIALS:
            context = self._run_credentials_profile(context)
        elif self.profile == PROFILE_BOOT:
            context = self._run_boot_profile(context)
        elif self.profile == PROFILE_MCU:
            context = self._run_mcu_profile(context)
        else:
            context = self._run_firmware_profile(context)

        if context.input_snapshot is not None:
            context.input_snapshot = reverify_source(context.input_snapshot)

        if self._analysis_cache is not None:
            context.cache_summary = self._analysis_cache.summary()

        context.completed_at = datetime.now(timezone.utc)
        build_assessment(
            context,
            controls=context.controls,
            limitations=self._limitations(context),
            extra_required=(StageId.ADVISORY,) if self.advisory_snapshot else (),
        )
        return context

    # ──────────────────────────────────────────
    # Phase 0: the rule set (once per run)
    # ──────────────────────────────────────────

    def _phase_rules(self, context: ScanContext) -> ScanContext:
        """Compile the packaged rules and any explicit additions, once."""
        console.print("[bold]═══ Phase 0: Rule set ═══[/bold]")
        try:
            engine = self.rule_engine()
        except Exception as exc:  # a broken rule install must not crash the scan
            record_stage(
                context,
                StageId.RULE_COMPILATION,
                StageStatus.FAILED,
                reason=f"the packaged rule set could not be compiled: {exc}",
                omissions=["credential, service, crypto and indicator rules never ran"],
            )
            console.print(f"  [red]✗[/red] Rule set unusable: {exc}")
            return context

        context.ruleset = engine.info
        errors = engine.diagnostics
        if not engine.is_available:
            record_stage(
                context,
                StageId.RULE_COMPILATION,
                StageStatus.UNAVAILABLE,
                reason="yara-python is not importable, so the packaged rules could not run",
                dependency="yara-python (the rule engine)",
                omissions=["credential, service, crypto and indicator rules never ran"],
            )
            console.print("  [yellow]![/yellow] No rule engine — rule-based stages cannot run")
            return context

        record_stage(
            context,
            StageId.RULE_COMPILATION,
            StageStatus.PARTIAL if errors else StageStatus.COMPLETE,
            reason=(
                f"{engine.rule_count} rule file(s) compiled from the "
                f"{engine.info.source.replace('+', ' + ')}; digest {engine.digest[:16]}…"
            ),
            inspected=engine.rule_count,
            eligible=engine.rule_count + len(errors),
            omissions=[f"{item['file']}: {item['reason']}" for item in errors],
        )
        console.print(
            f"  [green]✓[/green] {engine.rule_count} rule file(s) compiled "
            f"(digest {engine.digest[:16]}…)"
        )
        for item in errors:
            console.print(f"  [yellow]![/yellow] {item['file']}: {item['reason']}")
        return context

    def rule_engine(self) -> YaraEngine:
        """The shared, compiled rule set for this run."""
        if self._rule_engine is None:
            engine = YaraEngine(self.config, cache=self._analysis_cache)
            engine.load_rules()
            self._rule_engine = engine
        return self._rule_engine

    # ──────────────────────────────────────────
    # Profiles
    # ──────────────────────────────────────────

    # ──────────────────────────────────────
    # Stage isolation
    # ──────────────────────────────────────

    def _guarded(
        self,
        context: ScanContext,
        label: str,
        stages: tuple[StageId, ...],
        phase: Callable[[ScanContext], ScanContext],
    ) -> ScanContext:
        """Run one phase so an unexpected parser bug is incomplete work, not a crash.

        Untrusted bytes are parsed in-process. A ``struct.error``, an
        ``AttributeError`` from an odd member, a decoder bug — none of those is
        a documented exit status, and a traceback is not a report. The phase's
        stages are recorded FAILED with the exception type and message, the
        findings already collected survive, and the assessment becomes
        INCOMPLETE (exit 4). ``logger.exception`` keeps the traceback in the log
        for the engineer; it never reaches the operator's terminal or the JSON.

        ``ScannerError`` is re-raised unchanged: those exceptions already carry
        the documented exit code and must not be flattened into exit 4.
        """
        try:
            return phase(context)
        except ScannerError:
            raise
        except Exception as exc:
            logger.exception("%s raised an unexpected exception", label)
            reason = f"{label} hit an unexpected error: {type(exc).__name__}: {exc}"
            for stage in stages:
                record_stage(context, stage, StageStatus.FAILED, reason=reason)
            console.print(f"  [red]✗[/red] {reason}")
            return context

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
        context = self._guarded(
            context, "credentials", (StageId.CREDENTIAL_SCAN,), self._phase_credentials
        )
        context = self._guarded(
            context, "account records", (StageId.UNIX_ACCOUNTS,), self._phase_unix
        )
        return self._guarded(
            context,
            "named checks",
            (StageId.RISK_CONTROLS,),
            lambda current: self._phase_controls(current, advisory_assessed=False),
        )

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
            context = self._guarded(
                context,
                "filesystem enumeration",
                (StageId.ENUMERATION, StageId.SERVICE_ANALYSIS),
                self._phase_tree_filesystem,
            )
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
            context = self._guarded(
                context,
                "extraction",
                (StageId.EXTRACTION, StageId.ROOT_DISCOVERY),
                self._phase_extract,
            )
            context = self._guarded(
                context,
                "filesystem enumeration",
                (StageId.ENUMERATION, StageId.SERVICE_ANALYSIS),
                self._phase_filesystem,
            )
            context = self._guarded(context, "entropy", (StageId.ENTROPY,), self._phase_entropy)

        context = self._guarded(
            context,
            "binary inventory",
            (StageId.BINARY_INVENTORY, StageId.ELF_METADATA),
            self._phase_binary_intelligence,
        )
        context = self._guarded(
            context, "package database", (StageId.OPKG_INVENTORY,), self._phase_opkg
        )
        context = self._guarded(
            context, "credentials", (StageId.CREDENTIAL_SCAN,), self._phase_credentials
        )
        context = self._guarded(
            context, "account records", (StageId.UNIX_ACCOUNTS,), self._phase_unix
        )
        context = self._guarded(
            context, "advisory snapshot", (StageId.ADVISORY,), self._phase_advisory
        )
        context = self._guarded(
            context, "indicator sweep", (StageId.C2_INDICATORS,), self._phase_c2
        )
        return self._guarded(
            context,
            "named checks",
            (StageId.RISK_CONTROLS,),
            lambda current: self._phase_controls(
                current, advisory_assessed=self._advisory_assessed(current)
            ),
        )

    def _run_mcu_profile(self, context: ScanContext) -> ScanContext:
        """The bare-metal profile: an address map, not a filesystem."""
        for stage_id, reason in (
            (
                StageId.EXTRACTION,
                "a bare-metal encoding is a flat record stream; there is no container to decode",
            ),
            (
                StageId.ROOT_DISCOVERY,
                "a bare-metal image has no filesystem root; its bytes are addressed directly",
            ),
            (
                StageId.ENUMERATION,
                "there is no directory tree to enumerate; the address map is the coordinate system",
            ),
            (
                StageId.ENTROPY,
                "byte distribution is measured per decoded range inside mcu_analysis "
                "and is not a second pass over the file",
            ),
            (
                StageId.BINARY_INVENTORY,
                "a bare-metal payload has no ELF inventory; it is decoded as an address "
                "map instead",
            ),
            (
                StageId.ELF_METADATA,
                "no ELF structure is claimed for a bare-metal payload",
            ),
            (
                StageId.OPKG_INVENTORY,
                "a bare-metal image carries no package database",
            ),
            (
                StageId.CREDENTIAL_SCAN,
                "the compiled rule set is swept over the decoded payload in "
                "mcu_analysis; there are no files to read and no account databases to join",
            ),
            (
                StageId.UNIX_ACCOUNTS,
                "a bare-metal image carries no /etc/passwd or /etc/shadow",
            ),
            (
                StageId.SERVICE_ANALYSIS,
                "there is no init system to read; a start address is a declared "
                "intention, not a configured service",
            ),
            (
                StageId.C2_INDICATORS,
                "the indicator sweep runs over the decoded payload inside mcu_analysis, "
                "not over a filesystem",
            ),
            (
                StageId.ADVISORY,
                "a bare-metal image names no installed component to look up",
            ),
        ):
            record_stage(
                context,
                stage_id,
                StageStatus.NOT_APPLICABLE,
                reason=reason,
            )
        context = self._guarded(
            context, "MCU address space", (StageId.MCU_ANALYSIS,), self._phase_mcu
        )
        return self._guarded(
            context,
            "named checks",
            (StageId.RISK_CONTROLS,),
            lambda current: self._phase_controls(current, advisory_assessed=False),
        )

    # ──────────────────────────────────────────
    # Phase 3c: bare-metal address spaces (slice 3C)
    # ──────────────────────────────────────────

    def _phase_mcu(self, context: ScanContext) -> ScanContext:
        """Decode one bare-metal image and sweep the decoded bytes once."""
        console.print("[bold]═══ Phase 3c: MCU address space ═══[/bold]")
        reader = open_bounded(self._read_path(context))
        head = reader.read_head(4096)
        mcu_format = identify_mcu_format(head) or format_hint(context.firmware_path.suffix)
        if mcu_format is None:
            record_stage(
                context,
                StageId.MCU_ANALYSIS,
                StageStatus.FAILED,
                reason=(
                    "the artifact is neither an Intel HEX, S-record nor UF2 encoding, and "
                    "the filename does not name one; nothing was decoded"
                ),
                inspected=0,
                eligible=1,
                omissions=["no address map could be derived from these bytes"],
            )
            console.print("  [red]✗[/red] Not a recognised bare-metal encoding")
            return context

        try:
            analysis = analyse_mcu(
                reader,
                format=mcu_format,
                locator=context.firmware_name,
                digest=context.file_hash_sha256,
                max_payload_bytes=self.config.max_mcu_payload_mb * 1024 * 1024,
                max_records=self.config.max_mcu_records,
            )
        except McuFormatError as exc:
            record_stage(
                context,
                StageId.MCU_ANALYSIS,
                StageStatus.FAILED,
                reason=f"malformed or truncated {mcu_format} encoding: {exc}",
                inspected=0,
                eligible=1,
                omissions=[
                    "no address map was recorded: a partial map would present "
                    "unobserved bytes as absent ones"
                ],
            )
            console.print(f"  [red]✗[/red] {exc}")
            return context
        except Exception as exc:  # a decoder bug must be incomplete, not empty
            record_stage(
                context,
                StageId.MCU_ANALYSIS,
                StageStatus.FAILED,
                reason=f"the bare-metal image could not be decoded: {exc}",
                inspected=0,
                eligible=1,
            )
            console.print(f"  [red]✗[/red] {exc}")
            return context

        context.mcu = analysis
        context.mcu_matches = self._sweep_mcu_payload(context, analysis)
        context.image_map = ImageMap(
            root_artifact_id="a0",
            nodes=[
                ArtifactNode(
                    artifact_id="a0",
                    parent_id=None,
                    digest_sha256=analysis.digest,
                    format=analysis.format,
                    coordinate_system="device-address",
                    offset=analysis.ranges[0].start if analysis.ranges else 0,
                    length=analysis.payload_bytes,
                    decoder=analysis.decoder,
                    decoder_version=analysis.decoder_version,
                    depth=0,
                    locator=analysis.locator,
                    details={
                        "ranges": len(analysis.ranges),
                        "gaps": len(analysis.gaps),
                        "records": analysis.records,
                    },
                )
            ],
        )

        omissions = [
            f"{item.kind}: {item.detail}"
            for item in analysis.diagnostics
            if item.kind
            in {
                "conflict",
                "missing-eof",
                "missing-block",
                "record-count-mismatch",
                "unknown-record-type",
            }
        ]
        first = analysis.ranges[0]
        last = analysis.ranges[-1]
        record_stage(
            context,
            StageId.MCU_ANALYSIS,
            StageStatus.PARTIAL if omissions else StageStatus.COMPLETE,
            reason=(
                f"{analysis.format} decoded: {len(analysis.ranges)} range(s) over "
                f"{analysis.payload_bytes:,} byte(s), {analysis.records:,} record(s), "
                f"{first.start:#010x}-{last.end:#010x}"
                + (f", {len(analysis.gaps)} unobserved gap(s)" if analysis.gaps else "")
            ),
            inspected=len(analysis.ranges),
            eligible=len(analysis.ranges),
            omissions=omissions,
        )
        console.print(
            f"  [green]✓[/green] {analysis.format}: {len(analysis.ranges)} range(s), "
            f"{analysis.payload_bytes:,} byte(s) at {first.start:#010x}-{last.end:#010x}, "
            f"{analysis.records:,} record(s)"
        )
        console.print(
            f"  [green]✓[/green] payload digest {analysis.payload_sha256[:16]}… "
            "(over the addressed bytes only, never over a gap)"
        )
        if analysis.gaps:
            console.print(
                f"  [yellow]![/yellow] {len(analysis.gaps)} address gap(s) stay "
                "unobserved and were not zero-filled"
            )
        if context.mcu_matches:
            console.print(
                f"  [yellow]![/yellow] {len(context.mcu_matches)} rule match(es) in the "
                "decoded payload (review findings, with addresses)"
            )
        for omission in omissions:
            console.print(f"  [yellow]![/yellow] {omission}")
        return context

    def _sweep_mcu_payload(self, context: ScanContext, analysis: McuAnalysis) -> list:
        """One compiled rule set, swept once over the decoded payload.

        The sweep is over the bytes that were **addressed**, not over the file:
        a hex record's ASCII is not firmware. Matches keep their destination from
        the rule's own category and carry the device address they were found at,
        so nothing here can be relabelled by a detector that saw it first.
        """
        engine = self.rule_engine()
        matches: list = []
        for start, payload in analysis.payload_ranges:
            for match in engine.scan_data(payload):
                # A YARA offset is relative to the range that was scanned, and
                # the range begins at a device address: the two are added once,
                # here, so every later reader sees an address it can look up.
                addresses = [start + offset for offset in match.offsets] or [start]
                match.meta["mcu_addresses"] = addresses
                match.file_path = Path(f"{analysis.locator}@{addresses[0]:#010x}")
                matches.append(match)
        return matches

    def _run_boot_profile(self, context: ScanContext) -> ScanContext:
        """The boot-manifest profile: nothing here is a root filesystem."""
        for stage_id, reason in (
            (
                StageId.EXTRACTION,
                "a boot manifest is a file, not a container; nothing was extracted",
            ),
            (
                StageId.ROOT_DISCOVERY,
                "a boot manifest declares no filesystem root",
            ),
            (
                StageId.ENUMERATION,
                "a boot manifest is parsed structurally; there is no filesystem to enumerate",
            ),
            (
                StageId.ENTROPY,
                "byte distribution is not a control for a boot manifest and is not measured",
            ),
            (
                StageId.BINARY_INVENTORY,
                "no Linux binaries are inspected by the firmware-boot profile",
            ),
            (
                StageId.ELF_METADATA,
                "no ELF file is inspected by the firmware-boot profile",
            ),
            (
                StageId.OPKG_INVENTORY,
                "a boot manifest carries no package database",
            ),
            (
                StageId.CREDENTIAL_SCAN,
                "a boot manifest carries no credential-bearing files to scan",
            ),
            (
                StageId.UNIX_ACCOUNTS,
                "a boot manifest carries no /etc/passwd or /etc/shadow",
            ),
            (
                StageId.SERVICE_ANALYSIS,
                "a boot manifest declares no configured service",
            ),
            (
                StageId.C2_INDICATORS,
                "the firmware-boot profile does not sweep a filesystem for indicators",
            ),
            (
                StageId.ADVISORY,
                "a boot manifest names no installed component to look up",
            ),
        ):
            record_stage(
                context,
                stage_id,
                StageStatus.NOT_APPLICABLE,
                reason=reason,
            )
        context = self._guarded(
            context, "boot manifest", (StageId.BOOT_ANALYSIS,), self._phase_boot
        )
        return self._guarded(
            context,
            "named checks",
            (StageId.RISK_CONTROLS,),
            lambda current: self._phase_controls(current, advisory_assessed=False),
        )

    # ──────────────────────────────────────────
    # Phase 3e: boot manifests and board descriptions (slice 3D)
    # ──────────────────────────────────────────

    def _phase_boot(self, context: ScanContext) -> ScanContext:
        """Parse one FDT/FIT, verifying only against operator-supplied keys."""
        console.print("[bold]═══ Phase 3e: Boot manifest ═══[/bold]")
        anchors: list[TrustAnchor] = []
        for path in self.trust_anchor_paths:
            try:
                anchors.append(load_trust_anchor(path))
            except (TrustAnchorError, OSError) as exc:
                record_stage(
                    context,
                    StageId.BOOT_ANALYSIS,
                    StageStatus.FAILED,
                    reason=f"trust anchor {path} could not be used: {exc}",
                    inspected=0,
                    eligible=1,
                    omissions=["no signature was verified against an unusable key"],
                )
                console.print(f"  [red]✗[/red] Trust anchor unusable: {exc}")
                return context
        if anchors:
            console.print(
                f"  [green]✓[/green] {len(anchors)} operator-supplied trust anchor(s), "
                f"sha256 {anchors[0].sha256[:16]}…"
            )
        else:
            console.print(
                "  [yellow]![/yellow] No trust anchor supplied; signature presence is "
                "recorded, authenticity stays unverified"
            )

        reader = open_bounded(self._read_path(context))
        try:
            artifact, omissions = analyse_boot(
                reader,
                locator=context.firmware_name or reader.path.name,
                digest=context.file_hash_sha256,
                artifact_id="a0",
                anchors=anchors,
            )
        except FitDtbError as exc:
            record_stage(
                context,
                StageId.BOOT_ANALYSIS,
                StageStatus.FAILED,
                reason=f"malformed or truncated boot artifact: {exc}",
                inspected=0,
                eligible=1,
                omissions=["no boot fact was recorded from an invalid structure"],
            )
            console.print(f"  [red]✗[/red] {exc}")
            return context
        except Exception as exc:  # a parser bug must be incomplete, not empty
            record_stage(
                context,
                StageId.BOOT_ANALYSIS,
                StageStatus.FAILED,
                reason=f"boot manifest could not be parsed: {exc}",
                inspected=0,
                eligible=1,
            )
            console.print(f"  [red]✗[/red] {exc}")
            return context

        context.boot = BootAnalysis(
            artifacts=[artifact],
            notes=[
                "Boot integrity, signature presence, signature verification and board "
                "enforcement are four separate facts; only the first three can be read "
                "from a static artifact.",
                "Physical boot enforcement remains unknown: a declared configuration "
                "is not evidence that the board enforces it.",
            ],
        )
        context.image_map = ImageMap(
            root_artifact_id=artifact.artifact_id,
            nodes=[
                ArtifactNode(
                    artifact_id=artifact.artifact_id,
                    parent_id=None,
                    digest_sha256=artifact.digest,
                    format=artifact.kind,
                    coordinate_system="container-bytes",
                    offset=0,
                    length=artifact.size,
                    decoder="ihs-fit-dtb",
                    decoder_version="1",
                    depth=0,
                    locator=artifact.locator,
                    details={
                        "fdt_version": artifact.fdt_version,
                        "configurations": len(artifact.configurations),
                        "referenced_payloads": len(artifact.referenced_payloads),
                    },
                )
            ],
        )

        status = StageStatus.PARTIAL if omissions else StageStatus.COMPLETE
        record_stage(
            context,
            StageId.BOOT_ANALYSIS,
            status,
            reason=(
                f"{artifact.kind} parsed: {len(artifact.configurations)} configuration(s), "
                f"{len(artifact.referenced_payloads)} referenced payload(s), "
                f"default {artifact.default_config or 'unknown'}"
            ),
            inspected=1,
            eligible=1,
            omissions=list(omissions),
        )
        signed = sum(1 for config in artifact.configurations if config.signature.present)
        verified = sum(1 for config in artifact.configurations if config.signature.verified is True)
        integrity = [p.integrity for p in artifact.referenced_payloads]
        console.print(
            f"  [green]✓[/green] {artifact.kind}: "
            f"{len(artifact.configurations)} config(s), "
            f"{integrity.count('match')}/{len(integrity)} payload digest(s) match, "
            f"{signed} signature(s) present, {verified} verified with a supplied key"
        )
        console.print("  [yellow]![/yellow] Physical boot enforcement remains unknown")
        for omission in omissions:
            console.print(f"  [yellow]![/yellow] {omission}")
        return context

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
        console.print(
            f"  [green]✓[/green] Type: {context.file_type} "
            f"[dim](identified by {context.file_type_source})[/dim]"
        )
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

            if image_map.nodes[0].format == "disk":
                # A disk image is not one filesystem: its table names partitions,
                # and each partition is decoded by its own magic bytes.
                return self._partitioned_extraction(context, builder, reader, scratch)

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

    def _partitioned_extraction(
        self,
        context: ScanContext,
        builder: Any,
        reader: Any,
        scratch: Path,
    ) -> ScanContext:
        """Phase 2 for a disk image: one partition at a time (slice 3A, part 2).

        Each partition is sliced into private scratch, decoded by its own magic
        bytes, and extracted with the same worker a single-image scan uses. A
        partition that holds no recognisable filesystem is recorded as such and
        does not fail the others: a disk image legitimately carries a bootloader,
        a `uboot-env` blob and two roots side by side.
        """
        from iot_hardware_scanner.scanner.extraction_worker import (
            ExtractionError,
            SquashfsWorker,
        )
        from iot_hardware_scanner.scanner.image_map import ImageMapError
        from iot_hardware_scanner.scanner.partitions import PartitionError

        # Phase 2's own header was already printed by the caller.
        image_map = context.image_map
        assert image_map is not None
        try:
            nodes = builder.add_partitions(reader)
        except PartitionError as exc:
            record_stage(
                context,
                StageId.EXTRACTION,
                StageStatus.FAILED,
                reason=f"the partition table is not decodable: {exc}",
                omissions=["filesystem never enumerated"],
            )
            record_stage(
                context,
                StageId.ROOT_DISCOVERY,
                StageStatus.UNAVAILABLE,
                reason="the partition table was rejected, so no partition was reached",
            )
            console.print(f"  [red]✗[/red] {exc}")
            return context

        scheme = str(image_map.nodes[0].details.get("partition_scheme", "partition")).upper()
        console.print(
            f"  [green]✓[/green] {scheme} table: {len(nodes)} partition(s), "
            "every declared range inside the image"
        )

        worker = SquashfsWorker(self.config)
        collected = ExtractionResult(
            success=False,
            extraction_dir=scratch / "extract",
            backend="unknown",
            state=EXTRACTION_UNAVAILABLE,
        )
        provenance: ExtractionProvenance | None = None
        roots: list[Path] = []
        omissions: list[str] = []
        filesystem_partitions = 0
        unavailable = False

        for node in nodes:
            try:
                sliced = builder.slice_partition(
                    reader, node, scratch / "partitions" / f"{node.artifact_id}.img"
                )
            except ImageMapError as exc:
                record_stage(
                    context,
                    StageId.EXTRACTION,
                    StageStatus.FAILED,
                    reason=f"partition {node.artifact_id} could not be read: {exc}",
                    omissions=["filesystem never enumerated"],
                )
                record_stage(
                    context,
                    StageId.ROOT_DISCOVERY,
                    StageStatus.UNAVAILABLE,
                    reason="a declared partition range could not be read",
                )
                console.print(f"  [red]✗[/red] {exc}")
                return context

            try:
                squashfs_path, child = self._decode_partition(sliced, node, builder)
            except ImageMapError as exc:
                node.details["content"] = "undecodable"
                node.details["content_note"] = str(exc)
                omissions.append(
                    f"{node.artifact_id}: declared bytes are not a decodable container"
                )
                console.print(f"  [yellow]![/yellow] {node.artifact_id}: {exc}")
                continue
            if squashfs_path is None:
                node.details["content"] = "unrecognised"
                omissions.append(f"{node.artifact_id}: no recognised filesystem in its bytes")
                console.print(
                    f"  [yellow]![/yellow] {node.artifact_id} ({node.details.get('type_name')}): "
                    "no SquashFS magic in its bytes"
                )
                continue

            try:
                result = worker.extract(squashfs_path, scratch / "extract" / node.artifact_id)
            except ExtractionError as exc:
                if exc.state == EXTRACTION_UNAVAILABLE:
                    unavailable = True
                node.details["content"] = "squashfs"
                node.details["extraction_state"] = exc.state
                omissions.append(f"{node.artifact_id}: {exc.message}")
                console.print(f"  [yellow]![/yellow] {node.artifact_id}: {exc.message}")
                continue

            node.details["content"] = "squashfs"
            node.details["extraction_state"] = result.state
            node.details["file_count"] = result.file_count
            if child is not None and result.provenance is not None:
                child.decoder_version = result.provenance.helper_version
            if not result.success or not result.root_filesystems:
                omissions.append(
                    f"{node.artifact_id}: {result.state}"
                    + (
                        f" ({'; '.join(result.extraction_errors)})"
                        if result.extraction_errors
                        else ""
                    )
                )
                console.print(f"  [yellow]![/yellow] {node.artifact_id}: extraction {result.state}")
                continue

            filesystem_partitions += 1
            roots.extend(result.root_filesystems)
            collected.file_count += result.file_count
            collected.total_size += result.total_size
            collected.omissions.extend(result.omissions)
            provenance = result.provenance or provenance
            collected.backend = result.backend
            collected.backend_version = result.backend_version
            collected.worker_digest = result.worker_digest
            manifest = _extract_manifest_metadata(result)
            for root in result.root_filesystems:
                context.root_sources[str(root)] = {
                    "metadata": manifest,
                    "metadata_source": "image" if manifest else "host",
                    "artifact_id": node.artifact_id,
                }
            console.print(
                f"  [green]✓[/green] {node.artifact_id} ({node.details.get('label')}): "
                f"SquashFS root, {result.file_count:,} file(s), "
                f"{len(result.root_filesystems)} root(s)"
            )

        if not roots:
            detail = "; ".join(omissions) or "no partition holds a recognised filesystem"
            state = EXTRACTION_UNAVAILABLE if unavailable else EXTRACTION_CORRUPT
            record_stage(
                context,
                StageId.EXTRACTION,
                StageStatus.UNAVAILABLE if unavailable else StageStatus.FAILED,
                reason=detail,
                dependency=EXTRACTION_DEPENDENCY if unavailable else None,
                omissions=["filesystem never enumerated"],
            )
            record_stage(
                context,
                StageId.ROOT_DISCOVERY,
                StageStatus.UNAVAILABLE,
                reason="no partition yielded an enumerable root filesystem",
            )
            collected.state = state
            collected.success = False
            collected.extraction_errors = list(omissions)
            context.extraction_result = collected
            console.print(f"  [yellow]![/yellow] No root filesystem: {detail}")
            return context

        collected.success = True
        collected.state = EXTRACTION_OK
        collected.root_filesystems = roots
        collected.provenance = provenance
        collected.omissions = list(dict.fromkeys(collected.omissions + omissions))
        context.extraction_result = collected
        context.extraction_provenance = provenance
        context.extracted_rootfs = roots[0]
        context.image_rootfs_artifact_id = (
            context.root_sources.get(str(roots[0]), {}).get("artifact_id")
            or image_map.root_artifact_id
        )
        record_stage(
            context,
            StageId.EXTRACTION,
            StageStatus.PARTIAL if omissions else StageStatus.COMPLETE,
            reason=(
                f"{filesystem_partitions} of {len(nodes)} partition(s) hold a filesystem; "
                f"{collected.backend} worker"
                + (f" {collected.backend_version}" if collected.backend_version else "")
                + (f", image {collected.worker_digest[:19]}…" if collected.worker_digest else "")
            ),
            inspected=filesystem_partitions,
            eligible=len(nodes),
            omissions=list(omissions),
        )
        record_stage(
            context,
            StageId.ROOT_DISCOVERY,
            StageStatus.COMPLETE,
            reason=(
                f"{len(roots)} root filesystem(s) located across "
                f"{filesystem_partitions} partition(s)"
            ),
            inspected=len(roots),
            eligible=len(roots),
        )
        console.print(
            f"  [green]✓[/green] {len(roots)} root(s) from {filesystem_partitions} partition(s), "
            f"{collected.file_count:,} file(s), {collected.total_size:,} bytes"
        )
        return context

    def _decode_partition(
        self, sliced: Path, node: ArtifactNode, builder: Any
    ) -> tuple[Path | None, ArtifactNode | None]:
        """Decide what one partition holds, from its first bytes.

        A partition is either a bare SquashFS image, a gzip-wrapped one, or
        neither. "Neither" is a fact about this partition, not a failure of the
        scan, so it returns ``(None, None)`` and the caller records it.
        """
        from iot_hardware_scanner.scanner.image_map import (
            GZIP_MAGIC,
            ImageMapError,
        )

        reader = open_bounded(sliced)
        head = reader.read_head(4)
        if head.startswith(GZIP_MAGIC):
            if builder.map is None:  # pragma: no cover - builder is always started
                raise ImageMapError("image map was not started")
            builder.map.root_artifact_id = node.artifact_id
            decoded = sliced.parent / f"{sliced.stem}.squashfs"
            try:
                _path, child = builder.decompress_gzip(
                    reader,
                    decoded,
                    max_decoded_bytes=self.config.max_decoded_bytes_mb * 1024 * 1024,
                    node_id=f"{node.artifact_id}g",
                )
            finally:
                builder.map.root_artifact_id = "a0"
            child.parent_id = node.artifact_id
            node.details["content"] = "gzip"
            return decoded, child
        if head.startswith(b"hsqs"):
            superblock = builder.parse_squashfs(reader)
            if superblock.bytes_used > node.length:
                raise ImageMapError(
                    f"the superblock declares {superblock.bytes_used:,} bytes used, more than "
                    f"the {node.length:,}-byte partition"
                )
            node.details["superblock"] = superblock.as_dict()
            node.extent_bytes = superblock.bytes_used
            return sliced, None
        return None, None

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
            root_id = f"rootfs{index + 1}" if len(roots) > 1 else "rootfs"
            # A disk image can carry two partitions whose relative paths collide.
            # Metadata and the artifact node are therefore taken per root, never
            # from one aggregate manifest.
            source = context.root_sources.get(str(rootfs), {})
            root_metadata = source.get("metadata") or metadata
            root_source = source.get("metadata_source") or ("image" if root_metadata else "host")
            inventory = scanner.scan(
                rootfs,
                root_id=root_id,
                metadata=root_metadata,
                metadata_source=root_source,
                artifact_id=source.get("artifact_id"),
            )
            _merge_inventory(merged, inventory)
            merged.boot_evidence.extend(scanner.collect_boot_evidence(rootfs, root_id=root_id))

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

        scanner = CredentialScanner(self.config, rule_engine=self.rule_engine())
        scanned_categories = {
            FileCategory.CRITICAL_CREDENTIAL,
            FileCategory.CRITICAL_CONFIG,
            FileCategory.HIGH_API_KEY,
            FileCategory.HIGH_CRYPTO,
            FileCategory.HIGH_DATABASE,
        }

        artifacts_scanned = 0
        if context.filesystem_inventory is not None:
            inventory = context.filesystem_inventory
            eligible = sum(len(inventory.categories.get(cat, [])) for cat in scanned_categories)
            eligible += sum(1 for finding in inventory.findings if finding.format == "elf")
            findings = scanner.scan_inventory(inventory)
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
                "inventory-scoped scan: text categories plus every ELF binary"
                if context.filesystem_inventory is not None
                else f"artifact-scoped bound read ({artifacts_scanned} artifact unit)"
            ),
            inspected=inspected,
            eligible=eligible,
            omissions=[
                f"{item['rule']} at {item['location']}: {item['reason']}"
                for item in scanner.suppressed
            ],
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

        scanner = CredentialScanner(self.config, rule_engine=self.rule_engine())
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
        """Phase 5: apply a local advisory snapshot, or say it was not assessed.

        Nothing here opens a socket. Without a snapshot the stage is SKIPPED and
        the report says applicability was not assessed; that is not a pass, and
        check 3 is OMITTED. With a snapshot, every component gets one lookup
        whose state says whether its question was answered.
        """
        from iot_hardware_scanner.intelligence.advisory import (
            AdvisorySnapshotError,
            assess,
            describe_snapshot,
            load_snapshot,
        )

        console.print("[bold]═══ Phase 5: Advisory ═══[/bold]")
        if not self.advisory_snapshot:
            record_stage(
                context,
                StageId.ADVISORY,
                StageStatus.SKIPPED,
                reason=(
                    "no advisory snapshot was supplied; advisory applicability was not "
                    "assessed (pass --advisory-snapshot to assess it offline)"
                ),
            )
            console.print("  [yellow]![/yellow] No advisory snapshot — applicability not assessed")
            return context

        path = Path(self.advisory_snapshot)
        if not path.is_file():
            record_stage(
                context,
                StageId.ADVISORY,
                StageStatus.UNAVAILABLE,
                reason=f"advisory snapshot {path} does not exist",
                dependency=f"local advisory snapshot ({path})",
            )
            console.print(f"  [red]✗[/red] Advisory snapshot missing: {path}")
            return context

        try:
            document, digest = load_snapshot(path)
        except AdvisorySnapshotError as exc:
            record_stage(
                context,
                StageId.ADVISORY,
                StageStatus.FAILED,
                reason=str(exc),
                omissions=["advisory applicability was not assessed"],
            )
            console.print(f"  [red]✗[/red] {exc}")
            return context

        snapshot = describe_snapshot(
            document, digest, path, self.config.advisory_snapshot_max_age_days
        )
        findings, assessment = assess(document, snapshot, context.software_components)
        context.cve_findings = findings
        context.advisory = assessment

        status = StageStatus.COMPLETE
        omissions: list[str] = []
        if assessment.state == "PARTIAL":
            status = StageStatus.PARTIAL
            omissions = [
                f"{lookup.component} {lookup.version}: {lookup.state}"
                + (f" — {lookup.reason}" if lookup.reason else "")
                for lookup in assessment.lookups
                if lookup.state in ("UNAVAILABLE", "PARTIAL")
            ]
        elif assessment.state == "STALE":
            status = StageStatus.PARTIAL
            omissions = [
                f"the snapshot is {snapshot.age_days:.0f} day(s) old; a clean result "
                "from it is not current"
            ]
        elif assessment.state == "UNAVAILABLE":
            status = StageStatus.NOT_APPLICABLE
            omissions = ["no component carried product and version evidence to match"]

        record_stage(
            context,
            StageId.ADVISORY,
            status,
            reason=(
                f"{len(assessment.lookups)} component lookup(s) against a "
                f"{snapshot.provider} snapshot ({snapshot.entries} advisor"
                f"{'y' if snapshot.entries == 1 else 'ies'}, digest {digest[:16]}…, "
                f"acquired {snapshot.acquired_at or 'undated'})"
            ),
            inspected=len(assessment.lookups),
            eligible=len(assessment.lookups),
            omissions=omissions,
        )
        console.print(
            f"  [green]✓[/green] {assessment.matched} applicable advisor"
            f"{'y' if assessment.matched == 1 else 'ies'}"
            f" ({assessment.kev_matches} in KEV) across {len(assessment.lookups)} component(s)"
        )
        if assessment.keyword_candidates_rejected:
            console.print(
                f"  [yellow]![/yellow] {assessment.keyword_candidates_rejected} keyword "
                "candidate(s) rejected: the advisory did not name the product and version"
            )
        return context

    @staticmethod
    def _advisory_assessed(context: ScanContext) -> bool:
        stage = next((s for s in context.stages if s.stage_id is StageId.ADVISORY), None)
        return stage is not None and stage.status in (StageStatus.COMPLETE, StageStatus.PARTIAL)

    def _phase_c2(self, context: ScanContext) -> ScanContext:
        """Phase 6: C2 and malicious indicator detection."""
        console.print("[bold]═══ Phase 6: C2 & Malware ═══[/bold]")
        from iot_hardware_scanner.scanner.c2_detector import C2Detector

        detector = C2Detector(
            self.config, rule_engine=self.rule_engine(), cache=self._analysis_cache
        )
        inventory = context.filesystem_inventory
        crypto: list = []

        if inventory is not None:
            findings = (
                detector.detect_domains(inventory)
                + detector.detect_ips(inventory)
                + detector.detect_malware_signatures(inventory)
            )
            crypto = detector.detect_crypto(inventory)
            context.crypto_findings = crypto
            record_stage(
                context,
                StageId.C2_INDICATORS,
                StageStatus.COMPLETE,
                reason=(
                    "indicator sweep over the enumerated inventory, with dependency "
                    "names and the shipped suffix list applied before scoring"
                ),
                inspected=len(inventory.findings),
                eligible=len(inventory.findings),
                omissions=detector.suppression_summary,
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
                omissions=detector.suppression_summary,
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
        if context.profile == PROFILE_BOOT:
            limitations.append(
                "A boot manifest declares what a build intends to boot; it does not "
                "show that the running device enforces it. Physical boot enforcement "
                "is unknown by construction, and no signature is trusted without an "
                "operator-supplied key."
            )
        if context.profile == PROFILE_MCU:
            limitations.append(
                "A bare-metal image is addressed bytes, not a filesystem: the report "
                "answers what the payload contains and where, and no named check is "
                "settled from it. Address gaps stay unobserved and are never zero-filled."
            )
            if context.mcu is not None and context.mcu.diagnostics:
                limitations.append(
                    f"{len(context.mcu.diagnostics)} structural diagnostic(s) were recorded "
                    "for the encoding; they describe the records, not the device."
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
    """Every installed package as a component, with its evidence range.

    One component per installed record: the package database is the inventory
    Milestone D compares, so a record without a NIST-mapped product is still
    emitted, named from its own package name with a recorded basis. Skipping
    unmapped records is what used to hide 193 of 196 packages.
    """
    from iot_hardware_scanner.intelligence.cpe_builder import resolve_product
    from iot_hardware_scanner.models import SoftwareComponent

    components: list[SoftwareComponent] = []
    for record in getattr(parsed, "records", []):
        if not record.installed:
            continue
        resolved = resolve_product(record.name, record.version, fallback_to_package_name=True)
        if resolved is None:  # pragma: no cover - the fallback always resolves
            continue
        components.append(
            SoftwareComponent(
                vendor=resolved.vendor,
                product=resolved.product,
                version=record.version,
                cpe_string=resolved.cpe_string,
                cpe_basis=resolved.basis,
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
