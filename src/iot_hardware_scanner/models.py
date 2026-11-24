"""Data models for IoT Hardware Scanner.

All dataclasses used across the pipeline. Phase-specific models are
co-located here so the orchestrator and report generator can import
from a single location.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

# ──────────────────────────────────────────────
# Enumerations
# ──────────────────────────────────────────────


class FileCategory(str, Enum):
    """Security-relevance categorization for filesystem files."""

    CRITICAL_CREDENTIAL = "CRITICAL_CREDENTIAL"
    CRITICAL_CONFIG = "CRITICAL_CONFIG"
    CRITICAL_SERVICE = "CRITICAL_SERVICE"
    CRITICAL_SCRIPT = "CRITICAL_SCRIPT"
    CRITICAL_BINARY = "CRITICAL_BINARY"
    HIGH_API_KEY = "HIGH_API_KEY"
    HIGH_CRYPTO = "HIGH_CRYPTO"
    HIGH_DATABASE = "HIGH_DATABASE"
    MEDIUM_LOG = "MEDIUM_LOG"
    MEDIUM_WEB = "MEDIUM_WEB"
    LOW_MISC = "LOW_MISC"


class Severity(str, Enum):
    """Finding severity taxonomy."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class RiskLevel(str, Enum):
    """Overall risk classification."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FirmwareSizeCategory(str, Enum):
    """Firmware size categorization for analysis strategy."""

    SMALL = "SMALL"  # < 50 MB
    MEDIUM = "MEDIUM"  # 50-500 MB
    LARGE = "LARGE"  # 500 MB - 2 GB


class InputKind(str, Enum):
    """Kind of artifact placed under analysis."""

    FILE = "file"  # a single image/blob, addressed by its byte digest
    TREE = "tree"  # a directory, addressed by a canonical tree-manifest digest
    BOOT = "boot"  # a flattened device tree or U-Boot FIT boot manifest
    MCU = "mcu"  # a bare-metal image addressed by its device address space


class StageId(str, Enum):
    """Named analysis stages. Stable identifiers used by reports and CI."""

    INGEST = "ingest"
    EXTRACTION = "extraction"
    ROOT_DISCOVERY = "root_discovery"
    ENUMERATION = "enumeration"
    ENTROPY = "entropy"
    BINARY_INVENTORY = "binary_inventory"
    ELF_METADATA = "elf_metadata"
    OPKG_INVENTORY = "opkg_inventory"
    CREDENTIAL_SCAN = "credential_scan"
    UNIX_ACCOUNTS = "unix_accounts"
    SERVICE_ANALYSIS = "service_analysis"
    ADVISORY = "advisory"
    C2_INDICATORS = "c2_indicators"
    RULE_COMPILATION = "rule_compilation"
    RISK_CONTROLS = "risk_controls"
    BOOT_ANALYSIS = "boot_analysis"
    MCU_ANALYSIS = "mcu_analysis"


class StageStatus(str, Enum):
    """Outcome of one stage.

    Only COMPLETE and NOT_APPLICABLE represent a settled question. PARTIAL,
    UNAVAILABLE, FAILED and SKIPPED all describe work that did not finish,
    and are listed with a reason so the caller can tell them apart.
    """

    COMPLETE = "COMPLETE"  # ran over its whole eligible population
    PARTIAL = "PARTIAL"  # ran, but some eligible members were not inspected
    UNAVAILABLE = "UNAVAILABLE"  # required capability is absent on this host/input
    FAILED = "FAILED"  # ran and errored
    SKIPPED = "SKIPPED"  # deliberately not requested by the operator
    NOT_APPLICABLE = "NOT_APPLICABLE"  # no eligible population for this input/profile


class CheckStatus(str, Enum):
    """Evidence status of a named check (control)."""

    PERFORMED = "PERFORMED"  # evidence was collected and a verdict rendered
    INCONCLUSIVE = "INCONCLUSIVE"  # evidence collected, but not sufficient for a verdict
    NOT_APPLICABLE = "NOT_APPLICABLE"  # check cannot apply to this artifact/profile
    OMITTED = "OMITTED"  # check was not run; reason recorded


class Completion(str, Enum):
    """Whether every stage the selected profile requires has completed."""

    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    UNKNOWN = "UNKNOWN"  # a legacy document that never recorded coverage


# ──────────────────────────────────────────────
# Core: Scan Context
# ──────────────────────────────────────────────


@dataclass
class StageResult:
    """What one stage actually did.

    ``inspected``/``eligible`` are ``None`` when the population could not be
    counted. An observed zero is meaningful only when ``eligible`` is 0.
    """

    stage_id: StageId
    status: StageStatus
    required: bool = False
    reason: str = ""
    inspected: int | None = None
    eligible: int | None = None
    omissions: list[str] = field(default_factory=list)
    #: Name of the external thing the operator could supply (backend, snapshot).
    #: Only a dependency makes an assessment stop with exit 5; anything else
    #: that did not finish is incomplete analysis (exit 4).
    dependency: str | None = None


@dataclass
class ControlResult:
    """One named security check, with its evidence status.

    There is deliberately no point value and no aggregate: the retired
    grade had no calibrated relationship to device risk.
    """

    control_id: int
    control_name: str
    status: CheckStatus
    result: str = "UNKNOWN"  # PASS | FAIL | REVIEW | UNKNOWN | NOT_APPLICABLE
    evidence: list[str] = field(default_factory=list)
    remediation: str = ""
    source_stage: StageId | None = None
    #: The question this check asks, in one sentence. Kept on the record so a
    #: reader never has to infer the question from a verdict.
    question: str = ""
    #: The evidence source that can answer the question. Missing evidence is
    #: reported as such, never as a pass.
    required_source: str = ""
    #: APPLICABLE | NOT_APPLICABLE (with the rule that decided it).
    applicability: str = "APPLICABLE"
    applicability_note: str = ""

    def __post_init__(self) -> None:
        """Keep the applicability flag and the evidence status consistent."""
        if self.status is CheckStatus.NOT_APPLICABLE and self.applicability == "APPLICABLE":
            self.applicability = "NOT_APPLICABLE"

    @property
    def evidence_status(self) -> str:
        """Alias kept for readers that speak of the check's evidence status."""
        return self.status.value


@dataclass
class ReportFinding:
    """Normalized finding used by the exit contract and every renderer.

    ``critical_qualified`` is true only when this rule has a documented
    evidence rule and both a positive and a lookalike-negative fixture.
    Everything else is a review finding, whatever its raw severity label.
    """

    rule_id: str
    severity: Severity
    title: str
    description: str
    category: str
    locations: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    remediation: str | None = None
    critical_qualified: bool = False
    #: Typed destination: credential | service | crypto | indicator | advisory.
    destination: str = "indicator"
    #: Rule namespaces that produced this finding, when it came from a rule set.
    namespaces: list[str] = field(default_factory=list)
    #: Digest of the compiled rule set that produced it, when applicable.
    ruleset_digest: str = ""


@dataclass
class Assessment:
    """Assessment completion, independent of any finding."""

    profile: str
    profile_version: str
    completion: Completion = Completion.INCOMPLETE
    stages: list[StageResult] = field(default_factory=list)
    controls: list[ControlResult] = field(default_factory=list)
    incomplete_reasons: list[str] = field(default_factory=list)
    missing_required_dependencies: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    started_at: datetime | None = None
    completed_at: datetime | None = None

    def stage(self, stage_id: StageId) -> StageResult | None:
        """Return the recorded result for a stage, if any."""
        for result in self.stages:
            if result.stage_id == stage_id:
                return result
        return None

    @property
    def check_counts(self) -> dict[str, int]:
        """Counts of assessed / inconclusive / inapplicable / omitted checks."""
        counts = {
            CheckStatus.PERFORMED.value: 0,
            CheckStatus.INCONCLUSIVE.value: 0,
            CheckStatus.NOT_APPLICABLE.value: 0,
            CheckStatus.OMITTED.value: 0,
        }
        for control in self.controls:
            counts[control.status.value] = counts.get(control.status.value, 0) + 1
        return counts


@dataclass
class ScanContext:
    """Top-level context object passed through all pipeline phases.

    Each phase populates its section. The orchestrator creates this
    at ingest and threads it through every scanner module.
    """

    scan_id: str
    firmware_path: Path
    output_dir: Path
    file_hash_sha256: str
    file_hash_md5: str
    file_size: int
    file_type: str
    firmware_name: str
    size_category: FirmwareSizeCategory
    started_at: datetime
    completed_at: datetime | None = None

    # Identity of the inspected artifact (added in schema 2)
    input_kind: InputKind = InputKind.FILE
    input_manifest_entries: int | None = None
    #: How ``file_type`` was established (schema 7): ``magic-bytes``, ``libmagic``,
    #: ``extension`` or ``directory``. A label without its source is not evidence:
    #: "ELF executable" from libmagic and from a ``.elf`` suffix are not the same
    #: observation, and a report that cannot tell them apart cannot be audited.
    file_type_source: str = "unknown"

    # Populated by the orchestrator: what ran, what did not, and why
    profile: str = "firmware-static"
    profile_version: str = "3.0"
    stages: list[StageResult] = field(default_factory=list)
    assessment: Assessment | None = None

    # Populated by Phase 1 (slice 2D): the verified private copy every later
    # read is bound to, and the deterministic manifest of a staged tree.
    input_snapshot: InputSnapshot | None = None
    tree_manifest: list[TreeManifestEntry] = field(default_factory=list)
    declared_manifest: DeclaredManifest | None = None
    #: Entries that changed while the tree was being catalogued.
    tree_changes: list[str] = field(default_factory=list)
    #: Set when the input could not be bound to a verified snapshot (2D). The
    #: scan is then reported as incomplete and no further bytes are read.
    input_binding_error: str | None = None

    # Populated by Phase 2
    extracted_rootfs: Path | None = None
    #: Per-root provenance, keyed by the root's absolute path: the extractor's
    #: manifest for *that* root, and the artifact node it came from. A single
    #: aggregate manifest cannot describe two partitions that hold the same
    #: relative path with different metadata, so this stays per root.
    root_sources: dict[str, dict[str, Any]] = field(default_factory=dict)
    extraction_result: ExtractionResult | None = None
    extraction_provenance: ExtractionProvenance | None = None

    # Populated by Phase 2a (slice 3A): the ancestry of every container and
    # file locator the scan actually inspected.
    image_map: ImageMap | None = None
    #: Artifact node the extracted root filesystem's file locators hang from.
    image_rootfs_artifact_id: str | None = None

    # Populated by Phase 2b
    filesystem_inventory: FilesystemInventory | None = None

    # Populated by Phase 3
    entropy_profile: EntropyProfile | None = None
    binary_intelligence: BinaryIntelligenceResult | None = None

    # Populated by Phase 3b (slice 3B): one record per ELF file parsed from its
    # own header, and by Phase 3c (slice 4B): the installed-package database.
    elf_metadata: list[ElfReport] = field(default_factory=list)
    opkg_inventory: OpkgInventory | None = None

    # Populated by Phase 4
    credential_findings: list[CredentialFinding] = field(default_factory=list)

    # Populated by Phase 5
    cve_findings: list[CVEFinding] = field(default_factory=list)
    software_components: list[SoftwareComponent] = field(default_factory=list)
    #: Result of applying a local advisory snapshot (slice 4C), or None when no
    #: snapshot was supplied and advisory applicability was not assessed.
    advisory: AdvisoryAssessment | None = None

    # Populated by Phase 5b (slices 4A/4D): cryptographic algorithms observed in
    # the artifact, kept separate from binary hardening.
    crypto_findings: list[CryptoFinding] = field(default_factory=list)

    # Populated by Phase 0b (slice 4A): the one compiled rule set this run used.
    ruleset: RuleSetInfo | None = None

    # Populated by Phase 6
    c2_findings: list[C2Finding] = field(default_factory=list)

    # Populated by Phase 7: named checks with evidence status. There is no
    # aggregate grade; see scanner/risk_scorer.py.
    controls: list[ControlResult] = field(default_factory=list)

    # Legacy only: a v1 report's historical grade, preserved for replay.
    # New scans never populate this (the grade is retired).
    risk_score: RiskScore | None = None

    #: Slice 5C: what the repeated-work cache did for this run, when one was
    #: enabled. ``None`` means the scan ran without a cache.
    cache_summary: dict[str, Any] | None = None

    #: Slice 3D: the parsed boot manifests, or ``None`` when the selected
    #: profile does not read a boot artifact.
    boot: BootAnalysis | None = None

    #: Slice 3C: the decoded bare-metal image (sparse address map), or ``None``
    #: when the selected profile does not decode one.
    mcu: McuAnalysis | None = None
    #: Slice 3C: compiled-rule matches found in the decoded payload, each with the
    #: device address it was found at. Routed by destination in the assessment.
    mcu_matches: list[YaraMatch] = field(default_factory=list)


# ──────────────────────────────────────────────
# Phase 1: Ingest Models
# ──────────────────────────────────────────────


# ──────────────────────────────────────────────
# Slice 2D: immutable input binding and staged-tree manifests
# ──────────────────────────────────────────────


@dataclass
class InputSnapshot:
    """A verified, read-only copy of the bytes a scan is allowed to read."""

    original_path: Path
    snapshot_path: Path
    declared_sha256: str
    verified_sha256: str
    size: int
    budget_bytes: int
    immutable: bool
    #: Set after analysis: the original path no longer has the declared digest.
    source_changed: bool = False
    #: Set after analysis: the original path was re-hashed successfully.
    source_reverified: bool = False

    @property
    def digest_matches(self) -> bool:
        """Whether the snapshot really holds the bytes that were hashed."""
        return self.verified_sha256 == self.declared_sha256


@dataclass
class TreeManifestEntry:
    """One entry of a deterministic staged-tree manifest.

    ``metadata_source`` records where the mode/ownership came from:
    ``host`` (observed on this machine), ``declared`` (read from a build
    manifest the operator supplied) or ``image`` (carried out of a container by
    the extractor). A permission-based conclusion may only rest on ``image`` or
    ``declared`` evidence.
    """

    relative_path: str
    kind: str  # file | dir | symlink | hardlink
    size: int = 0
    sha256: str = ""
    mode: int | None = None
    uid: int | None = None
    gid: int | None = None
    metadata_source: str = "host"
    hardlink_group: str | None = None
    link_target: str | None = None


@dataclass
class DeclaredManifest:
    """A build manifest of declared ownership/permissions, with its digest."""

    path: Path
    sha256: str
    entries: dict[str, dict[str, Any]] = field(default_factory=dict)
    entry_count: int = 0
    #: Names in the declaration that the tree does not contain, and vice versa.
    declared_only: list[str] = field(default_factory=list)
    observed_only: list[str] = field(default_factory=list)


@dataclass
class FirmwareMetadata:
    """Metadata extracted during firmware ingestion."""

    path: Path
    name: str
    size_bytes: int
    size_category: FirmwareSizeCategory
    sha256: str
    md5: str
    file_type: str
    extension: str
    is_regular_file: bool
    is_readable: bool


# ──────────────────────────────────────────────
# Phase 2: Extraction Models
# ──────────────────────────────────────────────


@dataclass
class SignatureResult:
    """A single binwalk signature match."""

    offset: int
    description: str
    size: int | None = None
    filesystem_type: str | None = None


#: Documented extraction outcomes. Each maps to one stage status:
#: ``OK`` and ``PARTIAL`` complete, ``UNAVAILABLE`` needs an operator-supplied
#: dependency (exit 5), everything else is incomplete analysis (exit 4).
EXTRACTION_OK = "OK"
EXTRACTION_PARTIAL = "PARTIAL"
EXTRACTION_UNAVAILABLE = "UNAVAILABLE"
EXTRACTION_CORRUPT = "CORRUPT_INPUT"
EXTRACTION_TIMEOUT = "TIMEOUT"
EXTRACTION_QUOTA = "QUOTA_EXCEEDED"
EXTRACTION_NONZERO = "HELPER_FAILED"
EXTRACTION_EMPTY = "EMPTY_OUTPUT"
EXTRACTION_NO_ISOLATION = "NO_ISOLATION"
EXTRACTION_INTERNAL = "INTERNAL_ERROR"

#: Failures an operator cannot fix by installing more software.
EXTRACTION_INCOMPLETE_STATES = frozenset(
    {
        EXTRACTION_CORRUPT,
        EXTRACTION_TIMEOUT,
        EXTRACTION_QUOTA,
        EXTRACTION_NONZERO,
        EXTRACTION_EMPTY,
        EXTRACTION_NO_ISOLATION,
        EXTRACTION_INTERNAL,
    }
)


@dataclass
class ExtractionProvenance:
    """Who extracted what, with which helper, under which limits.

    ``isolation`` is ``container`` when the helper ran in a container with no
    network, dropped capabilities and a private size-limited scratch, and
    ``host-process`` when it ran directly on the analysis host. A qualified
    result requires ``container``.
    """

    worker: str = "none"  # podman | docker | host-process | none
    isolation: str = "none"
    worker_image: str | None = None
    worker_digest: str | None = None
    helper: str = "unsquashfs"
    helper_version: str | None = None
    helper_argv: list[str] = field(default_factory=list)
    limits: dict[str, int | float | str] = field(default_factory=dict)
    decoded_bytes: int = 0
    extracted_bytes: int = 0
    extracted_entries: int = 0
    durations_seconds: float = 0.0
    scratch_released: bool = True


@dataclass
class ExtractionResult:
    """Result of firmware extraction.

    ``file_count`` is only meaningful when ``success`` is true: a failed
    extraction did not enumerate the filesystem, so the eligible count is
    unknown rather than zero.
    """

    success: bool
    extraction_dir: Path
    root_filesystems: list[Path] = field(default_factory=list)
    file_count: int = 0
    total_size: int = 0
    signatures_detected: list[SignatureResult] = field(default_factory=list)
    extraction_errors: list[str] = field(default_factory=list)
    backend: str = "unknown"
    backend_version: str | None = None
    worker_digest: str | None = None
    #: One of the ``EXTRACTION_*`` states, so the caller can tell a missing
    #: backend from a failed one without parsing prose.
    state: str = EXTRACTION_UNAVAILABLE
    provenance: ExtractionProvenance | None = None
    #: Entries the extractor saw but deliberately did not materialise.
    omissions: list[str] = field(default_factory=list)


# ──────────────────────────────────────────────
# Slice 3D: boot manifests and board descriptions
# ──────────────────────────────────────────────


@dataclass
class BootSignature:
    """One signature, with presence, key provenance and verification kept apart.

    ``verified`` is a tri-state. It is ``None`` unless an **operator-supplied**
    key was parsed and a signature was checked against it. An embedded key can
    show that a signature matches the key the artifact carries; that is not a
    trust decision, so ``key_source`` says so and ``verified`` stays ``None``.
    """

    present: bool = False
    algo: str | None = None
    key_source: str = "none"  # none | operator-supplied | embedded-not-trusted
    verified: bool | None = None
    key_sha256: str | None = None
    signed_nodes: list[str] = field(default_factory=list)
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "present": self.present,
            "algo": self.algo,
            "key_source": self.key_source,
            "verified": self.verified,
            "key_sha256": self.key_sha256,
            "signed_nodes": list(self.signed_nodes),
            "reason": self.reason,
        }


@dataclass
class BootPayload:
    """A payload a boot configuration references, with its integrity separate."""

    node: str
    kind: str  # kernel | fdt | ramdisk | loadable
    offset: int | None = None
    length: int | None = None
    digest_declared: str | None = None
    digest_observed: str | None = None
    integrity: str = "undeclared"  # match | mismatch | undeclared | out-of-bounds
    signature: BootSignature = field(default_factory=BootSignature)
    board: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "node": self.node,
            "kind": self.kind,
            "offset": self.offset,
            "length": self.length,
            "digest_declared": self.digest_declared,
            "digest_observed": self.digest_observed,
            "integrity": self.integrity,
            "signature": self.signature.as_dict(),
            "board": self.board,
        }


@dataclass
class BootConfiguration:
    """One FIT configuration: the payloads it selects and its own signature."""

    name: str
    default: bool = False
    kernel: str | None = None
    fdt: str | None = None
    ramdisk: str | None = None
    loadables: list[str] = field(default_factory=list)
    signature: BootSignature = field(default_factory=BootSignature)

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "default": self.default,
            "kernel": self.kernel,
            "fdt": self.fdt,
            "ramdisk": self.ramdisk,
            "loadables": list(self.loadables),
            "signature": self.signature.as_dict(),
        }


@dataclass
class BootArtifact:
    """One flattened device tree or FIT, attributed to the declaring artifact."""

    locator: str
    artifact_id: str
    kind: str  # fit | dtb
    size: int
    digest: str
    fdt_version: int = 0
    compatible: list[str] = field(default_factory=list)
    model: str | None = None
    configurations: list[BootConfiguration] = field(default_factory=list)
    default_config: str | None = None
    memory: list[dict[str, Any]] = field(default_factory=list)
    reserved_memory: list[dict[str, Any]] = field(default_factory=list)
    partitions: list[dict[str, Any]] = field(default_factory=list)
    referenced_payloads: list[BootPayload] = field(default_factory=list)
    boot_enforcement: str = "unknown"
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "locator": self.locator,
            "artifact_id": self.artifact_id,
            "kind": self.kind,
            "size": self.size,
            "digest": self.digest,
            "fdt_version": self.fdt_version,
            "compatible": list(self.compatible),
            "model": self.model,
            "configurations": [c.as_dict() for c in self.configurations],
            "default_config": self.default_config,
            "memory": list(self.memory),
            "reserved_memory": list(self.reserved_memory),
            "partitions": list(self.partitions),
            "referenced_payloads": [p.as_dict() for p in self.referenced_payloads],
            "boot_enforcement": self.boot_enforcement,
            "notes": list(self.notes),
        }


@dataclass
class BootAnalysis:
    """The boot section: what the artifacts declare, and what stays unknown."""

    artifacts: list[BootArtifact] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "artifacts": [a.as_dict() for a in self.artifacts],
            "notes": list(self.notes),
        }


# ──────────────────────────────────────────────
# Phase 3c: MCU address spaces (slice 3C)
# ──────────────────────────────────────────────


@dataclass
class McuRange:
    """One contiguous, observed byte range in the device's address space.

    ``start``/``end`` are **device addresses**, never file offsets, and ``end``
    is exclusive. A range exists because records declared those bytes; nothing
    here is inferred from the shape of the file.
    """

    start: int
    end: int
    length: int
    sha256: str
    source_records: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "start": self.start,
            "start_hex": f"0x{self.start:08x}",
            "end": self.end,
            "end_hex": f"0x{self.end:08x}",
            "length": self.length,
            "sha256": self.sha256,
            "source_records": self.source_records,
        }


@dataclass
class McuGap:
    """An unobserved address range between two declared ones.

    It is reported with ``observed: false`` and is never zero-filled: filling it
    would invent bytes the artifact did not carry.
    """

    start: int
    end: int
    length: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "start": self.start,
            "start_hex": f"0x{self.start:08x}",
            "end": self.end,
            "end_hex": f"0x{self.end:08x}",
            "length": self.length,
            "observed": False,
        }


@dataclass
class McuDiagnostic:
    """A structural observation about the encoding itself.

    ``kind`` is one of ``conflict``, ``duplicate``, ``out-of-order``,
    ``missing-eof``, ``missing-block``, ``duplicate-block``,
    ``record-count-mismatch``, ``unknown-record-type``.
    """

    kind: str
    detail: str
    address: int | None = None
    length: int | None = None
    records: list[int] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "detail": self.detail,
            "address": self.address,
            "address_hex": None if self.address is None else f"0x{self.address:08x}",
            "length": self.length,
            "records": list(self.records),
        }


@dataclass
class McuAnalysis:
    """A bare-metal image decoded into a sparse address map (slice 3C).

    ``payload_sha256`` is computed over the merged ranges in ascending address
    order (:data:`iot_hardware_scanner.scanner.mcu_image._DIGEST_PREFIX`), so
    the same payload yields the same digest whichever of the three encodings
    carried it. ``declared_bytes`` counts every byte any record declared;
    ``payload_bytes`` counts the bytes that ended up addressed once. They differ
    only when records overlap, and the difference is a ``conflict`` or
    ``duplicate`` diagnostic rather than a quiet correction.
    """

    format: str
    decoder: str
    decoder_version: str
    locator: str
    digest: str
    ranges: list[McuRange] = field(default_factory=list)
    gaps: list[McuGap] = field(default_factory=list)
    payload_bytes: int = 0
    declared_bytes: int = 0
    payload_sha256: str = ""
    records: int = 0
    start_address: int | None = None
    target_address: int | None = None
    family: str | None = None
    header: str | None = None
    diagnostics: list[McuDiagnostic] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    #: The decoded bytes, one entry per merged range, so the rule sweep reads the
    #: payload rather than re-parsing the encoding. Bounded by the payload budget
    #: and **never serialised**: a report carries addresses and digests, not a
    #: copy of the firmware.
    payload_ranges: list[tuple[int, bytes]] = field(default_factory=list, repr=False)

    def as_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "decoder": self.decoder,
            "decoder_version": self.decoder_version,
            "locator": self.locator,
            "digest": self.digest,
            "ranges": [item.as_dict() for item in self.ranges],
            "gaps": [item.as_dict() for item in self.gaps],
            "payload_bytes": self.payload_bytes,
            "declared_bytes": self.declared_bytes,
            "payload_sha256": self.payload_sha256,
            "records": self.records,
            "start_address": self.start_address,
            "start_address_hex": (
                None if self.start_address is None else f"0x{self.start_address:08x}"
            ),
            "target_address": self.target_address,
            "target_address_hex": (
                None if self.target_address is None else f"0x{self.target_address:08x}"
            ),
            "family": self.family,
            "header": self.header,
            "diagnostics": [item.as_dict() for item in self.diagnostics],
            "notes": list(self.notes),
        }


# ──────────────────────────────────────────────
# Phase 2b: Filesystem Models
# ──────────────────────────────────────────────


@dataclass
class ArtifactNode:
    """One container or file in the image map (slice 3A).

    Every node states the coordinate system its ``offset``/``length`` belong
    to, so a byte range in the gzip wrapper is never confused with a path
    inside the SquashFS filesystem it expands to. Wrapper size, expanded size
    and filesystem extent are separate numbers and stay separate.
    """

    artifact_id: str
    parent_id: str | None
    digest_sha256: str
    format: str  # gzip | squashfs | file | tree
    coordinate_system: str  # container-bytes | filesystem-path
    offset: int = 0
    length: int = 0
    decoder: str = ""
    decoder_version: str | None = None
    depth: int = 0
    locator: str = ""
    #: For a container node: the span it expands to inside its child.
    expanded_bytes: int | None = None
    #: For a filesystem node: declared extent (what the superblock says is used).
    extent_bytes: int | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class ImageMap:
    """The ancestry tree of everything the scan opened."""

    root_artifact_id: str
    nodes: list[ArtifactNode] = field(default_factory=list)

    def add(self, node: ArtifactNode) -> ArtifactNode:
        """Append a node and return it."""
        self.nodes.append(node)
        return node

    def by_id(self, artifact_id: str) -> ArtifactNode | None:
        """Look up a node by identifier."""
        return next((n for n in self.nodes if n.artifact_id == artifact_id), None)

    def children(self, artifact_id: str) -> list[ArtifactNode]:
        """Direct children of a node, in insertion order."""
        return [n for n in self.nodes if n.parent_id == artifact_id]


@dataclass
class SquashfsSuperblock:
    """The fields of a SquashFS v4 superblock this scanner validates."""

    offset: int
    magic: str
    version_major: int
    version_minor: int
    bytes_used: int
    block_size: int
    inode_count: int
    fragment_count: int
    compression: str
    mkfs_time: int
    declared_filesystem_size: int

    def as_dict(self) -> dict[str, Any]:
        """Serialisable form for the report document."""
        return {
            "offset": self.offset,
            "magic": self.magic,
            "version": f"{self.version_major}.{self.version_minor}",
            "bytes_used": self.bytes_used,
            "block_size": self.block_size,
            "inode_count": self.inode_count,
            "fragment_count": self.fragment_count,
            "compression": self.compression,
            "mkfs_time": self.mkfs_time,
        }


@dataclass
class FilesystemFinding:
    """A single file in the extracted filesystem with security categorization.

    ``format`` comes from the file's own first bytes, not from an extension or
    from a service category, so a renamed ELF is still analysed as ELF.
    ``metadata_source`` says whether ``permissions``/``owner_uid`` came out of
    the image (``image``, ``declared``) or from this host (``host``): a
    permission-based conclusion may only rest on the first two.
    """

    path: Path
    absolute_path: Path
    category: FileCategory
    file_type: str
    file_size: int
    permissions: str
    owner_uid: int
    owner_gid: int
    is_suid: bool
    is_world_writable: bool
    hash_sha256: str
    format: str = "other"  # elf | pe | macho | other
    artifact_id: str | None = None
    root_id: str = "rootfs"
    mode: int | None = None
    metadata_source: str = "extracted"
    hardlink_group: str | None = None
    hardlink_count: int = 1


@dataclass
class RootIdentity:
    """One filesystem root the scan enumerated, with its own identity.

    Two roots with the same relative path must stay distinguishable, so every
    locator is qualified by ``root_id`` (``slot_b/etc/shadow``), never by a bare
    relative path.
    """

    root_id: str
    locator: str
    files: int = 0
    directories: int = 0
    bytes: int = 0
    metadata_source: str = "extracted"
    artifact_id: str | None = None
    omissions: list[str] = field(default_factory=list)


@dataclass
class BootEvidence:
    """A configured startup directive observed on one boot path.

    ``source`` is the file the line came from and ``line_number`` locates it,
    so another engineer can open the same line. ``configured`` distinguishes a
    real startup directive from a commented-out example.
    """

    root_id: str
    source: str
    line_number: int
    directive: str
    action: str  # sysinit | respawn | wait | once | boot | start
    program: str
    configured: bool = True


@dataclass
class FilesystemInventory:
    """Complete inventory of an extracted filesystem."""

    rootfs_path: Path
    total_files: int = 0
    total_directories: int = 0
    total_size: int = 0
    findings: list[FilesystemFinding] = field(default_factory=list)
    categories: dict[FileCategory, list[FilesystemFinding]] = field(default_factory=dict)

    # Configured-boot evidence carried from each root through risk scoring
    boot_evidence: list[BootEvidence] = field(default_factory=list)
    metadata_source: str = "extracted"  # "extracted" | "host"
    #: One entry per root the scan enumerated, in enumeration order.
    roots: list[RootIdentity] = field(default_factory=list)
    #: Entries whose permission bits could not be determined (host-derived or
    #: missing), so a permission-based control must answer "unknown".
    permission_unknown_count: int = 0

    # Quick-access indices
    suid_binaries: list[FilesystemFinding] = field(default_factory=list)
    world_writable_files: list[FilesystemFinding] = field(default_factory=list)
    shadow_files: list[FilesystemFinding] = field(default_factory=list)
    ssl_cert_files: list[FilesystemFinding] = field(default_factory=list)
    init_scripts: list[FilesystemFinding] = field(default_factory=list)
    network_services: list[FilesystemFinding] = field(default_factory=list)


# ──────────────────────────────────────────────
# Phase 3: Entropy Models
# ──────────────────────────────────────────────


@dataclass
class EntropyBlock:
    """A single window with its computed entropy and true byte length.

    ``entropy`` is bits/byte on a 0.0-8.0 scale. ``length`` is the number of
    bytes actually in the window, so the final window of a 129-byte input with
    128-byte blocks reports length 1 and offset 128, not a padded 256.
    """

    offset: int
    entropy: float
    byte_distribution: dict[int, int] = field(default_factory=dict)
    length: int = 0


@dataclass
class EntropyRegion:
    """A contiguous region classified by entropy characteristics."""

    start_offset: int
    end_offset: int
    size: int
    avg_entropy: float
    classification: str  # compressed | encrypted | code | data | padding | unknown
    confidence: float  # 0.0 - 1.0


@dataclass
class EntropyProfile:
    """Complete entropy analysis of a firmware image.

    Units are explicit and non-negotiable: ``overall_entropy`` and every
    ``EntropyRegion.avg_entropy`` are Shannon entropy in **bits per byte** on a
    0.0-8.0 scale. ``window_mean_entropy`` is the mean of per-window values and
    is labelled as such; it is not a whole-input measurement.

    An entropy measurement is an observation about byte distribution. It never
    establishes that data is encrypted, readable, or that a control passed.
    """

    firmware_path: Path
    total_blocks: int
    block_size: int
    blocks: list[EntropyBlock] = field(default_factory=list)
    regions: list[EntropyRegion] = field(default_factory=list)
    overall_entropy: float = 0.0  # bits/byte over the combined histogram
    window_mean_entropy: float = 0.0  # mean of per-window values
    bytes_analyzed: int = 0
    bytes_sampled: bool = False  # True when only part of the input was read
    has_encrypted_regions: bool = False  # format evidence only, not entropy
    has_compressed_regions: bool = False  # format evidence only, not entropy
    firmware_partially_readable: bool = True  # never derived from entropy alone
    units: str = "bits/byte"


# ──────────────────────────────────────────────
# Phase 3b: Binary Intelligence Models
# ──────────────────────────────────────────────


@dataclass
class ElfReport:
    """What one ELF file declares about itself (slice 3B).

    Every field is read from a structure that supports it. ``unknown`` lists
    the properties that could not be decided — a stripped binary has no symbol
    table, so canary and FORTIFY stay unknown rather than false, and an image
    cannot earn hardening credit from missing evidence.
    """

    locator: str  # root-qualified path, e.g. "squashfs-root/bin/busybox"
    artifact_id: str | None = None
    digest_sha256: str = ""
    size: int = 0
    elf_class: str = ""  # ELF32 | ELF64
    byte_order: str = ""  # little | big
    machine: int = -1
    machine_name: str = ""
    elf_type: str = ""  # EXEC | DYN | REL
    os_abi: str = ""
    interpreter: str | None = None
    needed: list[str] = field(default_factory=list)
    soname: str | None = None
    segments: list[dict[str, Any]] = field(default_factory=list)
    build_id: str | None = None
    stack_executable: bool | None = None
    pie: bool | None = None
    relro: str | None = None  # full | partial | none | unknown
    canary: bool | None = None
    fortify: bool | None = None
    unknown: list[str] = field(default_factory=list)
    parser: str = "pyelftools"
    parser_version: str | None = None


@dataclass
class OpkgPackageRecord:
    """One installed-package stanza, read verbatim from the image."""

    name: str
    version: str  # full version string, including the -rN revision
    architecture: str
    status: str
    installed: bool
    held: bool
    source: str = ""
    depends: str = ""
    #: Byte range of the stanza in the status database, and its first line.
    evidence_start: int = 0
    evidence_end: int = 0
    evidence_line: int = 1


@dataclass
class OpkgInventory:
    """The installed-package database of one root filesystem."""

    locator: str
    database_sha256: str
    byte_length: int
    records: list[OpkgPackageRecord] = field(default_factory=list)
    installed_count: int = 0
    held_count: int = 0
    unparsed_stanzas: int = 0
    truncated: bool = False
    parser_version: str = "1"


@dataclass
class BinaryHardening:
    """Binary hardening check results."""

    nx_enabled: bool | None = None
    stack_canary: bool | None = None
    pie_enabled: bool | None = None
    relro: str | None = None  # "full" | "partial" | "none"
    fortify_source: bool | None = None


@dataclass
class BinaryMetadata:
    """Metadata extracted from an ELF/PE/Mach-O binary."""

    path: Path
    architecture: str | None = None
    endianness: str | None = None  # "little" | "big"
    link_type: str | None = None  # "static" | "dynamic"
    hardening: BinaryHardening = field(default_factory=BinaryHardening)
    version_strings: dict[str, str] = field(default_factory=dict)
    #: The full structural record, present when the file was parsed as ELF.
    elf: ElfReport | None = None


@dataclass
class BinaryIntelligenceResult:
    """Result of binary intelligence analysis across all binaries."""

    binaries: list[BinaryMetadata] = field(default_factory=list)
    total_binaries: int = 0
    hardened_binaries: int = 0
    unhardened_binaries: int = 0
    #: Files selected as eligible that could not be parsed, with the reason.
    rejected: list[dict[str, str]] = field(default_factory=list)


# ──────────────────────────────────────────────
# Phase 4: Credential Models
# ──────────────────────────────────────────────


@dataclass
class YaraMatch:
    """A single YARA match, with the destination its category earns.

    ``destination`` is the *typed* answer to "what kind of fact is this?" —
    a credential, a configured service, a cryptographic algorithm, or an
    indicator. A rule file's category decides it, once, in
    :mod:`iot_hardware_scanner.yara.yara_engine`, so a match can never be
    relabelled by the detector that happens to see it first.

    ``namespace`` is the compiled rule file's namespace, ``rule_file`` its
    name and ``ruleset_digest`` the digest of the whole compiled set, so a
    finding is traceable to the exact rules that produced it.
    """

    rule_name: str
    namespace: str
    meta: dict[str, Any] = field(default_factory=dict)
    strings: list[tuple[int, str, bytes]] = field(
        default_factory=list,
    )  # (offset, identifier, data)
    file_path: Path | None = None
    #: credential | service | crypto | indicator
    destination: str = "indicator"
    #: Category declared by the rule's own meta block.
    category: str = ""
    #: Severity declared by the rule's own meta block (a label, not a verdict).
    severity: str = "INFO"
    rule_file: str = ""
    ruleset_digest: str = ""

    @property
    def offsets(self) -> list[int]:
        """Every offset at which this rule matched, ascending."""
        return sorted({offset for offset, _ident, _data in self.strings})


@dataclass
class RuleFileRecord:
    """One compiled rule file, with the digest that identifies it."""

    namespace: str
    name: str
    sha256: str
    rule_count: int
    destinations: list[str] = field(default_factory=list)


@dataclass
class RuleSetInfo:
    """The one compiled rule set a run used, and what it could not compile."""

    digest: str = ""
    engine: str = "yara-python"
    engine_version: str | None = None
    files: list[RuleFileRecord] = field(default_factory=list)
    #: Files that were found but rejected, with the reason. A rejected rule is
    #: a coverage gap, so it is recorded rather than logged and forgotten.
    errors: list[dict[str, str]] = field(default_factory=list)
    source: str = "package"  # package | package+explicit

    @property
    def available(self) -> bool:
        """Whether any rule was compiled at all."""
        return bool(self.files)


@dataclass
class CredentialFinding:
    """A discovered credential or secret."""

    severity: Severity
    category: str  # password | api_key | private_key | token | connection_string
    file_path: Path
    line_number: int | None = None
    offset: int | None = None
    matched_pattern: str = ""
    masked_value: str = ""
    raw_value_hash: str = ""
    context: str = ""
    is_default: bool = False
    is_placeholder: bool = False
    rule_id: str = ""
    #: Every artifact location this finding was evidenced at. Deduplication
    #: keeps the union, so two copies of one secret stay two locations.
    occurrences: list[str] = field(default_factory=list)
    #: Namespace of the rule that produced the match, and the digest of the
    #: compiled rule set, when the finding came from YARA.
    namespace: str = ""
    ruleset_digest: str = ""
    #: Why a rule match was not promoted, when the semantics rules refused it.
    applicability_note: str = ""

    def with_rule_id(self, rule_id: str) -> CredentialFinding:
        """Attach the stable rule identifier used by the exit contract."""
        self.rule_id = rule_id
        return self


@dataclass
class PasswdEntry:
    """Parsed /etc/passwd entry."""

    username: str
    uid: int
    gid: int
    home: str
    shell: str
    has_password_field: bool = False
    is_root_equivalent: bool = False
    has_login_shell: bool = False
    password_state: str = "unknown"
    line_number: int | None = None


@dataclass
class ShadowEntry:
    """Parsed /etc/shadow entry."""

    username: str
    hash_algorithm: str | None  # MD5 | SHA-256 | SHA-512 | bcrypt | None
    hash_value: str = ""
    is_empty: bool = False
    is_locked: bool = False
    days_since_change: int | None = None
    severity: Severity = Severity.INFO
    line_number: int | None = None
    password_state: str = "unknown"


# ──────────────────────────────────────────────
# Phase 5: CVE Models
# ──────────────────────────────────────────────


@dataclass
class SoftwareComponent:
    """Detected software component with version.

    ``occurrences`` keeps every place the component was evidenced, so
    deduplication never loses a locator: two roots with different revisions of
    the same package remain two distinguishable records.
    """

    vendor: str
    product: str
    version: str
    cpe_string: str
    source_file: Path
    source_method: str  # opkg_status | string_extraction | elf_metadata
    architecture: str | None = None
    #: How the vendor/product pair was decided: ``nist-mapped`` (an
    #: authoritative NIST vendor/product row), ``opkg-package-name`` (no
    #: authoritative row; named from the package with vendor openwrt) or
    #: ``banner`` (a version string in a file, candidate confidence).
    cpe_basis: str = "nist-mapped"
    #: Exact locator inside the evidence, e.g. the opkg stanza byte range.
    evidence: str = ""
    digest_sha256: str = ""
    confidence: str = "recorded"  # recorded | candidate
    occurrences: list[str] = field(default_factory=list)


@dataclass
class CVEFinding:
    """A CVE discovered for a software component.

    Applicability is kept separate from severity and from exploitation:
    ``applicability`` states how the shipped version was matched,
    ``is_in_kev`` and ``exploit_available_public`` are independent facts about
    the CVE, and ``provider_score`` is the number the provider published rather
    than one derived here.
    """

    cve_id: str
    severity: Severity
    cvss_v3_score: float | None = None
    cvss_v3_vector: str | None = None
    description: str = ""
    affected_product: str = ""
    affected_version: str = ""
    published_date: str = ""
    references: list[str] = field(default_factory=list)
    is_in_kev: bool = False
    exploit_available: bool = False
    #: How the advisory's own applicability statement matched this component.
    applicability: str = "UNKNOWN"  # cpe-exact | version-range | keyword-unverified
    #: The provider's published score and the time the provider recorded it.
    provider_score: float | None = None
    provider: str = ""
    last_modified: str = ""
    #: Every component occurrence this CVE applies to is kept, never deduplicated away.
    occurrences: list[str] = field(default_factory=list)
    #: True when a vendor backport makes the recorded version uncertain.
    vendor_backport_uncertain: bool = False
    #: True when the match came from a stale snapshot.
    stale: bool = False


# ──────────────────────────────────────────────
# Phase 5b: Cryptographic algorithm evidence (slice 4A/4D)
# ──────────────────────────────────────────────


@dataclass
class CryptoFinding:
    """An observed cryptographic algorithm, distinct from binary hardening.

    ``strength`` is only ever ``weak`` when the rule set identified a named
    weak algorithm; the absence of a match is not evidence of strength.
    """

    rule_id: str
    algorithm: str
    strength: str  # weak | unknown
    file_path: Path
    offset: int | None = None
    matched_pattern: str = ""
    namespace: str = ""
    ruleset_digest: str = ""
    description: str = ""
    evidence: str = ""


# ──────────────────────────────────────────────
# Phase 5c: Advisory applicability (slice 4C)
# ──────────────────────────────────────────────


@dataclass
class AdvisorySnapshotInfo:
    """The local advisory snapshot a run applied, and where it came from."""

    path: str
    digest_sha256: str
    schema: str
    provider: str
    acquired_at: str
    entries: int
    age_days: float
    stale: bool
    includes_kev: bool = False
    sample: bool = False


@dataclass
class AdvisoryLookup:
    """One component's advisory lookup, with an explicit state.

    ``state`` is one of ``MATCHED``, ``KNOWN_EMPTY``, ``UNAVAILABLE``,
    ``STALE`` or ``PARTIAL``. A clean verdict requires every lookup to be
    ``KNOWN_EMPTY``; anything else is a stated gap.
    """

    component: str
    version: str
    cpe: str = ""
    state: str = "KNOWN_EMPTY"
    matches: int = 0
    reason: str = ""


@dataclass
class AdvisoryAssessment:
    """The result of applying one local snapshot to the component inventory."""

    snapshot: AdvisorySnapshotInfo | None = None
    lookups: list[AdvisoryLookup] = field(default_factory=list)
    state: str = "UNAVAILABLE"  # ASSESSED | STALE | PARTIAL | UNAVAILABLE
    matched: int = 0
    kev_matches: int = 0
    keyword_candidates_rejected: int = 0
    kev_source: str = ""

    @property
    def complete(self) -> bool:
        """Whether every lookup settled, so a clean result means something."""
        return bool(self.lookups) and all(
            lookup.state in ("MATCHED", "KNOWN_EMPTY") for lookup in self.lookups
        )


# ──────────────────────────────────────────────
# Phase 6: C2 Models
# ──────────────────────────────────────────────


@dataclass
class C2Finding:
    """A C2 or malicious indicator detection."""

    severity: str  # LIKELY_C2 | SUSPICIOUS | INFORMATIONAL
    indicator_type: str  # domain | ip | malware_signature | backdoor_service
    value: str
    file_path: Path
    suspicion_score: float = 0.0
    score_breakdown: dict[str, float] = field(default_factory=dict)
    threat_intel_match: str | None = None
    mitre_attack: str | None = None
    description: str = ""
    rule_id: str = ""
    #: Every artifact location this indicator was found in, sorted.
    occurrences: list[str] = field(default_factory=list)


# ──────────────────────────────────────────────
# Phase 7: Risk Score Models
# ──────────────────────────────────────────────


@dataclass
class ControlScore:
    """Score for a single security control."""

    control_id: int
    control_name: str
    result: str  # PASS | PARTIAL | FAIL
    points: float = 0.0
    max_points: float = 10.0
    evidence: list[str] = field(default_factory=list)
    remediation: str = ""


@dataclass
class RiskScore:
    """Overall risk assessment."""

    total_score: float
    risk_level: RiskLevel
    control_scores: list[ControlScore] = field(default_factory=list)
    weighted_breakdown: dict[str, float] = field(default_factory=dict)
    executive_summary: str = ""
    owasp_iot_mapping: dict[str, int] = field(default_factory=dict)


# ──────────────────────────────────────────────
# Universal Finding
# ──────────────────────────────────────────────


@dataclass
class Finding:
    """Universal finding schema for uniform processing across all modules."""

    finding_id: str
    scanner_module: str
    severity: Severity
    title: str
    description: str
    file_path: Path | None = None
    remediation: str | None = None
    references: list[str] = field(default_factory=list)
    confidence: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)
