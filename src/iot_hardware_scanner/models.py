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
    RISK_CONTROLS = "risk_controls"


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

    @property
    def applicability(self) -> str:
        """Whether this check applied to the selected profile and artifact."""
        return "NOT_APPLICABLE" if self.status is CheckStatus.NOT_APPLICABLE else "APPLICABLE"


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

    # Populated by the orchestrator: what ran, what did not, and why
    profile: str = "firmware-static"
    profile_version: str = "2.0"
    stages: list[StageResult] = field(default_factory=list)
    assessment: Assessment | None = None

    # Populated by Phase 2
    extracted_rootfs: Path | None = None
    extraction_result: ExtractionResult | None = None

    # Populated by Phase 2b
    filesystem_inventory: FilesystemInventory | None = None

    # Populated by Phase 3
    entropy_profile: EntropyProfile | None = None
    binary_intelligence: BinaryIntelligenceResult | None = None

    # Populated by Phase 4
    credential_findings: list[CredentialFinding] = field(default_factory=list)

    # Populated by Phase 5
    cve_findings: list[CVEFinding] = field(default_factory=list)
    software_components: list[SoftwareComponent] = field(default_factory=list)

    # Populated by Phase 6
    c2_findings: list[C2Finding] = field(default_factory=list)

    # Populated by Phase 7: named checks with evidence status. There is no
    # aggregate grade; see scanner/risk_scorer.py.
    controls: list[ControlResult] = field(default_factory=list)

    # Legacy only: a v1 report's historical grade, preserved for replay.
    # New scans never populate this (the grade is retired).
    risk_score: RiskScore | None = None


# ──────────────────────────────────────────────
# Phase 1: Ingest Models
# ──────────────────────────────────────────────


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


# ──────────────────────────────────────────────
# Phase 2b: Filesystem Models
# ──────────────────────────────────────────────


@dataclass
class FilesystemFinding:
    """A single file in the extracted filesystem with security categorization."""

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


@dataclass
class BinaryIntelligenceResult:
    """Result of binary intelligence analysis across all binaries."""

    binaries: list[BinaryMetadata] = field(default_factory=list)
    total_binaries: int = 0
    hardened_binaries: int = 0
    unhardened_binaries: int = 0


# ──────────────────────────────────────────────
# Phase 4: Credential Models
# ──────────────────────────────────────────────


@dataclass
class YaraMatch:
    """A single YARA rule match result."""

    rule_name: str
    namespace: str
    meta: dict[str, Any] = field(default_factory=dict)
    strings: list[tuple[int, str, bytes]] = field(
        default_factory=list,
    )  # (offset, identifier, data)
    file_path: Path | None = None


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
    """Detected software component with version."""

    vendor: str
    product: str
    version: str
    cpe_string: str
    source_file: Path
    source_method: str  # string_extraction | package_manifest
    architecture: str | None = None


@dataclass
class CVEFinding:
    """A CVE discovered for a software component."""

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
