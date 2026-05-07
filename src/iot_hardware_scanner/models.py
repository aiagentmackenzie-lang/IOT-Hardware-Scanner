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


# ──────────────────────────────────────────────
# Core: Scan Context
# ──────────────────────────────────────────────


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

    # Populated by Phase 7
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
    """Result of firmware extraction."""

    success: bool
    extraction_dir: Path
    root_filesystems: list[Path] = field(default_factory=list)
    file_count: int = 0
    total_size: int = 0
    signatures_detected: list[SignatureResult] = field(default_factory=list)
    extraction_errors: list[str] = field(default_factory=list)


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
class FilesystemInventory:
    """Complete inventory of an extracted filesystem."""

    rootfs_path: Path
    total_files: int = 0
    total_directories: int = 0
    total_size: int = 0
    findings: list[FilesystemFinding] = field(default_factory=list)
    categories: dict[FileCategory, list[FilesystemFinding]] = field(default_factory=dict)

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
    """A single block with its computed entropy."""

    offset: int
    entropy: float
    byte_distribution: dict[int, int] = field(default_factory=dict)


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
    """Complete entropy analysis of a firmware image."""

    firmware_path: Path
    total_blocks: int
    block_size: int
    blocks: list[EntropyBlock] = field(default_factory=list)
    regions: list[EntropyRegion] = field(default_factory=list)
    overall_entropy: float = 0.0
    has_encrypted_regions: bool = False
    has_compressed_regions: bool = False
    firmware_partially_readable: bool = True


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
