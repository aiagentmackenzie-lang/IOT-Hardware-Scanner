# Software Design Requirements (SDR)
# IoT Hardware Scanner — Firmware Security Analysis Platform

**Document Version:** 1.0  
**Classification:** Internal — Build Bible  
**Author:** Lead Security Engineer  
**Date:** 2025-05-06  
**Status:** Approved for Build  

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem Statement & Market Justification](#2-problem-statement--market-justification)
3. [Threat Landscape & Real-World Incidents](#3-threat-landscape--real-world-incidents)
4. [Project Scope & Build Boundaries](#4-project-scope--build-boundaries)
5. [Architecture Overview](#5-architecture-overview)
6. [Standards & Methodology Alignment](#6-standards--methodology-alignment)
7. [Phase 1 — Core Infrastructure & Firmware Ingestion](#7-phase-1--core-infrastructure--firmware-ingestion)
8. [Phase 2 — Extraction Engine & Filesystem Analysis](#8-phase-2--extraction-engine--filesystem-analysis)
9. [Phase 3 — Entropy & Binary Intelligence](#9-phase-3--entropy--binary-intelligence)
10. [Phase 4 — Credential & Secret Detection](#10-phase-4--credential--secret-detection)
11. [Phase 5 — CVE Matching & Vulnerability Correlation](#11-phase-5--cve-matching--vulnerability-correlation)
12. [Phase 6 — C2 & Malicious Indicator Detection](#12-phase-6--c2--malicious-indicator-detection)
13. [Phase 7 — Risk Scoring & Compliance Reporting](#13-phase-7--risk-scoring--compliance-reporting)
14. [Data Model & Schema Definitions](#14-data-model--schema-definitions)
15. [CLI & Output Specifications](#15-cli--output-specifications)
16. [Testing Strategy](#16-testing-strategy)
17. [Competitive Landscape Analysis](#17-competitive-landscape-analysis)
18. [Technology Decisions & Rationale](#18-technology-decisions--rationale)
19. [Directory Structure](#19-directory-structure)
20. [Appendix A — Supported Firmware Formats](#appendix-a--supported-firmware-formats)
21. [Appendix B — YARA Rule Catalog](#appendix-b--yara-rule-catalog)
22. [Appendix C — Default Credential Database Schema](#appendix-c--default-credential-database-schema)
23. [Appendix D — Threat Intelligence Feed Specification](#appendix-d--threat-intelligence-feed-specification)

---

## 1. Executive Summary

**IoT Hardware Scanner** is a Python-based, defensive firmware analysis platform that automates the static security assessment of IoT/embedded/OT firmware images. It covers the full static-analysis pipeline: firmware ingestion → extraction → filesystem analysis → credential detection → entropy analysis → CVE correlation → C2 indicator detection → risk-scored reporting.

The tool is **defensive-only**. It does not exploit vulnerabilities, generate payloads, or interact with live devices. It analyses firmware binaries offline to surface security weaknesses before deployment.

### Core Capabilities

| # | Capability | Output |
|---|---|---|
| 1 | Firmware extraction (binwalk + unblob) | Extracted filesystem tree |
| 2 | Entropy analysis (Shannon) | Entropy graph + high-entropy region map |
| 3 | Filesystem content scanning | Password files, configs, keys, services |
| 4 | Credential & secret detection | Hardcoded passwords, API keys, tokens, private keys |
| 5 | CVE matching via NVD API | CVEs per detected software component |
| 6 | C2 & malicious indicator detection | Hardcoded C2 domains, suspicious IPs, backdoor patterns |
| 7 | Risk scoring & compliance mapping | Numerical risk score + OWASP IoT mapping |
| 8 | Report generation | JSON, Markdown, terminal (colored) |

### Design Principles

1. **Modular** — every scanner is an independent module with a stable interface
2. **Deterministic** — same input always produces same output (no randomness in analysis)
3. **Offline-first** — all core analysis works without network; NVD API is optional/enhancement
4. **No execution** — firmware is never emulated or executed; purely static analysis
5. **Extensible** — YARA rules, credential patterns, and CVE mapping are user-overridable

---

## 2. Problem Statement & Market Justification

### The Problem

By 2025, over 75 billion IoT devices are deployed worldwide. The vast majority run firmware with:

- **Hardcoded credentials** baked into released binaries
- **Outdated libraries** (BusyBox 1.x, OpenSSL 1.0.x, dropbear) never patched
- **Backdoor services** (telnetd, debug shells) left in production images
- **C2 infrastructure** hardcoded in malware-compromised supply chains
- **No SBOM** — manufacturers have no visibility into their own component inventory

Professional firmware analysis tools exist but fall into two camps:

- **Enterprise/Commercial** (Forescout, Claroty, Forescout) — expensive, closed-source, CI-integrated
- **Research/Manual** (binwalk CLI, firmwalker bash script) — require expertise, no orchestration

**There is no mid-tier, modular, Pythonic, defensive firmware scanner that security teams can integrate into CI/CD or run as a standalone CLI without a 16-core Docker environment.**

### Our Differentiator

| Feature | EMBA (3.4K ⭐) | Firmwalker (1.2K ⭐) | IoT-Firmware-Scanner (0 ⭐) | **IoT Hardware Scanner** |
|---|---|---|---|---|
| Language | Bash | Bash | Python | Python |
| Extraction | Binwalk + QEMU | None (post-extract) | Binwalk subprocess | pybinwalk (native) |
| Entropy Analysis | Via binwalk -E | No | No | Standalone Shannon engine |
| Credential Detection | Regex | grep patterns | Regex + severity | YARA + regex + entropy-gated |
| CVE Matching | cve-bin-tool | None | NVD API | NVD API + local cache |
| C2 Detection | None | IP/URL grep | None | Threat-intel feed + YARA + domain heuristics |
| Compliance Scoring | None | None | 10-point checklist | 12-control risk model |
| SBOM Generation | CycloneDX/SPDX | None | None | CycloneDX (Phase 5+) |
| Resource Requirements | 8-16GB RAM, Docker | Any | Any | Any (no Docker required) |
| Architecture | Monolithic shell | Single shell script | Flat Python files | Modular Python package |

---

## 3. Threat Landscape & Real-World Incidents

The following incidents justify every detection category in this tool:

| Incident | Year | Detection Category | Our Module |
|---|---|---|---|
| **Mirai botnet** — scanned for default credentials, infected millions | 2016 | Hardcoded credentials | Credential Scanner |
| **VPNFilter** — Russian GRU malware, 500K+ routers infected via firmware exploit | 2018 | C2 domains in firmware | C2 Detector |
| **Silex malware** — bricked IoT devices by wiping firmware | 2019 | Unsafe service exposure | Filesystem Scanner |
| **CISA KEV Catalog** — mandated vulnerability patching for federal systems | 2021+ | Known exploited CVEs | CVE Scanner |
| **Jackskid botnet** — fast-flux C2 with ENS blockchain resolution, 98+ IPs | 2025-26 | C2 domain/IP detection | C2 Detector |
| **Kimwolf/Aisuru v7** — Ethereum ENS C2, Tor backup, DDoS 15+ methods | 2026 | Blockchain C2 indicators | C2 Detector |
| **CVE-2024-41592** — DrayTek GetCGI buffer overflow (CVSS 10.0) | 2024 | Known vulnerable CGI binaries | CVE Scanner |
| **CVE-2023-20198** — Cisco IOS XE, 40-50K devices compromised | 2023 | Outdated web server binaries | CVE Scanner |
| **CVE-2025-20334** — Cisco IOS XE HTTP API command injection | 2025 | Command injection in web services | Filesystem Scanner |

These are not theoretical. They are **ongoing, active, and escalating**.

---

## 4. Project Scope & Build Boundaries

### In Scope (Build)

- Static analysis of firmware binary images (`.bin`, `.img`, `.elf`, `.hex`, `.uf2`, `.fw`)
- Firmware extraction via binwalk (recursive Matryoshka extraction)
- Entropy analysis with configurable block sizes
- Filesystem content scanning for security-relevant files
- Hardcoded credential detection (passwords, keys, API tokens)
- CVE correlation against NVD for detected software components
- C2/malicious indicator detection (domains, IPs, backdoor services)
- YARA rule-based detection engine
- Risk scoring with compliance mapping (OWASP IoT Top 10)
- Multi-format reporting (JSON, Markdown, terminal)
- SBOM generation (CycloneDX format)

### Out of Scope (Explicit Exclusions)

- Dynamic analysis / firmware emulation (QEMU, Firmadyne)
- Runtime analysis / debugger attachment
- Exploit generation or proof-of-concept creation
- Network scanning of live devices
- MITM interception of firmware updates
- Hardware-level extraction (UART, JTAG, chip-off)
- Reverse engineering of encrypted/packed firmware payloads

These out-of-scope items align with OWASP FSTM Stages 6-9 (emulation, dynamic analysis, runtime analysis, exploitation), which are beyond our static-only build envelope.

---

## 5. Architecture Overview

### System Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                         IoT Hardware Scanner                        │
│                                                                     │
│  ┌───────────┐    ┌──────────────┐    ┌───────────────────────┐    │
│  │   CLI /    │    │   Orchestrator│    │    Report Generator    │    │
│  │  Python   │───▶│   (Pipeline)  │───▶│  JSON/MD/Terminal     │    │
│  │  API      │    │              │    │                       │    │
│  └───────────┘    └──────┬───────┘    └───────────────────────┘    │
│                           │                                        │
│          ┌────────────────┼────────────────┐                       │
│          │         Pipeline Stages         │                       │
│          ▼                                 ▼                       │
│  ┌──────────────┐              ┌──────────────────┐               │
│  │ Phase 1:     │              │ Phase 2:         │               │
│  │ Ingest &     │─────────────▶│ Extract &        │               │
│  │ Validate     │              │ Filesystem Map   │               │
│  └──────────────┘              └────────┬─────────┘               │
│                                          │                        │
│                  ┌───────────────────────┼───────────────┐        │
│                  ▼                       ▼               ▼        │
│         ┌──────────────┐    ┌──────────────┐  ┌──────────────┐   │
│         │ Phase 3:     │    │ Phase 4:     │  │ Phase 6:     │   │
│         │ Entropy &    │    │ Credential   │  │ C2 & Malware │   │
│         │ Binary Intel │    │ Detection   │  │ Indicators   │   │
│         └──────────────┘    └──────────────┘  └──────────────┘   │
│                                                       │         │
│                                            ┌──────────▼────┐     │
│                                            │ Phase 5:      │     │
│                                            │ CVE Matching  │     │
│                                            └───────────────┘     │
│                                                       │         │
│                                            ┌──────────▼────┐     │
│                                            │ Phase 7:      │     │
│                                            │ Risk & Report  │     │
│                                            └───────────────┘     │
│                                                                   │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                 Shared Resources                            │   │
│  │  YARA Engine │ NVD Cache │ Threat Intel DB │ Logger │ Config│   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### Module Dependency Graph

```
firmware_ingest
    └──► firmware_extractor (requires: pybinwalk)
              └──► filesystem_scanner  (requires: extracted rootfs path)
                        ├──► credential_scanner  (requires: file paths)
                        ├──► entropy_analyzer    (requires: raw binary + extracted files)
                        ├──► c2_detector         (requires: strings + extracted files + threat feeds)
                        └──► cve_scanner        (requires: detected software components)
                                  └──► risk_scorer  (requires: all findings)
                                            └──► report_generator  (requires: risk score + all findings)
```

---

## 6. Standards & Methodology Alignment

### OWASP Firmware Security Testing Methodology (FSTM)

Our tool covers **FSTM Stages 3-5** (static analysis portion):

| FSTM Stage | Description | Our Module |
|---|---|---|
| Stage 3 | Analyze firmware (file type, entropy, signatures) | `entropy_analyzer` + `firmware_ingest` |
| Stage 4 | Extract filesystem | `firmware_extractor` |
| Stage 5 | Analyze filesystem contents | `filesystem_scanner` + `credential_scanner` + `c2_detector` + `cve_scanner` |

### OWASP IoT Security Testing Guide (ISTG) Coverage

| ISTG Test Case | Our Detection |
|---|---|
| ISTG-FW-SCRT-001 | Secrets stored in public storage → `credential_scanner` |
| ISTG-FW-SCRT-002 | Unencrypted storage of secrets → `credential_scanner` (plaintext detection) |
| ISTG-FW-SCRT-003 | Hardcoded secrets → `credential_scanner` + YARA rules |
| ISTG-FW-CONF-001 | Outdated software → `cve_scanner` |
| ISTG-FW-CONF-002 | Unnecessary software → `filesystem_scanner` |
| ISTG-FW-CRYPT-001 | Weak cryptographic algorithms → `entropy_analyzer` + `cve_scanner` |

### OWASP IoT Top 10 (2018) Mapping

| IoT Top 10 | Our Detection |
|---|---|
| I1 — Weak/Hardcoded Passwords | `credential_scanner` |
| I2 — Insecure Network Services | `filesystem_scanner` (telnet, ssh, tftp detection) |
| I5 — Outdated Components | `cve_scanner` |
| I7 — Insecure Data Storage | `credential_scanner` (plaintext secrets) |
| I9 — Insecure Default Settings | `filesystem_scanner` (default configs) |

---

## 7. Phase 1 — Core Infrastructure & Firmware Ingestion

**Build Order:** First  
**Estimated Effort:** 3-4 days  
**Deliverable:** Working CLI that accepts firmware files, validates them, and produces initial metadata

### 7.1 Firmware Ingest Module

**File:** `src/scanner/firmware_ingest.py`

#### Responsibilities

1. Accept firmware file path via CLI or Python API
2. Validate file exists and is non-empty
3. Compute cryptographic hashes (SHA-256, MD5) for integrity tracking
4. Identify file type via `python-magic` / `file` command
5. Extract basic file metadata (size, extension, apparent architecture)
6. Create per-scan output directory structure
7. Initialize the scan context object passed through all phases

#### Interface

```python
class FirmwareIngest:
    def __init__(self, config: ScannerConfig) -> None: ...
    
    def ingest(self, firmware_path: Path) -> ScanContext:
        """
        Validate and catalog the firmware image.
        
        Returns:
            ScanContext with firmware metadata populated
        
        Raises:
            FirmwareNotFoundError: path does not exist
            FirmwareEmptyError: file is 0 bytes
            FirmwareTooLargeError: exceeds max_file_size_mb
            FirmwareUnreadableError: permission denied
        """
        ...
```

#### ScanContext Object

```python
@dataclass
class ScanContext:
    scan_id: str                # UUID for this scan
    firmware_path: Path         # Original firmware file path
    output_dir: Path            # Per-scan output directory
    file_hash_sha256: str      # SHA-256 of the firmware
    file_hash_md5: str         # MD5 of the firmware
    file_size: int             # Size in bytes
    file_type: str             # Detected file type (from magic bytes)
    firmware_name: str         # Filename without extension
    started_at: datetime       # Scan start timestamp
    
    # Populated by later phases
    extracted_rootfs: Path | None = None
    entropy_profile: EntropyProfile | None = None
    filesystem_findings: list[FilesystemFinding] = field(default_factory=list)
    credential_findings: list[CredentialFinding] = field(default_factory=list)
    c2_findings: list[C2Finding] = field(default_factory=list)
    cve_findings: list[CVEFinding] = field(default_factory=list)
    risk_score: RiskScore | None = None
```

#### File Size Limits

| Size Category | Limit | Behavior |
|---|---|---|
| Small | < 50 MB | Full analysis, small block size (256B) for entropy |
| Medium | 50-500 MB | Full analysis, adaptive block size |
| Large | 500 MB - 2 GB | Selective analysis, 1024B+ block size, skip known-benign regions |
| Too Large | > 2 GB | Reject with `FirmwareTooLargeError` |

#### Validation Rules

1. File must exist and be a regular file (not directory, symlink, or device)
2. File must be readable by current user
3. File must be > 0 bytes
4. File must not exceed `max_file_size_mb` (default: 2048)
5. Filename must not contain path traversal sequences (`..`, null bytes)

---

## 8. Phase 2 — Extraction Engine & Filesystem Analysis

**Build Order:** Second (depends on Phase 1)  
**Estimated Effort:** 5-6 days  
**Deliverable:** Firmware extraction + full filesystem inventory with security categorization

### 8.1 Firmware Extractor Module

**File:** `src/scanner/firmware_extractor.py`

#### Design Decisions

We use **pybinwalk** (Python bindings for Binwalk v3) as the primary extraction engine. This gives us:

- Native Python API (no `subprocess` calls)
- Rust-powered speed (Binwalk v3 is written in Rust)
- In-memory scanning capability (`scan_bytes()`)
- Configurable include/exclude filters for signature types

Falls back to `subprocess` invocation of `binwalk` CLI if pybinwalk is not installed.

#### Extraction Strategy

```
firmware.bin
    │
    ▼ binwalk scan ──► identify embedded filesystems (squashfs, jffs2, cramfs, ubifs, cpio, etc.)
    │
    ▼ binwalk extract ──► _firmware.bin.extracted/
        ├── squashfs-root/          ← primary root filesystem
        ├── 0-filesystem.jffs2/    ← secondary filesystem
        └── ...                     ← any additional embedded data
```

#### Interface

```python
class FirmwareExtractor:
    def __init__(self, config: ScannerConfig) -> None: ...
    
    def scan(self, firmware_path: Path) -> list[SignatureResult]:
        """Identify embedded files/data via binwalk signature scan (no extraction)."""
        ...
    
    def extract(self, firmware_path: Path, output_dir: Path) -> ExtractionResult:
        """
        Extract embedded filesystems recursively.
        
        Args:
            firmware_path: Path to firmware image
            output_dir: Directory for extracted contents
            
        Returns:
            ExtractionResult with paths to all extracted root filesystems
            
        Raises:
            ExtractionFailedError: binwalk extraction failed
            BinwalkNotFoundError: binwalk binary not found on system
        """
        ...
    
    def get_root_filesystems(self, extraction_dir: Path) -> list[Path]:
        """Return paths to all extracted root filesystem directories."""
        ...
```

```python
@dataclass
class ExtractionResult:
    success: bool
    extraction_dir: Path                    # Base extraction directory
    root_filesystems: list[Path]            # Paths to root filesystem dirs
    file_count: int                        # Number of files extracted
    total_size: int                        # Total extracted size in bytes
    signatures_detected: list[SignatureResult]  # All binwalk signatures found
    extraction_errors: list[str]            # Any non-fatal extraction errors
```

#### Supported Filesystem Types

| Filesystem | Extraction Tool | Priority |
|---|---|---|
| SquashFS | unsquashfs (via binwalk) | Highest (most common in IoT) |
| JFFS2 | jefferson | High |
| UBIFS | ubireader_extract_images | High |
| CramFS | binwalk内置 | Medium |
| CPIO / initramfs | cpio command | High |
| ROMFS | binwalk内置 | Low |
| YAFFS2 | binwalk内置 | Low |

#### Security Safeguards

- **Path traversal protection**: Validate all extracted paths stay within the output directory. Remove symlinks pointing outside the extraction root (Zip-Slip mitigation). This follows the design from `firmware-mcp`.
- **Post-extraction symlink audit**: After extraction, walk the tree and remove any symlink whose target resolves outside `output_dir`.
- **Disk space check**: Verify at least 3× firmware file size is free before extraction.
- **Timeout**: Extraction must complete within `extraction_timeout_seconds` (default: 300).

### 8.2 Filesystem Scanner Module

**File:** `src/scanner/filesystem_scanner.py`

#### Responsibilities

Walk the extracted filesystem tree and categorize every file by security relevance. This is the **backbone** of all subsequent scanning — every other module depends on the filesystem inventory this produces.

#### File Categorization Ontology

| Category | Examples | Security Relevance |
|---|---|---|
| `CRITICAL_CREDENTIAL` | `/etc/passwd`, `/etc/shadow`, `*.key`, `*.pem` | Direct credential exposure |
| `CRITICAL_CONFIG` | `/etc/inittab`, `*.conf`, `*.cfg`, `*.ini` | May contain secrets, services, defaults |
| `CRITICAL_SERVICE` | `sshd`, `telnetd`, `dropbear`, `httpd`, `nginx` | Network-exposed services |
| `CRITICAL_SCRIPT` | `*.sh` in `/etc/init.d/`, `/etc/rc.d/` | Boot-time configuration |
| `CRITICAL_BINARY` | ELF, Mach-O, PE executables | May contain backdoors, vulns |
| `HIGH_API_KEY` | Files with API key patterns (AWS, GitHub, Slack) | Hardcoded third-party credentials |
| `HIGH_CRYPTO` | `*.pem`, `*.crt`, `*.p12`, `*.jks` | Crypto material exposure |
| `HIGH_DATABASE` | `*.db`, `*.sqlite`, `*.sql` | May contain credentials or PII |
| `MEDIUM_LOG` | `*.log`, `/var/log/*` | May leak operational data |
| `MEDIUM_WEB` | `/www/*`, `/htdocs/*`, `*.cgi` | Web attack surface |
| `LOW_MISC` | Everything else | Low priority |

#### Interface

```python
class FilesystemScanner:
    def __init__(self, config: ScannerConfig) -> None: ...
    
    def scan(self, rootfs_path: Path) -> FilesystemInventory:
        """
        Walk the extracted rootfs and categorize every file.
        
        Args:
            rootfs_path: Path to extracted root filesystem
        
        Returns:
            FilesystemInventory with all files categorized
        """
        ...
    
    def get_files_by_category(self, category: FileCategory) -> list[Path]:
        """Return all files matching a security category."""
        ...


@dataclass
class FilesystemFinding:
    path: Path                    # Relative path within rootfs
    absolute_path: Path           # Full filesystem path
    category: FileCategory        # Security category
    file_type: str               # From `file` command
    file_size: int               # In bytes
    permissions: str              # Unix permission string (e.g., "rwxr-xr-x")
    owner_uid: int               # Owner UID
    owner_gid: int               # Group GID
    is_suid: bool                # SUID bit set
    is_world_writable: bool      # World-writable permission
    hash_sha256: str              # SHA-256 of file contents


@dataclass  
class FilesystemInventory:
    rootfs_path: Path
    total_files: int
    total_directories: int
    total_size: int
    findings: list[FilesystemFinding]
    categories: dict[FileCategory, list[FilesystemFinding]]
    
    # Quick-access indices
    suid_binaries: list[FilesystemFinding]
    world_writable_files: list[FilesystemFinding]
    shadow_files: list[FilesystemFinding]
    ssl_cert_files: list[FilesystemFinding]
    init_scripts: list[FilesystemFinding]
    network_services: list[FilesystemFinding]
```

#### Critical Detection Patterns

**Boot Process Analysis** (following OWASP FSTM Stage 5 guidance):

1. Identify init system: check `/sbin/init` → BusyBox? systemd? custom ELF?
2. Parse `/etc/inittab` for `sysinit` and `respawn` entries
3. Walk `/etc/init.d/` scripts for service startup commands
4. Check `/etc/rc.local` or `/etc/rcS.d/` for custom boot commands
5. Flag services: `telnetd`, `sshd`, `dropbear`, `httpd`, `goahead`, `lighttpd`

**Service Exposure Detection:**

| Service Binary | Risk | Detection Method |
|---|---|---|
| telnetd | CRITICAL — cleartext, often no auth | Find binary + check init scripts |
| dropbear | HIGH — SSH with default keys | Find binary + check for default host keys |
| httpd / nginx / lighttpd | HIGH — web admin interface | Find binary + check config for auth |
| vsftpd / tftpd | HIGH — file transfer, often misconfigured | Find binary + check for anonymous access |
| snmpd | MEDIUM — often community-string default | Find binary + check config |

---

## 9. Phase 3 — Entropy & Binary Intelligence

**Build Order:** Third (depends on Phase 1, partially Phase 2)  
**Estimated Effort:** 4-5 days  
**Deliverable:** Entropy profiles for firmware regions + binary metadata extraction

### 9.1 Entropy Analyzer Module

**File:** `src/scanner/entropy_analyzer.py`

#### Theory of Operation

Shannon entropy measures the randomness (information density) of a byte sequence:

```
H = -Σ p(xi) × log2(p(xi))
```

where `p(xi)` is the probability of byte value `xi` occurring in the block.

**Interpretation for firmware analysis (research-backed from ServiceNow Security Lab):**

| Entropy Range | Interpretation | Typical Firmware Content |
|---|---|---|
| 0.00 - 0.30 | Very low | Repeated bytes, padding, null regions, bootloader padding |
| 0.30 - 0.50 | Low | Structured data, pointers, firmware headers, configuration |
| 0.50 - 0.70 | Medium | Mixed code+data, ASCII text, uncompressed ELF sections |
| 0.70 - 0.85 | High | Compressed data (squashfs, gzip, LZMA regions) |
| 0.85 - 1.00 | Very high | Encrypted data, or high-compression payload |

**Key insight**: Compressed firmware regions typically have entropy 0.85-0.93. Encrypted regions are 0.93+. This narrow band distinction is critical for distinguishing compressed-but-readable from encrypted-and-unreadable.

#### Block Size Strategy (from Binwalk source analysis)

Binwalk v3 calculates block size as: `file_size / 2048` (rounded to nearest 1024). This adaptive approach works but can miss small low-entropy regions in large files.

**Our approach**: Three-tier analysis:

1. **Fast scan**: Binwalk-compatible block size (for overview)
2. **Standard scan**: 512-byte blocks (for most firmware < 100MB)
3. **Detailed scan**: 128-byte blocks (specifically around firmware partition boundaries)

#### Interface

```python
class EntropyAnalyzer:
    def __init__(self, config: ScannerConfig) -> None: ...
    
    def analyze(self, data: bytes, block_size: int | None = None) -> EntropyProfile:
        """
        Compute entropy across the firmware image.
        
        Args:
            data: Raw firmware bytes
            block_size: Block size for sliding window. None = auto-compute.
            
        Returns:
            EntropyProfile with per-block entropy values and region classification
        """
        ...
    
    def find_high_entropy_regions(self, profile: EntropyProfile, 
                                  threshold: float = 0.85) -> list[EntropyRegion]:
        """Identify regions with entropy above threshold (likely encrypted/compressed)."""
        ...
    
    def find_low_entropy_regions(self, profile: EntropyProfile,
                                  threshold: float = 0.30) -> list[EntropyRegion]:
        """Identify regions with entropy below threshold (likely headers/padding/configs)."""
        ...


@dataclass
class EntropyBlock:
    offset: int           # Byte offset in firmware
    entropy: float        # Shannon entropy value [0.0, 1.0]
    byte_distribution: dict[int, int]  # Histogram of byte values in block


@dataclass
class EntropyRegion:
    start_offset: int
    end_offset: int
    size: int
    avg_entropy: float
    classification: str   # "compressed" | "encrypted" | "code" | "data" | "padding" | "unknown"
    confidence: float    # 0.0-1.0 confidence in classification


@dataclass
class EntropyProfile:
    firmware_path: Path
    total_blocks: int
    block_size: int
    blocks: list[EntropyBlock]
    regions: list[EntropyRegion]
    overall_entropy: float
    has_encrypted_regions: bool
    has_compressed_regions: bool
    firmware_partially_readable: bool   # False if fully encrypted
```

### 9.2 Binary Intelligence Module

**File:** `src/scanner/binary_intelligence.py`

#### Responsibilities

Extract metadata from ELF/PE/Mach-O binaries found in the filesystem:

- Architecture (ARM, MIPS, x86, PowerPC, RISC-V)
- Endianness (little/big)
- Static vs dynamic linking
- Binary hardening checks (NX, ASLR, stack canaries, RELRO, FORTIFY_SOURCE)
- Embedded string extraction with context
- Version string detection (`BusyBox v1.28.4`, `OpenSSL 1.0.2k`, etc.)

#### Binary Hardening Check Matrix

| Check | Command | Finding if Absent |
|---|---|---|
| NX (No Execute) | `readelf -lW bin/ \| grep STACK` → check for 'E' flag | Executable stack — stack buffer overflow exploitable |
| Stack Canary | `readelf -aW bin/ \| grep stack_chk_fail` | No stack overflow protection |
| PIE | `readelf -h \| grep Type` → DYN = PIE, EXEC = no PIE | Fixed address — ROP easier |
| RELRO | `readelf -d \| grep BIND_NOW` | Partial or no GOT protection |
| FORTIFY | Check for `__ fortified` symbols | No source-level buffer overflow checks |

These checks follow the methodology from OWASP FSTM Stage 5 and the `checksec.sh` tool pattern.

#### Version String Extraction Patterns

```python
VERSION_PATTERNS = {
    "busybox":     r"BusyBox\s+v?([\d.]+)",
    "openssl":     r"OpenSSL\s+([\d.]+[a-z]?)",
    "dropbear":    r"Dropbear\s+ssh\s+([\d.]+)",
    "dnsmasq":     r"dnsmasq\s+([\d.]+)",
    "nginx":       r"nginx/([\d.]+)",
    "lighttpd":    r"lighttpd/([\d.]+)",
    "linux_kernel": r"Linux\s+version\s+([\d.]+)",
    "u_boot":      r"U-Boot\s+([\d.]+)",
    "curl":        r"libcurl/([\d.]+)",
    "openssh":     r"OpenSSH_([\d.]+p\d+)",
    "zlib":        r"zlib\s+([\d.]+)",
    "sqlite":      r"SQLite\s+version\s+([\d.]+)",
}
```

These version strings become the **input** for the CVE Scanner (Phase 5).

---

## 10. Phase 4 — Credential & Secret Detection

**Build Order:** Fourth (depends on Phase 2)  
**Estimated Effort:** 5-6 days  
**Deliverable:** Comprehensive credential/secret detection with YARA + regex + entropy-gated false-positive reduction

### 10.1 Credential Scanner Module

**File:** `src/scanner/credential_scanner.py`

#### Design Principles

1. **Layered detection** — YARA rules for high-confidence binary patterns, regex for structured text, entropy gating for false-positive reduction
2. **Severity-aware** — root/admin password = CRITICAL; generic token = LOW
3. **Context-aware** — skip placeholder/example values, respect file type boundaries
4. **Smart filtering** — never report credentials in test fixtures, docs, or template files

#### Detection Categories

| Category | Patterns | Severity | Example |
|---|---|---|---|
| **Unix Credentials** | `/etc/passwd`, `/etc/shadow` parsing | CRITICAL | `root:$1$XROmcfDX$...` |
| **Hardcoded Passwords** | `password=` `passwd=` `pwd=` in configs | CRITICAL-HIGH | `admin_password= admin123` |
| **API Keys** | AWS AKIA, GitHub ghp_, Slack xox, Stripe sk_live | HIGH | `AKIA3E...` |
| **Private Keys** | `-----BEGIN RSA/EC/OPENSSH PRIVATE KEY-----` | HIGH | SSH RSA key |
| **Tokens/Bearer** | `Bearer ...`, `token=...` | MEDIUM | `token=abc123def` |
| **Database Credentials** | Connection strings with embedded credentials | HIGH | `mysql://root:pass@host` |
| **Generic Secrets** | `secret=`, `key=`, `apikey=` | MEDIUM-LOW | `api_key=AK_LIVE_...` |

#### YARA Rule Engine

We use the `yara-python` package for high-performance pattern matching across binary and text files. YARA rules are loaded from a configurable directory with the following precedence:

1. **Built-in rules** (`rules/yara/iot_hardware_scanner.yar`) — bundled with the tool
2. **User rules** (`~/.iot_hardware_scanner/yara_rules/`) — user overrides
3. **Project rules** (`./yara_rules/` CWD-relative) — project-specific rules

#### Built-in YARA Rules (Phase 4 Scope)

```
rules/yara/
├── iot_hardware_scanner.yar     # Meta-rule file, includes below
├── credentials_passwords.yar   # Hardcoded password patterns
├── credentials_api_keys.yar    # Cloud service API keys
├── credentials_ssh_keys.yar    # SSH private key headers
├── credentials_db.yar          # Database connection strings
├── credentials_tokens.yar      # Bearer tokens, OAuth patterns
├── backdoor_services.yar       # Telnet backdoor, debug shell patterns
└── weak_crypto.yar             # Weak crypto constants (MD5, DES, RC4)
```

#### Credential Scanner Interface

```python
class CredentialScanner:
    def __init__(self, config: ScannerConfig) -> None: ...
    
    def scan_file(self, file_path: Path, file_category: FileCategory) -> list[CredentialFinding]:
        """Scan a single file for credentials/secrets."""
        ...
    
    def scan_inventory(self, inventory: FilesystemInventory) -> list[CredentialFinding]:
        """Scan all CRITICAL/HIGH category files in the inventory."""
        ...


@dataclass
class CredentialFinding:
    severity: str                 # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    category: str                 # "password" | "api_key" | "private_key" | "token" | "connection_string"
    file_path: Path               # Relative path within rootfs
    line_number: int | None       # Line number (for text files)
    offset: int | None           # Byte offset (for binary files)
    matched_pattern: str          # The regex/yara pattern that matched
    masked_value: str             # Value with sensitive parts masked: "root:$1$******"
    raw_value_hash: str           # SHA-256 hash of the raw discovered value (for dedup)
    context: str                  # Surrounding context (3 lines / 64 bytes)
    is_default: bool              # True if value matches known default credential
    is_placeholder: bool         # True if value looks like a placeholder (YOUR_API_KEY)
```

#### Unix Credential Parsing

Specialized parser for `/etc/passwd` and `/etc/shadow` files:

```python
class UnixCredentialParser:
    def parse_passwd(self, path: Path) -> list[PasswdEntry]:
        """
        Parse /etc/passwd format:
        username:x:uid:gid:gecos:home:shell
        
        Flag:
        - UID 0 entries (root-equivalent users)
        - Login shells (not /sbin/nologin or /bin/false)
        - Empty password field (x missing = no password required)
        """
        ...
    
    def parse_shadow(self, path: Path) -> list[ShadowEntry]:
        """
        Parse /etc/shadow format:
        username:$hash_algorithm$salt$hash:lastchange:min:max:warn:inactive:expire
        
        Detect:
        - Hash algorithm ($1=MD5, $5=SHA-256, $6=SHA-512, $2y$=bcrypt)
        - MD5 ($1$) = WEAK — flag as HIGH severity
        - Empty hash field = NO PASSWORD — flag as CRITICAL
        - Locked accounts (! or *) = OK
        """
        ...


@dataclass
class ShadowEntry:
    username: str
    hash_algorithm: str | None     # "MD5", "SHA-256", "SHA-512", "bcrypt", None
    hash_value: str                # The hash portion (masked in reports)
    is_empty: bool                 # No password set
    is_locked: bool                # Account locked (!/* prefix)
    days_since_change: int | None  # Password aging info
    severity: str                  # Derived from algorithm + state
```

#### False Positive Reduction

| Technique | Implementation |
|---|---|
| **Entropy gating** | If a "password" value has entropy < 1.5 bits/char, it may be a placeholder |
| **Placeholder blocklist** | Skip patterns: `YOUR_API_KEY`, `REPLACE_ME`, `<insert>`, `changeme`, `xxx`, `test` |
| **File extension filter** | Skip `.md`, `.rst`, `.txt` in `docs/` directories |
| **Binary skip** | Skip ELF/PE/Mach-O for regex patterns (YARA still runs on them) |
| **Context window** | If the 3 lines before a match contain `example`, `sample`, `template` — deprioritize |
| **Default credential DB** | Cross-reference matches against `data/default_credentials.json` — if it matches a known default, flag as `is_default=True` |

---

## 11. Phase 5 — CVE Matching & Vulnerability Correlation

**Build Order:** Fifth (depends on Phase 9.2 version strings)  
**Estimated Effort:** 4-5 days  
**Deliverable:** CVE lookup against NVD for all detected software components

### 11.1 CVE Scanner Module

**File:** `src/scanner/cve_scanner.py`

#### Architecture

```
Detected Software Versions (from binary_intelligence.py)
        │
        ▼
    Component Normalizer
        │  (normalize "BusyBox v1.28.4" → vendor=busybox, product=busybox, version=1.28.4)
        ▼
    CPE Constructor
        │  (build CPE: cpe:2.3:a:busybox:busybox:1.28.4)
        ▼
    NVD API Query ───► (online) ───► CVE Results
        │                                    │
        │ (offline fallback)                  ▼
        ▼                              CVE Finding
    Local NVD Cache (SQLite)
```

#### NVD API v2 Integration

Base URL: `https://services.nvd.nist.gov/rest/json/cves/2.0`

**Query strategy:**

1. First, try `keywordSearch` with product name + version
2. If no results, try `cpeName` with constructed CPE string
3. Fallback to `virtualMatchString` with version range
4. Results are cached locally in SQLite (7-day TTL)

**Rate limiting:** NVD requires 6-second delay without API key, 0.6-second with key. We use the `nvdlib` Python wrapper for clean API access.

#### Interface

```python
class CVEScanner:
    def __init__(self, config: ScannerConfig) -> None: ...
    
    def scan_component(self, component: SoftwareComponent) -> list[CVEFinding]:
        """Look up known CVEs for a specific software component."""
        ...
    
    def scan_all(self, components: list[SoftwareComponent]) -> list[CVEFinding]:
        """Scan all detected software components for known CVEs."""
        ...


@dataclass
class SoftwareComponent:
    vendor: str                  # e.g. "busybox"
    product: str                 # e.g. "busybox"  
    version: str                 # e.g. "1.28.4"
    cpe_string: str              # e.g. "cpe:2.3:a:busybox:busybox:1.28.4"
    source_file: Path            # Where we found this version string
    source_method: str           # "string_extraction" | "package_manifest"
    architecture: str | None     # Target arch (ARM, MIPS, etc.)


@dataclass
class CVEFinding:
    cve_id: str                  # CVE-2013-1813
    severity: str                # CRITICAL | HIGH | MEDIUM | LOW
    cvss_v3_score: float | None  # 7.5
    cvss_v3_vector: str | None    # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    description: str             # Summary of the vulnerability
    affected_product: str        # Product name
    affected_version: str        # Version range
    published_date: str           # ISO 8601
    references: list[str]         # URLs to advisories
    is_in_kev: bool              # Is this in CISA's Known Exploited Vulnerabilities catalog?
    exploit_available: bool      # Known public exploit exists
```

#### Supported Software Components (Priority Lookup)

| Product | Version Regex | Typical IoT Usage |
|---|---|---|
| BusyBox | `BusyBox\s+v?([\d.]+)` | Swiss-army knife for embedded Linux |
| OpenSSL | `OpenSSL\s+([\d.]+[a-z]?)` | TLS implementation |
| Dropbear | `Dropbear\s+([\d.]+)` | Lightweight SSH server |
| dnsmasq | `dnsmasq\s+([\d.]+)` | DNS/DHCP service |
| lighttpd | `lighttpd/([\d.]+)` | Web server |
| nginx | `nginx/([\d.]+)` | Web server / reverse proxy |
| Linux Kernel | `Linux\s+version\s+([\d.]+)` | OS kernel |
| U-Boot | `U-Boot\s+([\d.]+)` | Bootloader |
| curl | `libcurl/([\d.]+)` | HTTP client library |
| zlib | `zlib\s+([\d.]+)` | Compression library |
| OpenSSH | `OpenSSH_([\d.]+p\d+)` | SSH server (heavier than dropbear) |
| SQLite | `SQLite\s+version\s+([\d.]+)` | Embedded database |

#### KEV Catalog Integration

We check each discovered CVE against CISA's Known Exploited Vulnerabilities (KEV) catalog. CVEs in the KEV catalog are automatically escalated to CRITICAL severity regardless of their CVSS score, because they are **known to be exploited in the wild**.

---

## 12. Phase 6 — C2 & Malicious Indicator Detection

**Build Order:** Sixth (depends on Phase 2 + Phase 9 strings)  
**Estimated Effort:** 5-6 days  
**Deliverable:** Detection of hardcoded C2 domains, suspicious IPs, backdoor services, and known IoT malware signatures

### 12.1 C2 Detector Module

**File:** `src/scanner/c2_detector.py`

#### Detection Strategy

C2 indicators in firmware are found through three complementary methods:

1. **String extraction** — hardcoded domain names, IP addresses, URLs in binaries and configs
2. **YARA pattern matching** — known IoT malware signatures (Mirai, Gafgyt, Hajime, etc.)
3. **Threat intelligence feed comparison** — check extracted domains/IPs against known-bad feeds

#### Domain/IP Extraction Patterns

```python
IPV4_PATTERN = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
DOMAIN_PATTERN = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
URL_PATTERN = r'https?://[^\s"\'<>]+'
EMAIL_PATTERN = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
```

#### Domain Heuristic Scoring

Not every domain is a C2. We assign a suspicion score to each extracted domain:

| Signal | Points | Example |
|---|---|---|
| Domain in threat intel feed | +50 | `updates.firmware-vendor.com` in AbuseIPDB |
| Domain resolves to known malicious IP range | +40 | Resolves to `185.220.x.x` (Tor exit or bulletproof hosting) |
| Domain uses suspicious TLD | +15 | `.su`, `.xyz`, `.ru`, `.top`, `.cc` |
| Domain in firmware binary (not config) | +20 | Hardcoded in ELF `.rodata` section |
| Domain looks auto-generated | +25 | Random 8+ char subdomains: `a3x7k2m9.example.com` |
| Domain matches known botnet naming | +30 | Contains patterns from known Mirai/Gafgyt variants |
| Domain in `/etc/hosts` or config | +5 | Normal operational domain |
| Domain in known-benign list | -50 | `google.com`, `ntp.org`, `example.com` |
| Domain has valid SSL cert + established org | -20 | Legitimate vendor infrastructure |

**Threshold**: Score ≥ 40 → flag as `SUSPICIOUS`; Score ≥ 60 → flag as `LIKELY_C2`

#### Known IoT Malware YARA Signatures

We include YARA rules for detecting the most prevalent IoT malware families in extracted filesystems:

| Malware Family | Key Indicators | C2 Protocol |
|---|---|---|
| Mirai (and variants) | XOR key 0x37, credential table, `/proc/self/exe` manipulation | Custom binary protocol |
| Gafgyt / BASHLIFE | IRC-based C2, PONG commands | IRC PRIVMSG |
| Hajime | P2P overlay, encrypted config | DHT-based decentralized |
| VPNFilter | Stage 1/2 bootloader hook | Custom with Tor fallback |
| Mozi | P2P DHT botnet | BitTorrent DHT variant |
| Jackskid | `DEADBEEF CAFEBABE` cipher key, ChaCha20, ENS C2 | Custom encrypted + DoH |
| Kimwolf | ENS resolution, Android `netd_service` process name | Ethereum RPC + Tor backup |

#### C2 Finding Interface

```python
class C2Detector:
    def __init__(self, config: ScannerConfig) -> None: ...
    
    def detect_domains(self, inventory: FilesystemInventory) -> list[C2Finding]:
        """Extract and score domains from firmware for C2 indicators."""
        ...
    
    def detect_ips(self, inventory: FilesystemInventory) -> list[C2Finding]:
        """Extract and score IP addresses for malicious indicators."""
        ...
    
    def detect_malware_signatures(self, inventory: FilesystemInventory) -> list[C2Finding]:
        """Run YARA rules for known IoT malware family detection."""
        ...


@dataclass
class C2Finding:
    severity: str                # "LIKELY_C2" | "SUSPICIOUS" | "INFORMATIONAL"
    indicator_type: str          # "domain" | "ip" | "malware_signature" | "backdoor_service"
    value: str                  # The domain, IP, or signature match
    file_path: Path             # Where found
    suspicion_score: float      # 0.0 - 100.0
    score_breakdown: dict      # Why this scored this way
    threat_intel_match: str | None  # Which feed matched (AbuseIPDB, etc.)
    mitre_attack: str | None   # MITRE ATT&CK ICS technique ID if applicable
    description: str            # Human-readable explanation
```

#### Backdoor Service Detection

Beyond C2, we detect insecure or backdoor services from filesystem analysis:

| Service | Detection Method | Severity |
|---|---|---|
| Telnet with no auth | Check `/etc/inittab` for `telnetd` without auth wrapper | CRITICAL |
| Debug shell on serial port | Check `ttyS*::respawn:/bin/sh` in inittab | CRITICAL |
| SSH with default keys | Check for `dropbear` + presence of default host keys | HIGH |
| HTTP admin without auth | Check `httpd`/`nginx` config for missing auth directives | HIGH |
| ADB exposed | Check for ADB service config in init scripts | HIGH |
| Backdoor binary | YARA match on known backdoor patterns (reverse shell, bind shell) | CRITICAL |

---

## 13. Phase 7 — Risk Scoring & Compliance Reporting

**Build Order:** Seventh (depends on all prior phases)  
**Estimated Effort:** 4-5 days  
**Deliverable:** Numerical risk scoring + compliance mapping + multi-format reporting

### 13.1 Risk Scorer Module

**File:** `src/scanner/risk_scorer.py`

#### Scoring Model

We evaluate 12 security controls based on the IoT Security Foundation guidelines, OWASP IoT Top 10, and OWASP ISVS requirements:

| # | Security Control | Source | Evidence From | Points |
|---|---|---|---|---|
| 1 | No default/hardcoded credentials | OWASP I1 | `credential_scanner` | 0-10 |
| 2 | No unnecessary network services | OWASP I2 | `filesystem_scanner` | 0-10 |
| 3 | No outdated/vulnerable components | OWASP I5 | `cve_scanner` + KEV | 0-10 |
| 4 | Encrypted data at rest | OWASP I7 | `credential_scanner` (plaintext check) | 0-10 |
| 5 | Secure firmware update mechanism | OWASP I4 | `filesystem_scanner` (signature check) | 0-10 |
| 6 | Secure boot/integrity verification | ISVS V4.1 | `entropy_analyzer` (unencrypted check) | 0-8 |
| 7 | No backdoor interfaces | ISTG-FW-SCRT-003 | `c2_detector` | 0-10 |
| 8 | Strong cryptography used | ISTG-FW-CRYPT-001 | Binary hardening checks | 0-8 |
| 9 | Minimal attack surface | ISVS V3.2 | `filesystem_scanner` (SUID, services) | 0-8 |
| 10 | Binary hardening present | FSTM Stage 5 | `binary_intelligence` (NX, canary, RELRO) | 0-8 |
| 11 | No C2/malware indicators | MITRE ATT&CK ICS | `c2_detector` | 0-5 |
| 12 | Accurate component inventory (SBOM) | ISVS V1.1.1 | Component detection completeness | 0-3 |

**Maximum possible score: 100**

#### Risk Level Classification

| Score | Risk Level | Action Required |
|---|---|---|
| 90-100 | LOW | Acceptable — minor hardening recommended |
| 70-89 | MEDIUM | Moderate risk — several controls need attention |
| 50-69 | HIGH | Significant risk — immediate remediation required |
| < 50 | CRITICAL | Unacceptable — device should not be deployed |

#### Interface

```python
class RiskScorer:
    def __init__(self, config: ScannerConfig) -> None: ...
    
    def score(self, context: ScanContext) -> RiskScore:
        """
        Compute a numeric risk score from all findings.
        
        Each control is evaluated independently:
        - PASS (full points): No findings for this control
        - PARTIAL (50% points): Some findings, mitigated
        - FAIL (0 points): Findings indicate control is absent
        
        Returns:
            RiskScore with per-control scores and overall rating
        """
        ...


@dataclass
class ControlScore:
    control_id: int              # 1-12
    control_name: str             # "No default credentials"
    result: str                   # "PASS" | "PARTIAL" | "FAIL"
    points: float                 # 0-max
    max_points: float             # Maximum possible for this control
    evidence: list[str]           # Finding IDs that contributed to this score
    remediation: str              # What needs to be done to improve


@dataclass
class RiskScore:
    total_score: float            # 0-100
    risk_level: str              # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    control_scores: list[ControlScore]
    weighted_breakdown: dict      # Category → score contribution
    executive_summary: str        # One-paragraph human-readable summary
    owasp_iot_mapping: dict      # OWASP IoT Top 10 → finding counts
```

### 13.2 Report Generator Module

**File:** `src/scanner/report_generator.py`

#### Output Formats

| Format | Use Case | Content |
|---|---|---|
| `terminal` (colored) | Interactive CLI use | Summary + high-priority findings |
| `json` | CI/CD integration, tooling | Complete structured data |
| `markdown` | Documentation, PR reviews | Human-readable detailed report |
| `html` | Executive dashboards | Styled full report |

#### Report Sections

1. **Executive Summary** — risk score, risk level, finding counts by severity
2. **Firmware Metadata** — hashes, size, type, architecture
3. **Extraction Summary** — filesystem types, file counts, key directories
4. **Entropy Profile** — encrypted/compressed region map
5. **Credential Findings** — table of all discovered credentials, masked values
6. **CVE Findings** — table of CVEs with CVSS scores, KEV status
7. **C2/Malware Findings** — suspicious domains, IPs, malware signatures
8. **Risk Scorecard** — 12-control breakdown with remediation guidance
9. **OWASP IoT Top 10 Mapping** — which IoT Top 10 items are violated
10. **SBOM** — software bill of materials in CycloneDX format

---

## 14. Data Model & Schema Definitions

### Finding Severity Taxonomy

```
CRITICAL  → Immediate exploitation risk. Do not deploy.
HIGH      → Significant vulnerability. Remediate before deployment.
MEDIUM    → Potential risk. Remediate in next release.
LOW       → Informational. Consider hardening.
INFO      → For awareness only. No action required.
```

### Universal Finding Schema

All findings conform to a common schema for uniform processing:

```python
@dataclass
class Finding:
    finding_id: str              # UUID
    scanner_module: str          # Which module produced this ("credential_scanner")
    severity: str                # CRITICAL | HIGH | MEDIUM | LOW | INFO
    title: str                  # Short human-readable title
    description: str            # Detailed description
    file_path: Path | None      # File within firmware where found
    remediation: str | None     # How to fix
    references: list[str]       # URLs to advisories/documentation
    confidence: float           # 0.0-1.0 confidence in finding
    metadata: dict              # Module-specific extra data
```

---

## 15. CLI & Output Specifications

### Command-Line Interface

```bash
# Full scan (all phases)
iot-hardware-scanner scan firmware.bin

# Scan with output directory
iot-hardware-scanner scan firmware.bin --output ./reports/

# JSON output (for CI/CD)
iot-hardware-scanner scan firmware.bin --format json

# Markdown report
iot-hardware-scanner scan firmware.bin --format markdown --out report.md

# Scan with custom YARA rules
iot-hardware-scanner scan firmware.bin --yara-rules ./custom_rules/

# Scan with NVD API key (faster CVE queries)
iot-hardware-scanner scan firmware.bin --nvd-api-key YOUR_KEY

# Extract only (no analysis)
iot-hardware-scanner extract firmware.bin --output ./extracted/

# Entropy analysis only
iot-hardware-scanner entropy firmware.bin --block-size 512

# Check specific firmware hash against known vulnerabilities
iot-hardware-scanner lookup --hash sha256:abc123...

# Generate report from previous scan
iot-hardware-scanner report ./reports/scan-uuid.json --format html --out report.html

# Version check
iot-hardware-scanner --version
```

### Exit Codes

| Code | Meaning |
|---|---|
| 0 | Success — no CRITICAL findings |
| 1 | Success — CRITICAL findings detected (useful for CI/CD gate) |
| 2 | Invalid arguments / usage error |
| 3 | Firmware file not found or unreadable |
| 4 | Extraction failed |
| 5 | Dependency missing (binwalk, yara not installed) |
| 6 | Internal error (bug) |

### Terminal Output Format

```
╔══════════════════════════════════════════════════════════╗
║           IoT Hardware Scanner v1.0.0                    ║
║     Firmware Security Analysis Platform                  ║
╚══════════════════════════════════════════════════════════╝

[*] Target: router_firmware.bin (8.3 MB, SHA-256: a1b2c3...)
[*] Output: ./reports/scan-2025-05-06-143022/

═══ Phase 1: Ingest ═══════════════════════════════════════
  [✓] File validated
  [✓] SHA-256: a1b2c3d4e5f6...
  [✓] Type: DLOB firmware header (MIPS, little endian)

═══ Phase 2: Extraction ════════════════════════════════════
  [✓] 3 signatures detected (SquashFS, LZMA, gzip)
  [✓] Filesystem extracted: squashfs-root/ (2,688 inodes)
  [!] 2 extraction warnings (broken symlink, permission issue)

═══ Phase 3: Entropy ═══════════════════════════════════════
  [✓] 2 high-entropy regions detected (compressed/encrypted)
  [!] Region 0x0-0x40000 (256KB): entropy=0.97 — likely encrypted

═══ Phase 4: Credentials ══════════════════════════════════
  [!] CRITICAL: root account with MD5 hash in /etc/shadow
  [!] CRITICAL: hardcoded password 'admin123' in /etc/config.sh
  [!] HIGH: SSH private key in /etc/dropbear/dropbear_rsa_host_key

═══ Phase 5: CVE ══════════════════════════════════════════
  [!] CRITICAL: BusyBox 1.19.4 — 12 CVEs (3 in CISA KEV)
  [!] HIGH: OpenSSL 1.0.2k — 47 CVEs (8 CRITICAL, 2 in KEV)
  [i]  dnsmasq 2.78 — 3 CVEs (all MEDIUM)

═══ Phase 6: C2 & Malware ══════════════════════════════════
  [!] LIKELY_C2: updates.vendor-update.su (score: 72/100)
  [i]  SUSPICIOUS: 185.220.101.37 in /etc/hosts (Tor exit node)

═══ Phase 7: Risk Score ═══════════════════════════════════
  ╔═══════════════════════════════════╗
  ║  RISK SCORE: 28/100 — CRITICAL    ║
  ╠═══════════════════════════════════╣
  ║  ✗ Default credentials: FAIL (0/10) ║
  ║  ✗ No backdoors: FAIL (0/10)       ║
  ║  ✗ No vulnerable components: FAIL  ║
  ║  △ Encrypted storage: PARTIAL (5)  ║
  ║  ✓ No C2 indicators: PASS (5/5)    ║
  ╚═══════════════════════════════════╝

  ⚠  This firmware should NOT be deployed without remediation.

Report saved: ./reports/scan-2025-05-06-143022/report.json
Report saved: ./reports/scan-2025-05-06-143022/report.md
```

---

## 16. Testing Strategy

### Test Categories

| Category | Scope | Tool | Runs Where |
|---|---|---|---|---|
| **Unit** | Individual scanner functions | pytest + pytest-cov | Every PR |
| **Integration** | Multi-phase pipeline | pytest + sample firmware | Every PR |
| **Regression** | Known-bad firmware finds expected things | pytest + frozen test corpus | Every PR |
| **Performance** | Large firmware handling | pytest-benchmark + manual | Weekly |
| **Security** | Path traversal, zip-slip, injection | pytest + adversarial inputs | Every PR |

### Test Firmware Corpus

We need realistic but safe test firmware. Sources:

| Firmware | Purpose | License |
|---|---|---|
| OWASP IoTGoat | Deliberately vulnerable, covers OWASP Top 10 | OpenWrt GPL |
| Damn Vulnerable Router Firmware (DVRF) | MIPS binary vulns | Educational |
| OpenWrt stable release | Baseline "healthy" firmware (few findings expected) | GPL |
| Custom test fixtures | Unit-level: small crafted binaries with known patterns | Self-built |

**Test infrastructure**: All test firmware committed to `tests/fixtures/` — small synthetic binaries (< 1MB) for fast unit tests; larger realistic firmware downloaded on-demand for integration tests (not committed to git).

### Coverage Targets

| Module | Line Coverage Target |
|---|---|
| `firmware_ingest` | ≥ 90% |
| `firmware_extractor` | ≥ 80% |
| `filesystem_scanner` | ≥ 90% |
| `entropy_analyzer` | ≥ 95% |
| `credential_scanner` | ≥ 90% |
| `cve_scanner` | ≥ 80% |
| `c2_detector` | ≥ 85% |
| `risk_scorer` | ≥ 95% |
| `report_generator` | ≥ 80% |

---

## 17. Competitive Landscape Analysis

### Detailed Comparison

| Capability | EMBA | FACT | Firmwalker | **This Tool** |
|---|---|---|---|---|
| **Language** | Bash (monolithic) | Python (Flask) | Bash | Python (modular package) |
| **Install** | Docker required (8-16GB) | Docker required (4+ cores) | `chmod +x` | `pip install` |
| **Extraction** | Binwalk + unblob | Custom | N/A (post-extract) | pybinwalk (native) |
| **Entropy** | Via binwalk CLI flag | Basic | None | Standalone Shannon engine, 3-tier blocks |
| **Credential Detection** | Regex in bash | Regex | grep patterns | YARA + regex + entropy-gated + Unix parser |
| **CVE** | cve-bin-tool integration | Feed-based | None | NVD API v2 + local cache + KEV |
| **C2 Detection** | None | None | URL/IP grep | Domain scoring + threat intel + YARA + malware sigs |
| **Risk Scoring** | None | None | None | 12-control model (OWASP IoT + ISVS) |
| **SBOM** | CycloneDX/SPDX | Component listing | None | CycloneDX |
| **Report** | HTML (heavy) | Web dashboard | Text file | JSON + Markdown + terminal + HTML |
| **CI/CD integration** | No | REST API | No | Exit codes + JSON + stdin/stdout |
| **Resource req** | 8-16GB RAM, Docker | 16 cores, 64GB RAM | Any | Any (no Docker required) |
| **Binary hardening** | checksec.sh | Partial | None | Built-in NX/ASLR/canary/RELRO/PIE checks |
| **YARA rules** | No | No | No | First-class YARA engine with composable rules |

### Our Niche

We occupy the **mid-tier** that doesn't exist today:

- **Easier than EMBA** — pip install, no Docker, Python-native
- **More thorough than Firmwalker** — 7 analysis phases vs grep
- **CI/CD friendly** — JSON output, exit codes, deterministic results
- **Unique C2 detection** — no other open-source tool does domain scoring
- **Unique risk scoring** — numerical score mapped to OWASP IoT Top 10

---

## 18. Technology Decisions & Rationale

| Decision | Choice | Rationale |
|---|---|---|
| Language | Python 3.10+ | Ecosystem (yara-python, nvdlib, pybinwalk), readability, team skill |
| Entropy engine | Custom Python (no dependency) | No external binary needed; matches Binwalk's algorithm exactly |
| Extraction | pybinwalk (native API) | 100× faster than subprocess calls; Rust-backed Binwalk v3 |
| Credential detection | yara-python + regex dual engine | YARA for binary patterns, regex for structured text |
| CVE data source | NVD API v2 + local SQLite cache | Real-time data; cache enables offline operation |
| Threat intel | Local JSON feeds (AbuseIPDB, OTX format) | Privacy-preserving; no phone-home |
| Report engine | Jinja2 templates | Flexible; single source for all output formats |
| Config | Pydantic dataclass + YAML/TOML | Type validation + human-editable |
| Logging | Python stdlib `logging` | Consistent with Python conventions |
| CLI framework | Click | Widely used, decorator-based, auto-help generation |
| Testing | pytest | Industry standard; best fixture system |
| SBOM format | CycloneDX JSON | Industry standard; most tooling support |

### Dependency List

| Package | Purpose | Required/Optional |
|---|---|---|
| `pybinwalk` | Firmware extraction | Optional (fallback: subprocess binwalk) |
| `yara-python` | YARA rule engine | Required |
| `nvdlib` | NVD API wrapper | Optional (offline mode without) |
| `python-magic` | File type detection | Required |
| `click` | CLI framework | Required |
| `pydantic` | Config/data validation | Required |
| `jinja2` | Report template engine | Required |
| `rich` | Terminal colored output | Required |
| `cyclonedx-python-lib` | SBOM generation | Required |

---

## 19. Directory Structure

```
iot-hardware-scanner/
│
├── README.md
├── pyproject.toml                    # Build config (hatchling/maturin)
├── requirements.txt                  # Pinned deps
├── LICENSE                            # MIT
│
├── src/
│   └── iot_hardware_scanner/
│       ├── __init__.py
│       ├── __main__.py               # python -m iot_hardware_scanner
│       ├── cli.py                     # Click CLI entry point
│       ├── config.py                  # ScannerConfig (Pydantic)
│       ├── models.py                  # All dataclasses (ScanContext, Findings, etc.)
│       ├── orchestrator.py            # Pipeline orchestration (Phase → Phase)
│       ├── exceptions.py              # Custom exceptions
│       │
│       ├── scanner/
│       │   ├── __init__.py
│       │   ├── firmware_ingest.py      # Phase 1
│       │   ├── firmware_extractor.py   # Phase 2a
│       │   ├── filesystem_scanner.py   # Phase 2b
│       │   ├── entropy_analyzer.py     # Phase 3a
│       │   ├── binary_intelligence.py   # Phase 3b
│       │   ├── credential_scanner.py   # Phase 4
│       │   ├── unix_cred_parser.py     # Phase 4 specialized
│       │   ├── cve_scanner.py          # Phase 5
│       │   ├── c2_detector.py          # Phase 6
│       │   ├── risk_scorer.py          # Phase 7a
│       │   └── report_generator.py     # Phase 7b
│       │
│       ├── intelligence/
│       │   ├── __init__.py
│       │   ├── nvd_client.py          # NVD API client with caching
│       │   ├── threat_intel.py        # Threat feed manager
│       │   ├── domain_scorer.py       # Domain suspicion scoring
│       │   └── cpe_builder.py         # CPE string construction
│       │
│       └── yara/
│           ├── __init__.py
│           ├── yara_engine.py          # YARA rule loader + scanner
│           └── rules/                  # Built-in YARA rules
│               ├── iot_hardware_scanner.yar
│               ├── credentials_passwords.yar
│               ├── credentials_api_keys.yar
│               ├── credentials_ssh_keys.yar
│               ├── credentials_db.yar
│               ├── credentials_tokens.yar
│               ├── backdoor_services.yar
│               ├── weak_crypto.yar
│               └── malware/            # IoT malware family rules
│                   ├── mirai.yar
│                   ├── gafgyt.yar
│                   └── hajime.yar
│
├── data/
│   ├── default_credentials.json       # Known default credential DB
│   ├── benign_domains.txt             # Whitelist of known-good domains
│   ├── suspicious_tlds.txt            # High-risk TLD list
│   └── component_cpe_map.json        # Product → CPE vendor/product mapping
│
├── templates/
│   ├── report_json.j2                 # JSON report Jinja2 template
│   ├── report_markdown.j2             # Markdown report template
│   └── report_html.j2                 # HTML report template
│
├── tests/
│   ├── conftest.py                    # Shared fixtures
│   ├── test_ingest.py
│   ├── test_extractor.py
│   ├── test_filesystem_scanner.py
│   ├── test_entropy.py
│   ├── test_binary_intelligence.py
│   ├── test_credential_scanner.py
│   ├── test_cve_scanner.py
│   ├── test_c2_detector.py
│   ├── test_risk_scorer.py
│   ├── test_report_generator.py
│   ├── test_orchestrator.py
│   ├── test_security.py               # Path traversal, zip-slip, injection
│   └── fixtures/                      # Test firmware corpus
│       ├── minimal_firmware.bin       # Small synthetic test image
│       ├── iotgoat_snippet.bin        # OWASP IoTGoat excerpt
│       ├── busybox_1.19.4_mipsel       # Known-vulnerable BusyBox
│       └── clean_openwrt_snippet.bin  # Expected-few-findings baseline
│
└── docs/
    ├── architecture.md                # Detailed architecture doc
    ├── extending.md                    # How to add custom YARA rules
    ├── threat_model.md                 # Defensive threat model for this tool
    └── api_reference.md               # Python API usage docs
```

---

## Appendix A — Supported Firmware Formats

| Format | Extension | Extraction Method | Notes |
|---|---|---|---|
| Raw binary | `.bin` | Binwalk signature scan | Most common |
| MIPS/ARM ELF | `.elf` | Direct analysis | No extraction needed |
| U-Boot image | `.img`, `.uimg` | Binwalk + dd carve | Contains kernel + rootfs |
| Intel HEX | `.hex`, `.ihex` | Convert to binary first | Microcontroller firmware |
| SREC/Motorola S-Record | `.srec`, `.s19` | Convert to binary first | Microcontroller firmware |
| SquashFS | `.squashfs` | unsquashfs | Most common IoT filesystem |
| JFFS2 | `.jffs2` | jefferson | Common in older devices |
| UBIFS | `.ubifs` | ubireader_extract | NAND flash devices |
| CPIO | `.cpio` | cpio command | initramfs archives |
| Docker image | (via tar) | Layer extraction | Container-based firmware |
| VMware disk | `.vmdk` | Mount loopback | Virtual appliance firmware |
| Generic archive | `.zip`, `.tar.gz` | Standard extraction | Update packages |

---

## Appendix B — YARA Rule Catalog

### Rule: credentials_passwords.yar

```yara
rule hardcoded_password_variable {
    meta:
        description = "Hardcoded password assignment in config/script"
        severity = "HIGH"
        category = "credential"
    
    strings:
        $pwd1 = /password\s*=\s*["'][^"']{4,}["']/ nocase
        $pwd2 = /passwd\s*=\s*["'][^"']{4,}["']/ nocase
        $pwd3 = /pwd\s*=\s*["'][^"']{4,}["']/ nocase
        $pwd4 = /admin_password\s*=\s*["'][^"']{4,}["']/ nocase
    
    condition:
        any of ($pwd*)
}

rule unix_md5_hash {
    meta:
        description = "MD5 crypt hash detected (weak algorithm)"
        severity = "HIGH"
        category = "credential"
    
    strings:
        $md5 = /\$1\$[a-zA-Z0-9.\/]{0,8}\$[a-zA-Z0-9.\/]{22}/
    
    condition:
        $md5
}
```

### Rule: credentials_api_keys.yar

```yara
rule aws_access_key {
    meta:
        description = "AWS Access Key ID detected"
        severity = "HIGH"
        category = "credential"
    
    strings:
        $aws = /AKIA[0-9A-Z]{16}/
    
    condition:
        $aws
}

rule github_personal_access_token {
    meta:
        description = "GitHub Personal Access Token"
        severity = "HIGH"
        category = "credential"
    
    strings:
        $ghp = /ghp_[A-Za-z0-9_]{36}/
    
    condition:
        $ghp
}

rule stripe_secret_key {
    meta:
        description = "Stripe Secret Key"
        severity = "HIGH"
        category = "credential"
    
    strings:
        $sk = /sk_live_[0-9a-zA-Z]{24,}/
    
    condition:
        $sk
}
```

### Rule: backdoor_services.yar

```yara
rule telnetd_backdoor {
    meta:
        description = "Telnet daemon with no authentication in init script"
        severity = "CRITICAL"
        category = "backdoor_service"
    
    strings:
        $telnet1 = "telnetd" ascii nocase
        $telnet2 = "in.telnetd" ascii nocase
        $noauth1 = "-l /bin/sh" ascii
        $noauth2 = "--noauth" ascii
    
    condition:
        any of ($telnet*) and any of ($noauth*)
}
```

---

## Appendix C — Default Credential Database Schema

```json
{
    "credentials": [
        {
            "vendor": "D-Link",
            "models": ["DIR-600", "DIR-615", "DIR-890L"],
            "username": "admin",
            "password": "admin",
            "protocol": "http",
            "source": "https://192-168-1-1-ip.co/d-link-default-passwords/"
        },
        {
            "vendor": "TP-Link",
            "models": ["Archer C7", "WR841N"],
            "username": "admin",
            "password": "admin",
            "protocol": "http",
            "source": "https://default-password.info/tp-link/"
        },
        {
            "vendor": "Netgear",
            "models": ["WNR2000", "R7000"],
            "username": "admin",
            "password": "password",
            "protocol": "http",
            "source": "https://default-password.info/netgear/"
        },
        {
            "vendor": "Ubiquiti",
            "models": ["EdgeRouter", "UniFi AP"],
            "username": "ubnt",
            "password": "ubnt",
            "protocol": "ssh",
            "source": "https://default-password.info/ubiquiti/"
        }
    ]
}
```

---

## Appendix D — Threat Intelligence Feed Specification

### Feed Format (JSON Lines)

Each line is a JSON object representing one indicator:

```json
{"type": "domain", "value": "updates.firmware-vendor.com", "tags": ["mirai", "c2"], "confidence": 0.9, "source": "abuse_ch", "first_seen": "2025-01-15", "last_seen": "2025-05-01"}
{"type": "ip", "value": "185.220.101.37", "tags": ["tor_exit", "c2"], "confidence": 0.7, "source": "tor_project", "first_seen": "2024-06-01"}
{"type": "ip_range", "value": "5.187.35.0/24", "tags": ["botnet_infra", "dropper"], "confidence": 0.85, "source": "unit42", "first_seen": "2025-11-01"}
```

### Supported Feed Sources

| Source | Format | Update Frequency | Installation |
|---|---|---|---|
| Abuse.ch (URLhaus) | CSV | Daily | `curl` + cron |
| OTX (AlienVault) | JSON | Real-time | OTX CLI |
| CISA KEV Catalog | JSON | As-published | `curl` from CISA |
| Tor Exit Nodes | Text | Hourly | `curl` + cron |
| Custom (user-defined) | JSON Lines | Manual | File copy |

---

## Build Phase Delivery Schedule

| Phase | Scope | Dependencies | Duration | Milestone |
|---|---|---|---|---|
| **Phase 1** | Core infra + CLI + ingest | None | 3-4 days | `scan` command accepts firmware, produces metadata |
| **Phase 2** | Extraction + filesystem scanner | Phase 1 | 5-6 days | Root filesystem extracted and inventoried |
| **Phase 3** | Entropy + binary intelligence | Phase 1, 2 | 4-5 days | Entropy profile + version strings extracted |
| **Phase 4** | Credential scanner + YARA engine | Phase 2 | 5-6 days | All credential findings with severity |
| **Phase 5** | CVE scanner + NVD integration | Phase 3 | 4-5 days | CVEs per component with KEV status |
| **Phase 6** | C2 detector + threat intel | Phase 2, 3 | 5-6 days | Domain/IP scoring + malware signatures |
| **Phase 7** | Risk scoring + reporting | All phases | 4-5 days | Full risk score + multi-format reports |

**Total estimated effort: 30-37 days** (single engineer, sequential phases)

---

*End of SDR. This document serves as the authoritative build bible for the IoT Hardware Scanner project. All implementation must trace back to specifications herein.*