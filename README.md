# IoT Hardware Scanner

**Defensive static-analysis platform for IoT, embedded, and OT firmware security.**

[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-465%20passed-brightgreen.svg)](tests/)

Offline, modular, config-driven. No emulation, no exploitation, no live device interaction. Takes a firmware binary and produces a scored security report with CVE correlation, credential detection, C2 indicator analysis, and actionable remediation guidance.

---

## What It Does

```
firmware.bin → Ingest → Extract → Filesystem Map → Entropy → Credentials → CVE → C2 → Risk Score → Report
```

| Phase | Module | What It Detects |
|-------|--------|-----------------|
| **1** | `FirmwareIngest` | File validation, hashing, type detection |
| **2** | `FirmwareExtractor` + `FilesystemScanner` | Binwalk extraction, filesystem mapping, SUID/writable audit, boot analysis |
| **3** | `EntropyAnalyzer` + `BinaryIntelligence` | Shannon entropy profile, encrypted/compressed regions, ELF hardening checks (NX, PIE, RELRO, canary) |
| **4** | `CredentialScanner` | Hardcoded passwords, API keys, private keys, tokens, connection strings via YARA + regex, Unix /etc/passwd|shadow parsing |
| **5** | `CVEScanner` | NVD API CVE lookup by CPE + keyword, CISA KEV cross-reference (auto-escalates to CRITICAL) |
| **6** | `C2Detector` | Domain/IP extraction from binaries/configs, DGA detection, botnet naming patterns, YARA-based malware family matching |
| **7** | `RiskScorer` + `ReportGenerator` | 12-control risk model (100 points), OWASP IoT Top 10 mapping, multi-format reports |

---

## Quick Start

```bash
# Install
pip install git+https://github.com/aiagentmackenzie-lang/IOT-Hardware-Scanner.git

# With extraction support (recommended)
pip install "iot-hardware-scanner[extraction]"

# Full scan
iot-hardware-scanner scan firmware.bin

# JSON output for CI/CD
iot-hardware-scanner scan firmware.bin --format json --out report.json

# Markdown report
iot-hardware-scanner scan firmware.bin --format markdown --out report.md

# HTML report (dark-themed, self-contained)
iot-hardware-scanner scan firmware.bin --format html --out report.html

# Credential-only scan (skip CVE/C2 for speed)
iot-hardware-scanner scan firmware.bin --creds

# Entropy analysis only
iot-hardware-scanner entropy firmware.bin

# Regenerate report from a previous scan
iot-hardware-scanner report scan_output/report.json --format html

# Offline mode (skip NVD API + threat intel)
iot-hardware-scanner scan firmware.bin --offline

# Verbose + custom YARA rules
iot-hardware-scanner scan firmware.bin --verbose --yara-rules ./my_rules/
```

---

## Installation

### From Source

```bash
git clone https://github.com/aiagentmackenzie-lang/IOT-Hardware-Scanner.git
cd IOT-Hardware-Scanner
python -m venv .venv && source .venv/bin/activate
pip install -e ".[extraction,nvd,dev]"
```

### Dependencies

| Install | Provides |
|---------|----------|
| `pip install iot-hardware-scanner` | Core: Click, Pydantic, python-magic, Rich, Jinja2, yara-python |
| `[extraction]` | pybinwalk — firmware extraction |
| `[nvd]` | nvdlib — alternative NVD client |
| `[sbom]` | cyclonedx-python-lib — CycloneDX SBOM export |
| `[yaml_support]` | PyYAML — YAML config files |
| `[dev]` | pytest, pytest-cov, ruff, mypy |

---

## Report Output

### JSON — Machine-Readable
```json
{
  "scan_id": "scan-20260521-a1b2c3d4",
  "firmware": { "name": "router-v2.3.bin", "sha256": "...", ... },
  "credentials": { "total": 7, "by_severity": { "CRITICAL": 3, "HIGH": 2 }, ... },
  "cve": { "total": 12, "kev_count": 2, ... },
  "c2_malware": { "total": 4, "by_type": { "domain": 3, "malware_signature": 1 }, ... },
  "risk_score": { "total_score": 42.0, "risk_level": "CRITICAL", ... },
  "sbom": { "total": 24, ... }
}
```

### HTML — Dark-Themed, Self-Contained
Single-file HTML with severity color-coding (CRITICAL=red, HIGH=orange, PASS=green), OWASP mapping table, risk scorecard, and MITRE ATT&CK technique IDs.

---

## Architecture

```
src/iot_hardware_scanner/
├── config.py              # ScannerConfig — Pydantic dataclass, all config
├── models.py              # ScanContext + 20+ dataclasses (shared across all modules)
├── orchestrator.py        # Pipeline coordinator — single entry point
├── cli.py                 # Click CLI with 4 subcommands (scan, extract, entropy, report)
├── exceptions.py          # 10 exception types with exit codes
│
├── scanner/
│   ├── firmware_ingest.py       # Phase 1: validate, hash, identify
│   ├── firmware_extractor.py    # Phase 2a: binwalk extraction, symlink/hardlink audit
│   ├── filesystem_scanner.py    # Phase 2b: walk, categorize, SUID, boot analysis
│   ├── entropy_analyzer.py      # Phase 3a: Shannon entropy, mmap for large files
│   ├── binary_intelligence.py   # Phase 3b: ELF hardening, version extraction
│   ├── credential_scanner.py    # Phase 4: YARA + regex, placeholder filtering
│   ├── unix_cred_parser.py      # Phase 4: /etc/passwd, /etc/shadow
│   ├── cve_scanner.py           # Phase 5: NVD API, KEV cross-reference
│   ├── c2_detector.py           # Phase 6: domain/IP/malware detection
│   ├── risk_scorer.py           # Phase 7a: 12-control model, OWASP mapping
│   └── report_generator.py      # Phase 7b: JSON/MD/HTML/terminal reports
│
├── intelligence/
│   ├── nvd_client.py       # NVD API v2 with SQLite cache + retry/backoff
│   ├── cpe_builder.py      # CPE 2.3 string construction
│   ├── domain_scorer.py    # Domain suspicion scoring, DGA detection
│   └── threat_intel.py     # JSON Lines threat feed loader (domains/IPs/CIDR)
│
├── yara/
│   ├── yara_engine.py      # YARA rule loader, compiler, scanner
│   └── rules/              # 12 built-in YARA rule files
│       ├── credentials_*.yar   # Passwords, API keys, SSH keys, tokens, DB creds
│       ├── backdoor_services.yar
│       ├── weak_crypto.yar
│       └── malware/            # mirai, gafgyt, hajime, jackskid, kimwolf
│
└── data/                   # Runtime data
    ├── benign_domains.txt       # Domain whitelist
    ├── suspicious_tlds.txt      # High-risk TLDs
    ├── default_credentials.json # Known-default credential database
    ├── component_cpe_map.json   # Product → CPE vendor/product mapping
    └── kev_catalog.json         # CISA Known Exploited Vulnerabilities
```

### Design Principles

- **Modular:** Each scanner is an independent module. The orchestrator threads `ScanContext` through all phases.
- **Config-Driven:** `ScannerConfig` (Pydantic) controls every setting. Zero-config operation works out of the box.
- **Graceful Degradation:** All optional dependencies (pybinwalk, yara-python, nvdlib) are checked at runtime. Missing tools → warning, not crash.
- **Security-First:** Zip-Slip + hardlink audit, credential masking (fixed-length redaction), path traversal protection, OOM protection (mmap + size gates for all unbounded file reads).
- **CI-Ready:** Exit codes (0=clean, 1=CRITICAL, 2=non-critical, 3=validation, 4=extraction) for pipeline integration.

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No CRITICAL or LIKELY_C2 findings |
| 1 | CRITICAL findings or LIKELY_C2 indicators detected |
| 2 | Non-critical findings present (HIGH/MEDIUM/SUSPICIOUS) |
| 3 | Firmware file validation error (not found, empty, too large, unreadable) |
| 4 | Extraction failed |
| 5 | Dependency missing (binwalk, yara-python) |
| 6 | Internal error |

---

## Configuration

All via `ScannerConfig` — CLI flags, environment variables, or YAML/TOML config files.

```yaml
# scanner.yaml
max_file_size_mb: 2048
extraction_depth: 3
extraction_timeout_seconds: 300
max_entropy_scan_size_mb: 256    # OOM guard for entropy analysis
max_scan_file_size_mb: 50        # OOM guard for text scanning
nvd_max_retries: 3               # NVD API retry count
offline_mode: false
c2_suspicion_threshold: 40.0
c2_likely_threshold: 60.0
report_formats:
  - json
  - markdown
  - html
verbose: false
```

```bash
# Environment variable for NVD API key (faster rate limits)
export NVD_API_KEY="your-key-here"
iot-hardware-scanner scan firmware.bin
```

---

## Risk Scoring Model

12 security controls, 100 points total. Each control is independently evaluated as PASS/PARTIAL/FAIL.

| # | Control | Max Points | Evidence Source |
|---|---------|------------|-----------------|
| 1 | No default/hardcoded credentials | 10 | CredentialScanner |
| 2 | No unnecessary network services | 10 | FilesystemScanner |
| 3 | No outdated/vulnerable components | 10 | CVEScanner |
| 4 | Encrypted data at rest | 10 | EntropyAnalyzer + CredentialScanner |
| 5 | Secure firmware update mechanism | 10 | FilesystemScanner (signature checks) |
| 6 | Secure boot/integrity verification | 8 | FilesystemScanner (boot analysis) |
| 7 | No backdoor interfaces | 10 | C2Detector |
| 8 | Strong cryptography used | 8 | YARA (weak crypto rules) |
| 9 | Minimal attack surface | 8 | FilesystemScanner |
| 10 | Binary hardening present | 8 | BinaryIntelligence (NX/PIE/RELRO/canary) |
| 11 | No C2/malware indicators | 5 | C2Detector |
| 12 | Accurate component inventory (SBOM) | 3 | BinaryIntelligence |

**Risk Levels:** ≥90 LOW · ≥70 MEDIUM · ≥50 HIGH · <50 CRITICAL

Also maps to **OWASP IoT Top 10** controls automatically.

---

## YARA Rules

12 built-in rule files covering:
- **Credentials:** Passwords, API keys (AWS/GitHub/Stripe/Slack/Google), SSH private keys, JWT tokens, database connection strings
- **Weak Cryptography:** MD5, DES, RC4, static IVs, short RSA keys
- **Backdoor Services:** Telnet, FTP, RSH with suspicious configs
- **Malware Families:** Mirai, Gafgyt, Hajime, JackSkid, KimWolf — with MITRE ATT&CK ICS technique mapping

Custom rules: drop `.yar` files in `~/.iot_hardware_scanner/yara_rules/` or pass `--yara-rules ./dir/`.

---

## Security Hardening

Built into the platform itself:

| Measure | Detail |
|---------|--------|
| **OOM Protection** | `max_entropy_scan_size_mb` (mmap sampling), `max_scan_file_size_mb` (skip gates) |
| **Zip-Slip Mitigation** | Symlink audit (`_audit_symlinks`) — removes symlinks escaping extraction root |
| **Hard Link Audit** | `_audit_hardlinks` — detects hard links to sensitive host files |
| **Path Traversal** | `resolve()` validation before any path access |
| **Credential Masking** | Fixed-length redaction — prevents prefix/suffix/length information leaks |
| **NVD Rate Limiting** | 6s delay (no key) / 0.6s (with key), exponential backoff on 429/503 |
| **SQLite Caching** | NVD results cached with configurable TTL (default 7 days) |

---

## Testing

```bash
# Full suite
pytest tests/ -v

# With coverage
pytest tests/ --cov=src/iot_hardware_scanner --cov-report=term-missing

# Skip slow/integration tests
pytest tests/ -m "not slow and not integration"

# Lint
ruff check src/ tests/

# Type check
mypy src/
```

**465 tests** covering all modules. Test markers: `@pytest.mark.slow`, `@pytest.mark.integration`.

---

## Contributing

1. Read the [build specification](SDR.md) for architecture and design rationale
2. Tests are required — all modules have corresponding `tests/test_*.py` files
3. Follow the config-driven pattern — add new fields to `ScannerConfig`, wire through orchestrator phases
4. Optional dependencies are checked at runtime with graceful degradation
5. All external reads are gated against OOM (`max_scan_file_size_mb`)

---

## License

MIT — see [LICENSE](LICENSE).

---

## Credits

Built by [@aiagentmackenzie-lang](https://github.com/aiagentmackenzie-lang). Part of the Mackenzie Security portfolio.
