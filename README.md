# IoT Hardware Scanner

**Static analysis for firmware artifacts, built for the engineer who has to explain what went into a shipped image.**

[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.12%20%7C%203.14-blue.svg)](pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

The product answers one question honestly: *what can be established from these bytes, and what cannot?*
Every observation is tied to an input digest and a locator — a file in an image, a directory in a
staged tree, or a byte/line range in the artifact itself. It does not emulate firmware, does not
talk to devices, and does not reach the network unless asked.

---

## Status — version 2.0

Version 2 removes the aggregate 0–100 security grade and reports **named checks, findings,
limitations and completion** instead. See [What changed in 2.0](#what-changed-in-20) and
[docs/MIGRATION-v2.md](docs/MIGRATION-v2.md).

| Capability | State |
| --- | --- |
| Input identity (file SHA-256 / canonical tree digest) | ✅ implemented |
| Immutable input binding (private snapshot, verified digest) | ✅ implemented |
| Opaque or unsupported artifact handling | ✅ reports incomplete, never "clean" |
| Credential, secret and Unix-account detection | ✅ implemented, offline |
| Account joining (passwd ↔ shadow, per root) | ✅ implemented |
| Byte-distribution (entropy) measurement | ✅ implemented, units = bits/byte |
| Firmware image extraction (gzip → SquashFS v4) | ✅ implemented, pinned Linux worker |
| ELF identity, dependencies and hardening evidence | ✅ read from the file's own headers |
| Installed-package (opkg) inventory | ✅ read verbatim from the image |
| Staged root trees (`--input-tree`, declared manifests) | ✅ implemented |
| Advisory (CVE) applicability | ❌ not implemented; always reported as *unassessed*, never as clean |
| MCU / FIT / RAUC / partitioned images | ❌ later gates, not in this release |
| CycloneDX SBOM export | ❌ not implemented |
| Release-to-release comparison | ❌ not implemented |

When extraction is unavailable the run still produces a report: it names the missing backend,
records every stage that could not run, keeps any findings it did obtain, and exits non-zero.

---

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install iot-hardware-scanner
```

| Extra | Provides | Notes |
| --- | --- | --- |
| *(none)* | click, pydantic, python-magic, rich, jinja2, yara-python, pyelftools | Everything needed to scan a staged tree, an opaque artifact, or an extracted image |
| `[nvd]` | nvdlib | Optional online advisory refresh |
| `[yaml_support]` | PyYAML | YAML config files (TOML needs nothing extra on 3.11+) |
| `[dev]` | pytest, pytest-cov, ruff, mypy, pyyaml | Development and CI |

There is **no `extraction` extra**. Extraction does not run in-process: the gzip wrapper is decoded
here and the SquashFS filesystem is decoded by upstream `unsquashfs` in a pinned Linux worker, so
there is no Python dependency to install. `worker/Dockerfile` builds that worker:

```bash
docker build -t ihs-squashfs-worker:4.5.1 worker/     # or: podman build …
```

Advertised extras are audited in `tests/test_installed_cli.py`.

`python-magic` is used as a *hint* only. If libmagic is absent the scanner falls back to magic-byte
and extension checks and says so; it never changes a security conclusion.

---

## Use

```bash
# Scan a staged root tree, credentials only (no root privileges, no network)
iot-hardware-scanner scan ./staged-root --creds --format json --out report.json

# Scan a staged root tree with the full firmware profile (no extraction needed)
iot-hardware-scanner scan ./staged-root --input-tree --offline --format json --out report.json
iot-hardware-scanner scan ./staged-root --input-tree --build-manifest declared.json

# Scan a gzip-wrapped SquashFS image; offline by default
iot-hardware-scanner scan firmware.img.gz --offline --format json --out report.json

# Decode an image without analysing it
iot-hardware-scanner extract firmware.img.gz --output ./extracted

# The same image with the worker turned off: identifies the image, names the
# dependency, keeps what it could still see, and exits 5
iot-hardware-scanner scan firmware.img.gz --offline --worker none

# Markdown / HTML from the same document
iot-hardware-scanner scan firmware.img --format markdown --out report.md
iot-hardware-scanner scan firmware.img --format html --out report.html

# Byte-distribution measurement only
iot-hardware-scanner entropy firmware.img --block-size 4096 --format json

# Re-render a saved report without re-analysing anything
iot-hardware-scanner report report.json --format html --out report.html
```

`--out` is written **exactly** where you ask, atomically. If the write fails the process exits 6
and never prints a success line. `--offline` remains valid; it is also the default.

### Profiles

| Profile | Selected by | Required stages |
| --- | --- | --- |
| `firmware-static` | default for a file | ingest, extraction, root discovery, enumeration, entropy, binary inventory, ELF metadata, opkg inventory, credentials, Unix accounts, services, C2, checks |
| `firmware-tree` | `--input-tree`, or a directory positional | ingest, enumeration, binary inventory, ELF metadata, opkg inventory, credentials, Unix accounts, services, C2, checks — **no extraction, no entropy** |
| `credentials-only` | `--creds` / `--profile credentials-only` | ingest, enumeration, credentials, Unix accounts, checks |

A profile completes only when every stage it requires either ran or is genuinely inapplicable. A
staged tree has no container to decode, so it never carries an extraction prerequisite; the
extraction stage is recorded `NOT_APPLICABLE` with that reason.

---

## Exit codes

Precedence, highest first. The decision is written into the report as `outcome`, so the saved
document and the process status cannot disagree.

| Code | Meaning |
| --- | --- |
| 3 | Invalid input or configuration |
| 6 | Internal error, or the requested report could not be written |
| 1 | A critical finding that meets its **documented evidence rule** (including on an incomplete assessment) |
| 5 | A required dependency or snapshot is missing (no container runtime or worker image, for an image input) |
| 4 | Analysis incomplete (unsupported input, extraction failed, limit reached, input could not be bound) |
| 2 | Report delivered, review or non-critical finding |
| 0 | Report delivered, all required work completed, no findings |

`report` (replay) is the exception: it signals only whether rendering succeeded, because the
saved document already carries the scan's own outcome.

Only rules listed in `scanner/assessment.py::CRITICAL_RULE_EVIDENCE` can produce exit 1. Each has
a documented observation and both a positive and a lookalike-negative fixture. Everything else —
including `LIKELY_C2` indicators and unqualified YARA hits — is a review finding and exits 2.

---

## Report document

One schema-3 JSON document is the single source for every format. Full details in
[docs/MIGRATION-v3.md](docs/MIGRATION-v3.md); the schema-2 change is in
[docs/MIGRATION-v2.md](docs/MIGRATION-v2.md).

```json
{
  "schema_version": 3,
  "tool": {"name": "iot-hardware-scanner", "version": "2.0.0"},
  "artifact": {"kind": "tree", "sha256": "…", "size": 145, "file_type": "Staged root tree (2 files)"},
  "assessment": {
    "profile": "credentials-only",
    "completion": "COMPLETE",
    "incomplete_reasons": [],
    "check_counts": {"PERFORMED": 3, "INCONCLUSIVE": 3, "NOT_APPLICABLE": 0, "OMITTED": 6}
  },
  "stages":   [{"stage": "credential_scan", "status": "COMPLETE", "required": true,
                "inspected": 2, "eligible": 2, "reason": "inventory-scoped scan"}],
  "findings": [{"rule_id": "credential.unix.empty_password", "severity": "CRITICAL",
                "locations": ["slot_a/etc/shadow:2"], "critical_qualified": true}],
  "controls": [{"control_id": 1, "status": "FAIL", "result": "FAIL", "evidence": ["…"]}],
  "image_map": {"root_artifact_id": "a0", "nodes": [
    {"artifact_id": "a0", "format": "gzip", "coordinate_system": "container-bytes",
     "length": 4451127, "decoder": "python-zlib", "decoder_version": "1.2.12"},
    {"artifact_id": "a1", "parent_id": "a0", "format": "squashfs",
     "expanded_bytes": 109051904, "extent_bytes": 4348264,
     "decoder": "unsquashfs", "decoder_version": "unsquashfs version 4.5.1"}]},
  "extraction": {"state": "OK", "worker": "docker", "isolation": "container",
                 "worker_digest": "sha256:…", "helper_version": "unsquashfs version 4.5.1",
                 "limits": {"max_extracted_bytes": 1073741824, "max_entries": 200000}},
  "input_binding": {"declared_sha256": "8b5a…", "verified_sha256": "8b5a…",
                    "immutable": true, "source_changed": false},
  "elf": {"eligible": 209, "parsed": 209, "records": [
    {"locator": "rootfs/bin/busybox", "digest_sha256": "214a…", "machine": 183,
     "machine_name": "AArch64", "type": "EXEC", "hardening": {"pie": false, "relro": "full",
     "canary": null}, "unknown": ["no symbol table is present …"]}]},
  "opkg": {"locator": "rootfs/usr/lib/opkg/status", "installed": 196, "held": 4,
           "records": [{"name": "busybox", "version": "1.36.1-r2",
                        "architecture": "aarch64_generic",
                        "evidence": {"start": 2804, "end": 3095, "line": 102}}]},
  "data_sources": [{"name": "kev_catalog.json", "sample": true, "sha256": "…"}],
  "risk_score": null,
  "outcome": {"exit_code": 2, "exit_reason": "REPORTABLE_FINDING"}
}
```

`risk_score` is `null` for every new scan. It is only populated when replaying a v1 document that
already contained a grade, in which case `legacy_grade` labels it with its method.

### What a stage status means

| Status | Meaning |
| --- | --- |
| `COMPLETE` | Ran over its whole eligible population |
| `PARTIAL` | Ran, but some eligible members were not inspected |
| `UNAVAILABLE` | Required capability absent (backend, snapshot) |
| `FAILED` | Ran and errored |
| `SKIPPED` | Deliberately not requested |
| `NOT_APPLICABLE` | No eligible population for this input/profile |

`inspected` / `eligible` are `null` when the population could not be counted. An observed `0`
means the population really was enumerated and found empty.

---

## Named checks

The 12 control names are kept for continuity. Each is reported with its own evidence status
(`PERFORMED`, `INCONCLUSIVE`, `NOT_APPLICABLE`, `OMITTED`) and its result; there is no aggregate
score and no points.

| # | Check | Evidence source |
| --- | --- | --- |
| 1 | No default/hardcoded credentials | credential scan |
| 2 | No unnecessary network services | configured startup directives (with source line) |
| 3 | No outdated/vulnerable components | advisory snapshot — not implemented, so always unassessed |
| 4 | Encrypted data at rest | format evidence only; entropy can never pass it |
| 5 | Secure firmware update mechanism | enumerated update paths |
| 6 | Secure boot/integrity | **always unknown** from a static image |
| 7 | No backdoor interfaces | indicator sweep |
| 8 | Strong cryptography used | account hash algorithms and crypto-rule matches |
| 9 | Minimal attack surface | SUID / world-writable files |
| 10 | Binary hardening present | ELF program headers — positive evidence only; a stripped file's silence proves nothing |
| 11 | No C2/malware indicators | indicator sweep |
| 12 | Accurate component inventory | the image's own opkg records, with banner findings as candidates only |

Three rules worth stating plainly:

* **Entropy is a distribution, not an encryption detector.** Constant bytes measure 0 bits/byte,
  two alternating symbols measure 1, 256 equally frequent byte values measure 8. A high-entropy
  region is reported as `high_entropy` and nothing more.
* **A configured startup entry is not a listening socket.** Service findings carry the file and
  line that configured them and stay `INCONCLUSIVE`; device evidence is required to go further.
* **A locked password is one authentication method.** A `root:!…` shadow line is not a critical
  plaintext-password finding; an empty password field on a login account is.
* **A missing symbol table is not missing hardening.** A section-stripped binary yields `null` for
  canary and FORTIFY, and check 10 reports the property as unknown rather than as absent.
* **A host-derived permission bit is not an image permission bit.** A staged tree without a build
  manifest cannot produce a clean attack-surface result; the check answers `INCONCLUSIVE`.

---

## Configuration

Precedence: **explicit CLI values > environment > config file > defaults**.

```toml
# scanner.toml
max_file_size_mb = 2048
max_entropy_scan_size_mb = 256
max_scan_file_size_mb = 50
offline_mode = true
report_formats = ["json", "markdown"]
c2_suspicion_threshold = 40.0
c2_likely_threshold = 60.0
```

```bash
iot-hardware-scanner scan firmware.img --config scanner.toml --max-size 512
```

Every field can be set as `IOT_HARDWARE_SCANNER_<FIELD>` (for example
`IOT_HARDWARE_SCANNER_MAX_SCAN_FILE_SIZE_MB=25`). YAML needs the `yaml_support` extra; a missing
PyYAML fails with a clear message rather than being silently ignored.

---

## Offline by default

A scan never reaches the network: there is no code path that issues a request unless an operator
explicitly asks for a refresh, and refresh is a separate operation.

Advisory assessment is **not implemented in this release**. The advisory stage is recorded as
`SKIPPED` with that reason, check 3 is `OMITTED`, and the report says applicability was **not
assessed** — never that the image is clean.

Bundled data ships inside the installed package (nothing is loaded from the current directory or
your home directory) and each file's digest is recorded in `data_sources`. Files that are examples
are flagged as samples; conclusions that depend on them are indicative, not current.

Custom YARA rules are opt-in:

```bash
iot-hardware-scanner scan firmware.img --yara-rules ./my_rules/
```

---

## Security posture of the scanner itself

| Measure | Detail |
| --- | --- |
| Credential redaction | Values are replaced before a finding, log line or report is produced |
| Path handling | Traversal sequences and symlinked inputs rejected before any read |
| Bounded readers | Every read declares a byte budget; windows keep their original offsets |
| Immutable input | Analysis reads a private read-only snapshot whose digest is verified against ingest |
| Isolated extraction | Read-only input, no network, no capabilities, size-limited tmpfs, memory/pid/CPU limits, streamed output and a wall-clock deadline |
| Untrusted names | Every member name from the worker is validated before anything is created; symlinks are metadata only |
| Report writes | Atomic, to the exact requested path, with failures surfaced |
| No ambient rule loading | Rules come from the package or an explicit flag |
| Offline default | No network path is taken unless a snapshot/refresh is requested |

---

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

ruff check src/ tests/
mypy src/
pytest --cov=src/iot_hardware_scanner --cov-report=term --cov-fail-under=80
```

Release-qualification checks that need an external artifact are opt-in:

```bash
# Checksum-verified OpenWrt ARM64 image (never downloaded by the suite)
export IHS_REFERENCE_IMAGE=/path/to/openwrt-24.10.0-armsr-armv8-generic-squashfs-rootfs.img.gz
pytest tests/test_installed_cli.py -k openwrt

# Milestone B acceptance rows: needs the worker image as well
docker build -t ihs-squashfs-worker:4.5.1 worker/
pytest tests/test_installed_image_cli.py -v

# Run the acceptance harness against a console script installed from a built wheel
uv build && uv pip install dist/*.whl
IHS_INSTALLED_CLI=$(command -v iot-hardware-scanner) pytest tests/test_installed_cli.py
```

The reference image used for qualification is
`openwrt-24.10.0-armsr-armv8-generic-squashfs-rootfs.img.gz`, SHA-256
`8b5aa82659cafd90b26333dd419a0df9ad63c517ad94a2159e970a5bb5b6ff02` (4,451,127 bytes on the wire,
109,051,904 bytes decompressed, SquashFS v4 with 4,348,264 bytes used). Fetch and verify it
*outside* the scan.

---

## Known limitations

* **One container path.** gzip-wrapped SquashFS v4 only. Partitioned images, CPIO, JFFS2/UBIFS,
  MCU address spaces, FIT/DTB and RAUC bundles are later gates with their own fixtures; each is
  reported as unsupported rather than guessed at.
* **A worker is required for image extraction.** Without a container runtime the product still
  identifies the image and reports honestly, but it cannot enumerate the filesystem (exit 5).
* **Installed-package records are not file evidence.** The database says what the package manager
  recorded; it does not prove every package-owned file is present or intact.
* **Section-stripped binaries** yield `unknown` for canary and FORTIFY: the dynamic symbol table
  lives in a section these images do not carry.
* **Advisory applicability is unassessed** — check 3 is `OMITTED`, never a pass.
* **Static analysis cannot establish** runtime behaviour, exposed network services, physical boot
  enforcement or which A/B slot is running.
* **Staged-tree metadata is host-derived** unless a build manifest is supplied; a clean
  permission result is then `INCONCLUSIVE`, not a pass.
* **Banner-derived components are candidates**, ranked below the image's own package records.
* **Sample data** (`kev_catalog.json`, `threat_intel_sample.jsonl`) is bundled for exercise only.

## License

MIT — see [LICENSE](LICENSE).
