# IoT Hardware Scanner

**Static analysis for firmware artifacts, built for the engineer who has to explain what went into a shipped image.**

[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.12%20%7C%203.14-blue.svg)](pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

The product answers one question honestly: *what can be established from these bytes, and what cannot?*
Every observation is tied to an input digest and a locator — a file in an image, a directory in a
staged tree, or a byte/line range in the artifact itself. It does not emulate firmware, does not
talk to devices, and does not reach the network unless asked.

---

## Status — version 2.5.0

Version 2.5 is a **hardening release with no new format and no schema change**.
Every parser that consumes untrusted bytes — the gzip/SquashFS headers, FDT/FIT,
the opkg database, the extraction worker's tar stream and the saved-document
loaders — now has a committed adversarial corpus and property tests, and a
malformed artifact becomes a named `FAILED` stage with exit 4 instead of a
traceback. A saved document that is not a readable report is exit 3; a scanner
defect outside every stage is exit 6 with one line. Report schema stays 6 and the
profile version stays 5.0. Qualified in CI: run `44911766646`, 8/8 jobs green,
45 hostile-input rows with zero skips, wheel byte-identical macOS↔Linux.
Record: [docs/2E-HOSTILE-INPUT.md](docs/2E-HOSTILE-INPUT.md).

Version 2.4 added two post-D slices. **Boot manifests** (`firmware-boot`): bounded
parsers for flattened device trees and U-Boot FIT, with board compatibility,
memory, partitions, configurations and referenced payloads; digest integrity,
signature presence and verification against an **operator-supplied** key are
separate fields, and physical boot enforcement is always `unknown`.
**Repeated work** (5C): an opt-in content-addressed cache of deterministic
parser outputs, measured at 7.73 s → 1.81 s and 205.8 MB → 110.0 MB on the
pinned corpus, with identical reports. Report schema 6, profile version 5.0.
The aggregate 0–100 grade stays retired. Qualified in CI: run `44904681133`,
8/8 jobs green, 200 acceptance tests with zero skips in the job that runs the
real extraction path.

Version 2.3 delivered the release comparison, declaration reconciliation and
CycloneDX export; 2.2 was the first qualified release. See
[docs/MILESTONE-E.md](docs/MILESTONE-E.md) for the 2.4 slice record,
[docs/5C-DECISION.md](docs/5C-DECISION.md) for the measured cache decision,
[docs/MILESTONE-D.md](docs/MILESTONE-D.md) for 2.3,
[what changed](#what-changed-in-20), [docs/MIGRATION-v6.md](docs/MIGRATION-v6.md)
for report schema 6, and [docs/MIGRATION-v5.md](docs/MIGRATION-v5.md) for
schema 5.

The qualification record — formats, tested level, host requirements, corpus
descriptions and the measured detector numbers — is
[docs/SUPPORT-MATRIX.md](docs/SUPPORT-MATRIX.md). Every capability below links
to a passing case.

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
| One compiled rule set, with a published digest | ✅ implemented |
| Typed match destinations (credential / service / crypto / indicator) | ✅ implemented |
| 12 named checks, each with a named evidence source | ✅ implemented |
| Advisory applicability from a **local snapshot**, offline | ✅ implemented; needs `--advisory-snapshot` |
| Online advisory refresh inside a scan | ❌ never — refresh is a separate operation |
| Component inventory → CPE coverage | ✅ 196 of 196 records on the reference image carry a component, each with a recorded basis (5 `nist-mapped`, 191 `opkg-package-name`) |
| Release-to-release comparison (`compare`) | ✅ implemented, offline, on two saved scans |
| Build-declaration reconciliation (OpenWrt manifest, CycloneDX 1.4) | ✅ implemented, with each declaration's digest, binding and four outcomes |
| CycloneDX 1.6 BOM export (`sbom --validate`) | ✅ implemented, validated against a vendored schema |
| Flattened device trees and U-Boot FIT (`firmware-boot`) | ✅ bounded parse; configuration, payload integrity, signature presence/verification |
| Repeated-work cache (`--cache-dir`) | ✅ opt-in, bounded, atomic; measured cold/warm equivalence |
| MCU / RAUC / partitioned images / raw NAND | ❌ later gates, not in this release |

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
| `[nvd]` | nvdlib | Optional online advisory refresh (outside the scan) |
| `[yaml_support]` | PyYAML | YAML config files (TOML needs nothing extra on 3.11+) |
| `[dev]` | pytest, pytest-cov, ruff, mypy, pyyaml | Development and CI |

`yara-python` is a **required** part of the release profile: from version 2.2 the
`rule_compilation` stage is required, so a wheel without a working rule engine
reports a missing dependency (exit 5) instead of silently finding nothing.

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

# Apply a local advisory snapshot (still offline: the scan never fetches)
iot-hardware-scanner scan firmware.img.gz --offline \
  --advisory-snapshot advisory-2026-11.json --format json --out report.json

# Read a boot manifest: an FIT or a DTB. A key is only a trust anchor when the
# operator supplies it; an embedded key is never trusted.
iot-hardware-scanner scan board.itb --profile firmware-boot --format json --out board.json
iot-hardware-scanner scan board.itb --trust-anchor operator-key.pem --format json --out board.json

# Reuse deterministic parser output across runs (opt-in, bounded, offline)
iot-hardware-scanner scan firmware.img.gz --cache-dir ~/.cache/ihs-analysis \
  --format json --out report.json

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

# Compare two released images, from their saved scans (no extraction, no network)
iot-hardware-scanner compare release-1.json release-2.json \
  --format markdown --out comparison.md

# Reconcile the build declaration with the shipped bytes: an OpenWrt target
# manifest and the supplier's CycloneDX document, both read offline
iot-hardware-scanner compare release-1.json release-2.json \
  --declaration openwrt-24.10.0-armsr-armv8.manifest \
  --declaration openwrt-24.10.0-armsr-armv8.bom.cdx.json \
  --format json --out declaration-comparison.json

# Export the inventory as a CycloneDX 1.6 BOM and validate it offline
iot-hardware-scanner sbom release-2.json --out bom.cdx.json --validate
```

`sbom --validate` needs the `sbom` extra: `pip install 'iot-hardware-scanner[sbom]'`.
Without it the export still works and the validation step says what to install.

`--out` is written **exactly** where you ask, atomically. If the write fails the process exits 6
and never prints a success line. `--offline` remains valid; it is also the default.

### Profiles

| Profile | Selected by | Required stages |
| --- | --- | --- |
| `firmware-static` | default for a file | ingest, rule compilation, extraction, root discovery, enumeration, entropy, binary inventory, ELF metadata, opkg inventory, credentials, Unix accounts, services, C2, checks |
| `firmware-tree` | `--input-tree`, or a directory positional | ingest, rule compilation, enumeration, binary inventory, ELF metadata, opkg inventory, credentials, Unix accounts, services, C2, checks — **no extraction, no entropy** |
| `credentials-only` | `--creds` / `--profile credentials-only` | ingest, rule compilation, enumeration, credentials, Unix accounts, checks |
| `firmware-boot` | `--profile firmware-boot`, or an FDT/FIT magic | ingest, rule compilation, boot analysis, checks (5 and 6); every filesystem stage is `NOT_APPLICABLE` |

A profile completes only when every stage it requires either ran or is genuinely inapplicable. A
staged tree has no container to decode, so it never carries an extraction prerequisite; the
extraction stage is recorded `NOT_APPLICABLE` with that reason.

Supplying `--advisory-snapshot` promotes the advisory stage to **required** for that run. A missing
or unreadable snapshot then leaves the assessment incomplete and exits 5 or 4 — never 0.

---

## Exit codes

Precedence, highest first. The decision is written into the report as `outcome`, so the saved
document and the process status cannot disagree.

| Code | Meaning |
| --- | --- |
| 3 | Invalid input or configuration |
| 6 | Internal error, or the requested report could not be written |
| 1 | A critical finding that meets its **documented evidence rule** (including on an incomplete assessment) |
| 5 | A required dependency or snapshot is missing (no container runtime or worker image, for an image input; or a requested advisory snapshot that is absent) |
| 4 | Analysis incomplete (unsupported input, extraction failed, limit reached, input could not be bound) |
| 2 | Report delivered, review or non-critical finding |
| 0 | Report delivered, all required work completed, no findings |

`report` (replay) is the exception: it signals only whether rendering succeeded, because the
saved document already carries the scan's own outcome.

`compare` and `sbom` have their **own** documented contracts; neither reuses the scan table,
because neither produces a security assessment:

| `compare` | Meaning |
| --- | --- |
| 3 | An input could not be read as a scan document |
| 6 | The requested comparison could not be written |
| 2 | The comparison was determinate and something differs (image, findings, or declaration) |
| 4 | Nothing differs, but something could not be concluded (a detector that had findings did not settle, or a declaration row is unresolved/unbound) |
| 0 | Nothing differs and nothing was left unresolved |

| `sbom` | Meaning |
| --- | --- |
| 3 | The input is not a readable scan document, or it carries no exportable identity |
| 4 | The exported BOM failed validation against the vendored CycloneDX 1.6 schema |
| 6 | The BOM could not be written |
| 0 | BOM produced (and validated, when `--validate` was asked for) |

Only rules listed in `scanner/assessment.py::CRITICAL_RULE_EVIDENCE` can produce exit 1. Each has
a documented observation and both a positive and a lookalike-negative fixture. Everything else —
including `LIKELY_C2` indicators, unqualified YARA hits and crypto observations — is a review
finding and exits 2.

**Hostile input never produces a traceback.** A malformed, truncated or
out-of-bounds artifact fails the stage that could not read it, is reported with
the reason, and exits 4; the findings already collected survive. A saved document
that is not a readable report is invalid input (3) and is rejected before any
renderer indexes into it.

---

## Report document

One schema-6 JSON document is the single source for every format. Full details in
[docs/MIGRATION-v6.md](docs/MIGRATION-v6.md) for `boot` and `cache`;
[docs/MIGRATION-v5.md](docs/MIGRATION-v5.md) is the schema-5 change, the schema-4 change in
[docs/MIGRATION-v4.md](docs/MIGRATION-v4.md), the schema-3 change in
[docs/MIGRATION-v3.md](docs/MIGRATION-v3.md) and the schema-2 change in
[docs/MIGRATION-v2.md](docs/MIGRATION-v2.md).

A **comparison** is a different document type with its own version
(`ihs-comparison/1`), and an **SBOM** is CycloneDX 1.6. Neither is a scan
document, and neither is a substitute for one.

```json
{
  "schema_version": 6,
  "tool": {"name": "iot-hardware-scanner", "version": "2.5.0"},
  "artifact": {"kind": "tree", "sha256": "…", "size": 145, "file_type": "Staged root tree (2 files)"},
  "assessment": {
    "profile": "credentials-only",
    "profile_version": "5.0",
    "completion": "COMPLETE",
    "incomplete_reasons": [],
    "check_counts": {"PERFORMED": 3, "INCONCLUSIVE": 3, "NOT_APPLICABLE": 0, "OMITTED": 6}
  },
  "stages":   [{"stage": "credential_scan", "status": "COMPLETE", "required": true,
                "inspected": 2, "eligible": 2, "reason": "inventory-scoped scan"}],
  "findings": [{"rule_id": "credential.unix.empty_password", "severity": "CRITICAL",
                "destination": "credential", "namespaces": [], "ruleset_digest": "",
                "locations": ["slot_a/etc/shadow:2"], "critical_qualified": true}],
  "controls": [{"control_id": 1, "status": "FAIL", "evidence_status": "FAIL",
                "applicability": "APPLICABLE", "result": "FAIL",
                "question": "Does the artifact contain a default or hardcoded credential?",
                "required_source": "the credential rule set and the account databases …",
                "evidence": ["…"]}],
  "ruleset": {"digest": "2ca7a94b…", "engine": "yara-python", "engine_version": "4.5.4",
              "rule_files": [{"namespace": "weak_crypto", "name": "weak_crypto.yar",
                              "sha256": "…", "rule_count": 3,
                              "destinations": ["crypto"]}],
              "compile_errors": []},
  "advisory": {"state": "ASSESSED", "matched": 1, "kev_matches": 1,
               "snapshot": {"provider": "nvd", "acquired_at": "…", "digest_sha256": "…",
                            "age_days": 1.0, "stale": false},
               "lookups": [{"component": "busybox", "version": "1.36.1-r2",
                            "state": "MATCHED", "matches": 1}]},
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
  "components": [{"vendor": "busybox", "product": "busybox", "version": "1.36.1-r2",
                  "cpe": "cpe:2.3:a:busybox:busybox:1.36.1-r2:*:*:*:*:*:*:*",
                  "cpe_basis": "nist-mapped", "confidence": "recorded",
                  "evidence": "rootfs/usr/lib/opkg/status:2804-3095 (line 102)"}],
  "component_bases": {"counts": {"nist-mapped": 5, "opkg-package-name": 191, "banner": 0},
                      "total": 196},
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
| `UNAVAILABLE` | Required capability absent (backend, snapshot, rule engine) |
| `FAILED` | Ran and errored |
| `SKIPPED` | Deliberately not requested |
| `NOT_APPLICABLE` | No eligible population for this input/profile |

`inspected` / `eligible` are `null` when the population could not be counted. An observed `0`
means the population really was enumerated and found empty.

---

## Named checks

The 12 control names are kept for continuity. Each is reported with its own
**question**, the **evidence source** that can answer it, an evidence status
(`PERFORMED`, `INCONCLUSIVE`, `NOT_APPLICABLE`, `OMITTED`) and its result; there
is no aggregate score and no points. Every control has a positive, a contrary
and a missing-evidence case in `tests/test_control_matrix.py`.

| # | Check | Question | Required source |
| --- | --- | --- | --- |
| 1 | No default/hardcoded credentials | Does the artifact contain a default or hardcoded credential? | the credential rule set and the account databases, after placeholder, documentation and reachability rules |
| 2 | No unnecessary network services | Does the artifact configure a service, and is it listening? | startup directives with their source line (configured); a socket table from the device (listening) |
| 3 | No outdated/vulnerable components | Does an applicable advisory affect a shipped component? | a local advisory snapshot applied to observed product and version |
| 4 | Encrypted data at rest | Is data stored in the artifact encrypted? | format evidence; byte distribution is an observation, never a verdict |
| 5 | Secure firmware update mechanism | Does shipped content verify a signature or digest? | the update-path files in the enumerated image |
| 6 | Secure boot/integrity | Does the board enforce that verification at boot? | boot log, fuse/OTP state — **never** available from an image |
| 7 | No backdoor interfaces | Does the artifact contain a backdoor interface? | the indicator rule set and sweep, after reachability rules |
| 8 | Strong cryptography used | Does the artifact use a strong algorithm? | algorithm identifiers in shipped binaries, account hash algorithms, the TLS package record — **not** binary hardening |
| 9 | Minimal attack surface | Any SUID or world-writable file? | permission bits from the image or a declared manifest |
| 10 | Binary hardening present | Do binaries carry positive hardening evidence? | program headers: NX, PIE, RELRO; a stripped file's silence proves nothing |
| 11 | No C2/malware indicators | Does the artifact carry an indicator? | the indicator rule set and heuristic sweep, with typed destinations |
| 12 | Accurate component inventory | Is the inventory backed by the image's own records? | the installed-package database and read ELF metadata |

Rules worth stating plainly:

* **Entropy is a distribution, not an encryption detector.** Constant bytes measure 0 bits/byte,
  two alternating symbols measure 1, 256 equally frequent byte values measure 8. A high-entropy
  region is reported as `high_entropy` and nothing more. Check 4 can never pass on it.
* **A configured startup entry is not a listening socket.** Service findings carry the file and
  line that configured them and stay `INCONCLUSIVE`; device evidence is required to go further.
* **A locked password is one authentication method.** A `root:!…` shadow line is not a critical
  plaintext-password finding; an empty password field on a login account is.
* **A missing symbol table is not missing hardening.** A section-stripped binary yields `null` for
  canary and FORTIFY, and check 10 reports the property as unknown rather than as absent.
* **An algorithm being present is not an algorithm being used.** Check 8 reports weak-algorithm
  code with its file and offset, and reviews rather than failing the image.
* **Verification in a script is not enforcement at boot.** Check 5 and check 6 are separate.
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
advisory_snapshot = "advisory-2026-11.json"
advisory_snapshot_max_age_days = 30
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

Advisory assessment reads a **local snapshot** (`--advisory-snapshot`, or the
`advisory_snapshot` setting) and issues zero requests; `tests/test_advisory.py` asserts that with
`urllib.request.urlopen` replaced by a function that raises. Without a snapshot the advisory stage
is `SKIPPED` with that reason, check 3 is `OMITTED`, and the report says applicability was **not
assessed** — never that the image is clean. The snapshot format is documented in
[docs/MIGRATION-v4.md](docs/MIGRATION-v4.md#4-the-advisory-snapshot-format).

Bundled data ships inside the installed package (nothing is loaded from the current directory or
your home directory) and each file's digest is recorded in `data_sources`. Files that are examples
are flagged as samples; conclusions that depend on them are indicative, not current.

Rules are compiled **once per run** from the package plus any directory the operator names
explicitly, and the resulting digest is in the report. Custom rules are opt-in:

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
| No ambient rule loading | Rules come from the package or an explicit flag; a scan's verdict cannot change because of a file next to it |
| Typed matches | A rule's category decides what a match may become; no detector relabels another's match |
| Offline default | No network path is taken unless a snapshot/refresh is requested; the snapshot path is asserted to issue zero requests |

---

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

ruff check src/ tests/
mypy src/
pytest --cov=src/iot_hardware_scanner --cov-report=term --cov-fail-under=80
ruff format --check src/ tests/
```

Release-qualification checks that need an external artifact are opt-in:

```bash
# Checksum-verified OpenWrt ARM64 image (never downloaded by the suite)
export IHS_REFERENCE_IMAGE=/path/to/openwrt-24.10.0-armsr-armv8-generic-squashfs-rootfs.img.gz
pytest tests/test_installed_cli.py -k openwrt

# Acceptance rows that need the worker image as well
docker build -t ihs-squashfs-worker:4.5.1 worker/
pytest tests/test_installed_image_cli.py -v

# Run the acceptance harness against a console script installed from a built wheel
uv build && uv pip install dist/*.whl
IHS_INSTALLED_CLI=$(command -v iot-hardware-scanner) pytest tests/test_installed_cli.py
```

The qualified release for 2.2.0 is recorded in
[docs/SUPPORT-MATRIX.md](docs/SUPPORT-MATRIX.md): wheel, worker image, rule-set
and corpus digests, with the platform each was built on. The reference image is
`openwrt-24.10.0-armsr-armv8-generic-squashfs-rootfs.img.gz`, SHA-256
`8b5aa82659cafd90b26333dd419a0df9ad63c517ad94a2159e970a5bb5b6ff02` (4,451,127 bytes on the wire,
109,051,904 bytes decompressed, SquashFS v4 with 4,348,264 bytes used). Fetch and verify it
*outside* the scan.

---

## Known limitations

* **One container path.** gzip-wrapped SquashFS v4 only. Partitioned images, CPIO, JFFS2/UBIFS,
  MCU address spaces and RAUC bundles are later gates with their own fixtures; each is reported as
  unsupported rather than guessed at.
* **Boot manifests declare intent.** The `firmware-boot` profile reads what an FIT or DTB declares.
  Physical boot enforcement is always `unknown`; only an operator-supplied PEM key can set
  `signature.verified` to true, and no in-artifact key is trusted.
* **The cache is opt-in and measured on one corpus.** It stores per-file rule matches and text
  facts, never paths or verdicts, and does not make extraction cheaper.
* **A worker is required for image extraction.** Without a container runtime the product still
  identifies the image and reports honestly, but it cannot enumerate the filesystem (exit 5).
* **The rule set is now a hard requirement.** If the packaged rules cannot compile, the assessment
  is incomplete and the exit is 5 or 4. A rule file that is invalid is listed in
  `ruleset.compile_errors` and in the `rule_compilation` stage.
* **Advisory assessment needs a snapshot.** Without one, applicability is unassessed (check 3
  `OMITTED`) — never clean. A snapshot older than `advisory_snapshot_max_age_days` is reported
  stale, and a clean result from it cannot pass.
* **Domain indicators use a bounded suffix list.** `data/domain_suffixes.txt` is shipped and its
  digest recorded. A name under a suffix that is not listed is missed rather than guessed at; the
  alternative was reporting `libc.so` and `payload.offset` as C2 infrastructure.
* **A rule match is not a verdict.** A crypto finding says an implementation is present in a named
  file at a named offset; it does not say the device uses it.
* **Installed-package records are not file evidence.** The database says what the package manager
  recorded; it does not prove every package-owned file is present or intact.
* **Component naming has two kinds of authority.** Every one of the reference image's 196
  installed records is a component with its own evidence range. Three name a product NIST's CPE
  dictionary lists (`nist-mapped`); the other 193 have no authoritative entry, so the name is
  built from the opkg package's own name with vendor `openwrt` (`opkg-package-name`). The basis is
  recorded per component and counted in the report, so a reader can weigh it; the scanner never
  invents a vendor to make the number look better.
* **A comparison compares scans, not devices.** It says what changed between two saved documents.
  If the two scans selected different profiles, scanner versions or rule sets, the affected
  detector's findings are reported **indeterminate**, never resolved. A detector that was skipped
  on one side cannot be read as clean.
* **A build declaration is not proof.** A manifest or supplier SBOM is recorded with its digest
  and its binding to the image. One that names this image's digest is `bound`; one that names
  another image is `mismatched` and resolves nothing; one that names no digest is `unclaimed`, and
  its association is stated as scope-based and unverified rather than assumed.
* **The worker image id is not reproducible.** The package set and the `unsquashfs` version are
  pinned and reproducible; the Docker image id records a build timestamp, so it is published as
  observed, not as a reproducible artifact.
* **Section-stripped binaries** yield `unknown` for canary and FORTIFY.
* **Static analysis cannot establish** runtime behaviour, exposed network services, physical boot
  enforcement or which A/B slot is running.
* **Staged-tree metadata is host-derived** unless a build manifest is supplied; a clean
  permission result is then `INCONCLUSIVE`, not a pass.
* **Banner-derived components are candidates**, ranked below the image's own package records.
* **Sample data** (`kev_catalog.json`, `threat_intel_sample.jsonl`) is bundled for exercise only.
* **The reference image exits 1.** Stock OpenWrt 24.10.0 records `root::` in `/etc/shadow` — an
  empty password field joined to a `/bin/ash` login shell. That meets the documented critical
  rule, so the scanner reports it and exits 1 while the assessment is `COMPLETE`. It is a true
  observation about the shipped file; upstream leaves provisioning to first boot (Dropbear is
  key-only, there is no telnet). The finding carries that applicability note as evidence, and the
  observation is never suppressed. The decision is written up in
  [docs/MILESTONE-C.md](docs/MILESTONE-C.md).

## License

MIT — see [LICENSE](LICENSE).
