# Migrating to report schema 3 (IoT Hardware Scanner 2.1)

Schema 3 adds the evidence a shipped-image inventory needs. It does **not** change the exit
contract, the profile names or the renderer set, and it does not re-introduce an aggregate grade.

A schema-2 document stays readable: `report` upgrades it, keeps every recorded fact, and marks the
new sections as *not recorded* rather than empty. A schema-3 document is never downgraded.

---

## 1. What schema 3 adds

| Section | What it records | Why it exists |
| --- | --- | --- |
| `image_map` | Every container and file the scan opened: artifact id, parent, digest, format, coordinate system, offset/length, decoder and decoder version | Wrapper size, expanded size and filesystem extent are three different numbers. They are now separate fields, so a limit or a coverage claim cannot silently switch between them. |
| `extraction` | Worker (`podman`/`docker`/`host-process`), isolation, worker image and its digest, helper version, the budgets that were enforced, decoded/extracted bytes, entry count, elapsed time, whether scratch was released | A report that says "extracted" without naming the decoder is not reproducible. |
| `input_binding` | The private snapshot every read came from, its declared and verified digest, and whether the original path still matched afterwards | The bytes analysed are the bytes that were hashed. A build output replaced underneath the scan cannot be attributed to the old digest. |
| `elf` | One record per ELF file — class, byte order, machine, type, interpreter, dependencies, segments, build ID, stack permission, PIE, RELRO, canary, FORTIFY — plus `unknown[]` | Identification by header, not by suffix or service name, and missing evidence is listed rather than reported as absent hardening. |
| `opkg` | The installed-package database: locator, digest, byte length, every record with its **complete** version string, architecture, held state and byte range | `1.36.1-r2` and `1.36.1` are different facts. Every component in `components[]` can be traced back to the exact stanza. |
| `tree` | The deterministic per-entry manifest of a staged tree, any changes during traversal, and the declared build manifest compared against it | A tree scan states whether its ownership/permission observations are host-derived or declared. |

`components[]` gains `confidence` (`recorded` for a package-record or declared source,
`candidate` for a banner), `evidence` (the byte/line range in the source), `digest_sha256` and
`occurrences[]`. CPE strings are now complete CPE 2.3 names with all thirteen attributes.

`artifact.kind` is `file` or `tree`; `artifact.sha256` is the file digest or the canonical
tree-manifest digest.

---

## 2. New profile: `firmware-tree`

A staged root tree has no container to decode and no single byte stream to measure, so it cannot
honestly carry an extraction prerequisite. `--input-tree` (or a directory positional) selects:

| Profile | Required stages |
| --- | --- |
| `firmware-static` | ingest, extraction, root discovery, enumeration, entropy, binary inventory, ELF metadata, opkg inventory, credentials, Unix accounts, services, C2, checks |
| `firmware-tree` | ingest, enumeration, binary inventory, ELF metadata, opkg inventory, credentials, Unix accounts, services, C2, checks |
| `credentials-only` | ingest, enumeration, credentials, Unix accounts, checks |

`firmware-tree` records `extraction` and `root_discovery` as `NOT_APPLICABLE` with a reason, which is
visible in the report rather than merely absent. Selecting `firmware-static` on a directory is an
input error (exit 3) that names `--input-tree`.

---

## 3. Exit codes: one movement

| Case | schema 2 | schema 3 | Why |
| --- | --- | --- | --- |
| Opaque, non-container input (4,096 zero bytes) | 5 (no binwalk) | **4** | Unsupported input is incomplete analysis. No backend would make those bytes a SquashFS image, so naming a missing dependency would be wrong. |
| Supported image, worker not installed | 5 | 5 | Unchanged, and still the case that must not regress. |
| Supported image, worker present but failing | n/a | 4 | Corrupt payload, timeout, quota breach, non-zero helper exit, empty tree. Scratch is released and a retry succeeds. |
| Staged tree | 4 or 5 | 0/2 | No extraction prerequisite exists for this input. |

Nothing else moved: 1, 2, 3 and 6 are decided exactly as before by
`scanner/assessment.py::decide_exit`.

---

## 4. New CLI surface

```
scan  --input-tree              treat the positional input as a staged root tree
      --build-manifest PATH     JSON manifest of declared permissions/ownership
      --worker auto|podman|docker|host-process|none
      --profile firmware-static|firmware-tree|credentials-only
extract [--worker ...]          decode a gzip/SquashFS v4 image with the pinned worker
```

`--worker none` is the supported way to produce the partial report: the artifact is identified,
the dependency is named, findings that do not need the filesystem are kept, and the exit is 5.

Image extraction needs a Linux worker with upstream `unsquashfs`. The repository ships
`worker/Dockerfile`:

```bash
docker build -t ihs-squashfs-worker:4.5.1 worker/
iot-hardware-scanner scan firmware.img.gz --offline --format json --out report.json
```

Rootless Podman is preferred and used first when both are available. `host-process` runs
`unsquashfs` directly and is refused unless `extraction_require_isolation` is turned off; that mode
is recorded as `isolation: host-process` and is never a qualified result.

---

## 5. Reading a schema-2 document

```python
from iot_hardware_scanner.scanner.report_document import load_document

document = load_document(saved)          # schema 2 input
assert document["schema_version"] == 3
assert document["migration"]["from"] == 2
assert document["image_map"] is None     # not recorded, and said so
```

`migration.note` states what the older document never recorded. `findings`, `stages`, `controls`,
`components` and `assessment` are preserved unchanged.

A schema-1 document still upgrades as before (see `MIGRATION-v2.md`), ending at schema 3 with both
`legacy_grade` and the `migration` note.

---

## 6. Configuration additions

| Setting | Default | Meaning |
| --- | --- | --- |
| `extraction_worker` | `auto` | `auto`, `podman`, `docker`, `host-process`, `none` |
| `extraction_require_isolation` | `true` | refuse a host-process helper |
| `worker_image` | `ihs-squashfs-worker:4.5.1` | pinned worker image |
| `worker_memory_mb` | `1024` | worker memory limit |
| `max_decoded_bytes_mb` | `1024` | budget for bytes decoded from the wrapper |
| `max_extracted_bytes_mb` | `1024` | budget for bytes materialised from the filesystem |
| `max_extracted_entries` | `200000` | budget for entries in an extracted filesystem |
| `snapshot_budget_mb` | `4096` | storage budget for the private input snapshot |
| `bounded_window_kb` | `1024` | window size for bounded passes over a binary |
| `keep_scratch` | `false` | keep scratch after a failed run (diagnosis only) |

`extraction_timeout_seconds` now accepts a floor of 5 seconds instead of 30, so a short deadline is
a legitimate operator choice; when it expires the worker is killed and the analysis is reported
incomplete.
