# Milestone B — “Inventory one shipped Linux image”

Status: **complete, and qualified in CI.** CI run **`44848363402`** on `main` (`c64febb`) is
**7/7 jobs green**, including the new `linux-extractor` job: the worker image built from
`worker/Dockerfile`, the wheel installed outside the checkout, and **25 acceptance tests passed with
zero skips**. Milestone C is the first qualified release.

Starting point: `main` at `8596bf3` (milestone A green, CI run `44840789511`, 6/6 jobs).

Everything below was run with CPython **3.12.14**: once in the repository environment, once against
a wheel (`iot_hardware_scanner-2.1.0-py3-none-any.whl`) installed into a separate clean environment,
and once against that same wheel inside a Linux container. The reference corpus is the pinned
OpenWrt image, digest-verified before use, scanned with `--offline`.

---

## Gates

| Gate | Command | Result |
| --- | --- | --- |
| Lint | `ruff check src/ tests/` | all checks passed |
| Types | `mypy src/` | no issues in 35 source files |
| Tests + coverage | `pytest --cov=src/iot_hardware_scanner --cov-report=term --cov-fail-under=80` | **677 passed, 0 failed, 84.41%** (with `IHS_REFERENCE_IMAGE` set); **668 passed, 9 skipped, 83.99%** without it |
| Format | `ruff format --check src/ tests/` | 68 files already formatted |
| Wheel | `uv build` | `iot_hardware_scanner-2.1.0-py3-none-any.whl`; macOS build sha256 `238aadf56cac243b51d0956903e16a38179707b3bbca98c9df5ce87b4b56c325`, Linux CI build sha256 `e0243b8798b2d943f3984e08f304a679f58fa93de86c7bffa04fe2607733128a` (hatch builds are not byte-reproducible across platforms; the qualified artifact is the Linux one) |
| CI | GitHub Actions run `44848363402` on `main` | **7/7 jobs green**: py3.10 / py3.12 / py3.14 gates (661 passed, 16 skipped, 84.2% each), installed wheel with no backend, report contract + v2→v3 migration, OpenWrt reference image with the worker off (exit 5), and the **linux-extractor** gate (25 passed, 0 skipped, `unsquashfs 4.5.1`, worker image `sha256:954d9741…8c43`) |

Skipped tests in the three `python-gate` jobs are the acceptance rows that need a container runtime
or the reference image; that is by design, because those rows are qualified in `linux-extractor`,
where a skip fails the job (25 passed, 0 skipped).

---

## The reference image, through the shipped product

Three independent readers agree on every number.

| Observation | Installed wheel on Linux (host-process worker) | Installed wheel on macOS (container worker, `unsquashfs` 4.5.1) | Independent oracle (PySquashfsImage 0.9.0 + `struct`) |
| --- | --- | --- | --- |
| gzip SHA-256 | `8b5aa826…ff02` | `8b5aa826…ff02` | `8b5aa826…ff02` |
| bytes on the wire | 4,451,127 | 4,451,127 | 4,451,127 |
| expanded bytes | 109,051,904 | 109,051,904 | 109,051,904 |
| SquashFS extent (`bytes_used`) | 4,348,264 | 4,348,264 | 4,348,264 |
| block / inodes / fragments | 262,144 / 1,622 / 59 | same | 262,144 / 1,622 / 59 |
| `/usr/lib/opkg/status` SHA-256 | `9442acba…a3258` | `9442acba…a3258` | `9442acba…a3258` |
| installed records / held | 196 / 4 | 196 / 4 | 196 / 4 |
| BusyBox version | `1.36.1-r2` | `1.36.1-r2` | `1.36.1-r2` |
| `/bin/busybox` SHA-256 | `214a261c…696c` | `214a261c…696c` | `214a261c…696c` |
| ELF class / data / machine | ELF64, little, 183 | ELF64, little, 183 | ELF64, LE, 183 |
| assessment | `COMPLETE`, exit 1 | `COMPLETE`, exit 1 | n/a |

The oracle is a throwaway virtual environment running `gzip.decompress`, PySquashfsImage and a
hand-rolled `struct` read; it shares no code with the scanner.

`unsquashfs` in the pinned worker image is 4.5.1; the `python:3.12-slim` container used for the
Linux wheel check carries 4.6.1. Both agree with the oracle, and each report records the version it
actually used.

---

## Acceptance matrix

| # | Case | Expected | Observed | Verification |
| --- | --- | --- | --- | --- |
| 1 | Reference image inventory through the installed wheel | 196 records, `1.36.1-r2`, BusyBox hash, AArch64, all traceable | all four recovered; `components[]` carries the stanza byte range `2804-3095 (line 102)` and the database digest; the account database is joined and its empty root password field is reported as a critical finding (exit 1) | `pytest tests/test_installed_image_cli.py -k ReferenceImageInventory` |
| 2 | Reference image, worker off | useful partial report, dependency named, exit 5 | exit **5**, artifact identified, `image_map` still shows gzip→SquashFS and the 4,348,264-byte extent, `missing_required_dependencies` non-empty, findings kept | `iot-hardware-scanner scan … --worker none`; `pytest … -k WorkerOff` |
| 3 | Backend present but failing | exit 4, scratch released, retry succeeds | corrupt payload → `HELPER_FAILED`, quota (1 MB budget) → `QUOTA_EXCEEDED`, 5 s deadline → `TIMEOUT`, simulated non-zero helper → `HELPER_FAILED` (`unsquashfs exited 99`); each exit **4**, no `scratch/extract/rootfs` left, and the same command then completes on the good image | `pytest … -k FailingBackend` |
| 4 | Tree / image equivalence | identical normalised file findings, differences stated | identical `(rule_id, severity, category, locations, critical_qualified)` sets; differences limited to `artifact.kind`, `image_map`, boot evidence source and `metadata_source` (`image` vs `host`) | `pytest … -k TreeAndImage` |
| 5 | Staged tree, worker absent | no extraction prerequisite at all | exit 0/2, `COMPLETE`, `profile=firmware-tree`, `extraction`/`root_discovery` `NOT_APPLICABLE` and `required=false`, no missing dependencies | `… --input-tree --worker none` |
| 6 | Build output replaced between ingest and analysis | old snapshot used, or scan marked incomplete; new bytes never attributed to the old digest | *before binding*: exit **4**, `INCOMPLETE`, artifact sha256 is the ingest digest, no opkg/ELF evidence from the replacement. *after binding*: exit 2, `COMPLETE`, `input_binding.source_changed=true`, the 196-record inventory of the original bytes | `IHS_TEST_FAULTS=replace-input-after-ingest` / `…-after-bind` |
| 7 | `firmware-static` reaches COMPLETE | complete only where every required stage genuinely ran | `COMPLETE`, all 13 required stages `COMPLETE`/`NOT_APPLICABLE`, 209/209 ELF files parsed, 196/196 package records read | `pytest … -k ReferenceImageInventory` |
| 8 | Budgets on a sparse 2 GiB input | peak RSS, elapsed, scratch recorded | sampled run 6.9 s / 44.0 MB; whole-image run (2 GiB, 16 MiB windows) 34.1 s / 73.9 MB; scratch 0 bytes; recorded in `budgets.json` | `pytest … -k Budgets -s` |

Machine for row 8: macOS 26 arm64, CPython 3.12.14, `max_entropy_scan_size_mb=256` (sampled) and
`4096` (whole image). Peak RSS is `ru_maxrss` of the scan process, in bytes on macOS.

---

## What changed and why

* **One extraction path.** gzip → bounded scratch → SquashFS v4 superblock validation → upstream
  `unsquashfs` in a pinned, unprivileged Linux worker, streamed back as a tar under entry, path and
  byte budgets. The Binwalk adapter and the broken `[extraction]` extra are gone.
* **Immutable input.** Every later read is bound to a private read-only snapshot whose digest was
  verified against ingest.
* **Bounded reads everywhere.** Windows keep original offsets; text parsing, artifact sweeps and
  entropy all stream. The entropy pass no longer reads a whole file into memory.
* **ELF from the file's own structures.** pyelftools over a size-clipped stream; dependencies and
  dynamic flags are read from `PT_DYNAMIC` because OpenWrt's BusyBox has no section headers at all.
* **opkg verbatim.** Complete version strings, held state, architecture and the stanza's byte range.
* **One CPE mapping** and complete CPE 2.3 names (13 attributes), used by both the banner route and
  the package route.
* **Staged trees** (`--input-tree`, `--build-manifest`) with a deterministic manifest, hardlink
  reconciliation and honest metadata provenance.
* **Schema 3** with `image_map`, `extraction`, `input_binding`, `elf`, `opkg` and `tree`, plus a
  v2→v3 reader and `docs/MIGRATION-v3.md`.

---

## Known limitations carried forward

* **The reference image exits 1.** Stock OpenWrt 24.10.0 records `root::` in `/etc/shadow` — an
  empty password field joined to a `/bin/ash` login shell. That is the documented critical rule, so
  the scanner reports it as a critical finding and exits 1 while the assessment is COMPLETE. It is
  a true observation about the shipped file, and a property upstream deliberately leaves to
  first-boot provisioning (Dropbear is key-only, there is no telnet). Milestone C must decide
  whether the rule needs an applicability note for a distribution that provisions at first boot;
  what it must not do is suppress the observation.
* Adversary-grade detection semantics (slice 4A) are still milestone C. On the reference image the
  shipped YARA rules raise two `LIKELY_C2` malware-signature hits on `libmbedcrypto` and `dropbear`,
  plus nine domain indicators from string data inside shared libraries. All are review findings,
  none is critical-qualified, and the exit is 2 — but they are false-positive noise that detector
  work must remove before a release claim.
* Advisory applicability remains unassessed (check 3 `OMITTED`).
* Partitioned images, CPIO, MCU formats, FIT/DTB, RAUC and raw NAND are later gates.
* `host-process` extraction is supported for a Linux host with isolation explicitly disabled. It is
  recorded as `isolation: host-process` and is not a qualified result; only the container path is.
