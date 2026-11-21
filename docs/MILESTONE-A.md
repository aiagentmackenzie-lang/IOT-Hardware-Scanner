# Milestone A — “Correct the verdict”

Status: **complete** (development checkpoint, not a qualified release).
Repository state: `main` at `b6f6ca0` + working-tree changes for milestone A.

Everything below was run locally on macOS (arm64) with CPython **3.12.14** in a
fresh virtual environment created by `uv`, plus a wheel installed into a second
clean environment for the installed-CLI checks. The same gates are enforced in
`.github/workflows/ci.yml`, which was **re-enabled and executed** for this
checkpoint: the first green run is `44840789511` on `main` (6/6 jobs).

---

## Gates

| Gate | Command | Result |
| --- | --- | --- |
| Lint | `ruff check src/ tests/` | all checks passed |
| Format | `ruff format --check src/ tests/` | 52 files already formatted |
| Types | `mypy src/` | no issues in 29 source files |
| Tests + coverage | `pytest --cov=src/iot_hardware_scanner --cov-report=term --cov-fail-under=80` | **560 passed, 2 skipped, 85.44%** |
| Wheel | `uv build` | `iot_hardware_scanner-2.0.0-py3-none-any.whl`, sha256 `165d43e17b37c2ae6e1107e0829b9b12eb8fc3c15288208de58ee3f87be2921a` |
| CI | GitHub Actions run `44840789511` on `main` | **6/6 jobs green**, no annotations: py3.10 / py3.12 / py3.14 gates (557 passed, 5 skipped on 3.12; 85.34% coverage), installed wheel with no backend, report contract, and the OpenWrt reference image (`sha256sum -c: OK`, gate test passed) |

The two skips are `test_installed_cli.py::…openwrt…` (needs
`IHS_REFERENCE_IMAGE`) and the pre-existing Binwalk integration test. Both are
run explicitly below where the artifact was available.

---

## Acceptance matrix

All rows were run through the console script installed from the built wheel,
from a temporary working directory, with `--offline`.

| Case | Expected | Observed | Command |
| --- | --- | --- | --- |
| 4,096 zero bytes | report written, `INCOMPLETE`, no grade, nonzero exit | exit **5**, `requested.json` written, `completion=INCOMPLETE`, `risk_score=null` | `iot-hardware-scanner scan blank.bin --offline --format json --out requested.json` |
| OpenWrt `armsr/armv8` image, backend absent | identified, incomplete, nonzero exit | exit **5**, sha256 `8b5aa826…ff02`, `findings=[]`, no grade | same, with the pinned image |
| Critical password in an opaque artifact | exit **1** even though the scan is incomplete | exit **1**, one `critical_qualified` finding, `assessment=INCOMPLETE`, secret absent from the report | `scan opaque.bin --offline` |
| Lookalike `password="changeme"` | review finding only, not exit 1 | exit **5** (incomplete), finding `HIGH`, `critical_qualified=false` | `scan placeholder.bin --offline` |
| Locked root account | no critical password finding | exit **0**, no password-category findings | `scan tree --creds` |
| Empty password on a login account | exit **1** | exit **1**, `credential.unix.empty_password` critical, extra UID 0 account present as a review finding | `scan emptypw --creds` |
| Clean credentials-only tree | exit **0**, complete | exit **0**, `COMPLETE`, 1 performed / 11 not-applicable checks | `scan tree --creds` |
| Unwritable `--out` | exit **6**, no success message | exit **6**, “Report written” never printed | `scan blank.bin … --out blocked.json` (a directory) |
| Invalid config value | exit **3** | exit **3** | `entropy blank.bin --block-size 0` |
| Missing input | exit **3** | exit **3** | `scan nope.bin` |
| Exit 4 (incomplete, no missing dependency) | exit **4** | exit **4** at the decision-function level only — **blocked at CLI level**: reaching it needs an extraction backend that fails rather than is absent, and no backend is installed | `pytest tests/test_exit_contract.py -k row_4` |
| Replay a v1 report | finding and historical grade preserved, coverage unknown, input untouched | exit **0**, 1 finding, `legacy_grade` 88/MEDIUM (`v1-12-control-weighted`), `coverage=UNKNOWN`, input md5 unchanged | `report legacy.json --format json --out replayed.json` |
| Installed-wheel harness | all cases pass against a wheel-installed console script | `IHS_INSTALLED_CLI=… IHS_REFERENCE_IMAGE=… pytest tests/test_installed_cli.py` → **11 passed** | see `tests/test_installed_cli.py` |

Reference image: `openwrt-24.10.0-armsr-armv8-generic-squashfs-rootfs.img.gz`,
SHA-256 `8b5aa82659cafd90b26333dd419a0df9ad63c517ad94a2159e970a5bb5b6ff02`,
4,451,127 bytes on the wire, 109,051,904 bytes decompressed, SquashFS 4.0 with
4,348,264 bytes used. Fetched once, checked against the publisher index, then
scanned with the network unused.

---

## What a release engineer now sees for the real OpenWrt image

```
Assessment: INCOMPLETE — 7 required stage(s) did not finish (listed below)
Missing required dependencies:
  - extraction backend (binwalk / SquashFS helper) is not installed
Incomplete work:
  - binary_inventory: unavailable — no enumerated inventory; binaries were never selected
  - elf_metadata: unavailable — native ELF header parsing is not implemented in this release
  - enumeration: unavailable — no extracted root filesystem to enumerate
  - extraction: unavailable — binwalk not found. Install pybinwalk or binwalk CLI.
  - opkg_inventory: unavailable — installed-package record parsing is not implemented in this release
  - root_discovery: unavailable — no extraction backend, so no root filesystem was reached
  - service_analysis: unavailable — no enumerated filesystem, so no boot path could be read
Findings: none reported
Checks: 3 performed, 3 inconclusive, 6 omitted (of 12)
Entropy: 7.9607 bits/byte over 4451127 bytes (whole input)

Exit 5 — A required dependency is missing
```

Compare with v1.0.0 on the same bytes: “Risk Score: 94/100 — LOW”, zero
components, zero binaries analysed, exit 0. The verdict is now the opposite of
the truth it used to tell.

---

## Decisions taken

1. **One decision contract.** `scanner/assessment.py` holds the precedence
   table; the CLI and the JSON writer both read it, and `outcome` is written
   into the document so a saved report and a process status cannot diverge.
2. **Required stages are declared per profile.** `firmware-static` requires the
   whole chain including extraction and enumeration, so it cannot complete while
   extraction is unqualified. `credentials-only` requires a narrower set and
   completes.
3. **Two critical-evidence rules only.** `credential.regex.password` and
   `credential.unix.empty_password`, each with a documented observation and both
   a positive and a lookalike-negative fixture. `LIKELY_C2` and unqualified YARA
   hits are review findings.
4. **The grade is retired, not re-weighted.** New scans emit `risk_score: null`;
   controls carry a status and evidence, with no points. A v1 document keeps its
   grade under `legacy_grade`.
5. **One schema-2 document, four renderers.** The HTML report no longer reads a
   neighbouring Markdown file, and every interpolated value is escaped.
6. **Entropy is a distribution measurement.** Bits/byte, 0–8, whole-input entropy
   from the combined histogram, window means labelled separately, true window
   lengths, and no encryption readability or control verdict derived from it.
7. **Accounts are joined before being judged.** Password state is typed
   (`empty`, `locked`, `hash_present`, `delegated`, `unknown`, `absent`) across
   the passwd/shadow pair for a given root; privilege is reported separately.
8. **Indicator decisions are order-invariant.** Occurrences are collected first,
   each scored in its own context, then one documented aggregate (highest
   occurrence score) is applied.
9. **Resources ship in the package.** Rules and the six data files are loaded
   with `importlib.resources`; ambient rule directories are no longer scanned;
   loaded data is recorded with digests and sample flags.
10. **The extraction extra was removed.** `pybinwalk>=3.0` is unresolvable
    (only 0.0.3 exists and it lacks the required API). The `sbom` extra was
    removed too: no export path existed.

---

## Compatibility changes

* `schema_version: 2`; `firmware` → `artifact`; per-detector finding sections →
  one `findings[]` with `rule_id` and `locations`; `risk_score` is `null` for new
  scans.
* Exit codes: validation moved 2 → 3; `LIKELY_C2` no longer exits 1; a failed
  report write exits 6; incomplete analysis exits 4; a missing backend exits 5.
* `--out` is written exactly, atomically, and only announced on success.
* `--offline` is still accepted; offline is now the default.
* Package version 2.0.0. Migration guide and a CI example: `docs/MIGRATION-v2.md`.

---

## Remaining limitations (explicitly unqualified)

* No firmware-image extraction (gzip → SquashFS), no partitioned-image support,
  no CPIO. Milestone B.
* No ELF header parsing (`pyelftools`), so binary hardening and opkg inventory
  are declared `UNAVAILABLE` stages, not silent passes.
* Advisory assessment is not implemented; `ADVISORY` is always `SKIPPED` and
  check 3 is `OMITTED`.
* No CycloneDX export, no release-to-release comparison (Milestones C/D).
* Bounded-reader work (2C) and immutable input binding (2D) are not part of this
  milestone: `binary_intelligence._extract_version_strings` still reads whole
  files, and entropy sampling keeps offsets but not a digest-bound input copy.
* The installed-CLI harness runs locally in “relocated package copy” mode unless
  `IHS_INSTALLED_CLI` is set; the wheel-install path is exercised in this
  report by hand and is configured as a CI job.
* Delivered on branch `feat/milestone-a-correct-the-verdict`, merged to `main`.

---

## Fixtures added

| File | Purpose |
| --- | --- |
| `tests/test_installed_cli.py` | 1A harness + packaging regressions (wheel contents, extras) |
| `tests/test_exit_contract.py` | precedence table, combined conditions, critical-evidence registry |
| `tests/test_report_document.py` | renderer equivalence, HTML escaping, atomic writes, v1 replay |
| `tests/test_controls.py` | 12 checks × positive / contrary / missing evidence |
| `tests/test_unix_accounts.py` | password-state typing, join by root + username, two roots |
| `tests/test_boot_evidence.py` | `inittab` / init-script evidence into the control and the report |
| `tests/conftest.py` | blank image, opaque image, staged tree, legacy v1 report, reference-image hook |
