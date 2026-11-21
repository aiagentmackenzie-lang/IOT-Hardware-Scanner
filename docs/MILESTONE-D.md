# Milestone D — “Deliver the differentiating feature”

Status: **complete and qualified in CI.** Every Milestone D gate row and every
Part 1 item has a passing case, and GitHub Actions run **`44897056652`** on
`main` (`aa16f7a`) is **8/8 job instances green** with **`linux-extractor` 166
passed, 0 skipped** — the qualified job that fails on any skip. The acceptance
run there includes the two-release comparison, the declaration reconciliation
against the published OpenWrt manifest and supplier SBOM, and the CycloneDX
export with offline validation.

`e32e2a1` produced the first run (`44896433693`): 7/8 green, with one job red for
a defect in the CI gate itself, not in the product — the audited-extras step
imported the package with the job's interpreter instead of the venv the wheel
was installed into. `aa16f7a` fixes the gate and is the qualified run.

Starting point: `main` at `c4e0a7d`, version 2.2.0, report schema 4. This release
is **2.3.0**, report schema **5**, profile version **4.0**, and adds two
document types: `ihs-comparison/1` and CycloneDX 1.6.

Everything below was run with CPython **3.12.14** and `unsquashfs 4.5.1`.

---

## 1. Gates

| Gate | Command | Result |
| --- | --- | --- |
| Lint | `ruff check src/ tests/` | all checks passed |
| Types | `mypy src/` | no issues in 38 source files |
| Tests + coverage | `pytest --cov=src/iot_hardware_scanner --cov-report=term --cov-fail-under=80` | **839 passed, 0 skipped, 86.54%** with `IHS_REFERENCE_IMAGE`, `IHS_REFERENCE_MANIFEST` and `IHS_REFERENCE_SBOM` set and the worker + verification images present; **823 passed, 16 skipped, 86.54%** without |
| Format | `ruff format --check src/ tests/` | clean |
| Wheel | `uv build && shasum -a 256 dist/*.whl` | `iot_hardware_scanner-2.3.0-py3-none-any.whl`, sha256 `2f3a0bf6246de4e1fafc4b089425ce318afb2f1a1055f5ce9be723bd2b0e1505` (macOS arm64 build) |
| Installed-CLI acceptance, wheel mode | `IHS_INSTALLED_CLI=… IHS_REFERENCE_IMAGE=… pytest tests/test_installed_image_cli.py tests/test_installed_cli.py` | **34 passed, 0 skipped** against the 2.3.0 wheel installed in a clean 3.12.14 environment (was 27 before the D rows) |
| CI | run **`44897056652`** on `main` (`aa16f7a`) | **8/8 job instances green**: `python-gate` 3.10/3.12/3.14 (811 passed, 28 skipped each — the reference-image and container rows the qualified job runs), installed wheel with no backend, report contract (87 passed, 1 skipped), reference image with the worker off, `bounded-resources` (61 passed, 0 skipped; 2 GiB at 16 MiB windows in **105.06 s**, peak RSS **92,328 KiB**), and **`linux-extractor` 166 passed, 0 skipped** |

The skips without the reference image are the reference-image and container rows,
by design. In CI the qualified job fails on any skip, and it is where the D rows
must be green.

---

## 2. Part 1 — the five open items, in order

### 2.1 The worker image id is not reproducible — **closed, option 2 + published content evidence**

Of the three offered choices, this release took the second: **drop what a scan does
not need and pin what remains**.

* `binutils` is used only by release verification (the `readelf` cross-check), so
  it moved out of the runtime image into a `verification` build stage. The
  runtime image now contains exactly one scan-facing helper: upstream
  `unsquashfs`.
* Every installed package is pinned twice: to a Debian **snapshot date**
  (`snapshot.debian.org`, so the archive the build reads still exists) and to an
  exact version in `worker/packages.txt` (90 packages) /
  `worker/packages-verify.txt` (98 packages). Nothing resolves at build time.
* Two `--no-cache` builds on this machine produced **the same package set**
  (`dpkg-query -W` digest `2e938beb…`), the **same `unsquashfs`** (sha256
  `cb10af7f…`), and **different image ids** (`7970b906…`, `ae64e345…`). That is
  the honest result: the image *configuration* records a build timestamp, so the
  id is **observed, not reproducible**. The id is still recorded in the report
  (`extraction.worker_digest`), and the reproducible facts — the Dockerfile
  digest, the package list and `unsquashfs -version` — are published and printed
  by CI.

Acceptance, item by item: this document and §3 of `docs/MILESTONE-C.md` state
which choice was made; the report records the id it used; `unsquashfs -version`
is read through a pipe (it exits 1 by design) in the CLI, the tests and CI; the
CI job prints the Dockerfile digest, both package-list digests, the package list
read out of the image, the absence of `readelf` in the runtime image, both
observed ids and both tool versions.

### 2.2 Component → CPE coverage was 3 of 196 — **closed**

Every installed-package record now becomes a component, with its own evidence
range and a recorded `cpe_basis`:

| Basis | Reference image | Meaning |
| --- | --- | --- |
| `nist-mapped` | **5** | vendor/product from an authoritative NIST CPE dictionary row in the single mapping |
| `opkg-package-name` | **191** | no authoritative row; the opkg package's own name with vendor `openwrt` |
| `banner` | 0 | version string in a file, candidate confidence |

There is still exactly **one** mapping (`data/component_cpe_map.json`). It was
extended deliberately: candidate rows were taken from NIST's own CPE dictionary
by exact product-name query, and only rows whose vendor and product are
authoritative were added (`e2fsprogs` → `e2fsprogs_project:e2fsprogs`,
`luci` → `openwrt:luci`). Candidates that NIST lists under a vendor that is *not*
this product were rejected rather than accepted for the count: `kernel` →
`redhat:kernel` (RHEL's kernel), `libc` → `gnu:libc` (glibc, while OpenWrt ships
musl), `ppp` → `canonical:ppp` (a distribution package), `base-files` (two
unrelated vendors). Those packages resolve through the `opkg-package-name` basis,
which says exactly what it is.

Every component now carries a **complete CPE 2.3 formatted string** (13
attributes), and the version is verbatim: `1.36.1-r2` never becomes `1.36.1`.
Counts per basis are recorded in `component_bases`, and control 12's evidence
now states the real number: *“196 of 196 installed-package record(s) carry a
component with its own evidence range; naming basis: nist-mapped 5,
opkg-package-name 191.”*

`docs/MIGRATION-v5.md` documents the schema 5 bump, and a schema-4 reader
fixture proves a v4 document upgrades without inventing a basis.

### 2.3 The advisory refresh transport was never executed — **closed**

`tests/test_nvd_transport.py` stands up a **stdlib** HTTP server on
`127.0.0.1` with an ephemeral port and drives `NVDClient`'s real `urllib` path
through it:

| Case | Asserted |
| --- | --- |
| Two pages | `totalResults=2`, one result per page; requests carry `startIndex=0,1` and `resultsPerPage`; state `MATCHED`, `pages=2` |
| 429 then 200 | one bounded backoff of 2 s, then the second answer is used; `MATCHED` |
| Empty result | `KNOWN_EMPTY`, `pages=1`, no records — not “unavailable” |
| Page-bound breach | `PARTIAL` at the 2-page bound with the reason naming the bound |
| Cache hit from SQLite | a second client over the same cache file, pointed at a closed port, returns the cached answer: no request is made |
| Cached row | state and page count are what SQLite holds |

Nothing can leave loopback: the server binds `127.0.0.1`, and `urlopen` is
wrapped so any non-loopback host fails the test. The existing “offline advisory
assessment issues zero requests” assertion still passes. **No refresh
subcommand was added**, so there is still no network path anywhere near `scan`.

### 2.4 `report_generator.py` at 61% — **decided: raised with real cases**

The module is a thin delegation wrapper, but two behaviours are its own and were
untested: `generate()` writing many formats from **one** document, and the
behaviour when a destination cannot be written. `tests/test_report_generator.py`
now covers:

* every configured format is written from one document, and `terminal` is not a
  file;
* an invalid format is rejected by configuration **before** any renderer runs;
* a destination that cannot be written raises `ReportWriteError` instead of
  reporting success.

That is four cases for four real behaviours, and the file is at **100 %**. No
test was added to move a number.

### 2.5 Per-detector misses are “not measurable” — **one bounded claim added**

The generated two-release fixture gives ground truth for the **comparison**
detector, so `docs/SUPPORT-MATRIX.md` now records its true positives, false
positives and misses on that pair. The claim is not extended to the credential or
indicator detectors: for those, “not measurable: no ground-truth inventory exists
for this corpus” stands, unchanged.

---

## 3. Milestone D acceptance matrix

“Verification” names the case that proves the row, not the command that ran.

| # | Gate requirement | Expected | Observed | Verification |
| --- | --- | --- | --- | --- |
| 1 | A generated two-release pair distinguishes a **real package change** | one package reported changed, nothing else | `busybox 1.36.1-r2 → 1.36.1-r3` is the only changed package; 2 persistent; 0 new; 0 removed | `tests/test_installed_image_cli.py::TestTwoReleaseComparison::test_a_generated_pair_distinguishes_the_change_kinds` |
| 2 | …and a **coverage change** | a stage that did not run is shown as coverage, and its previous findings are never resolved | `advisory COMPLETE → SKIPPED` listed under `coverage_changes`; the advisory finding is `indeterminate`, `resolved == []` | same case, plus `::test_the_comparison_renders_without_re_reading_the_images` |
| 3 | …and a **declaration-only change** | a declaration difference with no image difference is distinguishable | image comparison clean; `agreement 1 / version-conflict 1 / declared-only 1 / observed-only 1` | `::TestDeclarationReconciliation::test_one_matching_one_mismatch_one_declared_only_one_observed_only` |
| 4 | One changed package and one removed finding | 1 changed package, 1 resolved finding | `packages.changed == [busybox]`, `findings.resolved == [credential.unix.empty_password]` | row 1 |
| 5 | A relocated identical component is recognised | same identity, different locator | `layout.relocated == 1`: `rootfs/usr/lib/tool → rootfs/usr/bin/tool`, 0 new / 0 removed | row 1 |
| 6 | A skipped detector yields an indeterminate comparison for its previous findings | indeterminate, not resolved | 1 indeterminate advisory finding with the stage reason | rows 2 |
| 7 | A coverage change never renders as resolved | `resolved` empty for it; terminal says indeterminate | asserted in the document and in the terminal render | rows 2 |
| 8 | Comparing package **records**, not mapped components | 196 records compared, not 5 mapped ones | reference image: `packages.base_names == 196`; the pair compares all three records including the unmapped `base-files` | `::TestReferenceDeclarationReconciliation::…`, `TestTwoReleaseComparison` |
| 9 | Identity is not a path | a moved file keeps its identity | row 5 | row 5 |
| 10 | Deduplication keeps every occurrence | two roots with different revisions stay two records | `tests/test_comparison.py::TestPackages::test_every_occurrence_is_kept_when_one_root_differs` | that case |
| 11 | A different ruleset digest / profile version / scanner version invalidates finding comparison | indeterminate | three cases: rule-set digest, scanner version, profile/profile-version | `tests/test_comparison.py::TestFindings::test_a_changed_rule_set_invalidates_rule_based_findings`, `::test_a_different_scanner_version_invalidates_every_destination` |
| 12 | The real OpenWrt case retains **196 image records** and **124 manifest rows, 72 image-only**, with provenance and scope | 196 / 124 / 72 | exactly those numbers, with the opkg database digest `9442acba…`, each row's evidence range and 72 observed-only names | `::TestReferenceDeclarationReconciliation::test_the_real_comparison_keeps_every_record_and_the_72_image_only_rows` |
| 13 | The supplier CycloneDX is compared as a declaration | BusyBox `1.36.1` unresolved at revision granularity, not a mismatch | `unresolved-revision`, both values kept | same case |
| 14 | A declaration for another image cannot resolve a finding | unbound, nothing resolved | `binding.status == mismatched`, every row `unbound`, `agreement == 0` | `::TestDeclarationReconciliation::test_a_declaration_for_another_image_resolves_nothing` |
| 15 | A generated declaration gives **four distinguishable outcomes** | agreement, mismatch, declared-only, observed-only | exactly one of each | row 3 |
| 16 | The comparison is available independently of the CycloneDX export | `compare` needs only the scans and the declaration | the D rows never run `sbom` | rows 1–3, 12–14 |
| 17 | CycloneDX 1.6 export validates **offline** against the vendored schema | valid 1.6 BOM | 196 components; validated offline | `::TestCycloneDXExport::test_the_reference_inventory_exports_and_validates`, `tests/test_sbom.py` |
| 18 | Every emitted component maps back to the same firmware digest and inventory record | one-to-one, by `bom-ref` and `ihs:evidence` | 196 of 196 | same case |
| 19 | The existing JSON inventory stays readable | unchanged section | unchanged; the export reads it | `tests/test_report_document.py`, `tests/test_report_schema3.py` |
| 20 | No request from a comparison or an export | zero sockets | the comparison and export read only local documents; the transport test guards loopback | §2.3, plus the scan's own zero-request assertion |

---

## 4. Evidence

| Item | Value |
| --- | --- |
| Interpreter / platform | CPython 3.12.14, macOS 27.2.1 arm64, colima (vz, 2 CPU / 4 GB) |
| Wheel | `iot_hardware_scanner-2.3.0-py3-none-any.whl`, sha256 `2f3a0bf6246de4e1fafc4b089425ce318afb2f1a1055f5ce9be723bd2b0e1505` — **byte-identical** from the macOS build (CPython 3.12.14) and both Linux CI builds (`installed-wheel-no-backend`, `linux-extractor`), as run `44897056652` printed |
| Worker image, runtime (CI amd64, qualified) | `sha256:8f9818aa4b33aa9c045308fa51d8e5d79dba135d9f7a43b43b7544d37f7e5262` — **observed, not reproducible** |
| Worker image, verification stage (CI amd64, qualified) | `sha256:a7c206d57ef05a403b7b102edc0cc089daca6495bfc521d0010249231605d11d` — observed |
| Worker image, local arm64 | runtime `sha256:91b0ebd4…110`, verification `sha256:fab6e227…840` — observed |
| Dockerfile / package lists | Dockerfile `44e6fb84…981e2`; `worker/packages.txt` `e26f55bd…900c9` (90 packages); `worker/packages-verify.txt` `7f238099…8eab` (98 packages) |
| Reproducibility check | two `--no-cache` builds: package-set digest `2e938beb…` identical, `unsquashfs` sha256 `cb10af7f…` identical, image ids differ |
| `unsquashfs` | `unsquashfs version 4.5.1 (2022/03/17)` |
| Rule set | `2ca7a94b511400528f49ea9290359d716e5a3e7ecb408ab0b62cbee6a946258d` (12 files) |
| Corpus | `8b5aa82659cafd90b26333dd419a0df9ad63c517ad94a2159e970a5bb5b6ff02` |
| Target manifest | `openwrt-24.10.0-armsr-armv8.manifest`, sha256 `e5951c2355950b187ed154dd6f46547e3cac240937094502dd8b66afcc65fbff` |
| Supplier SBOM | `openwrt-24.10.0-armsr-armv8.bom.cdx.json`, sha256 `50ca09d781aeb7bda85eed0069d0853c0cde506f5e450667374283d6c296a068` |
| Generated pair | A `367bab3d…a1153`, B `38b92541…60077` (gzip-wrapped SquashFS built with `mksquashfs` in the worker image) |
| Exported BOM (reference image) | sha256 `d590e82e…130b`, 196 components, CycloneDX 1.6 |
| CI run id | **`44897056652`** on `main` (`aa16f7a`) — 8/8 green, `linux-extractor` 166 passed with zero skips; `44896433693` (`e32e2a1`) was the 7/8 run whose only failure was the audited-extras gate itself |

Side by side with the independent oracle (§2 of the support matrix) — the
comparison numbers:

| Observation | Comparison document | Independent oracle |
| --- | --- | --- |
| image package records | 196 | 196 installed `Package` stanzas in the image's own database |
| target manifest rows | 124 | 124 non-empty lines |
| manifest rows that agree | 124 | all 124 name+version pairs equal the database |
| image-only rows | 72 | 72 database names not in the manifest |
| supplier rows | 124 | 124 CycloneDX components |
| supplier agreement / unresolved / declared-only / observed-only | 20 / 80 / 24 / 96 | 20 exact; 80 name-matched with the revision missing; 24 supplier names absent from the opkg database; 96 opkg names absent from the supplier document |
| components emitted from the image | 196 | 196 installed records |

Generated pair, four ground-truth outcomes:

| Change | Ground truth | Comparison |
| --- | --- | --- |
| package changed | busybox 1.36.1-r2 → r3 | 1 changed, named with both versions |
| finding removed | empty root password in A, locked in B | 1 resolved |
| coverage change | advisory assessed in A, not asked in B | `COMPLETE → SKIPPED`, previous finding indeterminate |
| declaration-only | declared 3 rows, one wrong version, one absent package, one installed-but-undeclared | 1 / 1 / 1 / 1 |
| relocation | identical helper at `usr/lib/tool` → `usr/bin/tool` | 1 relocated, 0 new, 0 removed |

---

## 5. Public behaviour changed

**New commands** (both documented in the README with runnable examples and in
`docs/MIGRATION-v5.md`):

```
compare BASE.json TARGET.json [--declaration PATH]… [--format terminal|json|markdown] [--out PATH]
sbom SCAN.json [--out PATH] [--validate]
```

* `compare` exits 3 (unreadable input), 6 (cannot write), 2 (differences),
  4 (nothing differs but something could not be concluded), 0 (clean). It does
  **not** reuse the scan exit table.
* `sbom` exits 3 (not a scan document, or no exportable identity), 4 (validation
  failed), 6 (cannot write), 0.
* `[sbom]` is an extra again (`jsonschema`), and the test that asserted its
  absence was updated deliberately.

**Report document:** schema 4 → **5**. `components[]` now carries every
installed-package record with `cpe_basis`; `component_bases` carries the counts.
A v4 document still reads (upgrade with `component_bases: null`, basis absent).
`docs/MIGRATION-v5.md` records the change; a v4 fixture proves the reader.

**New document types:** `ihs-comparison/1` and CycloneDX 1.6 JSON. Neither is a
scan document.

**Profile/version:** profile semantics unchanged — still `4.0`. No stage was added
or removed, and `REQUIRED_STAGES` is untouched.

**Configuration:** `nvd_api_base` and `nvd_cache_path` added for the transport
test; a scan still issues no request.

---

## 6. Reproduce

```bash
uv venv --python 3.12.14 .venv
uv pip install --python .venv/bin/python -e ".[dev]"

colima start
docker build -t ihs-squashfs-worker:4.5.1 worker/
docker build --target verification -t ihs-squashfs-worker:4.5.1-verify worker/

export IHS_REFERENCE_IMAGE=/path/to/openwrt-24.10.0-armsr-armv8-generic-squashfs-rootfs.img.gz
export IHS_REFERENCE_MANIFEST=/path/to/openwrt-24.10.0-armsr-armv8.manifest
export IHS_REFERENCE_SBOM=/path/to/openwrt-24.10.0-armsr-armv8.bom.cdx.json

.venv/bin/ruff check src/ tests/
.venv/bin/mypy src/
.venv/bin/python -m pytest --cov=src/iot_hardware_scanner --cov-report=term --cov-fail-under=80
.venv/bin/ruff format --check src/ tests/
uv build && shasum -a 256 dist/*.whl
```

CI runs the same gates in `.github/workflows/ci.yml`; `linux-extractor` is the
only job with the real extraction path, and it fails the build on any skip.

The reference image, the manifest and the SBOM are never committed and are never
fetched by the suite; `/tmp/ihs-corpus` is the operator's own staging area.

---

## 7. What is not closed

| Row | Why |
| --- | --- |
| — | (CI qualification is closed: run `44897056652`, 8/8 green, zero skips in the qualified job.) |
| The worker image id | The package set, the Dockerfile and `unsquashfs` are reproducible; the image id is not, and is published as observed. |
| The supplier SBOM's package names | The supplier document uses upstream names (`jansson`, `libblkid`), the opkg database uses distribution names (`jansson4`, `libblkid1`). The comparison reports that honestly as declared-only/observed-only rather than guessing a mapping between them. |
| Broader comparison accuracy | Measured on one generated pair and one frozen OpenWrt release. There is no held-out set of release pairs, so no accuracy claim beyond those fixtures is made. |
| MCU, RAUC, partitioned images, raw NAND | Separate gates with their own fixtures; not started. |
| FIT/DTB (3D) and 5C caching | **Delivered after D in 2.4.0**, as scheduled post-D slices, not as a new milestone. See [docs/MILESTONE-E.md](MILESTONE-E.md) and [docs/5C-DECISION.md](5C-DECISION.md). |
