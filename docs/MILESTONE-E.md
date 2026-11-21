# Post-D slice record — 5C (repeated work) and 3D (boot manifests), release 2.4.0

**This is not a new delivery milestone.** The plan's delivery table ends at D and
that gate stays closed. This document records the two slices the owner scheduled
after it: **5C**, whose entry condition was a measurement nobody had taken, and
**3D**, the boot-manifest gate with its own fixtures.

Starting point: `main` at `10c69a8`, version 2.3.0, schema 5, profile 4.0.
This release is **2.4.0**, schema **6**, profile **5.0**.

---

## 1. 5C — measured first, then implemented

The measurement and the cache contract are in
[docs/5C-DECISION.md](5C-DECISION.md). Summary:

| | No cache | Cache cold | Cache warm |
| --- | --- | --- | --- |
| wall time | 7.73 s | 5.18 s | **1.81 s** |
| peak RSS | 205.8 MB | 204.2 MB | **110.0 MB** |

About **83 %** of the run was a pure function of content + parser identity
(per-file YARA match sets 3.21 s, per-file text facts 3.15 s); extraction, which
a content-result cache cannot remove, was 8 %. The number justified the cache.
Cold and warm reports are semantically identical; a ruleset change invalidates
its dependents; entries are atomic, validated, bounded and path-free.

---

## 2. 3D — what was asked, in the plan's words

> Add bounded parsers for flattened device trees and U-Boot FIT. Extract
> declared board compatibility, memory regions, partition labels, configurations
> and referenced payloads. Record FIT digest integrity, signature presence and
> verification against an operator-supplied trust anchor as separate fields.
> Attribute board descriptions to the declaring artifact.

> Accept when a generated FIT/DTB pair resolves to the correct kernel and device
> tree, a mismatched payload fails integrity, an absent key yields unverified
> authenticity, and a valid signature asserts verification only for the selected
> configuration and supplied key. Each case leaves physical boot enforcement
> unknown.

### 2.1 Decisions taken

1. **New input kind and profile.** `InputKind.BOOT` and `firmware-boot`
   (`ingest`, `rule_compilation`, `boot_analysis`, `risk_controls`). Every
   filesystem stage is `NOT_APPLICABLE` with a reason, not `SKIPPED`. Profile
   version 4.0 → 5.0; **no existing profile's required set changed**.
2. **Schema 6.** A new `boot` section; `docs/MIGRATION-v6.md`; a v5 reader
   fixture proves the upgrade leaves `boot` and `cache` `null` rather than
   empty.
3. **Four separate facts.** `integrity` (`match|mismatch|undeclared|out-of-bounds`),
   `signature.present`, `signature.verified` (`true|false|null`), and
   `boot_enforcement` (always `"unknown"`).
4. **Where the code lives.** `scanner/fit_dtb.py` (parser), recognition in
   `firmware_ingest.py` and the orchestrator, report assembly in
   `report_document.py`, controls 5/6 in `risk_scorer.py`. No second entropy or
   ELF path; none of this is in `binary_intelligence.py`.
5. **Checks 5 and 6.** Check 5 gets a positive source for FIT (a signature/hash
   node with matching content) and stays `REVIEW`, never `PASS`. Check 6 stays
   `INCONCLUSIVE/UNKNOWN` with evidence naming the declared configuration.
6. **Trust anchor.** A PEM `PUBLIC KEY` / `RSA PUBLIC KEY` supplied by the
   operator, recorded by SHA-256. A certificate is rejected. No in-artifact key
   is treated as a trust anchor; an embedded key is ignored, so `verified`
   stays `null` (stricter than the minimum the plan asked for).
7. **Exit behaviour.** Malformed/truncated/over-deep/out-of-bounds structure is
   incomplete analysis (**4**). A digest mismatch is a `boot.payload_integrity`
   **HIGH review finding** (**2**), explicitly **not** critical-capable. No new
   rule was added to `CRITICAL_RULE_EVIDENCE`.

### 2.2 Acceptance matrix

| # | Requirement | Expected | Observed | Verification |
| --- | --- | --- | --- | --- |
| 1 | A generated FIT/DTB pair resolves the correct kernel and device tree | config → `kernel-1` + `fdt-1`, both digests match | yes; the `fdt` payload parses to `compatible = test,board, test,soc` | `tests/test_installed_cli.py::TestBootManifestProfile::test_a_fit_dtb_pair_resolves_kernel_and_device_tree` |
| 2 | A mismatched payload fails integrity | `mismatch`, reportable, no silent success | `mismatch`, HIGH finding, exit 2, control 5 `FAIL` | `::test_a_mismatched_payload_is_a_reportable_observation` |
| 3 | An absent key yields unverified authenticity | `present: true`, `verified: null`, `key_source: none` | exactly that; control 5 `PERFORMED/REVIEW` | `::test_an_absent_key_leaves_signature_presence_but_not_verification` |
| 4 | A valid signature asserts verification only for the selected configuration and supplied key | selected config `verified: true`, `operator-supplied` | exactly that; check 6 still `UNKNOWN` | `::test_a_supplied_key_verifies_only_the_selected_configuration` |
| 5 | A signature over a non-selected configuration must not be promoted | selected config unsigned; other config's `verified: true` is not used by check 5 | exactly that; check 5 evidence contains no "verifies with the supplied key" | `::test_a_signature_over_another_configuration_is_not_promoted` |
| 6 | Each case leaves physical boot enforcement unknown | `boot_enforcement == "unknown"` | always, by construction | rows 1–5, `tests/test_fit_dtb.py` |
| 7 | A truncated artifact is incomplete, not a finding | `boot_analysis FAILED`, exit 4, `boot: null` | exactly that | `::test_a_truncated_artifact_is_incomplete_not_a_finding` |
| 8 | An out-of-bounds payload range is bounded and named | `integrity: out-of-bounds`, stage `PARTIAL`, exit 4 | exactly that | `::test_an_out_of_bounds_payload_range_is_incomplete` |
| 9 | Deep nesting is rejected without recursion | `FAILED`, reason names the depth bound, exit 4 | exactly that | `::test_deep_nesting_is_rejected` |
| 10 | A DTB with no `/images` is a device tree, not a FIT | `kind: dtb`, no configurations, default `null` | exactly that | `::test_a_plain_device_tree_is_recognised_and_unknown_default_is_not_guessed` |
| 11 | A FIT with no `/configurations` has no selected configuration | default `null`, nothing guessed | exactly that | `tests/test_fit_dtb.py::TestFitAnalysis::test_no_configurations_means_no_selected_configuration` |
| 12 | Board facts are attributed to the declaring artifact | compatible/model/memory/partitions from the payload's own DTB | attached under `referenced_payloads[].board`, with the node path | `tests/test_fit_dtb.py::TestFitAnalysis::test_a_pair_resolves_the_kernel_and_the_device_tree` |
| 13 | Check 5 gets a positive FIT source; check 6 gets no verdict | 5 `PERFORMED/REVIEW`, 6 `INCONCLUSIVE/UNKNOWN` | exactly that | `::test_a_supplied_key_verifies_only_the_selected_configuration` |
| 14 | A parse issues no request | zero sockets | `socket.socket`/`create_connection` refuse the test | `tests/test_fit_dtb.py::test_boot_parsing_issues_no_request` |
| 15 | Independent oracle agrees on the fixture facts | model, memory, partition label, payloads, default config | `fdtget` and `mkimage -l` agree with the parser | `tests/test_fit_dtb.py::test_dtc_and_mkimage_agree_with_the_parsed_facts` |

### 2.3 Facts that stay `unknown`

| Fact | Why it is unknown |
| --- | --- |
| Physical boot enforcement | A static parser reads intent, not fuse/OTP state or a boot log. `boot_enforcement` is always `"unknown"`. |
| Whether the running device verifies at all | The artifact may declare a signature; the board may ignore it. Check 6 needs device evidence. |
| Which configuration the running board selected | The manifest names a default; the device may be configured otherwise. |
| Whether an embedded key is the pinned key | No in-artifact key is trusted, and none is compared. `verified` stays `null` without an operator key. |
| Payload semantics beyond the manifest | A matching digest proves the bytes match the declaration, not that the payload is safe. |
| Kernel/DTB compatibility at runtime | Compatible strings are declarations; the pair is resolved structurally, not proven bootable. |

### 2.4 Oracle

The **verification** worker image now carries, pinned like `binutils`:

| Tool | Version | Used for |
| --- | --- | --- |
| `fdtdump`, `fdtget` (`device-tree-compiler`) | **DTC 1.6.1** | parse the fixture DTB independently |
| `mkimage` (`u-boot-tools`) | **2023.01** | list FIT payloads, hashes and the default configuration |

The **runtime** image a scan uses still carries only `unsquashfs`; the cross-check
tools are in the `verification` stage and a scan never invokes them.

Side by side on the generated fixture:

| Fact | Scanner | Oracle |
| --- | --- | --- |
| board model | `IHS Test Board` | `fdtget … model` → `IHS Test Board` |
| memory `reg` | base `0x40000000`, size `0x10000000` | `fdtget … reg` → `0 1073741824 268435456` |
| partition label | `firmware` | `fdtget … label` → `firmware` |
| compatible | `test,board`, `test,soc` | `fdtdump` → `compatible = "test,board", "test,soc";` |
| FIT default configuration | `config-1` | `mkimage -l` → `Default Configuration: 'config-1'` |
| kernel payload | `/images/kernel-1`, sha256 match | `mkimage -l` lists `kernel-1` and its hash |
| device-tree payload | `/images/fdt-1`, sha256 match | `mkimage -l` lists `fdt-1`; the printed hash equals the DTB fixture's SHA-256 |

---

## 3. Gates (local, this machine)

| Gate | Command | Result |
| --- | --- | --- |
| Lint | `ruff check src/ tests/` | all checks passed |
| Types | `mypy src/` | no issues in 40 source files |
| Tests + coverage, qualified inputs | `pytest --cov=… --cov-fail-under=80` with the reference image, manifest, SBOM and both worker images | **910 passed, 0 skipped, 86.87 %** (2.3 baseline: 839 passed, 86.54 %) |
| Tests without those inputs | same command, no `IHS_*` | **894 passed, 16 skipped** (the by-design reference/container rows) |
| Format | `ruff format --check src/ tests/` | clean, run last |
| Wheel | `uv build && shasum -a 256 dist/*.whl` | `iot_hardware_scanner-2.4.0-py3-none-any.whl`, sha256 `ccec88c63eedab9a16a389c6978ac778e06642c1c0040995b59f4d0ac3665f7c` (macOS arm64 build) |
| Installed-CLI acceptance, wheel mode | `IHS_INSTALLED_CLI=… pytest tests/test_installed_image_cli.py tests/test_installed_cli.py` against the 2.4.0 wheel in a clean 3.12.14 venv | **46 passed, 0 skipped** (2.3: 34) |

## 4. Evidence

| Item | Value |
| --- | --- |
| Interpreter / platform | CPython 3.12.14, macOS 27.2.1 arm64 (colima vz, 2 CPU / 4 GB) |
| Version / schema / profile | 2.4.0 / 6 / 5.0 |
| Fixtures | `board.dtb` `77f4577348d693706d4921216bb057b7f5ba7a10ff99a6fa987a1506febdef70` (634 B); `fit.itb` `81a0e1aeadec9da17e9d165246fcb588172af24049ce5de0ef8127400f4d2574` (1,418 B); `fit-signed.itb` `c37eecb664f6f598cdb98acfe558db31af4643aee49425303d361fcdf83c758d` (1,825 B); `fit-mismatch.itb` `bc4c9a7c9d9398a0a1c6fabfef1eeb457757954e4abba6a8007d6c2b7f3f8c52`; operator key `0bafa46bd2d5b7ab51a30833d1cabff78944a8cc45a03da0c325ab309b744fb0` |
| Oracle | DTC 1.6.1 (`fdtdump`, `fdtget`), `mkimage` 2023.01, in `ihs-squashfs-worker:4.5.1-verify` |
| Worker package list | `worker/packages-verify.txt` adds `device-tree-compiler=1.6.1-4+b1`, `libfdt1=1.6.1-4+b1`, `libssl3=3.0.17-1~deb12u2`, `libyaml-0-2=0.2.5-1`, `u-boot-tools=2023.01+dfsg-2+deb12u1`; runtime list unchanged |
| 5C measurement | §1 and [docs/5C-DECISION.md](5C-DECISION.md) |

| Wheel (local build) | `iot_hardware_scanner-2.4.0-py3-none-any.whl`, sha256 `ccec88c63eedab9a16a389c6978ac778e06642c1c0040995b59f4d0ac3665f7c` |
| CI run | appended after the qualification run |
| Worker image ids | appended after the qualification run; the id is **observed, not reproducible** (the image configuration records a build timestamp), while the Dockerfile digest, both package lists and the tool versions are the reproducible facts |
| Local worker verification image | rebuilt with the added tools; `fdtdump`/`fdtget` report DTC 1.6.1 and `mkimage -V` reports 2023.01 |

---

## 5. Public behaviour changed

* New input kind `boot`; new profile `firmware-boot` with its own required set;
  profile version 5.0.
* New flags: `--profile firmware-boot` (also auto-selected by FDT magic),
  repeatable `--trust-anchor PATH`, `--cache-dir PATH`.
* New report fields: `boot`, `cache`; schema 5 → 6; `docs/MIGRATION-v6.md`.
* New finding id `boot.payload_integrity` (HIGH review, not critical-capable).
* Exit movement: a malformed boot artifact exits 4; a digest mismatch exits 2.
  No existing row of the scan precedence table changed.
* New verification-stage packages (release tooling only); the runtime image is
  unchanged.

---

## 6. Remaining limitations

* Physical boot enforcement is unknown by construction and is never guessed.
* No in-artifact key is parsed or trusted; only an operator-supplied PEM key can
  set `verified`.
* Only RSA/PKCS#1 v1.5 signatures with `sha1`, `sha256` or `sha512` and the
  documented `hashed-nodes` convention are verified; other algorithms are
  reported as unverified with a reason, not as valid.
* A FIT's `data-offset` (without `data-position`) is interpreted as U-Boot's
  end-relative offset; the fixtures use `data-position`, which is unambiguous.
* No release-to-release comparison is claimed for boot manifests.
* The cache is opt-in, measured on one corpus and one rule set; no claim is
  made for other corpora.
* The five boot-profile controls outside 5/6 are `NOT_APPLICABLE`, not
  "passing".

---

## 7. Queue after 3D — recorded, not started

In the plan's order for the product:

1. **3E — RAUC.** An update bundle as a proposed device state: system vs
   recovery payload, slot classes, partial-update dependency, running slot
   unknown.
2. **3A extended to partitioned images.** Two roots, in-bounds physical ranges,
   identical paths distinguishable.
3. **3C — Intel HEX**, then S-record, then UF2, as three separate changes with
   their own fixtures.
4. **Raw NAND geometry**, as its own gate with two equivalent fixtures (with
   and without spare bytes).

Each needs its own fixtures, its own support-matrix row and its own 6A/6B
qualification; none may borrow another's. A new format gate should be driven by
a paying customer or a validated revenue path, not plan order alone. The next
slice is the owner's call.
