# Support matrix and qualification record — release 2.4.0

This file is the answer to one question: **for each input this release claims to
handle, what has actually been demonstrated, on what, and by which code?** A
capability without a passing case is listed as unqualified.

Measured with `iot-hardware-scanner 2.4.0`, report schema 6, profile version 5.0.
Numbers come from runs recorded in [docs/MILESTONE-C.md](MILESTONE-C.md) (the
2.2 qualification), [docs/MILESTONE-D.md](MILESTONE-D.md) (the 2.3 comparison,
SBOM and inventory work) and [docs/MILESTONE-E.md](MILESTONE-E.md) (the 5C and
3D slices). The repeated-work cache is recorded separately in
[docs/5C-DECISION.md](5C-DECISION.md). Where a row is only measured locally it
says so.

---

## 1. Input formats

| Format | Tested level | Backend and version | Platform of the qualified run | Evidence |
| --- | --- | --- | --- | --- |
| Gzip-wrapped SquashFS v4 root image (OpenWrt) | **analyzed** — decoded, extracted, enumerated, inventoried, detected | `unsquashfs 4.5.1 (2022/03/17)` in `ihs-squashfs-worker:4.5.1` | Linux x86_64 container, arm64 container | `tests/test_installed_image_cli.py::TestReferenceImageInventory`, `::TestReleasedDetectionSemantics` |
| Unwrapped SquashFS v4 image at offset 0 | **analyzed** — superblock validated in place, then the same worker path | as above | as above | `tests/test_image_map.py`, `tests/test_installed_image_cli.py` |
| Staged root tree (`--input-tree`) | **analyzed** — no container, no extraction | local bounded reader | any host | `tests/test_staged_tree.py`, `tests/test_installed_image_cli.py::TestTreeAndImage` |
| Two saved scan documents (`compare`) | **analyzed** — records, components, layout and findings compared by identity | none (no extraction, no network) | any host | `tests/test_comparison.py`, `tests/test_installed_image_cli.py::TestTwoReleaseComparison`, `::TestReferenceDeclarationReconciliation` |
| OpenWrt target manifest as a declaration (`compare --declaration`) | **analyzed** — 124 rows reconciled against 196 image records, 72 image-only | none | any host | `tests/test_installed_image_cli.py::TestReferenceDeclarationReconciliation` |
| Supplier CycloneDX 1.4 as a declaration | **analyzed** — 124 rows; revision-less rows stay unresolved | none | any host | same case |
| CycloneDX 1.6 BOM export (`sbom`) | **analyzed** — exported and validated offline against the vendored schema | `jsonschema` (the `sbom` extra) | any host | `tests/test_sbom.py`, `tests/test_installed_image_cli.py::TestCycloneDXExport` |
| Build output with a declared manifest (`--build-manifest`) | **analyzed** — declared modes/ownership used instead of host bits | local | any host | `tests/test_staged_tree.py` |
| Single ELF file | **analyzed** — header, segments, `PT_DYNAMIC`, hardening, rules | pyelftools 0.32 | any host | `tests/test_elf_parser.py`, `tests/test_binary_intelligence.py`, `tests/test_rule_semantics.py` |
| Flattened device tree (`.dtb`, FDT magic) | **analyzed** — bounded structural parse; compatible/model, memory, reserved memory, partitions; no signature expectation | in-process parser (no helper) | any host | `tests/test_fit_dtb.py`, `tests/test_installed_cli.py::TestBootManifestProfile` |
| U-Boot FIT (`.itb`, FDT magic) | **analyzed** — configurations, selected default, referenced payloads, digest integrity, signature presence and (with an operator key) verification; board facts from the referenced DTB | in-process parser + RSA/PKCS#1 verification | any host | same, plus `::test_a_supplied_key_verifies_only_the_selected_configuration` |
| Repeated-work cache (`--cache-dir`) | **measured** — per-file rule matches and text facts; cold/warm reports equal | `ihs-analysis-cache/1` | any host | `tests/test_analysis_cache.py`, `tests/test_installed_cli.py::TestRepeatedWorkCache` |
| Opaque / unrecognised blob | **recognized** — identified, then reported as unsupported (exit 4) | none | any host | `tests/test_installed_cli.py::TestObservedFailuresStayFixed` |
| Advisory snapshot `ihs-advisory-snapshot/1` | **decoded and applied** offline | none (no network) | any host | `tests/test_advisory.py` |
| Partitioned images, CPIO, JFFS2/UBIFS, MCU address spaces, RAUC, raw NAND | **not supported** — reported as unsupported, never guessed at | — | — | later gates with their own fixtures |

A level means exactly this: **recognized** — the bytes were identified;
**decoded** — a container was opened; **extracted** — files were materialised;
**analyzed** — every stage the selected profile requires ran to completion and
the report says so.

### Comparison level per input format

The plan asks the support matrix to state, per format, how far a **comparison**
reaches. These are separate claims from “the format can be read”:

| Format | Comparison level | Identity used | What is *not* compared |
| --- | --- | --- | --- |
| Gzip/SquashFS v4 image (OpenWrt) | **record-level** — package records, components, ELF/tree layout and findings | `Package` name; `(vendor, product, cpe_basis)`; ELF build ID else file digest; rule + trailing path | package-owned files that no record names; runtime state |
| Staged root tree | **record-level**, same identities, tree manifest instead of ELF records | file digest from the tree manifest | declared vs observed metadata beyond the manifest |
| Single ELF file | **file-level** — its own ELF record and findings | build ID else digest | anything outside that file |
| Opaque / unsupported input | **none** — nothing to compare; the scan is incomplete and the comparison says so | — | everything |
| Build declaration (manifest, CycloneDX) | **declaration-level** — name and version against the image's records, with an explicit binding state | declared name; complete version string | whether the declared package's *files* are present |
| FIT / DTB boot manifests | **manifest-level** — the selected configuration is resolved against the artifact's own payloads, and declared vs observed digests are compared | configuration name; payload node; declared digest | anything across releases; runtime boot behaviour |
| MCU / RAUC / partitioned images | **not supported** — no comparison claim | — | — |

### Hosts

| Host | Python | Image extraction | Qualified? |
| --- | --- | --- | --- |
| Linux x86_64 (CI, `ubuntu-latest`) | 3.12 | container worker, `unsquashfs 4.5.1` | **yes — this is the qualified profile** |
| macOS arm64 (developer machine) | 3.12.14 | container worker in a colima VM, `unsquashfs 4.5.1` | measured, not the release profile |
| Linux with `host-process` extraction | any | direct `unsquashfs`, no isolation | **never** — recorded as `isolation: host-process` |

Image extraction needs a Linux container runtime with the pinned worker image.
Scanning a staged tree, a single file, a boot manifest, or applying an advisory
snapshot does not.

---

## 2. The pinned corpus

| Artifact | Where from | SHA-256 | Size |
| --- | --- | --- | --- |
| `openwrt-24.10.0-armsr-armv8-generic-squashfs-rootfs.img.gz` | `downloads.openwrt.org/releases/24.10.0/targets/armsr/armv8/`, fetched by the operator and verified before the scan | `8b5aa82659cafd90b26333dd419a0df9ad63c517ad94a2159e970a5bb5b6ff02` | 4,451,127 bytes on the wire, 109,051,904 expanded, SquashFS extent 4,348,264 |

The corpus is a **historical, redistributable release artifact**: a frozen
OpenWrt 24.10.0 image, not a live feed and not a vendor-supplied secret. The
suite never downloads it — `tests/conftest.py::reference_image` reads
`IHS_REFERENCE_IMAGE` and skips when it is unset, so a checkout without the
image still runs everything else.

Expected architecture and layout: AArch64 (`EM_AARCH64`, machine 183), ELF64
little-endian, SquashFS v4 with 262,144-byte blocks, 1,622 inodes, 59 fragments,
one root filesystem, 227 symlinks.

**Independent oracle.** A throwaway environment running `gzip.decompress`,
PySquashfsImage 0.9.0 and a hand-rolled `struct` read, sharing no code with the
scanner. The scanner and the oracle agree on every number in §3.

---

## 3. What the qualified run measured

| Observation | Scanner | Oracle |
| --- | --- | --- |
| gzip SHA-256 | `8b5aa826…ff02` | same |
| bytes on the wire / expanded / extent | 4,451,127 / 109,051,904 / 4,348,264 | same |
| files / directories enumerated | 1,283 / 110 | 1,283 files |
| eligible ELF files parsed | 209 of 209 (**100%**) | 209 ELF files |
| installed-package records read | 196 of 196, 4 held | 196, 4 |
| components emitted from those records | **196** — 5 `nist-mapped`, 191 `opkg-package-name`, 0 banner | 196 installed stanzas |
| `/usr/lib/opkg/status` SHA-256 | `9442acba…a3258` | same |
| BusyBox version / ELF | `1.36.1-r2`, ELF64 LE machine 183 | same |
| `/bin/busybox` SHA-256 | `214a261c…696c` | same |
| configured startup directives | 8 | — |
| entropy | 7.9607 bits/byte over 4,451,127 bytes, whole input | — |
| profile completion | `COMPLETE`, all 14 required stages settled | — |
| process result | exit **1** (one qualified critical finding) | — |

### Detector metrics on this corpus

Counts are over the enumerated population. A "miss" requires a ground truth for
the corpus; where none exists, the cell says so rather than claiming zero. The
comparison row is the one place where ground truth exists, because the
two-release fixture is generated: the expected change set is known before the
comparison runs. It is not extended to the other detectors.

| Detector | True positives | False positives | Misses | Population inspected |
| --- | --- | --- | --- | --- |
| Credential (rule set + account databases) | 1 — `credential.unix.empty_password` on `rootfs/etc/shadow:1` | 0 | not measurable: no ground-truth secret inventory exists for a stock vendor image | 229 eligible files (100%), 1 passwd/shadow pair |
| Indicator (domains, IPs, malware, backdoor) | 0 — and no indicator is expected in a stock image | **0**, down from 11 before this release | not measurable: no ground-truth malware set for this corpus | 1,283 files swept (100%) |
| Crypto algorithm evidence | 1 — DES implementation in `usr/lib/libmbedcrypto.so.3.6.2@37098` | 0 | not measurable: no per-binary algorithm ground truth | 209 ELF files (100%) |
| Component inventory | **196 of 196 installed records**, each with its own evidence range and a recorded basis (5 `nist-mapped`, 191 `opkg-package-name`) | 0 | 0 records dropped; 191 name a product with no authoritative NIST entry, which is stated per component rather than hidden | 196 of 196 records read |
| Advisory | 0 (no snapshot supplied in the qualified run) | n/a | n/a | unassessed, and reported as unassessed |
| Release comparison (2.3) | **package change: 1 of 1**; **relocation: 1 of 1**; **resolved finding: 1 of 1**; **coverage change: 1 of 1** | **0** false package changes, 0 false relocations, 0 findings wrongly resolved | **0** expected changes missed on the generated pair | 3 installed records and 2 ELF files per release on the generated pair; 196 records and 209 ELF files on the reference image (self-comparison: 196 persistent, 0 changed, 0 resolved) |

### Release metrics the plan asks to track

| Metric | Corpus count |
| --- | --- |
| Locked-account critical false positives | **0** — the one account with a locked hash (`$6$`, user) raises no finding; the one critical is an empty password field on a login shell, which is a true observation |
| Missed configured services | **0 of 8** enumerated startup directives; one `/etc/init.d/rcS` sysinit line is reported, and none is claimed to be listening |
| Cross-run verdict changes | **0** — permutation, rename, block-size and host-path invariance all agree (`tests/test_invariance.py`) |
| Proportion of eligible artifacts inspected | ELF 209/209, package records 196/196, credentials 229/229, indicator sweep 1,283/1,283 |

### Invariance

| Check | Result |
| --- | --- |
| Permuted filesystem enumeration | identical normalised findings, stages and controls |
| ELF renamed, bytes unchanged | identical ELF record except the locator; identical findings |
| Entropy block size 128 vs 256 | identical bytes read and identical whole-input entropy; regions move only at block boundaries |
| Same tree scanned twice from two host paths | identical normalised document except recorded paths |
| Two directories with different ambient `.yar` files | identical rule-set digest and identical findings (no ambient rule loading) |

---

## 4. Published artifacts for this release

| Artifact | Digest |
| --- | --- |
| Wheel (2.4.0, local macOS arm64 build) | `ccec88c63eedab9a16a389c6978ac778e06642c1c0040995b59f4d0ac3665f7c` — `iot_hardware_scanner-2.4.0-py3-none-any.whl`; the CI build is appended after the qualification run |
| Wheel (2.3.0, superseded) | `2f3a0bf6246de4e1fafc4b089425ce318afb2f1a1055f5ce9be723bd2b0e1505` — byte-identical from the macOS arm64 build and both Linux CI builds |
| Wheel (Linux CI build, qualified artifact) | same digest, built by `linux-extractor` in run `44897056652` |
| Worker image, runtime (Linux amd64, CI, qualified) | `sha256:8f9818aa4b33aa9c045308fa51d8e5d79dba135d9f7a43b43b7544d37f7e5262` — **observed, not reproducible** |
| Worker image, verification stage (Linux amd64, CI) | `sha256:a7c206d57ef05a403b7b102edc0cc089daca6495bfc521d0010249231605d11d` — observed |
| Worker image, local arm64 | runtime `sha256:91b0ebd4…110`, verification `sha256:fab6e227…840` — observed |
| Worker 2.3 Dockerfile / package lists | Dockerfile `44e6fb84…981e2`; `packages.txt` `e26f55bd…900c9` (90 exact versions, Debian snapshot); `packages-verify.txt` `7f238099…8eab` (98) |
| Worker content reproducibility | two `--no-cache` builds: `dpkg-query -W` digest `2e938beb…` and `/usr/bin/unsquashfs` sha256 `cb10af7f…` identical; image ids differ (`7970b906…`, `ae64e345…`) |
| Worker image (2.2, superseded) | runtime `sha256:9ec4ca96…` (CI amd64) / `sha256:3ec87f2d…` (local arm64); carried binutils, which the 2.3 runtime image does not |
| `unsquashfs` | `unsquashfs version 4.5.1 (2022/03/17)` |
| FDT/FIT oracle | DTC **1.6.1** (`fdtdump`, `fdtget`) and `mkimage` **2023.01**, verification stage only |
| Boot fixtures | `board.dtb` `77f45773…def70`; `fit.itb` `81a0e1ae…d2574`; `fit-signed.itb` `c37eecb6…c758d` |
| 5C measurement (2.4, local) | cold no-cache **7.73 s** / 205.8 MB; cache cold **5.18 s**; cache warm **1.81 s** / 110.0 MB on the pinned corpus — see `docs/5C-DECISION.md` |
| Rule set | `2ca7a94b511400528f49ea9290359d716e5a3e7ecb408ab0b62cbee6a946258d` (12 rule files, yara-python 4.5.4) — unchanged in 2.3 |
| Corpus | `8b5aa82659cafd90b26333dd419a0df9ad63c517ad94a2159e970a5bb5b6ff02` |
| Target manifest | `e5951c2355950b187ed154dd6f46547e3cac240937094502dd8b66afcc65fbff` (124 rows, all matching) |
| Supplier CycloneDX 1.4 | `50ca09d781aeb7bda85eed0069d0853c0cde506f5e450667374283d6c296a068` (124 components) |
| CycloneDX 1.6 schema (vendored) | `data/cyclonedx-1.6/` — `bom-1.6.schema.json`, `spdx.schema.json`, `jsf-0.82.schema.json`, shipped in the wheel |
| Exported BOM (reference image) | 196 components, sha256 `d590e82e159e686d73fc97a20feb8b6bf2e135eb8733ddcf2103755d8643130b` |

The rule-set digest is over the sorted `namespace|file|sha256(content)` of the
compiled sources, so it is independent of install path and file order.

The worker image id is not reproducible and is not claimed to be: the 2.3
Dockerfile pins the base by digest, pins every installed package to an exact
version from a Debian snapshot date, and moved `binutils` into a verification
stage that a scan never uses. Two `--no-cache` builds produce the same package
set and the same `unsquashfs`, and different ids, because the image
configuration records a build timestamp. The report records the id it actually
used; the Dockerfile digest, the package list and `unsquashfs version 4.5.1
(2022/03/17)` are the reproducible facts.

Qualified run for 2.3: GitHub Actions **`44897056652`** on `main` (`aa16f7a`),
**8/8 job instances green**, `linux-extractor` **166 passed with zero skips**
(including the comparison, declaration and SBOM rows), `bounded-resources` 61
passed with zero skips (2 GiB at 16 MiB windows in 105.06 s, peak RSS
92,328 KiB). The 2.2 qualification was run `44863590710` on `c00b0e5`, 8/8 green,
`linux-extractor` 113 passed.

Run `44896433693` on `e32e2a1` was 7/8: the only red job failed in the CI gate
itself (the audited-extras step imported the package with the job's interpreter
rather than the venv holding the wheel). `aa16f7a` fixed the gate.
