# Support matrix and qualification record — release 2.2.0

This file is the answer to one question: **for each input this release claims to
handle, what has actually been demonstrated, on what, and by which code?** A
capability without a passing case is listed as unqualified.

Measured with `iot-hardware-scanner 2.2.0`, report schema 4, profile version 4.0.
Every number below comes from a run recorded in
[docs/MILESTONE-C.md](MILESTONE-C.md).

---

## 1. Input formats

| Format | Tested level | Backend and version | Platform of the qualified run | Evidence |
| --- | --- | --- | --- | --- |
| Gzip-wrapped SquashFS v4 root image (OpenWrt) | **analyzed** — decoded, extracted, enumerated, inventoried, detected | `unsquashfs 4.5.1 (2022/03/17)` in `ihs-squashfs-worker:4.5.1` | Linux x86_64 container, arm64 container | `tests/test_installed_image_cli.py::TestReferenceImageInventory`, `::TestReleasedDetectionSemantics` |
| Unwrapped SquashFS v4 image at offset 0 | **analyzed** — superblock validated in place, then the same worker path | as above | as above | `tests/test_image_map.py`, `tests/test_installed_image_cli.py` |
| Staged root tree (`--input-tree`) | **analyzed** — no container, no extraction | local bounded reader | any host | `tests/test_staged_tree.py`, `tests/test_installed_image_cli.py::TestTreeAndImage` |
| Build output with a declared manifest (`--build-manifest`) | **analyzed** — declared modes/ownership used instead of host bits | local | any host | `tests/test_staged_tree.py` |
| Single ELF file | **analyzed** — header, segments, `PT_DYNAMIC`, hardening, rules | pyelftools 0.32 | any host | `tests/test_elf_parser.py`, `tests/test_binary_intelligence.py`, `tests/test_rule_semantics.py` |
| Opaque / unrecognised blob | **recognized** — identified, then reported as unsupported (exit 4) | none | any host | `tests/test_installed_cli.py::TestObservedFailuresStayFixed` |
| Advisory snapshot `ihs-advisory-snapshot/1` | **decoded and applied** offline | none (no network) | any host | `tests/test_advisory.py` |
| Partitioned images, CPIO, JFFS2/UBIFS, MCU address spaces, FIT/DTB, RAUC, raw NAND | **not supported** — reported as unsupported, never guessed at | — | — | later gates with their own fixtures |

A level means exactly this: **recognized** — the bytes were identified;
**decoded** — a container was opened; **extracted** — files were materialised;
**analyzed** — every stage the selected profile requires ran to completion and
the report says so.

### Hosts

| Host | Python | Image extraction | Qualified? |
| --- | --- | --- | --- |
| Linux x86_64 (CI, `ubuntu-latest`) | 3.12 | container worker, `unsquashfs 4.5.1` | **yes — this is the qualified profile** |
| macOS arm64 (developer machine) | 3.12.14 | container worker in a colima VM, `unsquashfs 4.5.1` | measured, not the release profile |
| Linux with `host-process` extraction | any | direct `unsquashfs`, no isolation | **never** — recorded as `isolation: host-process` |

Image extraction needs a Linux container runtime with the pinned worker image.
Scanning a staged tree, a single file, or applying an advisory snapshot does not.

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
| `/usr/lib/opkg/status` SHA-256 | `9442acba…a3258` | same |
| BusyBox version / ELF | `1.36.1-r2`, ELF64 LE machine 183 | same |
| `/bin/busybox` SHA-256 | `214a261c…696c` | same |
| configured startup directives | 8 | — |
| entropy | 7.9607 bits/byte over 4,451,127 bytes, whole input | — |
| profile completion | `COMPLETE`, all 14 required stages settled | — |
| process result | exit **1** (one qualified critical finding) | — |

### Detector metrics on this corpus

Counts are over the enumerated population. A "miss" requires a ground truth for
the corpus; where none exists, the cell says so rather than claiming zero.

| Detector | True positives | False positives | Misses | Population inspected |
| --- | --- | --- | --- | --- |
| Credential (rule set + account databases) | 1 — `credential.unix.empty_password` on `rootfs/etc/shadow:1` | 0 | not measurable: no ground-truth secret inventory exists for a stock vendor image | 229 eligible files (100%), 1 passwd/shadow pair |
| Indicator (domains, IPs, malware, backdoor) | 0 — and no indicator is expected in a stock image | **0**, down from 11 before this release | not measurable: no ground-truth malware set for this corpus | 1,283 files swept (100%) |
| Crypto algorithm evidence | 1 — DES implementation in `usr/lib/libmbedcrypto.so.3.6.2@37098` | 0 | not measurable: no per-binary algorithm ground truth | 209 ELF files (100%) |
| Component inventory | 3 mapped components of 196 installed records | 0 | **173 installed records have no CPE mapping in this release** — a stated gap, not a claim | 196 of 196 records read |
| Advisory | 0 (no snapshot supplied in the qualified run) | n/a | n/a | unassessed, and reported as unassessed |

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
| Wheel | `610ce64d87623fc5d2413d36198f800492adcbdf2910ecd3da4cdc78cfbe8391` — `iot_hardware_scanner-2.2.0-py3-none-any.whl`; identical from the macOS (CPython 3.12.14) and Linux CI builds |
| Wheel (Linux CI build, qualified artifact) | same digest, built by `linux-extractor` in run `44863590710` |
| Worker image (Linux amd64, CI, qualified) | `sha256:9ec4ca966a7d9a62d8c14614886a08fe33d884b8fec311da2cf89b684fadba26` |
| Worker image (macOS arm64, local) | `sha256:3ec87f2d57639e770efa65155d918e232222d0b12dc84353724927cf6772739c` |
| `unsquashfs` | `unsquashfs version 4.5.1 (2022/03/17)` |
| Rule set | `2ca7a94b511400528f49ea9290359d716e5a3e7ecb408ab0b62cbee6a946258d` (12 rule files, yara-python 4.5.4) |
| Corpus | `8b5aa82659cafd90b26333dd419a0df9ad63c517ad94a2159e970a5bb5b6ff02` |

The rule-set digest is over the sorted `namespace|file|sha256(content)` of the
compiled sources, so it is independent of install path and file order.

The worker image id is not reproducible: the Dockerfile pins the base image by
digest and `squashfs-tools` by version, but `binutils` and the rest of the base
resolve at build time. The report records the id it actually used; `unsquashfs
version 4.5.1 (2022/03/17)` is the reproducible fact.

Qualified run: GitHub Actions `44863590710` on `main` (`c00b0e5`), 8/8 job
instances green, `linux-extractor` 113 passed with zero skips.
