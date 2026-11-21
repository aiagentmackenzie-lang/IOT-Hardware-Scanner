# Milestone C — “Ship the qualified scanner”

Status: **complete, and qualified in CI.** Two runs on `main` are **8/8 job
instances green**: **`44863590710`** (`c00b0e5`, the release commit) and
**`44864141977`** (`08254bf`, a docs-only re-run). Both include the
`linux-extractor` gate:
the pinned worker image built from `worker/Dockerfile`, the wheel installed
outside the checkout, the reference image digest-verified before the scan, and
**113 acceptance tests passed with zero skips**. Slices 4A → 4D → 4C → 6A → 6B
are implemented, and every mandatory fixture outcome passes with zero skips
(765 passed, 0 skipped locally; the same total in CI, with the reference-image
rows run in the qualified job).

The first run of this release, `44863090126`, failed one step: the blank-image
gate asserted `schema_version == 3` as a literal while every other job passed.
That is fixed in `c00b0e5` — the gate now reads `SCHEMA_VERSION` from the wheel
under test — because a duplicated constant is how a gate goes stale.

Starting point: `main` at `0373f25` (milestone B green, CI runs `44848363402` and
`44848829742`, 7/7 jobs each). Version **2.2.0**, report **schema 4**, profile
version **4.0**.

Everything below was run with CPython **3.12.14**: in the repository
environment, and against the built wheel (`iot_hardware_scanner-2.2.0-py3-none-any.whl`)
installed into a clean environment. The reference corpus is the pinned OpenWrt
image, digest-verified before use, scanned with `--offline`.

---

## 1. Gates

| Gate | Command | Result |
| --- | --- | --- |
| Lint | `ruff check src/ tests/` | all checks passed |
| Types | `mypy src/` | no issues in 36 source files |
| Tests + coverage | `pytest --cov=src/iot_hardware_scanner --cov-report=term --cov-fail-under=80` | **765 passed, 0 skipped, 86.44%** with `IHS_REFERENCE_IMAGE` set and the worker image present; **751 passed, 14 skipped, 86.06%** without |
| Format | `ruff format --check src/ tests/` | 73 files already formatted |
| Wheel | `uv build` | `iot_hardware_scanner-2.2.0-py3-none-any.whl`, sha256 `610ce64d87623fc5d2413d36198f800492adcbdf2910ecd3da4cdc78cfbe8391` — **byte-identical between the macOS build and the Linux CI build** for this release |
| Installed-CLI acceptance, wheel mode | `IHS_INSTALLED_CLI=… IHS_REFERENCE_IMAGE=… pytest tests/test_installed_image_cli.py tests/test_installed_cli.py` | **27 passed, 0 skipped** |
| CI | GitHub Actions run `44863590710` on `main` (`c00b0e5`) | **8/8 green**: `python-gate` on 3.10 / 3.12 / 3.14 (744 passed, 21 skipped each — the reference-image and container rows, which the qualified job runs), installed wheel with no backend, report contract, reference image with the worker off, `bounded-resources` (61 passed, 0 skipped; 2 GiB at 16 MiB windows in 78.62 s, peak RSS 91,492 KiB), and **`linux-extractor` (113 passed, 0 skipped)** |

The fourteen skips without the image are the reference-image and container rows,
by design; the `linux-extractor` CI job is where a skip fails the build.

---

## 2. Acceptance matrix

Each row is a release-gate requirement. "Verification" names the case that
proves it, not the command that happened to run.

| # | Case | Expected | Observed | Verification |
| --- | --- | --- | --- | --- |
| 1 | Rule set compiled **once** per run, with one digest | one compile, one digest, independent of path and order | 12 rule files, digest `2ca7a94b…58d`; a second `load_rules()` recompiles nothing; both detectors share the engine | `tests/test_rule_semantics.py::TestOneCompiledRuleSet` |
| 2 | No ambient rule loading | a decoy `.yar` beside the input changes nothing | identical digest and findings from two working directories | `…::test_the_digest_is_independent_of_the_working_directory` |
| 3 | Every shipped category has a typed destination | credential / service / crypto / indicator, decided by the rule's own category | all four present; no detector can relabel another's match | `…::TestTypedDestinations` |
| 4 | Benign positive **and** lookalike negative per category | positive matches; the FP shapes do not | `"Bearer "` alone, a PEM header alone, a bare MD5/DES/RC4 constant, `"expand 32-byte k"`, a 0x37 run: no finding. Real key, telnetd `-l /bin/sh`, MD5 const + `MD5_Init`, mirai credential pair: finding | `…::TestCredentialSemantics`, `::TestServiceSemantics`, `::TestCryptoSemantics`, `::TestIndicatorSemantics` |
| 5 | The 11 false positives measured in Milestone B are gone | zero C2 findings on the stock image | zero `c2.*` findings; the 318 rejected domain-shaped tokens are reported as stage coverage | `tests/test_installed_image_cli.py::TestReleasedDetectionSemantics::test_the_reference_image_raises_no_indicator_noise` |
| 6 | Weak-crypto fixture reaches its **own** control | a weak algorithm is reported by check 8, not by hardening | check 8 `PERFORMED`/`REVIEW` with the DES implementation named; check 10 stays hardening | `tests/test_control_matrix.py::test_control_8_algorithm_evidence_is_not_hardening` |
| 7 | All 12 checks, three evidence situations each | table-driven positive / contrary / missing | 12 checks × 3 rows, plus stale and partial advisory states | `tests/test_control_matrix.py` |
| 8 | Entropy never passes "encrypted at rest" | `INCONCLUSIVE` at 7.99 bits/byte | `INCONCLUSIVE`/`UNKNOWN` with the observation quoted | `…::test_control_4_entropy_never_passes_and_plaintext_fails` |
| 9 | Content verification split from board enforcement | check 5 about files, check 6 about the board | check 5 `REVIEW` with the verifying file; check 6 always `INCONCLUSIVE`, evidence points at check 5 | `…::test_control_5_positive_contrary_and_missing`, `::test_control_6_is_never_answered_by_the_image` |
| 10 | A secret never reaches an output channel | absent from findings, JSON, Markdown, HTML, terminal | absent from all five | `tests/test_rule_semantics.py::TestRedaction` |
| 11 | Advisory: recorded provider responses | paginated results, excluded versions, ambiguous keyword, cached empty, expired feed, rate limiting | 2 pages read and the total recorded; excluded version not applicable; keyword candidate rejected; `KNOWN_EMPTY`; expired cache returned `STALE`; 429 retried with bounded backoff | `tests/test_advisory.py::TestPaginatedProviderResponses`, `::TestRateLimiting`, `::TestApplicability` |
| 12 | Offline advisory assessment issues **zero** requests | `urlopen` never called | asserted with `urlopen` replaced by a raising function, end to end through the orchestrator | `tests/test_advisory.py::TestOfflineStage` |
| 13 | A requested snapshot is a required input | exit 5 / 4 when absent or unusable, never 0 or 2 | missing snapshot → `INCOMPLETE`, dependency named, exit 5 | `…::test_a_missing_snapshot_is_a_required_dependency` |
| 14 | Reference image, installed wheel, Linux worker | 196 records, `1.36.1-r2`, BusyBox digest, AArch64, 209/209 ELF, exit 1 | all recovered; `COMPLETE`; one critical (`rootfs/etc/shadow:1`) and one true crypto observation; exit 1 | `tests/test_installed_image_cli.py::TestReferenceImageInventory`, `::TestReleasedDetectionSemantics` |
| 15 | Resource-limit cases are mandatory fixtures | quota, timeout, non-zero helper all exercised | `QUOTA_EXCEEDED`, `TIMEOUT`, `HELPER_FAILED`, each exit 4 with scratch released and a retry that succeeds | `tests/test_installed_image_cli.py::TestFailingBackend` |
| 16 | Invariance on the same data | permutation, rename, block size, host path | all four agree after normalisation | `tests/test_invariance.py` |
| 17 | Digests published | wheel, worker image, rules, corpus, with the platform each was built on | see §4 | `docs/SUPPORT-MATRIX.md` |
| 18 | Release notes describe coverage, v1 migration, Linux host requirement | present | [SUPPORT-MATRIX.md](SUPPORT-MATRIX.md), [MIGRATION-v4.md](MIGRATION-v4.md), §5 below | this document |

---

## 3. The defects measured in Milestone B, closed or open

| # | Defect | State |
| --- | --- | --- |
| 1 | Eleven indicator false positives on the reference image | **closed.** Two `LIKELY_C2` malware hits gone (the ChaCha20 sigma constant rule is deleted; the Mirai rule now requires its family string). Nine domain findings gone (suffix list, `.so` shape, dependency names). One `ssh_private_key` and one `bearer_token` match, which were invisible only because binaries were not scanned for credentials, are gone as well — and binaries **are** scanned now. |
| 2 | YARA compiled per detector | **closed.** One engine per run, built once by the orchestrator, shared by the credential, C2 and crypto paths; one digest in `ruleset.digest`. |
| 3 | Check 8 `OMITTED` with no evidence source | **closed.** Check 8 now has three named sources: account hash algorithms, algorithm identifiers next to structural constants in shipped binaries, and the TLS package record. On the reference image: `PERFORMED`/`REVIEW`, naming DES in `libmbedcrypto`. It is never turned into a pass. |
| 4 | Advisory applicability unassessed | **closed as a capability, opt-in.** A local snapshot is applied offline with per-component lookup states, preserved applicability bounds, provider scores, KEV as a separate fact, and zero requests. Without a snapshot it stays `OMITTED`, and the release notes say so rather than implying coverage. |
| 5 | Coverage holes (`nvd_client` 44%, `report_generator` 61%) | **partly closed.** `nvd_client` moved from 44% to 79% with the pagination/state work, and `advisory.py` arrives at 81%; `report_generator` unchanged at 61% (it is a thin wrapper whose lines are only reached on renderer failure). `cli.py`/`orchestrator.py` were not chased artificially; the acceptance tests run the CLI as a subprocess by design. |
| 6 | Reference image exits 1 on a stock image | **decided in writing, see §5.** The observation stays, the rule stays critical, and the finding carries an applicability note as evidence. No exit movement. |

---

## 4. Evidence

| Item | Value |
| --- | --- |
| Interpreter / platform | CPython 3.12.14, macOS 27.2.1 arm64 (`Darwin`), colima VM (vz, 2 CPU / 4 GB) for the container path |
| Wheel | `iot_hardware_scanner-2.2.0-py3-none-any.whl` — `610ce64d87623fc5d2413d36198f800492adcbdf2910ecd3da4cdc78cfbe8391`, identical from the macOS build and the Linux CI build |
| Worker image | CI amd64 (qualified) `sha256:9ec4ca966a7d9a62d8c14614886a08fe33d884b8fec311da2cf89b684fadba26`; local arm64 `sha256:3ec87f2d57639e770efa65155d918e232222d0b12dc84353724927cf6772739c` |
| `unsquashfs` | `unsquashfs version 4.5.1 (2022/03/17)` |
| Rule set | `2ca7a94b511400528f49ea9290359d716e5a3e7ecb408ab0b62cbee6a946258d` (`yara-python 4.5.4`, 12 files) |
| Corpus | `8b5aa82659cafd90b26333dd419a0df9ad63c517ad94a2159e970a5bb5b6ff02` |
| CI run id | **`44863590710`** on `main` (`c00b0e5`) — 8 job instances, all green. The workflow defines six jobs: `python-gate` (3.10/3.12/3.14), `installed-wheel-no-backend`, `report-contract`, `reference-image`, `bounded-resources`, `linux-extractor` |
| Profile result | `firmware-static` v4.0, `COMPLETE`, 15 stages settled, exit 1 |

Reference image, installed wheel, worker present — side by side with the
independent oracle (PySquashfsImage 0.9.0 + `struct`, sharing no code):

| Observation | Scanner | Oracle |
| --- | --- | --- |
| corpus digest / wire / expanded / extent | `8b5aa826…`, 4,451,127 / 109,051,904 / 4,348,264 | identical |
| files / directories enumerated | 1,283 / 110 | 1,283 files |
| ELF parsed | 209 of 209 | 209 ELF files |
| installed records / held | 196 / 4 | 196 / 4 |
| BusyBox version / digest / machine | `1.36.1-r2`, `214a261c…696c`, 183 (`AArch64`) | identical |
| opkg database digest | `9442acba…a3258` | identical |
| findings | 1 critical (empty root password field), 1 review (DES implementation), 0 indicators | — |
| process result | exit **1** | — |

---

## 5. Decision in writing: the empty root password on a stock OpenWrt image

`/etc/shadow` line 1 of the shipped image is `root::0:0:99999:7:::`. Read on its
own terms that is an account with an empty password field and a login shell
(`/bin/ash`). It meets `credential.unix.empty_password` exactly as documented,
so the finding stands and the process exits 1.

The distribution has a reason for that line: credentials are provisioned at
first boot, Dropbear is key-only and there is no telnet listener. That is an
argument about the *deployment*, not about the bytes. The scan was asked what
the image contains, and the image contains an account that authenticates with
no password until provisioning runs.

The decision, therefore:

* **the rule stays critical and the observation stays in the report** — no
  suppression, no severity reduction, no exit movement;
* the finding carries an applicability note as evidence: the field describes
  the file as shipped, a first-boot distribution still ships it, and whether
  provisioning ran is device evidence;
* the release notes state the note exists and that it is descriptive, not
  exculpatory (README, Known limitations).

An operator who wants this image to exit 0 has to change the image. That is the
honest answer, and it is the one a firmware review should give.

---

## 6. What is not closed

| Row | Why |
| --- | --- |
| Advisory refresh, end to end over the network | Deliberately out of the scan. `NVDClient` pagination, retry, rate limiting and cache states are unit-tested against recorded responses; no test in this suite opens a socket, by design. |
| Worker image id is not reproducible | The image pins `debian:bookworm-slim` by digest and `squashfs-tools=1:4.5.1-1` by version, but `binutils` and the rest of the base resolve at build time, so the image id differs between the previous release (`sha256:954d9741…`) and this one (`sha256:9ec4ca96…`). The report records the id it actually used; the `unsquashfs` version is the reproducible fact. |
| Component inventory → CPE coverage | 3 of the reference image's 196 installed records map to a product in the shipped CPE map, so `components[]` is much smaller than `opkg.records[]`. This is slice 4B's mapping table, not a detector defect, and it is now stated in the release notes and the support matrix instead of being implied. |
| Broader accuracy claims | A held-out corpus of sufficient size does not exist here. Per-detector misses are recorded as *not measurable* on this corpus rather than as zero. |

A skip in CI leaves that capability unqualified. The `linux-extractor` and
`bounded-resources` jobs fail on any skip for exactly that reason.
