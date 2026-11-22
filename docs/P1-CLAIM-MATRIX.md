# Slice P1 — the claims are executable (2.5.1)

**Not a new milestone.** The plan's delivery table ends at D and stays closed.
This slice adds no format, no profile, no report field and no exit-code row. It
makes the published claim surface and the CI skip gates executable, and it
repairs one asymmetry in the v1 reader that the new compatibility fixtures
found.

Starting point: `main` at `787b1d4`, version 2.5.0, report schema 6, profile
version 5.0.

---

## 1. Why

The support matrix is the public answer to *what has actually been demonstrated,
on what, and by which code*. It was maintained by hand, and so were the
milestone acceptance matrices. Two failures were possible and neither was
visible to a run:

1. A renamed acceptance test left a matrix row pointing at a node id that no
   longer exists. The row still read like evidence.
2. The qualified CI jobs enforced "no skips" by `grep -qE "[0-9]+ skipped"` over
   a pytest log. That is a proxy: it depends on the summary line being printed,
   on the log being the one that ran, and on nobody reordering the shell steps.
   A skip that pytest recorded could survive a grep that did not match the
   summary format.

The v1 reader had a third, smaller asymmetry: every upgrade path from schema 2
onward added the sections its source version could not record as explicit
`null`, but the v1 path simply omitted them. `document["image_map"]` raised
`KeyError` for a v1 replay and returned `None` for a v2 replay, for the same
absence. P1's compatibility fixtures found it; §4 records the fix.

---

## 2. What changed

| Layer | File | Change |
| --- | --- | --- |
| Claim parsing | `tests/claims.py` | Reads `docs/SUPPORT-MATRIX.md`, extracts every backticked test reference, and resolves module, class, function and `tests/conftest.py::fixture` forms, including `::name` continuations. Shared by the test module and the session-end gate. |
| Claim checks | `tests/test_claim_matrix.py` | Every reference resolves to a collected node; every acceptance class in the two installed-entrypoint modules is named by a row; unclaimed tests are reported (never failed). |
| Outcome record | `tests/run_recorder.py` | One process-level record of what each node did, with `failed > skipped > passed` precedence. |
| Skip gate and claim verdict | `tests/conftest.py` | `--fail-on-skips` fails the process on any skip, naming the node id and reason. A session-end verdict fails on a claimed test that failed and reports claimed skips. |
| Schema compatibility | `tests/test_schema_compat.py` | One fixture per report schema 1–6, the exact upgrade result asserted: migration source, preserved facts, exact top-level key set, and every unrecordable fact `None`. |
| v1 reader | `scanner/report_document.py` | `_upgrade_v1` now emits the explicit `null` sections the other upgrade paths already emitted. No field is invented and no fact changes. |
| CI | `.github/workflows/ci.yml` | Three `grep -qE "[0-9]+ skipped"` blocks replaced by `--fail-on-skips`. The logs are still written for humans, and are no longer parsed. The claim and schema modules run in the qualified extractor job. |
| Claims | `docs/SUPPORT-MATRIX.md` | New failure/artifact/compatibility rows naming the acceptance classes that had no row: entrypoints, wheel contents, worker-absent, failing backend, replaced build output, budgets, generated declaration reconciliation, schema compatibility, and the claim check itself. |
| Version | `pyproject.toml`, `README.md`, `__init__.py` | 2.5.0 → **2.5.1**. The wheel bytes change and a v1 replay's JSON gains fields, so the artifact gets its own patch version. |

Deliberately unchanged: the scan exit precedence table and `decide_exit`, the
profile required sets, schema 6, profile version 5.0, the cache contract, every
rule and every format.

---

## 3. The claim check: exactly what is enforced

**Exists.** `tests/test_claim_matrix.py::test_every_matrix_reference_resolves`
collects the whole suite in a subprocess (not `request.session.items`, because a
CI job that selects ten files must still notice a claim that names a test
outside the selection) and requires every matrix reference to match at least one
collected node id. A `tests/conftest.py::reference_image` form is checked as a
fixture definition instead, because it names the gate that skips the corpus rows,
not a test.

**Passes.** A per-test check cannot see a failure in a module pytest has not
reached yet — the first version of this slice had exactly that bug, and a
deliberately failing claimed test in `tests/test_sbom.py` was not caught because
`test_claim_matrix.py` sorts earlier. The verdict therefore lives in
`pytest_sessionfinish`: a claimed node that failed fails the process and prints
the matrix line, the node id and the failure. A claimed node that *skipped* is
printed as `UNVERIFIED`; it fails the process when the run is strict.

**Coverage of the acceptance surface.**
`test_every_acceptance_class_is_named_by_a_row` enumerates the classes of
`tests/test_installed_cli.py` and `tests/test_installed_image_cli.py` and
requires each to be named by at least one matrix row. This is the check that
turns a deleted acceptance row red.

**Reported, never failed.**
`test_unclaimed_tests_are_reported` prints how many collected tests and modules
back no claim, and names the modules. On 2.5.1 that is 334 of 976 tests and 30 of
47 modules: the rest of the suite is unit-level work that carries no public
claim. Reporting keeps the gap visible without pretending every unit test is a
release gate.

**Not checked, deliberately.** The historical slice records under `docs/`
(`MILESTONE-*.md`) are records of what was true at a release, not live claims.
They are not rewritten to follow a later rename, and they are not parsed here.

---

## 4. Schema compatibility — one exact result per version

`tests/test_schema_compat.py` carries six fixtures. Each contains only the
fields its own version recorded; nothing from a later version leaks backwards,
which is what makes "no field is invented" meaningful. The top-level key set of
every upgrade is asserted exactly, so adding a section without a migration
decision fails here.

| Source | Migration record | Preserved | Becomes `null` (could not be recorded) |
| --- | --- | --- | --- |
| v1, unversioned | none; provenance in `schema_note` | one finding lifted from `credentials[]` under its `matched_pattern`; historical grade under `legacy_grade` **and** `risk_score`, labelled `v1-12-control-weighted`; `assessment.coverage = "UNKNOWN"`; empty `stages` | `image_map`, `extraction`, `input_binding`, `elf`, `opkg`, `tree`, `ruleset`, `advisory`, `component_bases`, `boot`, `cache` |
| v2 | `from: 2` | every recorded finding, stage, artifact and outcome | the five v3 evidence sections, `ruleset`, `advisory`, `component_bases`, `boot`, `cache`; `elf` is the documented empty-record shape |
| v3 | `from: 3` | `image_map`, `extraction`, `input_binding`, `opkg`, the ELF record list | `ruleset`, `advisory`, `component_bases`, `boot`, `cache`; no `destination`, `namespaces` or `ruleset_digest` is added to a finding |
| v4 | `from: 4` | `ruleset`, `advisory` | `component_bases`, `boot`, `cache`; no component gains a `cpe_basis` |
| v5 | `from: 5` | `component_bases` | `boot`, `cache` |
| v6 | none | the whole document, unchanged | nothing |

The v1 fixture also proves the compatibility gate the plan asks for: the
document still renders its historical display — the finding, the "Legacy grade"
line and the "Coverage unknown" note — in Markdown and terminal output. A v1
replay is still not a claim that anything was re-analysed.

### The one behaviour change

`_upgrade_v1` now returns `image_map`, `extraction`, `input_binding`, `elf`,
`opkg`, `tree`, `ruleset`, `advisory` and `component_bases` as `null`. Before
2.5.1 those keys were absent, so the same "not recorded" fact was `KeyError` on
a v1 replay and `None` on every other upgrade. `outcome` and `data_sources` stay
absent: they are schema-2 fields a v1 document never wrote, and the renderers
already treat their absence as unknown. No fact is invented and no exit path
moves.

---

## 5. `--fail-on-skips`

Implemented with `pytest_runtest_logreport` in `tests/conftest.py`. At session
end, if the flag was set and any node skipped, the process exits
`pytest.ExitCode.TESTS_FAILED` and prints every skip with its node id and
reason. The reason comes from pytest's own record (`Skipped: …`), not from a log
regex.

Three CI blocks were replaced, all in jobs where a skip means "unqualified":

| Job | Was | Now |
| --- | --- | --- |
| `installed-wheel-no-backend`, hostile inputs | `pytest … \| tee log` then `grep -qE "[0-9]+ skipped"` | `pytest … --fail-on-skips \| tee log` |
| `bounded-resources`, reader and budgets | `pytest … \| tee log` then a grep step | `pytest … --fail-on-skips \| tee log` |
| `linux-extractor`, acceptance rows | `pytest … \| tee log` then a `grep` step with `if: always()` | `pytest … --fail-on-skips \| tee log` |

The `report-contract` job keeps its one allowed skip and does not use the flag:
it runs the document contract without a container, and that skip is declared
behaviour rather than an unqualified capability.

---

## 6. Negative controls, observed

| Control | Observed |
| --- | --- |
| Delete the gzip/SquashFS row from the matrix | `test_every_acceptance_class_is_named_by_a_row` red: `TestReferenceImageInventory` and `TestReleasedDetectionSemantics` back no row. Restored from a byte copy. |
| Rename `TestReleasedDetectionSemantics` | Two failures: `line 24: '::TestReleasedDetectionSemantics' -- no collected test node matches`, and the renamed class backs no row. Restored. |
| Break a claimed test (`test_boot_parsing_issues_no_request`) | Session-end gate: `CLAIM MATRIX: a claimed test did not pass; its row is unqualified` with `line 33: tests/test_fit_dtb.py -> tests/test_fit_dtb.py::test_boot_parsing_issues_no_request: AssertionError…`; exit 1. Restored. |
| Skip a claimed row with the flag | `FAIL-ON-SKIPS` prints `SKIPPED tests/test_installed_image_cli.py::TestWorkerOff::…` and the reference-image reason; exit 1. Without the flag the same run exits 0 and the skip is reported. |

The first two are the acceptance requirement. The third is the check that an
in-module test would have missed.

---

## 7. Acceptance matrix

| # | Requirement | Expected | Observed | Verification |
| --- | --- | --- | --- | --- |
| 1 | Every backticked test node id in the matrix exists | resolves to a collected node | 39 references, 17 modules, all resolve | `tests/test_claim_matrix.py::test_every_matrix_reference_resolves` |
| 2 | Every acceptance class is named by a row | no unclaimed class | 17 classes across the two modules, all named | `::test_every_acceptance_class_is_named_by_a_row` |
| 3 | A claimed test that fails leaves its row unqualified | process fails, row and node named | exactly that | session-end gate, negative control §6 |
| 4 | A claimed skip is a gap, and fails a strict run | `UNVERIFIED`, exit 1 under the flag | exactly that | `--fail-on-skips`, §5–6 |
| 5 | Deleting a row or renaming an acceptance test breaks CI | red | red, both controls | §6 |
| 6 | Tests that back no claim stay visible | reported, not failed | 334 of 976 tests, 30 of 47 modules | `::test_unclaimed_tests_are_reported` |
| 7 | One fixture per schema 1–6, exact upgrade | version, migration, preserved facts, exact key set | all six, 18 rows | `tests/test_schema_compat.py` |
| 8 | Absent facts are `null`, never `[]`, never `false` | `is None` for every unrecordable section | exactly that for 1–6 | `::test_absent_facts_are_null_for_every_upgrade` |
| 9 | No upgrade invents a field | exact top-level key set per version | exactly that | `::test_no_upgrade_invents_a_field` |
| 10 | A v1 document keeps its historical display and records unknown coverage | finding, legacy grade, `UNKNOWN` coverage, renders | exactly that | `::test_schema_1_keeps_the_historical_grade_and_records_unknown_coverage` |
| 11 | A skip fails a qualified job without log grepping | exit 1, node + reason | exactly that | `tests/conftest.py::pytest_sessionfinish`, three CI jobs |
| 12 | Schema rows pass on 3.10/3.12/3.14 | green in `python-gate` | see the CI run recorded in §8 | `.github/workflows/ci.yml` |
| 13 | No settled contract moved | schema 6, profile 5.0, exit table unchanged | no source file outside `report_document._upgrade_v1` changed | `git diff --stat` |

---

## 8. Evidence

| Item | Value |
| --- | --- |
| Interpreter / platform | CPython 3.12.14, macOS arm64 (colima vz, 2 CPU / 4 GB) |
| Version / schema / profile | **2.5.1** / 6 / 5.0 |
| Qualified local suite (corpus + both worker images) | **976 passed, 0 skipped, 87.15 %** — 2.5.0 baseline 955 / 0 / 87.04 % |
| Unqualified local suite (no corpus, no container runtime) | **950 passed, 26 skipped, 86.86 %** — 2.5.0 same-method baseline 929 / 26 / 86.75 % |
| New tests | 21: 18 schema-compatibility rows, 3 claim rows |
| Lint / types / format | `ruff check` clean; `mypy src/` no issues; `ruff format --check` clean, run last |
| Worker images | runtime `ihs-squashfs-worker:4.5.1` id `91b0ebd48c76`, verification `4.5.1-verify` id `0abefb6fc75d` — **observed, not reproducible**, unchanged from 2.5.0 |
| Corpus | `8b5aa826…ff02`, unchanged; manifest `e5951c23…fbff`; supplier SBOM `50ca09d7…a068` |
| Wheel | `iot_hardware_scanner-2.5.1-py3-none-any.whl`, sha256 `4f7fa23e1141cfe251894358b8b557de8f268fe8800666f285c6cb4a6f185add`; two consecutive local builds are byte-identical |

### 8.1 Installed wheel and CI

README text is embedded in the wheel METADATA, so the documentation above was
finished before the build. The wheel was installed into a clean CPython 3.12.14
venv outside the checkout (`[sbom]` extra plus `pytest` and `hypothesis`) and the
acceptance battery ran with `IHS_INSTALLED_CLI`, the reference corpus and both
worker images:

| Item | Value |
| --- | --- |
| Installed-wheel acceptance | **112 passed, 0 skipped** — `test_installed_cli`, `test_installed_image_cli`, the 45 2E hostile/property/isolation rows, plus the 21 new claim/schema rows, with `--fail-on-skips` (2.5.0 wheel mode: 91) |
| CI | recorded below once the run finishes: see §8.2 |

### 8.2 CI run

Filled in after the push.

---

## 9. Public behaviour changed (2.5.1)

* A replayed **v1** document, written as JSON, now carries the explicit `null`
  sections every other upgrade path already produced (`image_map`, `extraction`,
  `input_binding`, `elf`, `opkg`, `tree`, `ruleset`, `advisory`,
  `component_bases`). No fact changes, no renderer output changes, no schema
  version changes.
* Package version 2.5.0 → **2.5.1**. No format, input kind, profile, required
  stage, flag, report field, document type or exit-code row changed. No
  migration document is needed: schema 6 and profile 5.0 are unchanged.
* CI behaviour: the hostile-input, bounded-resource and qualified-extractor jobs
  now fail on any skip through pytest itself, and the claim/schema modules run
  in the qualified job. This enforces what those jobs already claimed.
* New test-only modules (`tests/claims.py`, `tests/run_recorder.py`) ship in the
  source tree, not in the wheel.

---

## 10. Remaining limitations, stated plainly

* **A deleted row whose evidence another row also carries is not detected.**
  The enforced invariant is "no acceptance class loses its last claim"; a
  duplicate claim can be removed silently. Detecting that would require a
  machine-readable capability-to-claim mapping, which does not exist.
* **The schema fixtures are hand-written shapes**, reconstructed from the
  migration records, not documents emitted by the 1.x/2.0–2.3 wheels. The
  upgrade code is what is tested; the historical writers are not installed here.
* **Historical milestone records are not checked.** They are records, not live
  claims; renaming a test does not edit them.
* **334 of 976 tests back no claim.** That is reported on every run, not
  enforced. Growing the claim surface is deliberate work, not a side effect.
* **No JSON Schema for report schema 6 was published.** The queue made it
  optional "only if a consumer needs it"; none does today, and a second
  hand-maintained schema would be one more claim surface to drift. The
  compatibility fixtures are the executable contract instead.
* `pytest-benchmark` is still a declared, unused dependency: that is P2.
* No mutation testing. A surviving mutant in `decide_exit` or `bounded_reader`
  would still mean a test is theatre.

---

## 11. Queue after P1

1. **P1 — executable claims.** Done (this slice): 2.5.1, locally qualified.
2. **P2 — performance under contract.** Approved for the next session: four
   `pytest-benchmark` cases on generated inputs (cold ~100 MiB image/tree, warm
   with `--cache-dir`, ~1 MiB DTB, 2 GiB windowed entropy), a baseline JSON as a
   CI artifact with a +25 % wall / +15 % RSS envelope, the recorded decision
   **not** to cache extraction, and the numbers published with the machine and
   fixture sizes.
3. **P3 — capability, customer-gated.** 3E RAUC, then 3A partitioned images, then
   3C Intel HEX → S-record → UF2, then raw NAND (blocked: no supplied artifacts).
   None may start without the owner naming a paying customer or a validated
   revenue path for that format.
