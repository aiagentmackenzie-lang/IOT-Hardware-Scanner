# Slice 2E — hostile input is incomplete work, never a traceback

**Not a new milestone.** The plan's delivery table ends at D and stays closed.
This is a hardening slice taken after the lead-engineer review; it adds **no
format, no schema field and no public capability**. Version **2.5.0**, report
schema **6** and profile version **5.0** are unchanged.

Starting point: `main` at `7d7a16c`, version 2.4.0.

---

## 1. Why this slice, and why not a format

The review found three gaps; this slice closes the first and largest.

1. **The parsers were not adversarially tested.** The extraction worker is
   sandboxed (`--network none`, `--read-only`, `cap-drop ALL`,
   `no-new-privileges`, tmpfs, pid/memory/cpu limits). The parsers are not: the
   gzip/SquashFS header reader, the FDT/FIT parser, the opkg reader, the tar
   collector and the saved-document loaders all consume attacker-controlled
   bytes **in-process**. Before this slice there was no fuzzing, no property
   test and no committed adversarial corpus — only fixtures for cases someone
   had thought of.
2. The public claim surface is hand-maintained and can drift from the tests.
3. Performance has a ceiling but no baseline.

The decision gate was applied: no customer evidence existed for 3E (RAUC), 3A
(partitioned images), 3C (MCU) or NAND, so no format slice was started. 2E is
not a new project: it hardens work that is already qualified and claimed.

---

## 2. What changed

| Layer | File | Change |
| --- | --- | --- |
| Stage isolation | `orchestrator.py` | `_guarded()` wraps every phase that reads untrusted bytes. An unexpected exception records the phase's stages `FAILED` with `"<label> hit an unexpected error: <Type>: <message>"`, keeps collected findings, and returns; `ScannerError` is re-raised unchanged so a documented exit code is never flattened. The traceback goes to `logger.exception`, never to the terminal or the JSON. |
| Document validation | `scanner/report_document.py` | `_validate_document_shape()` checks the containers the renderers walk (`findings`/`controls`/`stages`/`components` lists of objects; `artifact`/`assessment`/`boot`/`cache`/… objects or null) and rejects a present-but-non-integer `schema_version`. An unversioned document is read as v1 **only** if it has the historical v1 shape (`firmware`/`scan_id` plus object sections); anything else is invalid input. |
| CLI backstops | `cli.py` | `scan`, `report`, `compare`, `sbom` convert a defect outside every stage into exit **6** with one line. `report` now reads a saved document through `open_bounded` (64 MiB budget) instead of `Path.read_text()`, and treats `RecursionError` from deeply nested JSON as invalid input. |
| Comparison reader | `scanner/comparison.py` | `RecursionError` is a documented read failure for scan documents and CycloneDX declarations. |
| Tests | `tests/hostile_fixtures.py`, `tests/test_hostile_inputs.py`, `tests/test_parser_properties.py`, `tests/test_stage_isolation.py` | 45 new cases: 14 hostile artifacts through the installed CLI, 11 hostile documents, 9 hypothesis properties, 4 isolation/backstop rows, plus the tar-member and opkg-budget rows. |
| CI | `.github/workflows/ci.yml` | `installed-wheel-no-backend` installs `hypothesis` and runs the hostile + property + isolation rows against the **installed wheel**, failing the job on any skip. |

Deliberate non-changes: no second extraction path, no new runtime helper, no
cache change, no rule added to `CRITICAL_RULE_EVIDENCE`, no exit-code table row
changed.

---

## 3. The guarantee, in two layers

1. **Inside a stage.** A parser failure is *incomplete analysis*: the stage is
   `FAILED` with a reason, the assessment is `INCOMPLETE`, the report is still
   delivered, and the process exits **4**. Findings collected before the failure
   survive (pinned by a test: a critical credential observation still exits 1
   when an unrelated stage fails).
2. **Outside every stage.** A defect in the pipeline driver or a renderer is an
   **internal error**: exit **6**, one line, no report claimed. Both layers are
   non-zero, so automation cannot mistake either for success.

A `ScannerError` is neither: it carries its documented code (3/4/5) and is
re-raised untouched.

Document input has its own rule: a saved document that is not a readable report
is **invalid input (3)** and is rejected before any renderer indexes into it.
`compare` and `sbom` reach the same validator through `load_scan`.

---

## 4. Fixtures — one lie each

| Fixture | The lie | Expected |
| --- | --- | --- |
| `gzip_truncated_header` | 3 bytes of a gzip member | extraction `FAILED`, exit 4 |
| `gzip_corrupt_body` | valid header, undecodable deflate | extraction `FAILED`, exit 4 |
| `gzip_isize_lie` | trailer declares a different decoded size | extraction `FAILED`, exit 4 |
| `squashfs_huge_extent` | ~4 GiB used in a 200-byte file | extraction `FAILED`, exit 4 |
| `squashfs_future_version` | v5 superblock | extraction `FAILED`, exit 4 |
| `squashfs_zero_block_size` | block size 0 | extraction `FAILED`, exit 4 |
| `squashfs_magic_only` | magic, no superblock | extraction `FAILED`, exit 4 |
| `fdt_totalsize_lie` | totalsize past EOF | boot `FAILED`, exit 4 |
| `fdt_struct_offset_lie` | structure block past totalsize | boot `FAILED`, exit 4 |
| `fdt_header_only` | 24 bytes of a 40-byte header | boot `FAILED`, exit 4 |
| `fdt_deep_nesting` | 40 nested nodes (bound 32) | boot `FAILED`, exit 4 |
| `fit_out_of_bounds` | payload range beyond the artifact | boot `PARTIAL`, exit 4 |
| `fit_truncated` | valid FIT cut in half | boot `FAILED`, exit 4 |
| `opkg_oversized` | database over the parse budget | `opkg_inventory` `FAILED`, exit 4 |
| `opkg_binary_garbage` | NULs and invalid UTF-8 around one stanza | documented completion, no crash |
| `hostile_documents()` (11 cases) | wrong section types, non-integer version, unversioned non-v1, deeply nested JSON | `report`/`compare`/`sbom` exit 3 |
| `tar_with_member("../escape"|"/etc/passwd")` | worker returns a path outside the tree | `ExtractionError(CORRUPT)`, nothing created |

The property tests assert the invariant across arbitrary bytes rather than
enumerating cases: container headers raise only `ImageMapError`, the boot parser
only `FitDtbError`, the opkg parser is total, every bounded-reader window is
inside the artifact, the document loader raises only `ValueError`, and the
member-name check is total. Hypothesis is configured with `derandomize=True`, so
a CI failure is reproducible.

---

## 5. Acceptance matrix

| # | Requirement | Expected | Observed | Verification |
| --- | --- | --- | --- | --- |
| 1 | A malformed container is incomplete, not a finding | stage `FAILED`, exit 4 | exactly that, report still written | `tests/test_hostile_inputs.py::test_hostile_artifact_is_incomplete_not_a_traceback[squashfs-huge-extent]` |
| 2 | A truncated gzip is rejected, not half-read | `FAILED`, exit 4 | exactly that | `…[gzip-isize-lie]` |
| 3 | An FDT that lies about its size is rejected | `FAILED`, exit 4 | exactly that | `…[fdt-totalsize-lie]` |
| 4 | Over-deep nesting is rejected without recursion | `FAILED`, reason names the depth bound | exactly that | `…[fdt-deep-nesting]` |
| 5 | An out-of-bounds FIT payload stays `PARTIAL`, not silent | integrity `out-of-bounds`, exit 4 | exactly that | `…[fit-out-of-bounds]` |
| 6 | An oversized package database fails its stage only | `opkg_inventory` `FAILED`, exit 4 | exactly that | `::test_an_oversized_package_database_is_a_failed_stage` |
| 7 | Invalid UTF-8 in a package database is data | documented completion, no crash | exit 0, stages reported | `::test_binary_garbage_in_a_package_database_does_not_crash` |
| 8 | A saved document is validated before rendering | exit 3, one line | exactly that for all 11 shapes | `::test_a_hostile_saved_document_is_invalid_input` |
| 9 | Deep JSON nesting is a parser bound, not an internal error | exit 3 | exactly that | `::test_deeply_nested_json_is_invalid_input` |
| 10 | `compare` and `sbom` share the validator | exit 3 | exactly that | `::test_compare_and_sbom_reject_a_hostile_document` |
| 11 | The worker's tar stream cannot escape the tree | `ExtractionError(CORRUPT)` | exactly that; nothing created | `tests/test_parser_properties.py::test_the_tar_collector_rejects_an_escaping_member` |
| 12 | Arbitrary bytes never leak a non-parser exception | only the parser's own error type | holds for the gzip/SquashFS, FDT/FIT, opkg and document parsers | `tests/test_parser_properties.py` |
| 13 | An unexpected parser bug is stage `FAILED`, not a crash | `FAILED`, exit 4, reason names the type | exactly that | `tests/test_stage_isolation.py::test_an_unexpected_parser_bug_becomes_incomplete_work` |
| 14 | Findings survive an unrelated stage failure | critical credential finding still exits 1 | exactly that | `::test_findings_collected_before_a_bug_survive` |
| 15 | A documented error keeps its exit code | `ScannerError` propagates | exactly that | `::test_a_documented_error_is_not_flattened` |
| 16 | A defect outside every stage is exit 6, no traceback | exit 6, one line, no report | exactly that | `::test_the_cli_backstop_is_exit_6_without_a_traceback` |
| 17 | A renderer/comparison/export defect is exit 6 | exit 6, one line | exactly that (three rows) | `::test_a_renderer_defect_is_exit_6`, `::test_a_comparison_defect_is_exit_6`, `::test_an_export_defect_is_exit_6` |
| 18 | Reading a saved document is bounded | 64 MiB budget, no `read()` of arbitrary size | `open_bounded(...).read_all_bounded(...)` | `cli.py::report` |
| 19 | Hostile input issues no network request | zero sockets | property tests do no I/O beyond a temp file; the CLI rows pass `--offline` | `tests/test_fit_dtb.py::test_boot_parsing_issues_no_request` (unchanged) |

Facts that stay **unknown**, by construction: what a parser would have found
past the bound (a rejected artifact is not analysed further), and whether a
device would accept the artifact the parser rejected.

---

## 6. Evidence

| Item | Value |
| --- | --- |
| Interpreter / platform | CPython 3.12.14, macOS 27.2.1 arm64 (colima vz, 2 CPU / 4 GB) |
| Version / schema / profile | **2.5.0** / 6 / 5.0 (only the package version moved) |
| Wheel | `iot_hardware_scanner-2.5.0-py3-none-any.whl`, sha256 `3af486a4e922010300d13365c09b98bb1e7a7ce00501e2ef6f85f4ab912b3303` — **byte-identical** from the macOS arm64 build and the Linux CI build; two consecutive local builds are also byte-identical |
| Installed-wheel acceptance (corpus + both worker images) | **91 passed, 0 skipped** (`test_installed_cli.py`, `test_installed_image_cli.py`, plus the 45 new rows) |
| Qualified local suite | **955 passed, 0 skipped, 87.04 %** (2.4 baseline: 910 passed, 0 skipped, 86.88 %) |
| Unqualified local suite (no corpus env, worker absent) | 929 passed, 26 skipped, 86.75 % (2.4 local baseline measured the same way: 881 passed, 29 skipped, 86.59 %) |
| Lint / types / format | `ruff check` clean, `mypy src/` no issues in 40 files, `ruff format --check` clean (run last) |
| Worker images (local arm64) | runtime `ihs-squashfs-worker:4.5.1` id `91b0ebd48c76`, verification `4.5.1-verify` id `0abefb6fc75d` — **observed, not reproducible** |
| CI | run **`44911766646`** on `main` (`9d4f3dc`): **8/8 jobs green**. `python-gate` **926 passed, 29 skipped** on 3.10, 3.12 and 3.14 (the reference-image and container rows the qualified job runs); `installed-wheel-no-backend` **45 hostile/property/isolation rows, 0 skipped** plus its 22 acceptance rows; `linux-extractor` **200 passed, 0 skipped**; `bounded-resources` 61 passed, 0 skipped; `report-contract` 88 passed, 1 skipped. The CI wheel digest equals the local one, so 2.5.0 is byte-identical macOS↔Linux |
| Corpus | `8b5aa826…ff02`, unchanged |

---

## 7. Public behaviour changed (2.5.0)

* A saved document that is not a report now exits **3**. Previously an
  unversioned or wrongly-shaped object could be relabelled "legacy" and render
  with exit 0.
* `report` reads a saved document through the bounded reader (64 MiB budget);
  an oversized document exits 3.
* A defect outside every stage exits **6** with one line instead of a Python
  traceback.
* A parser bug inside a stage now leaves the stage `FAILED` and exits **4**
  instead of escaping.
* **No schema change, no profile change, no new flag, no exit-table row
  change.** No migration document is needed.
* New test dependency: `hypothesis` (dev extra only; not a runtime dependency).

---

## 8. Remaining limitations, stated plainly

* Hypothesis is **not** coverage-guided fuzzing. It explores structure, not
  input-space coverage; an `atheris`/libFuzzer target is still worth adding as a
  nightly job.
* The tar-member validation is exercised by calling `_collect_tar` directly with
  a synthetic stream; the full worker path is covered by the existing extraction
  rows, not by a hostile worker image.
* Document validation is **shallow by design**: containers and element types,
  not every field. A hostile document that passes validation and breaks a
  renderer is reported as an internal error (6), not invalid input (3).
* No mutation testing yet. A surviving mutant in `decide_exit` or
  `bounded_reader` would mean a test is theatre; that is the next quality gate.
* The claim surface is still hand-maintained: this slice did not add the
  support-matrix/test-node check.
* Performance has a ceiling but no baseline; `pytest-benchmark` remains a
  declared, unused dependency.

---

## 9. Queue

1. **2E — hostile input.** Done (this slice): 2.5.0, locally qualified.
2. **P1 — make claims executable.** Support-matrix rows checked against test
   node ids, a schema-compat fixture per version 1–6, and `--fail-on-skips`
   replacing the log greps.
3. **P2 — performance under contract.** Four benchmarks on generated inputs, a
   +25 % envelope, and an explicit decision *not* to cache extraction.
4. **P3 — capability, customer-gated.** 3E RAUC (needs a named OTA/update-review
   revenue path), then 3A partitioned images (shares the multi-root
   qualification), then 3C Intel HEX → S-record → UF2, then raw NAND (blocked:
   no supplied artifacts).
