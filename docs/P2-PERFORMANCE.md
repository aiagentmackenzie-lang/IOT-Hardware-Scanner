# P2 — performance under contract

Status: **added to the 2.5.1 tree; no engine change, no version bump.**
No format,
schema, profile or exit path changed. This slice adds a measurement harness, a
recorded baseline and a gate; it adds no capability.

The queue (see [docs/2E-HOSTILE-INPUT.md](2E-HOSTILE-INPUT.md) §9 and
[docs/P1-CLAIM-MATRIX.md](P1-CLAIM-MATRIX.md) §11) asked for four benchmarks on
generated inputs, a baseline JSON with a **+25 % wall / +15 % RSS** envelope, the
recorded decision **not** to cache extraction, and the numbers published with
the machine and fixture sizes. That is what this document records.

Two slices ago the honest criticism of this repository was: *"performance is
measured once per release by hand, with a ceiling but no baseline, and
`pytest-benchmark` is a declared dependency used nowhere."* A ceiling without a
baseline answers "is it catastrophically broken"; it cannot answer "did this
commit make it 20 % slower". This slice closes that gap without pretending that a
laptop and a shared CI runner are the same instrument.

---

## 1. The four cases and why these four

The 5C profile measured where a scan's time actually goes on the pinned OpenWrt
corpus: per-file YARA matches **3.21 s (41 %)**, per-file text facts **3.15 s
(41 %)**, ELF **0.48 s (6 %)**, extraction **0.62 s (8 %)**, everything else
**< 2 %**. The benchmarks follow that profile rather than the shape of the code.

| Case | Measures | Why it is one of the four |
| --- | --- | --- |
| `cold-scan` | full `firmware-tree` scan of a generated 98.6 MiB root tree, no cache | the product's hot path; the number a customer feels |
| `warm-scan` | the same tree with `--cache-dir` populated by a prior run | guards the 5C cache's value: a cache that stops helping is a defect |
| `fit-parse` | one 1,068,232-byte device tree through `parse_fdt` | the 3D parser is in-process and consumes attacker bytes; its cost is on the hostile-input path |
| `entropy-2gib` | the whole 2 GiB file through the windowed reader, 16 MiB blocks | the bounded reader's memory contract, at the size the resource ceiling is stated in |

**No case needs Docker.** The tree profile does not extract, so the contract runs
on any host with the Python dependencies and never depends on a worker image.
The extraction path (8 % of the 5C profile) is deliberately *not* benchmarked
here: it is a subprocess in a pinned container, its cost is the worker's, and
measuring it in CI would mean building the worker image in the performance job.
That omission is stated rather than hidden.

The image path is still measured where it matters: the `bounded-resources` CI job
runs the 2 GiB sparse measurement through the CLI and asserts its ceiling.

## 2. Machine and fixtures

| | |
| --- | --- |
| Machine | Apple M4 Pro, 48 GiB, macOS 27.2.1, arm64 |
| Python | CPython 3.12.14 |
| yara-python | 4.5.4 (rule set `2ca7a94b…`, unchanged) |
| Engine | 2.5.1 (recorded, not compared: see §4.1) |

Fixtures are generated deterministically and are never committed. A benchmark
that downloads a corpus cannot run in CI, and a checked-in fixture becomes a
different measurement the moment it is edited.

| Fixture | Size | Identity |
| --- | --- | --- |
| Root tree | **357 files, 103,360,793 bytes (98.6 MiB)** | plan digest `56504e3d7ad111313e0e7ded698871762c946af0d11a2df81dde084309a23392` |
| Device tree | **1,068,232 bytes**, 3,001 nodes | sha256 `d2786248d34b1ee19419c3853d7e7bf4735b6d53672159063316b8a90391c57b` |
| Entropy input | **2,147,483,648 bytes** (sparse) | size is the identity; content is zeros |

The tree is 200 valid ELFs (the two reviewed shapes from `tests/elf_fixtures.py`,
alternating), a 400-stanza `/usr/lib/opkg/status`, `/etc/passwd` + `/etc/shadow`
(40 service accounts), 70 config/script files, 60 JS/HTML assets, and 25 × 4 MiB
blobs with URLs, IPs and credential-shaped strings embedded every 4 KiB. The
blob count is derived from the 100 MiB target, so the declared size and the built
size cannot drift apart; the achieved size is 98.6 MiB and is printed by the
harness rather than assumed.

The device tree is built with 3,000 nodes and a fat `description` property, not
with an artificial node count: the parser caps a device tree at 4,096 nodes and
16,384 properties, and a fixture that trips the bound would measure the rejection
path, not the parse.

## 3. The numbers

Recorded 2026-11-22 on the machine above, `benchmarks/baseline.json`. Wall is
the **minimum** of the rounds (the definition the contract uses); mean and
standard deviation are from `pytest-benchmark`. RSS is the peak of a fresh child
process per case.

| Case | Rounds | Wall min | Wall mean ± sd | Peak RSS |
| --- | --- | --- | --- | --- |
| `cold-scan` | 3 | **17.287 s** | 17.339 s ± 0.214 s | **470.8 MiB** |
| `warm-scan` | 3 | **1.813 s** | 1.817 s ± 0.013 s | **480.9 MiB** |
| `fit-parse` | 10 | **11.057 ms** | 12.093 ms ± 1.736 ms | **45.1 MiB** |
| `entropy-2gib` | 2 | **31.101 s** | 31.112 s ± 0.012 s | **76.2 MiB** |

Derived, and reported by the contract on every run:

* the cache saves **90 %** of the wall time on this tree (17.287 s → 1.813 s),
  consistent with the 5C finding that per-file rule matches and text facts are
  the dominant repeated work;
* the 2 GiB windowed pass peaks at **76.2 MiB**, i.e. it holds roughly five
  16 MiB windows and never the file.

### 3.1 Two observations a lead should not paper over

1. **Peak RSS is ~4.8× the input on the tree case**, and the cache does not
   reduce it (470.8 → 480.9 MiB). Traced after the baseline was recorded; see
   §3.2 for the cause and for a second defect it exposed. This is not fixed by
   this slice, and it is the first thing to look at if a customer scans a 2 GiB
   rootfs.
2. **Cold time grew 25 % (13.85 s → 17.29 s) when the fixture grew 19 % in bytes**
   (86.6 → 103.4 MB). The added bytes were high-entropy 4 MiB blobs, which is the
   most expensive per-byte content in the mix. The contract pins the absolute
   number; the superlinearity itself is a property of the content mix and is
   recorded here so nobody reads "25 % more bytes, 25 % more time" into it.

### 3.2 Where the memory goes: a measured diagnosis, and a defect it exposed

Found by sampling RSS and the main-thread stack during a scan, then isolating the
operation. The peak is **not** in YARA (52 MiB after compiling the rule set and
56 MiB after scanning all 25 blobs), and not in the Python heap the scan retains
(`tracemalloc` peak 99.9 MiB, 6.9 MiB live at the end). It is one control.

| Experiment | Peak RSS |
| --- | --- |
| cold scan as shipped | **470 MiB** |
| the same scan with control 5's file read decoded as `latin-1` instead of `utf-8` | **97 MiB** |
| the same scan with control 5's file read removed | **89 MiB** |

**Mechanism.** Control 5 (`_eval_update`, "secure firmware update mechanism")
selects update-related files **by path keyword** (`update`, `upgrade`,
`firmware`, `ota`, `sysupgrade`), so a directory named `.../firmware/` selects 25
binary blobs. For each one it calls `_read_text_bounded`, which decodes up to
`max_scan_file_size_mb` (**50 MiB** by default) as **UTF-8 with
`errors="replace"`**. Arbitrary bytes produce code points above U+FFFF, so the
result is a 4-byte-per-character string: a 50 MiB file can become a ~200 MiB
string, and `.lower()` makes a second one.

Isolated, the discarded strings are not returned on this interpreter (CPython
3.12.14, macOS arm64): decoding a 4 MiB blob to a UCS-4 string and dropping it
grows RSS by **15.3 MiB per iteration, linearly, after `gc.collect()`**. Controls
that rule out the obvious explanations:

| Variant | RSS over 20 iterations |
| --- | --- |
| `b"\xff" * 4 MiB` → UCS-2 string (2 bytes/char) | flat at 48 MiB |
| `b"a" * 4 MiB` → UCS-1 string | flat at 44 MiB |
| `b"\xf0\x9f\x98\x80" * 1 MiB` → UCS-4, 4 MiB string | **+4 MiB per iteration** |
| the real 4 MiB blob → UCS-4, 15.2 MiB string | **+15.3 MiB per iteration** |
| allocating the same 16 MiB string directly (`"\U0001F600" * n`) | flat at 34 MiB |
| as above with `PYTHONMALLOC=malloc` | same growth (not pymalloc) |
| the same decode with `errors="ignore"` | same growth (not the error handler) |
| a 1 MiB UCS-4 input, 40 iterations | flat at 21 MiB |

So the growth is proportional to the decoded string and appears above a size
threshold; it is not the error handler, not pymalloc, and not plain allocation.
**The scanner's exposure does not depend on which of those is "the bug": the
read budget bounds the bytes, not the decoded form, and nothing bounds the total
across a corpus.** A hostile rootfs of 50 MiB blobs named `firmware-*` is a
memory-amplification denial of service, and 2.5.0's hostile-input slice did not
catch it because it measured crashes and time, not resident cost.

**The second defect, and the worse one.** The same control reports
`PERFORMED / REVIEW` on this fixture with the evidence *"24 update-related
file(s); a verification step is present in tree/usr/share/firmware/blob-00.bin,
…"*. The "verification step" was found by searching **random binary bytes** for
`verify`, `signature`, `gpg`, `sha256sum`, `checksum` or `ed25519`; seven of the
25 blobs contain one of those strings by chance. A binary blob is not an update
script, and a coincidental string is not evidence that the device verifies
anything. That is the same failure this project's control rules exist to prevent
("no PASS without positive evidence"), reached through a file-selection rule
rather than through a scoring rule.

**Not fixed here.** Both live in `risk_scorer._eval_update` (selection by path
keyword, unbounded decoded form, evidence from any file) and the second is a
correctness claim, not just a cost. The fix is one slice: select update files by
what they are (text, size-capped, not a binary), stream the keyword test over
bounded lines instead of materialising the file, cap the decoded form, and make
the evidence name a script. It will change the recorded baseline (for the
better), so `benchmarks/baseline.json` must be re-recorded with it — which is the
contract working as intended, not a reason to avoid the change.

A third, smaller observation from the same walk: `c2_detector._text_facts_from_content`
runs `lowered.count(domain)` **per unique domain** over the whole 4 MiB content
(1,028 domains × 4 MiB ≈ 4.3 GB of scanning per file, 0.16 s), so its cost is
`domains × bytes` with both factors attacker-controlled. It is not the dominant
cost at this fixture size, but it is the same shape of unbounded work.

## 4. The contract: two rules with different scopes

`benchmarks/perf_contract.py` decides two things, and keeps them apart.

### 4.1 The envelope is machine-relative

The baseline records a fingerprint: `system`, `machine`, `python`, `cpu_count`,
`yara`, `engine` and the fixture plan digest. A wall-time budget recorded on a Mac
mini is not evidence about a shared GitHub runner, and a gate that pretends
otherwise becomes a flaky test that someone eventually deletes.

* Fingerprint matches → wall may grow by **+25 %**, peak RSS by **+15 %**; a
  breach is a failure naming the case and both numbers.
* The engine version is recorded but **not** part of the fingerprint. Otherwise
  every release would expire its own baseline and the gate would quietly become a
  recorder exactly when a regression is most likely; comparing this release's
  timing against the last release's is the point.
* Fingerprint differs → the run is **recorded, not judged**. Exit 0, the output
  says `applicable: false` / `NOT APPLICABLE`, and it never prints a pass. With
  `--require-applicable` the command fails instead (the release-gate posture:
  "this measurement does not apply here" is then an error, not a shrug).

Both numbers come from a harness that exists for them: wall is the minimum of
the `pytest-benchmark` rounds (its statistics are not re-implemented here), peak
RSS is the child-process `ru_maxrss` from `benchmarks/measure.py` (one process per
case, because RSS is not resettable and a shared process would charge the
largest case to every case after it).

### 4.2 The invariants are machine-independent

Three claims hold on any host and are enforced on every run, baseline or not:

| Invariant | Why it is not machine-relative |
| --- | --- |
| `warm-scan` is faster than `cold-scan` | a cache that does not help is a defect at any clock speed |
| `entropy-2gib` peak RSS < 256 MiB | a windowed pass cannot legitimately need a flat 2 GiB allocation; the window is 16 MiB |
| every case runs and returns a semantic result | a benchmark that measures a broken path quickly is worse than no benchmark |

Each benchmark asserts its own semantics (files scanned, ELFs parsed, package
records, findings non-zero, assessment `COMPLETE`, cache hits > 0, FDT nodes and
compatible strings, blocks > 100 and `sampled == false`). If the scan stops
producing findings, the timing is not allowed to stand as a pass.

### 4.3 Negative controls, observed

Run against the recorded baseline, then restored:

| Control | Observed |
| --- | --- |
| `cold-scan` wall reported **+30 %** | `FAIL cold-scan: wall 22.473 s vs 17.287 s baseline (+30.0 %, envelope +25 %)`, exit **1** |
| Fingerprint machine/system changed to `x86_64`/`Linux` | `NOT APPLICABLE ... differs in: system, machine`, `RESULT recorded only`, exit **0**, no envelope printed |
| the same with `--require-applicable` | exit **1** |
| `warm-scan` wall set equal to `cold-scan` (cache stops helping) | `FAIL ... the cache is not earning its place` |
| `entropy-2gib` RSS above the windowed ceiling | `FAIL ... over the 256 MiB windowed ceiling` |
| a case that did not run | `FAIL MISSING <case>: the case did not run` |

The logic, the thresholds, the not-applicable path and the exit codes have their
own tests in the qualified suite — `tests/test_perf_contract.py`, 13 cases, no
timing and no fixtures — because a gate without tests is a hope. That is the
same lesson P1 recorded: a claim that is not executable drifts.

## 5. The recorded decision: extraction is **not** cached

5C's cache stores per-file YARA match sets and per-file text facts, keyed by
content digest plus the rule-set or extractor identity. It deliberately does not
cache extraction, and that decision stands. Reasons, in order:

1. **The number does not ask for it.** Extraction is **0.62 s of 7.73 s (8 %)**
   on the pinned corpus. A cache that removes at most 8 % is not worth a new
   artefact class.
2. **The key would be new and worse.** Caching an extracted tree needs the image
   bytes, the container offset, the worker image identity and the `unsquashfs`
   version — a second identity scheme beside the content digest, with its own
   invalidation rules. D28–D33's lesson in the sibling repository applies: a
   cache keyed by something other than the bytes it returns is how "the same
   output" becomes a claim nobody can check.
3. **The failure modes are worse than the win.** A corrupt or partial extraction
   entry would be indistinguishable from a clean one at the stage boundary, and
   the worker's own errors are part of the evidence. 5C already discards corrupt
   entries; an extracted tree is orders of magnitude more to validate.
4. **No measured demand.** Nothing in the vault or the workspace names a customer
   scanning repeatedly at the extraction stage. If that appears, the entry
   condition is the same as 5C's: measure per-phase time first, then implement.

## 6. CI

New job `performance-contract` (ubuntu-latest, CPython 3.12):

```bash
pytest benchmarks/ --benchmark-json=bench.json
python benchmarks/measure.py --out measure.json
python benchmarks/perf_contract.py --measure measure.json --bench bench.json
```

The runner's fingerprint does not match the recorded baseline, so CI **records
and uploads** `bench.json` and `measure.json` as artifacts and enforces only the
machine-independent invariants. The envelope is enforced on the machine the
baseline was recorded on — by running the same three commands there, in the
release checklist.

This is deliberate. A wall-time gate on a shared runner is noise with a build
badge; a recorded artifact is evidence a human can compare across releases.

## 7. Not done, and why

* **No wall-time gate on the CI runner.** See above; the fingerprint rule is the
  honest alternative. The cost is that a macOS-only regression is caught at the
  next local qualification, not on the next push.
* **No extraction or Docker benchmark.** Stated in §1.
* **No per-phase profile in the repository.** The 5C profiler stays outside the
  product on purpose (it is a profiler, not product code). If per-phase timing is
  wanted in CI, it should be a separate, explicitly-labelled measurement, not a
  hidden phase in the four cases.
* **No distribution claim.** A minimum over 2–3 rounds with the machine named is
  not a confidence interval, and the document does not present it as one.
* **One machine, one Python.** 3.10 and 3.14 are tested for correctness, not
  benchmarked. A baseline is per machine class; recording another one is a
  command, not a redesign.
* **No benchmark of the 64 MiB artifact cap or the hostile-input corpus.** Those
  are correctness bounds with their own tests; the 2 GiB case covers the reader's
  memory behaviour.
* **The defect in §3.2 is diagnosed, not fixed.** This slice produced the
  instrument and the baseline; changing a control's evidence rule is its own
  slice with its own fixtures, and it must re-record the baseline.
* **The reported wall time excludes the report renderers.** The case is
  `Orchestrator.run`, the product's analysis path; JSON/HTML rendering is
  exercised by its own contract job.

## 8. Reproduce

```bash
# fixtures are generated once under ~/.cache/ihs-perf (override: IHS_PERF_WORKDIR)
pytest benchmarks/ --benchmark-json=bench.json        # wall time, statistics
python benchmarks/measure.py --out measure.json       # peak RSS, one child per case
python benchmarks/perf_contract.py --measure measure.json --bench bench.json

# record a baseline on a new machine class (clean tree, quiet machine)
python benchmarks/record_baseline.py --bench bench.json --measure measure.json
```

`pytest benchmarks/` is never part of a bare `pytest`: `pyproject.toml` sets
`testpaths = ["tests"]`.

---

## 9. Summary of the slice

| | |
| --- | --- |
| Added | `benchmarks/` (cases, harness, baseline, contract, baseline recorder), `tests/test_perf_contract.py`, CI job `performance-contract` |
| Changed | nothing in `src/`; no schema, profile, format, exit code or report field |
| Baseline | 2026-11-22, Apple M4 Pro arm64, CPython 3.12.14 — cold **17.287 s / 470.8 MiB**, warm **1.813 s / 480.9 MiB**, DTB **11.057 ms / 45.1 MiB**, 2 GiB entropy **31.101 s / 76.2 MiB** |
| Envelope | +25 % wall, +15 % RSS, applied only on a matching fingerprint |
| Invariants | warm < cold, 2 GiB RSS < 256 MiB, every case runs and returns a semantic result |
| Decision | extraction is not cached (measured 8 %, key and failure modes worse than the win) |
