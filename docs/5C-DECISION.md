# 5C decision — repeated deterministic work is material, so it was measured and cached

Status: **implemented in 2.4.0**, after a measurement on the pinned corpus.
The entry condition in `FIRMWARE_SCANNER_PLAN.md` is a number: *"Take 5C only
after the profile shows repeated work is a material cost."* No such profile
existed before this session. Here it is.

This is not a release milestone and it does not change the scan exit table.

---

## 1. How it was measured

Machine: macOS arm64, CPython 3.12.14, colima (vz, 2 CPU / 4 GB), worker image
`ihs-squashfs-worker:4.5.1` (`unsquashfs 4.5.1`). Corpus:
`openwrt-24.10.0-armsr-armv8-generic-squashfs-rootfs.img.gz`, sha256
`8b5aa826…ff02`, read from `/tmp/ihs-corpus` and digest-checked before use.

```bash
/usr/bin/time -l .venv/bin/python -m iot_hardware_scanner scan \
  /tmp/ihs-corpus/openwrt-24.10.0-armsr-armv8-generic-squashfs-rootfs.img.gz \
  --offline --worker docker \
  --output ~/.cache/ihs-5c/run1 --format json --out ~/.cache/ihs-5c/run1/report.json

# Per-phase wall time, measured with perf_counter around each orchestrator
# phase, plus resource.getrusage(RUSAGE_SELF/CHILDREN):
.venv/bin/python ~/.cache/ihs-5c/measure.py image <corpus> ~/.cache/ihs-5c/warm1

# Per-detector split (same corpus, same method):
.venv/bin/python ~/.cache/ihs-5c/measure-detectors.py <corpus> ~/.cache/ihs-5c/warm2
```

The measurement harness lives outside the repository on purpose: it is a
profiler, not product code.

### Full scan (no cache)

| Observation | Value |
| --- | --- |
| wall time | **7.73 s** |
| peak RSS (`/usr/bin/time -l`) | **205,750,272 bytes** |
| input on the wire | 4,451,127 bytes |
| gzip-expanded bytes | 109,051,904 |
| bytes materialised by the worker | 18,403,184 |
| entropy bytes read | 4,451,127 |
| files / directories | 1,283 / 110 |
| ELF files parsed | 209 of 209 |
| opkg records | 196 of 196 |
| child-process CPU (`getrusage`) | 0.03 s user, 0.03 s sys |

`/usr/bin/time -l` reports `0 block input operations` on this macOS host; that
counter is not usable here, so "bytes read" is reported from the scanner's own
counters above (wrapper hashed, entropy read, worker decoded, files
materialised) rather than inferred from a host counter.

### Per-phase wall time

| Phase | Seconds | Share |
| --- | --- | --- |
| C2 / indicator sweep | 3.746 | 48 % |
| credentials | 2.733 | 35 % |
| extraction | 0.623 | 8 % |
| binary intelligence (ELF) | 0.476 | 6 % |
| filesystem enumeration | 0.105 | 1 % |
| entropy | 0.093 | 1 % |
| ingest | 0.014 | <1 % |
| rule compilation | 0.005 | <1 % |
| opkg | 0.002 | <1 % |
| controls, advisory, accounts | <0.01 | <1 % |

### Per-detector split

| Call | Seconds |
| --- | --- |
| `YaraEngine.scan_file` (all destinations) | 3.206 |
| `C2Detector.detect_domains` (text extraction + email check) | 3.147 |
| `C2Detector.detect_crypto` (YARA) | 0.269 |
| `C2Detector.detect_malware_signatures` (YARA) | 0.268 |
| `C2Detector.detect_ips` (text extraction) | 0.204 |

**The pure-function share is about 83 %.** Per-file YARA match sets and per-file
text facts depend only on `(content digest, rule-set digest, engine/extractor
version, settings)`. Extraction — which no content-result cache can remove — is
8 %. This is well over the ~20 % threshold, and it is not dominated by
extraction. The number said: implement 5C.

---

## 2. What was implemented

`scanner/analysis_cache.py` plus two consumers:

| Entry kind | Stored value | Key dependencies |
| --- | --- | --- |
| `yara-file` / `yara-data` | the typed match set (rule, namespace, meta, match strings) | `ruleset_digest`, `engine_version` |
| `text-facts` | domains, IPv4 strings, email-only domains | `extractor_version`, `max_bytes` |

The contract, in the terms the plan asked for:

* **Key.** `sha256(canonical JSON{format, kind, content_sha256, dependencies})`.
  A ruleset update changes `ruleset_digest`, so its dependent entries are never
  read again. Feed-driven **scoring** is not cached at all, so a threat-intel
  update applies on the next run even on a warm cache.
* **Locations stay out.** An entry never contains a path. A hit is rebound to
  the current artifact path when it is read, so moving a file does not move a
  cached observation.
* **Atomic.** Temporary file in the destination directory, `fsync`, then
  `os.replace`. A reader never sees a partial entry. A sweep removes
  `.tmp-*` files abandoned by an interrupted writer.
* **Validated and discarded.** Format marker, kind, content digest, dependency
  echo and key digest are checked; a mismatch or corrupt JSON is deleted and
  counted as `invalid`, then treated as a miss.
* **Bounded.** Default 20,000 entries / 256 MiB, oldest evicted first; a value
  over 4 MiB is not stored. Reads are bounded; the cache performs no network
  I/O.
* **Opt-in.** `--cache-dir` / `analysis_cache_dir`. Without it, nothing is
  written and `cache` in the report is `null`.

Not cached, deliberately: extraction, the filesystem walk, ELF parsing (6 %),
entropy, opkg parsing, advisory matching, and every scoring/threshold decision.
Those either depend on bytes the run must still read or are too cheap to justify
a second identity surface.

---

## 3. Measured result (same corpus, same machine)

| Run | Wall time | Peak RSS | Entries | Hits | Misses | Writes |
| --- | --- | --- | --- | --- | --- | --- |
| cold, cache enabled, empty cache | **5.18 s** | 204,210,176 B | 1,303 | 1,929 | 1,303 | 1,303 |
| warm, same cache | **1.81 s** | **110,002,176 B** | 1,303 | 3,232 | 0 | 0 |

Warm is **2.9× faster** (65 % less wall time) and **46 % lower peak RSS**. The
cold run is also faster than the 7.73 s no-cache run because duplicate file
contents within the single run already hit the cache (1,929 hits). Extraction
still happens on both runs; the cache does not touch it.

The cache directory held 1,303 entries / 473,301 bytes.

### Equivalence

Cold and warm reports were compared after removing run-specific values only
(`scan_id`, timestamps, scratch paths, the `cache` section). Every semantic
field was identical: stages, controls, findings, components, ELF records, opkg
records, entropy, advisory state and outcome. This is pinned by
`tests/test_installed_cli.py::TestRepeatedWorkCache::test_a_warm_run_reproduces_the_cold_report`.

### Invalidation

`tests/test_installed_cli.py::TestRepeatedWorkCache::test_a_ruleset_change_invalidates_its_dependents`
adds one rule file, runs, then runs again:

* first run with the new rule set: rule-match misses > 0, the new finding is
  present, text-fact entries still hit;
* second run: 0 misses, the finding is still present, and the reports are equal.

`tests/test_analysis_cache.py` pins the key identity, corrupt-entry discard,
bounded eviction, atomic write, abandoned-temporary sweep and parallel writers.

---

## 4. What this does not claim

* No performance claim is made for any other corpus, host or rule set.
* A cache hit is an observation of the same bytes by the same parser version.
  It is not a fresh read, and the report says how many entries came from cache.
* The cache cannot make extraction, enumeration or ELF parsing cheaper, and it
  does not cache a verdict that depends on a feed, a threshold or a control.
* Physical boot enforcement, runtime behaviour and network exposure remain
  unknown; 5C changes none of them.
