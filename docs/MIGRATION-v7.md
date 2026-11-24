# Migration to report schema 7 — 2.7.0

Schema 7 adds two facts the document was missing: **how an artifact's type label
was produced**, and **what the host that ran the scan could actually use**. No
section was renamed and no fact changed type. A schema-6 document still reads.

This is a *corrective* release. The plan's first rule is that every observation
is tied to an input digest and a locator; the same rule applies to the scanner's
own claims about itself.

---

## 1. What was wrong

| Symptom on 2.6.0 | Why it mattered |
| --- | --- |
| `artifact.file_type` was a bare string | `"ELF 32-bit LSB executable, ARM"` from libmagic, the same words from a `.elf` suffix, and an FDT read from its own magic byte were indistinguishable in the report. Two scans of the same bytes on two hosts could disagree with no recorded cause. |
| `tool` carried `name` and `version` only | Whether libmagic loaded, which `pyelftools` and `yara-python` produced the records, and whether a container runtime was even on `PATH` were invisible to a reader of the JSON. The support matrix names those tools; the document did not. |
| The fallback log blamed the wrong package | With `python-magic` installed and the shared library missing, ingest logged "python-magic not installed". The scan degraded to magic-byte and extension detection and said nothing true about why. |

## 2. What schema 7 records

### `artifact.file_type_source`

One of four values, never a guess:

| Value | Meaning |
| --- | --- |
| `magic-bytes` | The file's own magic was read before any library was consulted (an FDT/FIT today). |
| `libmagic` | The libmagic binding answered for this file. |
| `extension` | Neither of the above produced an answer; the label comes from the filename suffix. |
| `directory` | The artifact is a staged root tree, identified by its kind, not by bytes. |

A type label with source `extension` is a weaker claim than the identical words
with source `libmagic`, and the report now says which one it is making. This is
the same distinction the plan already draws between a recorded package version
and a banner-derived candidate.

### `tool.capabilities`

```json
"tool": {
  "name": "iot-hardware-scanner",
  "version": "2.7.0",
  "capabilities": {
    "libmagic": {"available": false, "version": null,
                 "detail": "failed to find libmagic.  Check your installation"},
    "pyelftools": {"available": true, "version": "0.33", "detail": null},
    "yara-python": {"available": true, "version": "4.5.4", "detail": null},
    "container_runtime_on_path": ["podman", "docker"]
  }
}
```

Three deliberate limits on that claim:

* `libmagic.available` is proved by **calling** the library, not by importing the
  binding. `detail` keeps the real reason, so "the package is missing" and "the
  shared library is missing" stay distinguishable.
* `container_runtime_on_path` is presence on `PATH` and nothing more. It does
  **not** say the daemon is reachable or the worker image exists. Reachability,
  the isolation mode and the image actually used are recorded in `extraction`,
  which is where a scan states what it did rather than what it could have done.
* An unavailable capability is a recorded fact, not a failed scan. A tree scan
  on a host with no container runtime is still `COMPLETE`.

## 3. Reading a schema-6 document

`load_document` accepts 1 through 7. A v6 document keeps every recorded fact and
gains two explicit absences:

```json
"migration": {"from": 6, "to": 7, "note": "…"},
"artifact": {…, "file_type_source": null},
"tool": {…, "capabilities": null}
```

`null` means **"that version never recorded it"**. It is not `"extension"`, not
an empty runtime list, and not `{"available": false}`. The Markdown and terminal
renderers print the provenance only when it exists, so an upgraded document
renders exactly as it did before.

## 4. One defect this change exposed

A schema-3 `image_map` node without a `length` crashed the **terminal** renderer
(`TypeError: unsupported format string passed to NoneType.__format__`) — a
traceback from a saved document, which the plan forbids. The validator checks
container shapes, not every numeric field, so the renderer assumed one. It now
prints `length unrecorded` and keeps going. A partial document renders as a
partial document.

## 5. Gates recorded with this change

| Gate | Command | Result |
| --- | --- | --- |
| Lint / format | `ruff check src/ tests/ benchmarks/`, `ruff format --check` | clean |
| Types | `mypy src/` | clean, 40 source files |
| Tests | `pytest` (local, macOS arm64, CPython 3.12.14) | **1014 collected, 988 passed, 0 failed, 26 skipped** — the skips are the container, verify-image and reference-image rows, which the qualified CI job runs |
| Schema reader | `pytest tests/test_schema_compat.py` | one fixture per version 1–7, exact upgrade asserted |

CI evidence for this release is recorded **after** the push that follows this
change; it is not claimed in this document. The qualified job that decides it is
`linux-extractor` (zero skips), as in 2.2.0–2.6.0.

## 6. What did not change

* Report **schema 7** is the only version bump. Profile semantics stay **5.0**,
  and no stage was added or removed.
* `ihs-comparison/1` and CycloneDX 1.6 are unchanged.
* No scoring, detector or control behaviour changed, with one dead exception:
  `domain_scorer.py` carried `_SCORE_SSL_ORG = -20.0` marked "stub: not
  implemented, always 0". A signal that can never fire is not coverage, so it is
  gone. TLS and registrar reputation are impossible for an offline scanner and
  were never applied.
