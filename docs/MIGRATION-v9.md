# Report schema 8 → 9 — the extraction backend

Release 2.9.0 wrote **schema 8**. This release writes **schema 9** and adds one
field. Every 2.x document still reads.

## What changed

| Section | v8 | v9 |
| --- | --- | --- |
| `extraction.backend` | absent | `"docker"`, `"podman"`, `"in-process"`, … — the decoder that produced the tree |

`extraction` is `null` when no extraction was attempted, and that has not
changed. When it is present, `backend` now says **what did the work**.

## Why one field was worth a schema version

Until 2.10.0 every enumeration came from a worker, so
`{"state": "ok", "success": true}` plus the worker's own fields was enough to
reconstruct what happened. CPIO initramfs archives are decoded **in-process**, and
that made two very different situations produce the same document:

* an initramfs decoded by this scanner (no worker was needed), and
* a worker-backed extraction whose provenance was lost.

The document is the artifact a client keeps, and it is re-rendered from JSON by
`report` — a fact that is not in the document is gone. The stage reason already
said "in-process … no worker", but a reader should not have to parse prose to
learn which decoder produced the tree; and the terminal renderer printed
`Extraction: OK via None (None)` for the in-process case, which is a defect in the
renderer that only a recorded field can fix.

The alternative — an `omissions` note — was rejected: an omission says "something
was skipped", and this is the opposite of a skip.

## Reading a v8 document as v9

`_upgrade_v8` preserves every field and sets:

```json
"extraction": {"worker": "docker", "helper_version": "4.5.1", "backend": null}
```

`null` means **not recorded**. It does not mean "no backend ran" — a v8 document
was produced before the field existed, and the migration note says so:

```json
"migration": {
  "from": 8,
  "to": 9,
  "note": "This document was produced before the report named the extraction backend. The field is absent, which means the producer did not record it -- not that no backend ran."
}
```

If a v8 document had no `extraction` section at all, it stays `null`: there was no
extraction to describe, and inventing an object to hold one absence would be the
same mistake one level down.

## Everything else is unchanged

* **Profile version stays 6.0.** No stage was added or removed; `REQUIRED_STAGES`
  is untouched, and a CPIO scan reaches `COMPLETE` through the stages that already
  existed.
* **No detector or control changed.** The twelve named checks score exactly as they
  did, and a permission conclusion still rests only on `metadata_source: "image"`
  or `"declared"`.
* **Other document types are untouched**: `ihs-comparison/1` and CycloneDX 1.6 are
  not scan documents and carry no schema of this reader's.
* **v1 replays still gain explicit `null`s** rather than empty values, and the
  schema-compatibility corpus now runs 1 → 9 with the exact upgrade result asserted
  per version (`tests/test_schema_compat.py`).

## Evidence

`tests/test_schema_compat.py::test_schema_9_round_trips_without_a_migration_record`
reads a v9 document unchanged; `::test_no_upgrade_invents_a_field` asserts the exact
top-level key set for every source version; `::test_schema_3_keeps_its_evidence_and_gains_v4_absences`
proves a v3 extraction section gains `backend: null` and keeps its worker and helper
version verbatim.
