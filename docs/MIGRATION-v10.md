# Report schema 9 → 10 — the RAUC update bundle

Release 2.10.0 wrote **schema 9**. This release writes **schema 10** and adds one
section. Every 2.x document still reads.

## What changed

| Section | v9 | v10 |
| --- | --- | --- |
| `rauc` | absent | the bundle's declaration, its payloads and what the bytes did about each, or `null` when the scan opened no bundle |

The section is `null` for every scan that is not a RAUC bundle — a staged tree, a
bare SquashFS image, a CPIO initramfs, a partitioned disk. `null` means "no bundle
was described", not "a bundle with nothing in it".

## What the section carries

| Field | Meaning |
| --- | --- |
| `compatible` | the board string the manifest declares — recorded, never matched against a device |
| `version`, `description`, `build`, `bundle_format` | the rest of `[update]` and `[bundle]`, as declared |
| `images[]` | one entry per `[image.<slot>]` section: `slot`, `slot_class`, `slot_name`, `filename`, declared and actual size and SHA-256, `state`, `root_id`, `hooks`, `detail` |
| `images[].state` | `VERIFIED` (size **and** digest match), `MISMATCH` (the bytes are not the ones declared), `MISSING` (the bundle does not carry the file), `UNCHECKED` (no digest declared, or no digest computed) |
| `images[].root_id` | the root this payload produced, when it was decoded — always `null` for a payload that lost its association |
| `signature` | `present`, `bytes`, `verified`, `reason` |
| `running_slot` | always `"unknown"` |
| `handler` | the custom handler section, when the manifest has one — an artifact to scan, never executed |
| `diagnostics` | what the bundle said about itself, in words, including a manifest that could not be parsed |

## Why one section was worth a schema version

A bundle is the only input in this release that answers a question about a
**future** device state, and the document was carrying nothing about it. The
alternative — folding slot facts into `extraction.omissions` prose — would have
made the two most important facts (which payload a finding came from, and which
payload was *not* trusted) unqueryable, and a `compare` between two releases could
not have named the payload that changed.

`false` is never used for an unverified signature. `verified: null` plus a stated
reason separates "there is a signature and nobody checked it" from "there is a
signature and it is invalid"; only the second is a finding.

## Reading a v9 document as v10

`_upgrade_v9` preserves every field and sets:

```json
"rauc": null
```

with a migration note that says a v9 document never described a bundle — not that
its bundle had no slots:

```json
"migration": {
  "from": 9,
  "to": 10,
  "note": "This document was produced before the report described a RAUC update bundle. The rauc section is absent, not empty."
}
```

## Everything else is unchanged

* **Profile version stays 6.0.** No stage was added or removed and
  `REQUIRED_STAGES` is untouched: the bundle phase runs inside extraction, and a
  bundle payload that is decoded becomes an additional root through the same
  `root_sources` path a partition uses.
* **No detector or control changed.** A finding in a payload is qualified by the
  payload's slot-class root id (`rootfs/etc/shadow:1`), which is the same
  root-qualified locator 2.9.0 introduced for partitions.
* **Other document types are untouched**: `ihs-comparison/1` and CycloneDX 1.6 are
  not scan documents. `compare` does not yet diff two bundles — that is a separate
  identity contract and this release does not claim one.
* **The schema-compatibility corpus now runs 1 → 10**, with the exact upgrade
  result asserted per version (`tests/test_schema_compat.py`).

## Evidence

`tests/test_schema_compat.py::test_schema_10_round_trips_without_a_migration_record`
reads a v10 document unchanged; `::test_no_upgrade_invents_a_field` asserts the exact
top-level key set for every source version; `::test_no_upgrade_invents_a_capability_record`
asserts that a v9 document's `rauc` is `null` and a v7/v8 document's `extraction.backend`
is `null`, never `false`.
