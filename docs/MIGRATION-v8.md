# Migration to report schema 8 — 2.8.0

Schema 8 adds the **bare-metal address map**. A v8 scan of an Intel HEX,
S-record or UF2 image records what the encoding actually declares: where the
bytes live, what was never declared, and one digest over the payload that does
not depend on the encoding. No section was renamed, no fact changed type, and a
schema-7 document still reads.

This closes slice **3C** of `FIRMWARE_SCANNER_PLAN.md`.

---

## 1. Why this exists

Until 2.7.0 those three encodings were recognised by extension and then reported
as unsupported: a `.hex` file reached the firmware profile, failed at extraction
(it is not a container), and exited 4 with everything after ingest unobserved.
That is honest but useless to the engineer holding a board image: the artifact
*is* fully readable, just not as a filesystem.

The plan's acceptance rows for this slice:

> equivalent generated payloads in all three encodings yield the same address map
> and payload hash, a gap stays unobserved, and a bare-metal scan completes with a
> profile appropriate to an image without a Linux root filesystem.

## 2. What schema 8 records

```json
"mcu": {
  "format": "intel-hex",
  "decoder": "ihs-mcu",
  "decoder_version": "1",
  "locator": "board",
  "digest": "<sha256 of the file>",
  "ranges": [
    {"start": 134217728, "start_hex": "0x08000000",
     "end": 134217812, "end_hex": "0x0800012c",
     "length": 300, "sha256": "…", "source_records": "1-10"}
  ],
  "gaps": [
    {"start": 134217772, "start_hex": "0x0800012c",
     "end": 134218240, "end_hex": "0x08000200",
     "length": 468, "observed": false}
  ],
  "payload_bytes": 500,
  "declared_bytes": 500,
  "payload_sha256": "…",
  "records": 10,
  "start_address": 134217728,
  "start_address_hex": "0x08000000",
  "target_address": null,
  "family": null,
  "header": null,
  "diagnostics": [
    {"kind": "out-of-order", "detail": "…", "address": null, "address_hex": null,
     "length": null, "records": []}
  ],
  "notes": ["record 11 declares a start address 0x08000000; …"]
}
```

`null` for `mcu` means "this scan decoded no bare-metal image" — a filesystem
scan, a boot manifest scan, or any document from 2.7.0 or earlier.

### The payload digest is the contract

```text
for each merged range, in ascending address order:
    b"IHS-MCU-1 " + f"{start:016x} {length:016x}" + b"\n" + payload bytes
```

Consequences, each with a test:

| Property | Why it matters |
| --- | --- |
| Encoding-independent | the same payload as Intel HEX, S-record and UF2 has one digest (`test_all_three_encodings_agree`) |
| Chunk-independent | re-chunking 512 bytes as 128-byte or 16-byte records keeps the digest (`test_the_digest_is_over_addresses_not_record_boundaries`) |
| Gap-free | a gap is never zero-filled, so filling the hole changes the digest (`test_a_gap_stays_unobserved`) |
| Address-ordered | out-of-order records cannot change it (`test_out_of_order_records_are_reported_but_still_mapped`) |

`declared_bytes` counts every byte a record declared; `payload_bytes` counts the
bytes that ended up addressed once. They differ only when records overlap, and
that difference is always accompanied by a `conflict` or `duplicate` diagnostic.

### Diagnostics are facts about the encoding

| `kind` | Meaning | Effect on the stage |
| --- | --- | --- |
| `conflict` | two records write different bytes to one address; the first in address order is kept | `PARTIAL` |
| `duplicate` | two records write identical bytes to one address | complete |
| `out-of-order` | a record declares a lower address than its predecessor | complete |
| `missing-eof` | no Intel HEX type-01 record: the stream's own terminator is absent | `PARTIAL` |
| `record-count-mismatch` | an S5/S6 count disagrees with the data records present | `PARTIAL` |
| `missing-block` | UF2 blocks are absent; their addresses are unobserved | `PARTIAL` |
| `duplicate-block` | a UF2 block number appears twice | complete |
| `unknown-record-type` | a record type this decoder does not interpret | `PARTIAL` |

A `PARTIAL` stage makes the assessment incomplete and exits 4. A clean decode of
a payload with no rule matches is exit 0, and findings are review findings
(exit 2) — none of the twelve critical-evidence rules is satisfied by "a rule
matched somewhere in flash".

### Coordinates

* `start`/`end` are **device addresses**. `end` is exclusive.
* `source_records` names the record span (`"1-10"`, `"4,9"`), so a byte range can
  be quoted back to the encoding that carried it.
* S-record `S0` header text is kept in `header`; the `S7/S8/S9` start address is
  `start_address` and is labelled an intention in `notes`.
* UF2 keeps `family` (hex), `target_address`, and the not-main-flash /
  file-container / extension-tag flags as notes rather than silent drops.

## 3. Reading a schema-7 document

`load_document` accepts 1 through 8. A v7 document keeps every recorded fact and
gains one explicit absence:

```json
"migration": {"from": 7, "to": 8, "note": "…"},
"mcu": null
```

`null` is "that version never recorded an address map", not an empty one. The
terminal, Markdown and HTML renderers print a `Bare-metal image` block only when
the section exists, so an upgraded document renders exactly as before.

## 4. Profile semantics — 5.0 → 6.0

`firmware-mcu` is a new profile with a new stage id (`mcu_analysis`). **No
existing profile's required set changed.** The version bump records that a new
profile and a new stage exist, exactly as 4.0 → 5.0 did for `firmware-boot`.

| Stage | Status in `firmware-mcu` |
| --- | --- |
| ingest, rule compilation, mcu analysis, risk controls | required |
| extraction, root discovery, enumeration, entropy, binary inventory, ELF metadata, opkg inventory, credentials, Unix accounts, services, C2, advisory | `NOT_APPLICABLE`, each with its own reason |

All twelve named checks are `NOT_APPLICABLE` in this profile. That is a decision,
not an omission: a byte map cannot answer "does this device enforce secure boot?"
and turning a rule match into `FAIL` for control 1 would present a heuristic as a
verdict. The finds are still reported — as findings, with addresses.

## 5. Bounds

| Bound | Default | Config |
| --- | --- | --- |
| decoded payload bytes | 64 MiB | `max_mcu_payload_mb` |
| records/blocks read | 500,000 | `max_mcu_records` |
| one record's payload | 512 bytes | fixed (Intel HEX ≤ 255, UF2 ≤ 476) |
| address | 32-bit | fixed; an overflow is a named error, not a wrap |

A decode that hits a bound is a `FAILED` stage with exit 4. A partial map is
never produced: it would present unobserved bytes as absent ones. The decoded
bytes are held only for the rule sweep and are **never serialised** — a report
carries addresses and digests, not a copy of the firmware.

## 6. Gates recorded with this change

| Gate | Command | Result |
| --- | --- | --- |
| Lint / format | `ruff check src/ tests/ benchmarks/`, `ruff format --check` | clean |
| Types | `mypy src/` | clean, 41 source files |
| Tests | `pytest` (local, macOS arm64, CPython 3.12.14) | **1072 collected, 1046 passed, 0 failed, 26 skipped** — the skips are the container, verify-image and reference-image rows the qualified CI job runs |
| Slice 3C | `pytest tests/test_mcu_image.py tests/test_mcu_profile.py` | 54 passed, 0 skipped |

CI evidence for this release is recorded after the push that follows this
change. The qualified job remains `linux-extractor` (zero skips).
