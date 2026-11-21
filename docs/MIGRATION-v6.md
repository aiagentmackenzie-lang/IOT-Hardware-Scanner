# Migrating to report schema 6 (IoT Hardware Scanner 2.4)

2.4 adds **boot-manifest analysis** (slice 3D) and the **repeated-work cache**
(slice 5C). The report document moves from schema 5 to **schema 6**, the profile
version from 4.0 to **5.0**, and there is one new input kind and one new profile.
No existing profile's required stage set changed.

A schema-5 document still reads. It upgrades with `boot: null` and `cache: null`,
which mean "this version did not record those facts", never "no boot manifest
was found" and never "the cache missed". A schema-4 or earlier document upgrades
through the existing chain and gains the same explicit absences.

---

## 1. What schema 6 adds

| Section | Type | Meaning |
| --- | --- | --- |
| `boot` | object or `null` | One entry per parsed boot artifact. `null` means the selected profile did not read a boot manifest. |
| `cache` | object or `null` | What the repeated-work cache did for this run. `null` means the operator did not enable a cache. |

### `boot`

```json
{
  "artifacts": [
    {
      "locator": "board.itb",
      "artifact_id": "a0",
      "kind": "fit",
      "size": 1418,
      "digest": "…",
      "fdt_version": 17,
      "compatible": ["test,board", "test,soc"],
      "model": "IHS Test Board",
      "configurations": [
        {
          "name": "config-1",
          "default": true,
          "kernel": "kernel-1",
          "fdt": "fdt-1",
          "ramdisk": null,
          "loadables": [],
          "signature": {
            "present": true,
            "algo": "sha256,rsa2048",
            "key_source": "operator-supplied",
            "verified": true,
            "key_sha256": "…",
            "signed_nodes": ["/configurations/config-1"],
            "reason": "verified over /configurations/config-1 with the supplied 2048-bit RSA key"
          }
        }
      ],
      "default_config": "config-1",
      "memory": [{"name": "/memory@40000000", "base": 1073741824, "size": 268435456, "reg": [1073741824, 268435456]}],
      "reserved_memory": [],
      "partitions": [{"label": "firmware", "offset": 0, "size": 4194304, "node": "/flash@0/partitions/partition@0"}],
      "referenced_payloads": [
        {
          "node": "/images/fdt-1",
          "kind": "fdt",
          "offset": 838,
          "length": 634,
          "digest_declared": "77f4…",
          "digest_observed": "77f4…",
          "integrity": "match",
          "signature": {"present": false, "algo": null, "key_source": "none", "verified": null},
          "board": {"compatible": ["test,board"], "memory": [], "partitions": [], "fdt_version": 17}
        }
      ],
      "boot_enforcement": "unknown",
      "notes": []
    }
  ],
  "notes": []
}
```

**Four separate facts.** A reader must not collapse them:

1. `referenced_payloads[].integrity` — `match | mismatch | undeclared | out-of-bounds`.
2. `signature.present` — whether a signature node exists.
3. `signature.verified` — `true | false | null`. It is `null` unless an
   **operator-supplied** key was parsed and a signature was checked against it.
4. `boot_enforcement` — always `"unknown"` from a static parser.

`key_source` is `none`, `operator-supplied`, or `embedded-not-trusted`. An
embedded key can show that a signature matches the key the artifact carries; it
is never promoted to a trust decision, and `verified` stays `null`.

### `cache`

```json
{
  "enabled": true,
  "format": "ihs-analysis-cache/1",
  "path": "/operator/chosen/dir",
  "entries": 1303,
  "bytes": 473301,
  "max_entries": 20000,
  "max_bytes": 268435456,
  "hits": 3232,
  "misses": 0,
  "writes": 0,
  "invalid": 0,
  "evicted": 0,
  "skipped": 0,
  "note": "Cache entries hold deterministic parser outputs keyed by content digest …"
}
```

---

## 2. New input kind and profile

| | Before | 2.4 |
| --- | --- | --- |
| `artifact.kind` | `file`, `tree` | `file`, `tree`, **`boot`** |
| Profile | `firmware-static`, `firmware-tree`, `credentials-only` | adds **`firmware-boot`** |
| Profile version | 4.0 | **5.0** |

`firmware-boot` requires `ingest`, `rule_compilation`, `boot_analysis` and
`risk_controls`. Extraction, root discovery, enumeration, entropy, binary and
ELF inventory, opkg, credentials, accounts, services, indicators and advisory
are recorded `NOT_APPLICABLE` for this profile, with a reason — not `SKIPPED`.

The profile version bump records the new profile and the new `boot_analysis`
stage id. **No existing profile's required set changed**; a 2.3 profile-4.0
document and a 2.4 profile-5.0 document mean the same thing for those profiles.

A file whose first four bytes are the FDT magic `0xd00dfeed` selects
`firmware-boot` automatically when no other profile was named. `--profile
firmware-static` on such a file is still parsed as boot, because the firmware
profile's extraction stage has nothing to decode.

---

## 3. New flags

```
scan board.itb --profile firmware-boot [--trust-anchor operator-key.pem]…
scan image.img.gz --cache-dir ~/.cache/ihs-analysis
```

* `--trust-anchor PATH` (repeatable) accepts a PEM `PUBLIC KEY` or
  `RSA PUBLIC KEY`. A certificate is rejected with a reason; it is not silently
  ignored. The key is recorded by SHA-256.
* `--cache-dir PATH` enables the content-addressed cache. Without it, a scan
  behaves exactly as 2.3 did and `cache` is `null`.

---

## 4. Exit behaviour

No row of the scan precedence table changed, and `boot` does not reuse the
`compare` or `sbom` tables.

| Case | Result |
| --- | --- |
| Malformed, truncated, over-deep or out-of-bounds structure | `boot_analysis` **FAILED** or **PARTIAL**, assessment `INCOMPLETE`, **exit 4**. No silent empty `boot` section. |
| Payload digest mismatch | The stage completes; a `boot.payload_integrity` **HIGH review finding** is emitted, **exit 2**. It is **not** critical-capable: a static parser sees a disagreement, not which side a bootloader would use. |
| Valid signature with a supplied key | control 5 `PERFORMED / REVIEW`; control 6 stays `INCONCLUSIVE / UNKNOWN`; exit 0. |
| Signature present, no key | control 5 `PERFORMED / REVIEW` with "unverified"; exit 0. |
| No configuration selected | `default_config: null`; nothing is guessed; control 5 can still review declared digests. |

A boot manifest never produces a critical finding, so it cannot move exit 0/2 to
exit 1 by itself.

---

## 5. Reader example

```python
import json
from iot_hardware_scanner.scanner.report_document import SCHEMA_VERSION, load_document

with open("board.json") as handle:
    document = load_document(json.load(handle))

assert document["schema_version"] == SCHEMA_VERSION  # 6
boot = document["boot"]
if boot is None:
    print("this report did not read a boot manifest")
else:
    for artifact in boot["artifacts"]:
        print(artifact["kind"], artifact["default_config"], artifact["boot_enforcement"])
        for payload in artifact["referenced_payloads"]:
            print(payload["node"], payload["integrity"], payload["signature"]["verified"])
```

`verified` is a tri-state. Write `if value is True`, never `if value`.
