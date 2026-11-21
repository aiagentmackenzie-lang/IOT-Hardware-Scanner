# Migrating to report schema 4 (IoT Hardware Scanner 2.2)

Schema 4 is the first release that states **what each finding is** and **what
each check rests on**. It does not change the exit contract, the profile names
or the renderer set, and it does not re-introduce an aggregate grade.

A schema-3 document stays readable: `report` upgrades it, keeps every recorded
fact, and marks the new sections as *not recorded* rather than empty. A
schema-4 document is never downgraded. Schema 2 and schema 1 still upgrade as
before, ending at schema 4.

---

## 1. What schema 4 adds

| Section | What it records | Why it exists |
| --- | --- | --- |
| `ruleset` | The digest of the **one** compiled rule set, the engine and its version, and one record per rule file: namespace, name, file digest, rule count, the destinations it can route to, and every rule file that could not be compiled with the reason | A finding is only reproducible if the rules that produced it are named. A rule file that fails to compile is a coverage gap, so it is in the document — and in the `rule_compilation` stage — rather than in a log line. |
| `advisory` | The local snapshot applied (`digest_sha256`, provider, `acquired_at`, entry count, age, `stale`, `sample`), one **lookup per component** with an explicit state, the match and KEV counts, the KEV source, and the number of keyword candidates that were rejected | "No advisories" and "we could not ask" are different answers. A clean result is only a pass when every lookup settled against a current snapshot. |

`findings[]` gains three fields:

| Field | Values | Meaning |
| --- | --- | --- |
| `destination` | `credential` \| `service` \| `crypto` \| `indicator` \| `advisory` | The kind of fact the match is. It comes from the rule file's own `category`, once, and no detector can relabel it. |
| `namespaces` | list | The compiled rule file namespaces that produced the finding. |
| `ruleset_digest` | hex or `""` | The digest of the compiled set that produced it. |

`findings[].locations` now holds **every** location a deduplicated finding was
observed at, not just the first one. Two copies of one default password are one
finding with two locations.

`controls[]` gains four fields and keeps the four it had:

| Field | Meaning |
| --- | --- |
| `question` | The question the check asks, in one sentence. |
| `required_source` | The evidence source that can answer it. A missing source is `OMITTED` or `INCONCLUSIVE`, never a pass. |
| `applicability` | `APPLICABLE` or `NOT_APPLICABLE`, decided by the selected profile. |
| `applicability_note` | A note about what the observation does *not* mean, when one is needed. |
| `evidence_status` | The same value as `status`, under the name the plan uses. |

### `stages[]`: one new stage id

`rule_compilation` is a new stage, and it is **required** by all three profiles
from profile version 4.0. It reports:

| Status | Meaning |
| --- | --- |
| `COMPLETE` | Every rule file compiled. |
| `PARTIAL` | Some rule files were rejected; each is listed in `omissions` and in `ruleset.compile_errors`. |
| `UNAVAILABLE` | `yara-python` is not importable. The stage records it as a dependency, so the exit is 5, not a quiet zero. |

`assessment.profile_version` is now `4.0`.

---

## 2. Two behaviour changes to know about

### 2.1 Advisory assessment is a requested stage

A scan without `--advisory-snapshot` is unchanged: the `advisory` stage is
`SKIPPED`, `findings[]` has no advisory entries, check 3 is `OMITTED`, and
`advisory` is `null`. That is *not* a clean result, and the report says so.

Supplying `--advisory-snapshot PATH` makes advisory assessment a **required**
stage for that run. If the snapshot is missing, unreadable, the wrong schema or
too large, the assessment is incomplete and the exit is 5 (missing required
input) or 4 (the supplied input could not be applied), never 0 or 2.

There is still no way to make a scan fetch advisory data. Refresh remains a
separate operation; see §4.

### 2.2 Some findings disappeared, on purpose

Eleven review findings on the stock OpenWrt reference image were false
positives. They are gone, and the rules behind them were tightened rather than
special-cased:

| Removed noise | Why it was wrong |
| --- | --- |
| `LIKELY_C2` on `libmbedcrypto` and `dropbear` | `jackskid_chacha20` matched `"expand 32-byte k"`, which is the standard sigma constant of a *strong* cipher and is present in mbedTLS and OpenSSH. The rule is deleted; the family-specific ENS rule remains. |
| nine `c2.domain` findings from shared-library string tables | `libc.so`, `lucihttp.parser.urlencoded`, `payload.offset` and `pf.os` were scored as C2 domains because a token with a dot was accepted. A candidate must now end in a suffix from the shipped list, must not be a `.so` name, and must not be the basename of a file in the image. |
| `credential.yara.ssh_private_key` in mbedTLS | The rule matched the PEM **header**, which a parser carries by design. It now requires key material between the header and the END line. |
| `credential.yara.bearer_token` in `uhttpd_ubus` | The rule matched the literal `"Bearer "`, an HTTP header name. It now requires a 20+ character token value. |
| a `$1$…` hash inside libc | `unix_md5_hash` is removed. Stored hashes are read verbatim from the account databases, which is the only place the observation means anything. |
| `weak_crypto` on bare constants | `des_weak_key`, `rc4_implementation` and `md5_constant` matched 8 or 16 anonymous bytes. Each now requires an algorithm identifier next to the constant. |

What replaced them is reported instead: `crypto.*` findings say that a weak
algorithm **implementation is present** in a named file at a named offset, and
check 8 says exactly that and nothing stronger.

---

## 3. Reading an older document

```python
from iot_hardware_scanner.scanner.report_document import load_document

document = load_document(saved)          # schema 3 input
assert document["schema_version"] == 4
assert document["migration"]["from"] == 3
assert document["ruleset"] is None       # not recorded, and said so
assert document["advisory"] is None
```

A schema-2 document additionally gains `None` for the schema-3 sections
(`image_map`, `extraction`, `input_binding`, `opkg`, `tree`). A schema-1
document still upgrades as before, ending at schema 4 with `legacy_grade` and
the `migration` note.

Findings carried up from an older document keep the fields they recorded. They
have no `destination`, and a renderer shows that as `unrecorded` rather than
guessing one.

---

## 4. The advisory snapshot format

`ihs-advisory-snapshot/1`. Produce it in a separate, explicit refresh step —
the scan itself never opens a socket.

```json
{
  "schema": "ihs-advisory-snapshot/1",
  "provider": "nvd",
  "acquired_at": "2026-11-01T00:00:00+00:00",
  "sample": false,
  "kev": {"source": "cisa-kev", "published": "2026-10-01", "cves": ["CVE-2024-0001"]},
  "advisories": [
    {
      "cve_id": "CVE-2024-0002",
      "description": "…",
      "published": "2024-03-01T00:00:00",
      "last_modified": "2024-04-01T00:00:00",
      "provider_score": 7.5,
      "provider_vector": "CVSS:3.1/…",
      "references": ["https://…"],
      "matches": [
        {
          "cpe": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
          "vulnerable": true,
          "version_start_including": "3.0.0",
          "version_end_excluding": "3.0.16"
        }
      ],
      "excluded_versions": ["3.0.15-r1"],
      "exploit_available_public": false,
      "vendor_backport_uncertain": false
    }
  ],
  "lookups": [
    {"component": "busybox", "version": "1.36.1-r2", "state": "KNOWN_EMPTY"}
  ]
}
```

* `matches[].cpe` must be a complete CPE 2.3 formatted string. The version
  bounds are the provider's; the scanner does not infer them.
* `keyword_search: true` marks an advisory that arrived from a keyword query.
  It is promoted only when it names the shipped product **and** its version
  statement includes the shipped version; otherwise it is counted in
  `advisory.keyword_candidates_rejected`.
* `lookups` is optional. A recorded `UNAVAILABLE` or `PARTIAL` state for a
  component makes that component's lookup a stated gap, so check 3 cannot pass.
* `kev.cves` is a separate list. KEV membership is recorded on the finding
  (`is_in_kev`) and read by check 3; it never rewrites the provider's score, and
  it is not the same fact as public exploit availability.
* A snapshot older than `advisory_snapshot_max_age_days` (default 30) is
  reported `stale`. Its matches are still reported, with `stale: true`, but
  check 3 answers `INCONCLUSIVE`.

---

## 5. New CLI surface

```
scan  --advisory-snapshot PATH   apply a local advisory snapshot offline; makes
                                 advisory assessment a required stage for this run
```

No other flags changed. `--offline` remains the default and remains valid.

---

## 6. Configuration additions

| Setting | Default | Meaning |
| --- | --- | --- |
| `advisory_snapshot` | none | Snapshot to apply. Equivalent to `--advisory-snapshot`. |
| `advisory_snapshot_max_age_days` | `30` | Age at which a snapshot is reported stale. |
| `nvd_max_pages` | `5` | Bound on pages fetched for one online advisory query. Reaching it is a `PARTIAL` lookup. |
| `nvd_max_results_per_page` | `2000` | Page size requested from the provider (NVD's own maximum). |
