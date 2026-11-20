# Migrating to IoT Hardware Scanner 2.0

Version 2 changes the two things CI depends on: the saved report shape and the exit-code
contract. Both changes are deliberate and both are documented here with a migration example.

There is no compatibility shim. A reader that understands schema 1 will not silently
misinterpret a schema-2 document: `schema_version` is explicit, and the fields it used to read
are gone.

---

## 1. The aggregate grade is retired

`schema 1` emitted `risk_score: {total_score, risk_level, control_scores, …}` on every report.
That number had no calibrated relationship to device risk, and it was computed as if missing
analysis were passing analysis: an image that was never extracted scored 94/100 LOW.

In schema 2:

* `risk_score` is `null` for every new scan.
* `assessment.completion` says whether the requested work actually happened.
* `stages[]` records what ran, what did not and why, with inspected/eligible counts.
* `controls[]` records each named check with its evidence status (`PERFORMED`,
  `INCONCLUSIVE`, `NOT_APPLICABLE`, `OMITTED`) and its result.
* Replaying a schema-1 document keeps its historical grade under `legacy_grade`, labelled
  `method: v1-12-control-weighted`, and records `assessment.coverage: "UNKNOWN"`.

Nothing synthesises a grade for a schema-2 scan, including a complete one.

---

## 2. Field map

| Schema 1 | Schema 2 |
| --- | --- |
| `firmware.name/path/size/sha256/md5/file_type` | `artifact.name/path/size/sha256/md5/file_type` |
| — | `artifact.kind` (`file` \| `tree`) |
| — | `artifact.manifest_entries` (tree inputs) |
| `credentials.findings[]` | `findings[]` with `rule_id`, `severity`, `locations`, `critical_qualified` |
| `cve.findings[]` | `findings[]` with `rule_id: "advisory.<CVE>"` |
| `c2_malware.findings[]` | `findings[]` with `rule_id: "c2.<indicator_type>"` |
| `sbom.components[]` | `components[]` |
| `entropy.*` | `entropy.*` (now carries `units`, `bytes_analyzed`, `sampled`, `window_mean_entropy`) |
| `risk_score` | `null` for new scans; `legacy_grade` on replay of a v1 document |
| — | `assessment`, `stages`, `controls`, `data_sources`, `outcome` |

Every finding now has a **locator**: `path:line`, `path@offset` or a root-qualified relative path
inside an image (`rootfs/etc/shadow:2`). A finding without a locator is not emitted.

---

## 3. Exit codes

| Code | Schema 1 | Schema 2 |
| --- | --- | --- |
| 0 | no CRITICAL / LIKELY_C2 | report delivered, all required work complete, no findings |
| 1 | any CRITICAL or LIKELY_C2 | critical finding meeting a **documented evidence rule** |
| 2 | non-critical finding | report delivered, review or non-critical finding |
| 3 | validation error | invalid input **or configuration** |
| 4 | extraction failed | analysis incomplete |
| 5 | dependency missing | required **dependency** (extraction backend) missing |
| 6 | internal error | internal error **or the report could not be written** |

Three behaviour changes that break naive CI:

1. An unanalysed artifact no longer exits 0. If extraction is unavailable, expect **5**; if a
   required stage failed for another reason, expect **4**.
2. `LIKELY_C2` no longer exits 1. It is a heuristic indicator and now exits **2** unless a
   qualified critical rule also matched. Qualified rules are listed in
   `src/iot_hardware_scanner/scanner/assessment.py::CRITICAL_RULE_EVIDENCE`.
3. A failed report write exits **6** even when critical findings exist, and the success line is
   never printed.

---

## 4. `--out` writes where you ask

Schema 1 printed `Report saved: <path>` and did not write that path; it wrote `report.json` into
a generated scan directory instead (`tests/test_cli.py::TestOpaqueInput` covers this).

Schema 2 writes the exact path given to `--out`, atomically. Without `--out`, a non-terminal
`--format` writes `report.<ext>` inside the scan output directory (`--output`). Nothing else is
written.

---

## 5. Migration example — a CI gate that means something

Before (schema 1):

```yaml
- name: Firmware scan
  run: iot-hardware-scanner scan fw.img --format json --out report.json
  # exit 0 whenever nothing matched -- including when nothing was analysed
```

After (schema 2):

```yaml
- name: Firmware scan
  run: |
    set +e
    iot-hardware-scanner scan fw.img --offline --format json --out report.json
    status=$?
    set -e

    python - <<'PY'
    import json, sys
    doc = json.load(open("report.json"))
    assert doc["schema_version"] == 2, "report came from an older scanner"

    assessment = doc["assessment"]
    findings = doc["findings"]
    critical = [f for f in findings if f["critical_qualified"]]
    review = [f for f in findings if not f["critical_qualified"]]

    print(f"completion: {assessment['completion']}")
    print(f"critical:   {len(critical)}  review: {len(review)}")

    if assessment["completion"] != "COMPLETE":
        for reason in assessment["incomplete_reasons"]:
            print(f"  incomplete: {reason}")

    # Fail the build on a qualified critical finding, even on a partial scan.
    sys.exit(1 if critical else 0)
    PY

    case "$status" in
      0|2) exit 0 ;;   # complete: clean, or review findings only
      1)   exit 1 ;;   # qualified critical finding
      *)   echo "scan did not deliver a usable assessment (exit $status)"; exit 1 ;;
    esac
```

The point of splitting the two steps: a finding and an incomplete assessment are independent
facts. Automation should be able to act on the finding while still recording that the scan was
partial.

---

## 6. Reading a saved report from another tool

* Read `schema_version` first. `2` means the document has `assessment` and `outcome`.
  An unversioned document is schema 1: it has `risk_score` and section-per-detector findings.
* `iot-hardware-scanner report <file> --format json --out upgraded.json` upgrades a schema-1
  document in memory and writes a schema-2 rendering that preserves the finding section and the
  historical grade under `legacy_grade`. The input file is never modified.
* `outcome.exit_code` in the document equals the process exit code that produced it. A replay
  does not re-run analysis and does not overwrite `outcome`.
