# Migrating to report schema 5 (IoT Hardware Scanner 2.3)

Schema 5 makes the component inventory complete and says how each component was
named. It does not change the exit contract, the profile names, the renderer set
or any stage. It does not re-introduce an aggregate grade.

A schema-4 document stays readable: `report`, `compare` and `sbom` upgrade it,
keep every recorded fact, and mark the new section as *not recorded* rather than
empty. A schema-5 document is never downgraded. Schema 2, 3 and 4 still upgrade
as before, ending at schema 5.

Version 2.3 also adds two document types that are **not** scan documents:

* `ihs-comparison/1` — a release comparison (`compare`);
* `CycloneDX 1.6 JSON` — a BOM export (`sbom`).

---

## 1. What schema 5 adds

| Section | What it records | Why it exists |
| --- | --- | --- |
| `components[]` | **Every** installed-package record, one component each, with `cpe_basis` | Milestone C emitted a component only when the package name had a CPE mapping. On the reference image that was 3 of 196 records, so the inventory a comparison needs was not there. |
| `components[].cpe_basis` | `nist-mapped` \| `opkg-package-name` \| `banner` | A component's vendor is either authoritative, derived from the distribution's own package name, or a candidate from a version string. The difference matters and is now recorded instead of implied. |
| `component_bases` | `{counts: {…}, total}` | The same fact at document level, so a reader sees the shape of the inventory without counting rows. |

### 1.1 The three bases

| Basis | Meaning | Example |
| --- | --- | --- |
| `nist-mapped` | The vendor and product pair comes from an authoritative NIST CPE dictionary row, recorded in the single shipped mapping (`data/component_cpe_map.json`). | `cpe:2.3:a:busybox:busybox:1.36.1-r2:*:*:*:*:*:*:*` |
| `opkg-package-name` | No authoritative NIST row exists. The name is the opkg package's **own** name with vendor `openwrt`. It is a traceable identity for the inventory it came from — not a claim that NIST knows the product. | `cpe:2.3:a:openwrt:libustream-mbedtls20201210:2024.01.01-r1:*:*:*:*:*:*:*` |
| `banner` | A version string found in a file. Candidate confidence; never an installed-package record. | `cpe:2.3:a:busybox:busybox:1.36.1:*:*:*:*:*:*:*` (candidate) |

There is **one** mapping. A short `cpe:2.3:a:v:p:ver` string is not CPE 2.3 —
it has the wrong number of components — so every emitted name carries all
thirteen attributes. Versions are verbatim: `1.36.1-r2` never becomes `1.36.1`,
because the revision is a distinct fact.

---

## 2. Reading a schema-4 document

```python
from iot_hardware_scanner.scanner.report_document import load_document

document = load_document(saved)          # schema 4 input
assert document["schema_version"] == 5
assert document["migration"]["from"] == 4
assert document["component_bases"] is None        # not recorded, and said so
assert "cpe_basis" not in document["components"][0]
```

`component_bases` is `None`, not zero: a v4 document may have had a complete
inventory that simply never recorded a basis, and writing `{"nist-mapped": 0,
…}` would be a false statement about it. The per-component field is absent for
the same reason.

A schema-3 document additionally gains `None` for `component_bases`, and
`None` for the schema-4 sections (`ruleset`, `advisory`). A schema-2 document
additionally gains `None` for the schema-3 sections (`image_map`, `extraction`,
`input_binding`, `opkg`, `tree`). A schema-1 document still upgrades as before,
ending at schema 5 with `legacy_grade` and the `migration` note.

---

## 3. The comparison document (`ihs-comparison/1`)

`compare BASE.json TARGET.json` writes one document. It is not a scan document:
it has no assessment, no findings of its own and no exit table in common with
`scan`. Its sections:

| Section | Contents |
| --- | --- |
| `inputs` | For each side: scan id, artifact name/digest/size, scanner version, profile and profile version, rule-set digest, advisory snapshot digest/provider/time, opkg database digest and locator, component count, worker image |
| `environment` | The instruments compared field by field (`changed` per field), the human-readable `changes`, and `coverage_changes` — every stage whose status or required flag differs, with both reasons |
| `comparability` | Per destination (`credential`/`service`/`crypto`/`indicator`/`advisory`): `comparable` and, when not, the reasons. Overall `comparable` / `partial` / `indeterminate` |
| `packages` | Records compared by `Package` name, every occurrence kept: `persistent`, `changed`, `new`, `removed`, `relocated`, with counts and the record-level evidence ranges |
| `components` | Compared by `(vendor, product)` with every complete version and occurrence; reports relocation and both scans' basis counts |
| `layout` | Content identity (ELF build ID, else file digest; tree-manifest digest for a staged tree): `relocated`, `rebuilt_at_same_path`, `new`, `removed` |
| `findings` | Matched by rule and location (trailing path components): `new`, `persistent`, `changed`, `resolved`, `indeterminate`, plus per-destination counts, and `identity` — what was matched |
| `declarations` | One entry per supplied declaration (see §4) |
| `notes` | What the document is, and what it refuses to guess |

Rules the document follows, in order:

1. **Instruments first.** A changed scanner version, profile/profile version,
   rule-set digest or advisory snapshot is stated before any difference.
2. **No detector, no verdict.** If a stage that can produce a destination did not
   settle (`SKIPPED`, `PARTIAL`, `UNAVAILABLE`, `FAILED`) on either side, or the
   rule-set digest differs, or the scanner versions differ, that destination's
   findings are `indeterminate` — never `resolved`.
3. **Identity is not a path.** A file that moved keeps its content identity; a
   component that moved keeps its `(vendor, product)` identity; a finding that
   followed its file is `persistent` and `relocated`.
4. **Every occurrence survives.** Two roots with the same package name and
   different revisions remain two records on each side.

### 3.1 The `compare` exit codes

| Code | Meaning |
| --- | --- |
| 3 | An input could not be read as a scan document |
| 6 | The requested comparison could not be written |
| 2 | Determinate comparison with differences (packages, layout, findings, or a declaration's version conflicts / declared-only / observed-only rows) |
| 4 | Nothing differs, but something could not be concluded (a detector with findings did not settle; or a declaration row is unresolved or unbound) |
| 0 | Nothing differs and nothing was left unresolved |

---

## 4. Declarations (`--declaration`, repeatable)

Two kinds are read, by content rather than by filename:

* an **OpenWrt target manifest** — line-oriented `name - version`;
* a **CycloneDX 1.4** (or later) JSON document with `bomFormat: "CycloneDX"`.

Each is recorded with its own SHA-256, byte length, kind, spec version and
scope. Binding is decided from evidence, never from proximity:

| `binding.status` | When | Effect |
| --- | --- | --- |
| `bound` | The declaration carries this image's SHA-256 | Its rows may resolve observations |
| `mismatched` | The declaration carries a different image digest | Every row is `unbound`; nothing is resolved, and `observed-only` is not computed |
| `unclaimed` | The declaration carries no image digest | Its rows are compared, and the association is recorded as scope-based and **unverified** |

Outcomes per declared row:

| `state` | Meaning |
| --- | --- |
| `agreement` | The declared version equals the image's complete version string |
| `unresolved-revision` | The declared version is the image's version less a package revision (`-rN`) or build suffix (`~<commit>`, `+…`). Unresolved at that granularity; **not** upgraded to agreement and **not** reported as a mismatch. Both values are kept |
| `version-conflict` | The versions genuinely differ |
| `declared-only` | Declared and absent from the image's installed records |
| `observed-only` | Installed in the image and not declared |

Reconciliation needs **no** CycloneDX export: it reads the declaration and the
image's own package records. Both documents and the scan stay offline.

The published OpenWrt 24.10.0 case, measured: 196 image records; the target
manifest declares 124 rows, all 124 agree, 72 are image-only; the supplier
CycloneDX declares 124 rows and uses upstream package names, which gives 20
agreements, 80 unresolved revisions, 24 declared-only and 96 observed-only.

---

## 5. The SBOM export (`sbom`)

`sbom SCAN.json --out bom.cdx.json` writes CycloneDX **1.6** JSON:

* `metadata.component` is the artifact, with its SHA-256 hash and deterministic
  `urn:ihs:firmware:<sha256>` `bom-ref`;
* one `components[]` entry per scan component, with a deterministic
  `urn:ihs:component:<sha256 of vendor·product·version>` `bom-ref`, its CPE when
  the scan recorded one, and `properties` carrying `ihs:firmware-sha256`,
  `ihs:evidence`, `ihs:occurrence…`, `ihs:cpe-basis`, `ihs:confidence`,
  `ihs:source-method` and `ihs:database-sha256`;
* one `dependencies` entry naming the firmware and every component, which is the
  evidence-backed relationship the scan established: these records are in this
  image.

A component with no version, product or evidence is refused rather than written
with a placeholder: an untraceable component is worse than no export.

`--validate` checks the BOM against the CycloneDX 1.6 schema **vendored inside
the package** (`data/cyclonedx-1.6/`, together with `spdx.schema.json` and
`jsf-0.82.schema.json`), so validation needs no network and no "latest schema"
guess. It needs the `sbom` extra (`jsonschema`).

The existing JSON inventory is unchanged and remains readable: the export reads
it, it does not replace it.

---

## 6. New CLI surface

```
compare BASE.json TARGET.json
        [--declaration PATH]…            reconcile a manifest or CycloneDX document
        [--format terminal|json|markdown] [--out PATH]

sbom SCAN.json
        [--out PATH] [--validate]        CycloneDX 1.6 export, offline validation
```

No existing flag changed. `--offline` remains the default and remains valid, and
neither new command can issue a request.

---

## 7. Configuration additions

None. The two new commands take no scanner configuration; the comparison budget
(256 MiB per document) is a module constant, and the SBOM export reads only the
scan document.

The advisory transport gained two test-facing settings, which a scan never uses
because a scan is offline:

| Setting | Default | Meaning |
| --- | --- | --- |
| `nvd_api_base` | `""` (the provider's published endpoint) | Base URL for the advisory API; exists so the transport can be driven against a loopback server in tests |
| `nvd_cache_path` | none (the default cache file) | Explicit SQLite cache path |
