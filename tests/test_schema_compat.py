"""P1/P3 — the schema-9 reader is tested against every report version it claims.

One fixture per report schema 1 to 9, each carrying only the fields that version
actually recorded, and the *exact* upgrade result asserted:

* the version lands on :data:`SCHEMA_VERSION`;
* the migration record names the source version (v1 keeps its provenance in
  ``schema_note`` and ``assessment.coverage`` -- see the v1 test);
* facts the source version recorded are preserved byte for byte;
* facts it could not record are ``None`` -- never ``[]``, never ``False``, never
  a zero that reads as "we looked and found nothing";
* no field is invented. The top-level key set is asserted exactly, so adding a
  section without a migration decision fails here.

Schema 7 is the only version where a null ``artifact.file_type_source`` or
tool ``capabilities`` means "this scan did not establish it"; schema 8 is the only
one where a null ``mcu`` means "no bare-metal image was decoded"; schema 9 is the
only one where a null ``extraction.backend`` means "no backend ran". For an
upgrade the same null means "that version never recorded it", and the
``migration`` note says so.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest

from iot_hardware_scanner.scanner.report_document import (
    SCHEMA_VERSION,
    load_document,
    render,
)

#: The facts every saved scan document from schema 2 onward records.
_BASE_KEYS = frozenset(
    {
        "schema_version",
        "tool",
        "scan_id",
        "scan_date",
        "report_generated",
        "artifact",
        "assessment",
        "stages",
        "controls",
        "findings",
        "inventory",
        "entropy",
        "components",
        "risk_score",
        "outcome",
        "data_sources",
    }
)

_PROFILE_VERSIONS = {2: "2.0", 3: "3.0", 4: "4.0", 5: "4.0", 6: "5.0"}


def _artifact() -> dict[str, Any]:
    return {
        "kind": "file",
        "name": "rootfs.img.gz",
        "path": "rootfs.img.gz",
        "size": 4_451_127,
        "sha256": "8b5a" + "0" * 60,
        "md5": "b" * 32,
        "file_type": "gzip compressed data",
        "size_category": "SMALL",
        "manifest_entries": None,
    }


def _assessment(version: int) -> dict[str, Any]:
    return {
        "profile": "firmware-static",
        "profile_version": _PROFILE_VERSIONS[version],
        "completion": "COMPLETE",
        "coverage": "COMPLETE",
        "incomplete_reasons": [],
        "missing_required_dependencies": [],
        "limitations": [],
        "check_counts": {"PERFORMED": 12},
        "started_at": "2025-01-01T00:00:00+00:00",
        "completed_at": "2025-01-01T00:00:01+00:00",
    }


def _stage() -> dict[str, Any]:
    return {
        "stage": "ingest",
        "status": "COMPLETE",
        "required": True,
        "reason": None,
        "inspected": 1,
        "eligible": 1,
        "omissions": [],
        "dependency": None,
    }


def _finding(version: int) -> dict[str, Any]:
    """One finding with the fields that version recorded.

    Schema 4 is when a finding gained its typed destination, the namespaces that
    produced it and the rule-set digest. A v2 or v3 upgrade must not add them.
    """
    entry: dict[str, Any] = {
        "rule_id": "credential.unix.empty_password",
        "severity": "HIGH",
        "title": "Empty password field",
        "description": "The shadow record has an empty password field.",
        "category": "credential",
        "locations": ["etc/shadow:1"],
        "evidence": ["etc/shadow:1"],
        "remediation": None,
        "critical_qualified": False,
    }
    if version >= 4:
        entry["destination"] = "credential"
        entry["namespaces"] = ["credential"]
        entry["ruleset_digest"] = "c" * 64
    return entry


def _component(version: int) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "name": "busybox",
        "version": "1.36.1-r2",
        "vendor": "busybox",
        "product": "busybox",
        "cpe": "cpe:2.3:a:busybox:busybox:1.36.1-r2:*:*:*:*:*:*:*",
        "source": "opkg",
        "confidence": "recorded",
        "evidence": "usr/lib/opkg/status:1-8",
        "digest_sha256": "d" * 64,
        "occurrences": ["/bin/busybox"],
    }
    if version >= 5:
        entry["cpe_basis"] = "nist-mapped"
    return entry


def _base(version: int) -> dict[str, Any]:
    return {
        "schema_version": version,
        "tool": {"name": "iot-hardware-scanner", "version": f"2.{version - 1}.0"},
        "scan_id": f"scan-v{version}",
        "scan_date": "2025-01-01T00:00:00+00:00",
        "report_generated": "2025-01-01T00:00:02+00:00",
        "artifact": _artifact(),
        "assessment": _assessment(version),
        "stages": [_stage()],
        "controls": [],
        "findings": [_finding(version)],
        "inventory": None,
        "entropy": None,
        "components": [_component(version)],
        "risk_score": None,
        "outcome": {
            "exit_code": 2,
            "exit_reason": "REVIEW_FINDINGS",
            "summary": "report delivered with review findings",
            "reasons": [],
        },
        "data_sources": [{"name": "component_cpe_map.json", "sha256": "e" * 64}],
    }


# ──────────────────────────────────────────────
# One fixture per version. Each is the shape that version wrote; nothing from a
# later version appears in an earlier fixture, which is what makes "no field is
# invented" meaningful.
# ──────────────────────────────────────────────


def schema_1() -> dict[str, Any]:
    """v1: unversioned, per-detector sections, one aggregate grade."""
    return {
        "scan_id": "legacy-001",
        "scan_date": "2025-01-01T00:00:00+00:00",
        "firmware": {
            "name": "legacy_fw",
            "path": "legacy.bin",
            "sha256": "a" * 64,
            "md5": "b" * 32,
            "size": 1024,
            "file_type": "ELF",
        },
        "entropy": None,
        "credentials": {
            "total": 1,
            "by_severity": {"HIGH": 1},
            "findings": [
                {
                    "severity": "HIGH",
                    "category": "password",
                    "matched_pattern": "unix_shadow_parse",
                    "file_path": "etc/config/system",
                    "line_number": 12,
                    "masked_value": "root:****",
                    "is_default": False,
                    "is_placeholder": False,
                }
            ],
        },
        "cve": {"total": 0, "findings": []},
        "c2_malware": {"total": 0, "findings": []},
        "risk_score": {
            "total_score": 88.0,
            "risk_level": "MEDIUM",
            "control_scores": [],
            "weighted_breakdown": {},
            "executive_summary": "legacy",
            "owasp_iot_mapping": {},
        },
        "sbom": {"total": 0, "components": []},
    }


def schema_2() -> dict[str, Any]:
    return _base(2)


def schema_3() -> dict[str, Any]:
    document = _base(3)
    document.update(
        {
            "image_map": {
                "nodes": [
                    {
                        "artifact_id": "a0",
                        "parent_id": None,
                        "format": "gzip",
                        "extent_bytes": 4_348_264,
                    }
                ]
            },
            "extraction": {"worker": "docker", "helper_version": "4.5.1"},
            "input_binding": {"declared_sha256": "8b5a" + "0" * 60, "source_reverified": True},
            "elf": {"eligible": 1, "parsed": 1, "records": [], "rejected": []},
            "opkg": {"installed": 1, "records": []},
            "tree": None,
        }
    )
    return document


def schema_4() -> dict[str, Any]:
    document = schema_3()
    document["schema_version"] = 4
    document.update(
        {
            "ruleset": {"digest": "c" * 64, "engine": "yara-python", "files": []},
            "advisory": {"snapshot": None, "lookups": [], "state": "UNAVAILABLE"},
        }
    )
    return document


def schema_5() -> dict[str, Any]:
    document = schema_4()
    document["schema_version"] = 5
    document["component_bases"] = {"total": 1, "counts": {"nist-mapped": 1}}
    return document


def schema_6() -> dict[str, Any]:
    document = schema_5()
    document["schema_version"] = 6
    document["boot"] = {
        "artifacts": [
            {
                "locator": "board.itb",
                "kind": "fit",
                "default_config": "config-1",
                "boot_enforcement": "unknown",
            }
        ],
        "notes": [],
    }
    document["cache"] = {"enabled": True, "entries_read": 3, "entries_written": 2}
    return document


def schema_8() -> dict[str, Any]:
    """v8 adds the decoded bare-metal address map."""
    document = schema_7()
    document["schema_version"] = 8
    document["mcu"] = {
        "format": "intel-hex",
        "decoder": "ihs-mcu",
        "decoder_version": "1",
        "locator": "board.hex",
        "digest": "c" * 64,
        "ranges": [
            {
                "start": 0x08000000,
                "start_hex": "0x08000000",
                "end": 0x08000020,
                "end_hex": "0x08000020",
                "length": 32,
                "sha256": "d" * 64,
                "source_records": "1-4",
            }
        ],
        "gaps": [],
        "payload_bytes": 32,
        "declared_bytes": 32,
        "payload_sha256": "e" * 64,
        "records": 4,
        "start_address": None,
        "target_address": None,
        "family": None,
        "header": None,
        "diagnostics": [],
        "notes": [],
    }
    return document


def schema_9() -> dict[str, Any]:
    """v9 records which backend produced the extracted tree."""
    document = schema_8()
    document["schema_version"] = 9
    if isinstance(document.get("extraction"), dict):
        document["extraction"] = {**document["extraction"], "backend": "docker"}
    return document


def schema_7() -> dict[str, Any]:
    """v7 adds the source of the type label and the host's capabilities."""
    document = schema_6()
    document["schema_version"] = 7
    document["artifact"]["file_type_source"] = "libmagic"
    document["tool"]["capabilities"] = {
        "libmagic": {"available": True, "version": "540", "detail": None},
        "pyelftools": {"available": True, "version": "0.33", "detail": None},
        "yara-python": {"available": True, "version": "4.5.4", "detail": None},
        "container_runtime_on_path": ["podman"],
    }
    return document


CASES = {
    1: (schema_1, None),
    2: (schema_2, 2),
    3: (schema_3, 3),
    4: (schema_4, 4),
    5: (schema_5, 5),
    6: (schema_6, None),
    7: (schema_7, None),
    8: (schema_8, None),
    9: (schema_9, None),
}


@pytest.fixture(params=sorted(CASES), ids=lambda version: f"schema-{version}")
def upgraded(request: pytest.FixtureRequest) -> tuple[int, dict[str, Any]]:
    version = request.param
    factory, _ = CASES[version]
    return version, load_document(copy.deepcopy(factory()))


# ──────────────────────────────────────────────
# One exact result per version
# ──────────────────────────────────────────────


def test_schema_1_keeps_the_historical_grade_and_records_unknown_coverage() -> None:
    """v1 has no ``schema_version``; it upgrades without inventing coverage."""
    document = load_document(schema_1())

    assert document["schema_version"] == SCHEMA_VERSION
    # The historical display survives, labelled with the method that produced it.
    assert document["legacy_grade"]["total_score"] == 88.0
    assert document["legacy_grade"]["method"] == "v1-12-control-weighted"
    assert document["risk_score"] == document["legacy_grade"]
    # Coverage is unknown, not complete and not empty.
    assert document["assessment"]["coverage"] == "UNKNOWN"
    assert document["assessment"]["completion"] == "UNKNOWN"
    assert "did not record stage coverage" in document["assessment"]["incomplete_reasons"][0]
    assert document["stages"] == []
    # The finding is lifted from the v1 detector section under its own rule id.
    assert len(document["findings"]) == 1
    assert document["findings"][0]["rule_id"] == "unix_shadow_parse"
    assert document["findings"][0]["locations"] == ["etc/config/system:12"]
    # v1 keeps its provenance in the note, not in a migration record it never had.
    assert "upgraded from an unversioned (v1) report" in document["schema_note"]
    assert "migration" not in document
    # Fields a v1 document never recorded are not invented.
    assert "outcome" not in document
    assert "data_sources" not in document

    # It still renders: the finding, the historical grade and the unknown coverage.
    markdown = render(document, "markdown")
    assert "etc/config/system:12" in markdown
    assert "Legacy grade" in markdown
    assert "Coverage unknown" in markdown
    terminal = render(document, "terminal")
    assert "UNKNOWN" in terminal
    assert "unix_shadow_parse" in terminal


def test_schema_2_gains_v3_sections_as_absent_not_empty() -> None:
    source = schema_2()
    document = load_document(source)

    assert document["schema_version"] == SCHEMA_VERSION
    assert document["migration"]["from"] == 2
    # Every recorded fact is preserved (the v7 capability keys are added as
    # explicit absences, never as invented facts).
    assert document["artifact"] == {**source["artifact"], "file_type_source": None}
    assert document["findings"] == source["findings"]
    assert document["stages"] == source["stages"]
    assert document["artifact"] == source["artifact"]
    assert document["outcome"] == source["outcome"]
    # The v3 evidence sections were never recorded: null, with one documented
    # exception -- an ELF record list that says "no records", not "unknown".
    for section in (
        "image_map",
        "extraction",
        "input_binding",
        "opkg",
        "tree",
        "ruleset",
        "advisory",
        "component_bases",
        "boot",
        "cache",
    ):
        assert document[section] is None, section
    assert document["elf"] == {"eligible": 0, "parsed": 0, "records": [], "rejected": []}


def test_schema_3_keeps_its_evidence_and_gains_v4_absences() -> None:
    source = schema_3()
    document = load_document(source)

    assert document["schema_version"] == SCHEMA_VERSION
    assert document["migration"]["from"] == 3
    assert document["image_map"] == source["image_map"]
    # v9 adds the backend as an explicit absence: that version never recorded it.
    assert document["extraction"] == {**source["extraction"], "backend": None}
    assert document["input_binding"] == source["input_binding"]
    assert document["opkg"] == source["opkg"]
    for section in ("ruleset", "advisory", "component_bases", "boot", "cache"):
        assert document[section] is None, section
    # A v3 finding has no typed destination, and the reader does not add one.
    assert "destination" not in document["findings"][0]
    assert "namespaces" not in document["findings"][0]
    assert "ruleset_digest" not in document["findings"][0]


def test_schema_4_does_not_invent_a_component_basis() -> None:
    source = schema_4()
    document = load_document(source)

    assert document["schema_version"] == SCHEMA_VERSION
    assert document["migration"]["from"] == 4
    assert document["ruleset"] == source["ruleset"]
    assert document["advisory"] == source["advisory"]
    assert document["component_bases"] is None
    assert document["boot"] is None
    assert document["cache"] is None
    # A v4 component never recorded how its vendor/product pair was decided.
    assert "cpe_basis" not in document["components"][0]


def test_schema_5_does_not_invent_boot_or_cache() -> None:
    source = schema_5()
    document = load_document(source)

    assert document["schema_version"] == SCHEMA_VERSION
    assert document["migration"]["from"] == 5
    assert document["component_bases"] == source["component_bases"]
    assert document["boot"] is None
    assert document["cache"] is None


def test_schema_6_does_not_invent_a_capability_record() -> None:
    source = schema_6()
    document = load_document(source)

    assert document["schema_version"] == SCHEMA_VERSION
    assert document["migration"]["from"] == 6
    # v6 facts survive untouched.
    assert document["boot"] == source["boot"]
    assert document["cache"] == source["cache"]
    assert document["artifact"]["file_type"] == source["artifact"]["file_type"]
    # Two facts v6 never recorded are null: "not recorded", not "nothing found".
    assert document["artifact"]["file_type_source"] is None
    assert document["tool"]["capabilities"] is None
    assert document["tool"]["version"] == source["tool"]["version"]


def test_schema_7_does_not_invent_an_address_map() -> None:
    source = schema_7()
    document = load_document(source)

    assert document["schema_version"] == SCHEMA_VERSION
    assert document["migration"]["from"] == 7
    assert document["mcu"] is None
    assert document["artifact"]["file_type_source"] == source["artifact"]["file_type_source"]

    # An upgraded document says nothing about a bare-metal image.
    assert "Bare-metal" not in render(document, "terminal")
    assert "Bare-metal" not in render(document, "markdown")


def test_schema_9_round_trips_without_a_migration_record() -> None:
    source = schema_9()
    document = load_document(source)

    assert document == source
    assert document["schema_version"] == SCHEMA_VERSION
    assert "migration" not in document
    assert "schema_note" not in document
    # A recorded boot manifest, cache summary, type source and capability set
    # are facts, not absences.
    assert document["boot"]["artifacts"][0]["default_config"] == "config-1"
    assert document["cache"]["entries_read"] == 3
    assert document["artifact"]["file_type_source"] == "libmagic"
    assert document["tool"]["capabilities"]["pyelftools"]["version"] == "0.33"
    assert document["mcu"]["format"] == "intel-hex"
    assert document["extraction"]["backend"] == "docker"

    # It renders with the provenance and the address map visible.
    markdown = render(document, "markdown")
    assert "identified by libmagic" in markdown
    assert "Host capabilities" in markdown
    assert "0x08000000" in markdown
    terminal = render(document, "terminal")
    assert "identified by libmagic" in terminal
    assert "Bare-metal image" in terminal


# ──────────────────────────────────────────────
# The invariant that applies to every version
# ──────────────────────────────────────────────

#: Facts each source version could not record. They must be ``None`` in the
#: upgrade: an empty list or ``False`` would read as a measured negative.
ABSENT_BY_VERSION: dict[int, tuple[str, ...]] = {
    1: (
        "image_map",
        "extraction",
        "input_binding",
        "elf",
        "opkg",
        "tree",
        "ruleset",
        "advisory",
        "component_bases",
        "boot",
        "cache",
    ),
    2: (
        "image_map",
        "extraction",
        "input_binding",
        "opkg",
        "tree",
        "ruleset",
        "advisory",
        "component_bases",
        "boot",
        "cache",
    ),
    3: ("ruleset", "advisory", "component_bases", "boot", "cache"),
    4: ("component_bases", "boot", "cache"),
    5: ("boot", "cache"),
    6: (),
    7: (),
    8: (),
    9: (),
}


def test_absent_facts_are_null_for_every_upgrade(
    upgraded: tuple[int, dict[str, Any]],
) -> None:
    version, document = upgraded
    for section in ABSENT_BY_VERSION[version]:
        value = document[section]
        assert value is None, (
            f"schema {version}: {section} upgraded to {value!r}; an absent fact"
            " must be null, never [] or false"
        )
        assert not isinstance(value, (list, bool))


def test_no_upgrade_invents_a_capability_record(
    upgraded: tuple[int, dict[str, Any]],
) -> None:
    """Before schema 7, the two nested facts are null rather than empty."""
    version, document = upgraded
    if version in (7, 8, 9):
        # Recorded by that version, so not an absence.
        assert document["artifact"]["file_type_source"] == "libmagic"
        assert document["tool"]["capabilities"] is not None
        if version == 7:
            # ... but a v7 document never recorded an address map.
            assert document["mcu"] is None
        if version in (7, 8):
            # ... nor which backend produced the extracted tree.
            assert document["extraction"]["backend"] is None
        return
    assert document["artifact"]["file_type_source"] is None, (
        f"schema {version}: the type source was invented"
    )
    assert document["tool"]["capabilities"] is None, (
        f"schema {version}: a capability map was invented; an empty map reads as"
        ' "nothing was available"'
    )
    # And the absence stays out of the rendered output.
    assert "Host capabilities" not in render(document, "markdown")


def test_no_upgrade_invents_a_field(upgraded: tuple[int, dict[str, Any]]) -> None:
    """The top-level key set is exact for each source version.

    Schema 6 is the reference shape. Every upgrade adds exactly the migration
    note and the migration record; v1 additionally keeps ``legacy_grade`` and
    never gains the schema-2 ``outcome``/``data_sources`` it never wrote.
    """
    version, document = upgraded
    schema_nine = set(schema_9())
    if version == 9:
        expected = schema_nine
    elif version == 1:
        expected = (schema_nine - {"outcome", "data_sources"}) | {
            "schema_note",
            "legacy_grade",
        }
    else:
        expected = schema_nine | {"schema_note", "migration"}
    assert set(document) == expected, (
        f"schema {version}: unexpected keys {sorted(set(document) - expected)};"
        f" missing {sorted(expected - set(document))}"
    )
    if version in (2, 3, 4, 5, 6, 7, 8):
        assert document["migration"]["to"] == SCHEMA_VERSION
