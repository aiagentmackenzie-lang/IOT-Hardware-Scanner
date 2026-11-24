"""The versioned report document and every renderer.

One document is the single source for JSON, Markdown, HTML and terminal
output. Renderers read the document, never the live ``ScanContext``, so what is
written to disk and what is printed can never disagree, and replay renders the
same facts the original scan recorded.

Schema history
--------------
**Schema 2** (milestone A) introduced assessment completion, per-stage coverage,
named checks and findings as separate top-level sections, and retired the
aggregate grade for new scans.

**Schema 4** (milestone C) typed every finding's destination, recorded the one
compiled rule set and its digest, recorded the local advisory snapshot and one
lookup per component, and made ``rule_compilation`` a required stage. Schema 5
adds the component basis: every installed-package record now becomes a
component, and each one records whether its vendor/product pair is
``nist-mapped``, named from the ``opkg-package-name``, or a ``banner``
candidate. Counts per basis are recorded beside ``components``.

**Schema 3** (milestone B) adds the evidence a shipped-image inventory needs:

* ``image_map`` — artifact/parent/digest/format/coordinate system/offset/length
  and decoder for every container and file the scan opened;
* ``extraction`` — the worker, its image digest, the helper version and the
  budgets that were enforced;
* ``elf`` — one record per ELF file, read from its own header and program
  headers, with the properties that stayed unknown listed;
* ``opkg`` — the installed-package database: every record with its complete
  version string, architecture, held state and byte range in the database;
* ``input_binding`` — the private snapshot every read was bound to, and whether
  the original path still matched afterwards;
* ``tree`` — the deterministic per-entry manifest and any declaration compared
  against it.

Reading a schema-2 document is supported: :func:`load_document` adds the new
sections as explicitly unavailable rather than guessing, and
``docs/MIGRATION-v2.md`` records the change.

Reading an unversioned (v1) document
------------------------------------
:func:`load_document` upgrades v1 in place of guessing: findings are lifted out
of ``credentials``/``cve``/``c2_malware``, the historical grade is kept under
``legacy_grade``, and coverage is recorded as unknown rather than assumed
complete.
"""

from __future__ import annotations

import html
import json
import logging
import os
import shutil
import tempfile
from datetime import datetime, timezone
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import Any

from iot_hardware_scanner.models import (
    Completion,
    ControlResult,
    ScanContext,
    StageResult,
)

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 8

#: Schema versions this reader upgrades. A v2 document keeps every recorded
#: fact and gains explicit "not recorded" markers for the v3 sections.
READABLE_SCHEMA_VERSIONS = frozenset({2, 3, 4, 5, 6, 7, 8})

#: Component bases, in report order. Every count is present even when zero.
COMPONENT_BASES = ("nist-mapped", "opkg-package-name", "banner")
TOOL_NAME = "iot-hardware-scanner"

_EXTENSIONS = {"json": ".json", "markdown": ".md", "html": ".html", "terminal": ".txt"}


class ReportWriteError(Exception):
    """Raised when the requested report destination cannot be written."""


# ──────────────────────────────────────────────
# Building the document from a scan
# ──────────────────────────────────────────────


def _stage_to_dict(stage: StageResult) -> dict[str, Any]:
    return {
        "stage": stage.stage_id.value,
        "status": stage.status.value,
        "required": stage.required,
        "reason": stage.reason,
        "inspected": stage.inspected,
        "eligible": stage.eligible,
        "omissions": stage.omissions,
        "dependency": stage.dependency,
    }


def _control_to_dict(control: ControlResult) -> dict[str, Any]:
    return {
        "control_id": control.control_id,
        "control_name": control.control_name,
        "status": control.status.value,
        "evidence_status": control.evidence_status,
        "applicability": control.applicability,
        "question": control.question,
        "required_source": control.required_source,
        "applicability_note": control.applicability_note,
        "result": control.result,
        "evidence": control.evidence,
        "remediation": control.remediation,
        "source_stage": control.source_stage.value if control.source_stage else None,
    }


def _tool_section(version: str) -> dict[str, Any]:
    """The scanner, and what this host could actually use (schema 7).

    A version string alone is not enough to audit a report: whether libmagic
    loaded, and which parser versions produced the records, change what the run
    could see. The plan's rule is to record what ran, not what was available in
    principle.
    """
    return {
        "name": TOOL_NAME,
        "version": version,
        "capabilities": {
            "libmagic": _libmagic_capability(),
            "pyelftools": _package_capability("pyelftools"),
            "yara-python": _package_capability("yara-python"),
            # Presence on PATH only. Reachability, the isolation mode and the
            # image actually used are recorded in the extraction section.
            "container_runtime_on_path": [
                name for name in ("podman", "docker") if shutil.which(name)
            ],
        },
    }


def _package_capability(distribution: str) -> dict[str, Any]:
    """Whether a required parser package is installed, and its version."""
    try:
        version = importlib_metadata.version(distribution)
    except importlib_metadata.PackageNotFoundError:
        return {"available": False, "version": None, "detail": f"{distribution} not installed"}
    return {"available": True, "version": version, "detail": None}


def _libmagic_capability() -> dict[str, Any]:
    """Whether this host can use libmagic, and why not when it cannot.

    ``import magic`` fails for two different reasons -- the binding is missing,
    or the shared library is -- so the reason is kept instead of being flattened
    into "not installed".
    """
    try:
        import magic
    except ImportError as exc:
        return {
            "available": False,
            "version": None,
            "detail": str(exc) or "python-magic is not installed",
        }
    try:
        # Importing the binding is not proof the library answers: call it.
        magic.from_buffer(b"\x7fELF\x02\x01\x01\x00", mime=True)
    except Exception as exc:  # pragma: no cover - depends on the host library
        return {"available": False, "version": None, "detail": str(exc)}
    version = None
    version_query = getattr(magic, "version", None)
    if callable(version_query):
        try:
            version = str(version_query())
        except Exception:  # pragma: no cover - depends on the host library
            version = None
    return {"available": True, "version": version, "detail": None}


def build_document(context: ScanContext, version: str) -> dict[str, Any]:
    """Build a report document at :data:`SCHEMA_VERSION` for a completed scan."""
    from iot_hardware_scanner.scanner.assessment import collect_findings

    assessment = context.assessment
    findings = collect_findings(context)

    document: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "tool": _tool_section(version),
        "scan_id": context.scan_id,
        "scan_date": context.started_at.isoformat() if context.started_at else None,
        "report_generated": datetime.now(tz=timezone.utc).isoformat(),
        "artifact": {
            "kind": context.input_kind.value,
            "name": context.firmware_name,
            "path": str(context.firmware_path),
            "size": context.file_size,
            "sha256": context.file_hash_sha256,
            "md5": context.file_hash_md5,
            "file_type": context.file_type,
            "file_type_source": context.file_type_source,
            "size_category": context.size_category.value,
            "manifest_entries": context.input_manifest_entries,
        },
        "assessment": _assessment_section(context),
        "stages": [_stage_to_dict(s) for s in (assessment.stages if assessment else [])],
        "controls": [_control_to_dict(c) for c in context.controls],
        "findings": [_finding_to_dict(f) for f in findings],
        "inventory": _inventory_section(context),
        "entropy": _entropy_section(context),
        "image_map": _image_map_section(context),
        "extraction": _extraction_section(context),
        "input_binding": _input_binding_section(context),
        "elf": _elf_section(context),
        "opkg": _opkg_section(context),
        "tree": _tree_section(context),
        "ruleset": _ruleset_section(context),
        "advisory": _advisory_section(context),
        "components": _components_section(context),
        "component_bases": _component_bases_section(context),
        "boot": _boot_section(context),
        "cache": _cache_section(context),
        "mcu": _mcu_section(context),
        "data_sources": _data_sources_section(),
        "risk_score": None,
    }
    return document


def _cache_section(context: ScanContext) -> dict[str, Any] | None:
    """What the repeated-work cache did, when the operator enabled one (5C)."""
    return context.cache_summary


def _boot_section(context: ScanContext) -> dict[str, Any] | None:
    """The boot artifacts, or ``None`` when this profile read no boot manifest."""
    return context.boot.as_dict() if context.boot is not None else None


def _mcu_section(context: ScanContext) -> dict[str, Any] | None:
    """The decoded address map, or ``None`` when no bare-metal image was decoded.

    The decoded bytes themselves are never serialised: a report carries
    addresses, digests and diagnostics, not a second copy of the firmware.
    """
    return context.mcu.as_dict() if context.mcu is not None else None


def _data_sources_section() -> list[dict[str, Any]]:
    """Record which bundled data backed this run, with digests."""
    from iot_hardware_scanner import resources

    try:
        return resources.describe_loaded()
    except Exception as exc:  # a missing install resource is a real finding
        return [{"name": "<unavailable>", "error": str(exc)}]


def _assessment_section(context: ScanContext) -> dict[str, Any]:
    assessment = context.assessment
    if assessment is None:
        return {
            "profile": context.profile,
            "profile_version": context.profile_version,
            "completion": Completion.UNKNOWN.value,
            "coverage": "UNKNOWN",
            "incomplete_reasons": ["no assessment was recorded for this scan"],
        }
    counts = assessment.check_counts
    return {
        "profile": assessment.profile,
        "profile_version": assessment.profile_version,
        "completion": assessment.completion.value,
        "coverage": "RECORDED",
        "incomplete_reasons": assessment.incomplete_reasons,
        "missing_required_dependencies": assessment.missing_required_dependencies,
        "limitations": assessment.limitations,
        "check_counts": counts,
        "started_at": assessment.started_at.isoformat() if assessment.started_at else None,
        "completed_at": assessment.completed_at.isoformat() if assessment.completed_at else None,
    }


def _finding_to_dict(finding: Any) -> dict[str, Any]:
    return {
        "rule_id": finding.rule_id,
        "severity": finding.severity.value,
        "title": finding.title,
        "description": finding.description,
        "category": finding.category,
        "locations": finding.locations,
        "evidence": finding.evidence,
        "remediation": finding.remediation,
        "critical_qualified": finding.critical_qualified,
        "destination": finding.destination,
        "namespaces": finding.namespaces,
        "ruleset_digest": finding.ruleset_digest,
    }


def _inventory_section(context: ScanContext) -> dict[str, Any] | None:
    inventory = context.filesystem_inventory
    if inventory is None:
        return None
    return {
        "files": inventory.total_files,
        "directories": inventory.total_directories,
        "bytes": inventory.total_size,
        "metadata_source": inventory.metadata_source,
        "permission_unknown": inventory.permission_unknown_count,
        "roots": [
            {
                "root_id": root.root_id,
                "locator": root.locator,
                "files": root.files,
                "directories": root.directories,
                "bytes": root.bytes,
                "metadata_source": root.metadata_source,
                "artifact_id": root.artifact_id,
                "omissions": root.omissions,
            }
            for root in inventory.roots
        ],
        "suid_binaries": [str(f.path) for f in inventory.suid_binaries],
        "world_writable_files": [str(f.path) for f in inventory.world_writable_files],
        "boot_evidence": [
            {
                "root_id": e.root_id,
                "source": e.source,
                "line": e.line_number,
                "action": e.action,
                "program": e.program,
                "configured": e.configured,
                "directive": e.directive,
            }
            for e in inventory.boot_evidence
        ],
    }


def _entropy_section(context: ScanContext) -> dict[str, Any] | None:
    profile = context.entropy_profile
    if profile is None:
        return None
    return {
        "units": profile.units,
        "overall_entropy": profile.overall_entropy,
        "window_mean_entropy": profile.window_mean_entropy,
        "bytes_analyzed": profile.bytes_analyzed,
        "sampled": profile.bytes_sampled,
        "block_size": profile.block_size,
        "total_blocks": profile.total_blocks,
        "regions": [
            {
                "start": r.start_offset,
                "end": r.end_offset,
                "size": r.size,
                "avg_entropy": r.avg_entropy,
                "classification": r.classification,
            }
            for r in profile.regions
        ],
        "notes": [
            "Entropy describes byte distribution only. It does not establish "
            "encryption, readability, or any control verdict.",
        ],
    }


def _ruleset_section(context: ScanContext) -> dict[str, Any] | None:
    """The one compiled rule set this run used, and what it could not compile."""
    info = context.ruleset
    if info is None:
        return None
    return {
        "digest": info.digest,
        "engine": info.engine,
        "engine_version": info.engine_version,
        "source": info.source,
        "rule_files": [
            {
                "namespace": record.namespace,
                "name": record.name,
                "sha256": record.sha256,
                "rule_count": record.rule_count,
                "destinations": record.destinations,
            }
            for record in info.files
        ],
        "compile_errors": list(info.errors),
        "notes": [
            "The rule set is compiled once per run and shared by every detector.",
            "A compile error is a coverage gap: it is listed here and in the "
            "rule_compilation stage.",
        ],
    }


def _advisory_section(context: ScanContext) -> dict[str, Any] | None:
    """The local snapshot that was applied, and one lookup per component."""
    advisory = context.advisory
    if advisory is None:
        return None
    snapshot = advisory.snapshot
    return {
        "state": advisory.state,
        "complete": advisory.complete,
        "matched": advisory.matched,
        "kev_matches": advisory.kev_matches,
        "kev_source": advisory.kev_source,
        "keyword_candidates_rejected": advisory.keyword_candidates_rejected,
        "snapshot": (
            {
                "path": snapshot.path,
                "digest_sha256": snapshot.digest_sha256,
                "schema": snapshot.schema,
                "provider": snapshot.provider,
                "acquired_at": snapshot.acquired_at,
                "entries": snapshot.entries,
                "age_days": snapshot.age_days,
                "stale": snapshot.stale,
                "includes_kev": snapshot.includes_kev,
                "sample": snapshot.sample,
            }
            if snapshot is not None
            else None
        ),
        "lookups": [
            {
                "component": lookup.component,
                "version": lookup.version,
                "cpe": lookup.cpe,
                "state": lookup.state,
                "matches": lookup.matches,
                "reason": lookup.reason,
            }
            for lookup in advisory.lookups
        ],
        "notes": [
            "The scan issued no network request: the snapshot was read from disk.",
            "KEV membership, public exploit availability and applicability are "
            "independent facts and are recorded separately.",
        ],
    }


def _component_bases_section(context: ScanContext) -> dict[str, Any]:
    """How many components came from each basis, and what each basis means."""
    counts = dict.fromkeys(COMPONENT_BASES, 0)
    for component in context.software_components:
        basis = component.cpe_basis or "banner"
        counts[basis] = counts.get(basis, 0) + 1
    return {
        "counts": counts,
        "total": len(context.software_components),
        "notes": [
            "nist-mapped: vendor and product come from an authoritative NIST CPE "
            "dictionary row, recorded in the single shipped mapping.",
            "opkg-package-name: no authoritative NIST row exists; the name is the "
            "opkg package's own name with vendor openwrt. It is a traceable "
            "identity, not a claim that NIST knows the product.",
            "banner: a version string found in a file. Candidate confidence, never "
            "an installed-package record.",
        ],
    }


def _components_section(context: ScanContext) -> list[dict[str, Any]]:
    return [
        {
            "vendor": c.vendor,
            "product": c.product,
            "version": c.version,
            "cpe": c.cpe_string,
            "cpe_basis": c.cpe_basis,
            "source_file": str(c.source_file),
            "source_method": c.source_method,
            "architecture": c.architecture,
            "confidence": c.confidence,
            "evidence": c.evidence,
            "digest_sha256": c.digest_sha256,
            "occurrences": c.occurrences,
        }
        for c in context.software_components
    ]


def _input_binding_section(context: ScanContext) -> dict[str, Any] | None:
    snapshot = context.input_snapshot
    if snapshot is None:
        return None
    return {
        "original_path": str(snapshot.original_path),
        "snapshot_path": str(snapshot.snapshot_path),
        "declared_sha256": snapshot.declared_sha256,
        "verified_sha256": snapshot.verified_sha256,
        "size": snapshot.size,
        "budget_bytes": snapshot.budget_bytes,
        "immutable": snapshot.immutable,
        "source_changed": snapshot.source_changed,
        "source_reverified": snapshot.source_reverified,
        "digest_matches": snapshot.digest_matches,
        "note": (
            "Every analysis read came from this read-only snapshot, whose digest was "
            "verified against the one recorded at ingest."
        ),
    }


def _image_map_section(context: ScanContext) -> dict[str, Any] | None:
    image_map = context.image_map
    if image_map is None:
        return None
    return {
        "root_artifact_id": image_map.root_artifact_id,
        "nodes": [
            {
                "artifact_id": node.artifact_id,
                "parent_id": node.parent_id,
                "digest_sha256": node.digest_sha256,
                "format": node.format,
                "coordinate_system": node.coordinate_system,
                "offset": node.offset,
                "length": node.length,
                "decoder": node.decoder,
                "decoder_version": node.decoder_version,
                "depth": node.depth,
                "locator": node.locator,
                "expanded_bytes": node.expanded_bytes,
                "extent_bytes": node.extent_bytes,
                "details": node.details,
            }
            for node in image_map.nodes
        ],
        "notes": [
            "Wrapper size, expanded size and filesystem extent are three different "
            "numbers and are reported separately.",
            "Offsets belong to the coordinate system named on each node: a byte range "
            "in a container, or a path inside an extracted filesystem.",
        ],
    }


def _extraction_section(context: ScanContext) -> dict[str, Any] | None:
    provenance = context.extraction_provenance
    result = context.extraction_result
    if provenance is None and result is None:
        return None
    payload: dict[str, Any] = {
        "state": result.state if result is not None else None,
        "success": result.success if result is not None else None,
        "omissions": list(result.omissions) if result is not None else [],
        "errors": list(result.extraction_errors) if result is not None else [],
    }
    if provenance is not None:
        payload.update(
            {
                "worker": provenance.worker,
                "isolation": provenance.isolation,
                "worker_image": provenance.worker_image,
                "worker_digest": provenance.worker_digest,
                "helper": provenance.helper,
                "helper_version": provenance.helper_version,
                "helper_argv": provenance.helper_argv,
                "limits": provenance.limits,
                "decoded_bytes": provenance.decoded_bytes,
                "extracted_bytes": provenance.extracted_bytes,
                "extracted_entries": provenance.extracted_entries,
                "durations_seconds": provenance.durations_seconds,
                "scratch_released": provenance.scratch_released,
            }
        )
    return payload


def _elf_section(context: ScanContext) -> dict[str, Any]:
    return {
        "eligible": sum(1 for f in context.filesystem_inventory.findings if f.format == "elf")
        if context.filesystem_inventory
        else 0,
        "parsed": len(context.elf_metadata),
        "records": [
            {
                "locator": record.locator,
                "artifact_id": record.artifact_id,
                "digest_sha256": record.digest_sha256,
                "size": record.size,
                "class": record.elf_class,
                "byte_order": record.byte_order,
                "machine": record.machine,
                "machine_name": record.machine_name,
                "type": record.elf_type,
                "os_abi": record.os_abi,
                "interpreter": record.interpreter,
                "needed": record.needed,
                "soname": record.soname,
                "segments": record.segments,
                "build_id": record.build_id,
                "hardening": {
                    "stack_executable": record.stack_executable,
                    "pie": record.pie,
                    "relro": record.relro,
                    "canary": record.canary,
                    "fortify": record.fortify,
                },
                "unknown": record.unknown,
                "parser": record.parser,
                "parser_version": record.parser_version,
            }
            for record in context.elf_metadata
        ],
        "rejected": (
            list(context.binary_intelligence.rejected) if context.binary_intelligence else []
        ),
    }


def _opkg_section(context: ScanContext) -> dict[str, Any] | None:
    opkg = context.opkg_inventory
    if opkg is None:
        return None
    return {
        "locator": opkg.locator,
        "database_sha256": opkg.database_sha256,
        "byte_length": opkg.byte_length,
        "installed": opkg.installed_count,
        "held": opkg.held_count,
        "unparsed_stanzas": opkg.unparsed_stanzas,
        "truncated": opkg.truncated,
        "parser_version": opkg.parser_version,
        "records": [
            {
                "name": record.name,
                "version": record.version,
                "architecture": record.architecture,
                "status": record.status,
                "installed": record.installed,
                "held": record.held,
                "source": record.source,
                "depends": record.depends,
                "evidence": {
                    "start": record.evidence_start,
                    "end": record.evidence_end,
                    "line": record.evidence_line,
                },
            }
            for record in opkg.records
        ],
        "notes": [
            "Version strings are recorded verbatim, including the -rN package revision.",
            "Database membership is not evidence that every package-owned file is present.",
        ],
    }


def _tree_section(context: ScanContext) -> dict[str, Any] | None:
    if context.input_kind.value != "tree" and context.declared_manifest is None:
        return None
    declared = context.declared_manifest
    return {
        "entries": len(context.tree_manifest),
        "by_kind": _count_kinds(context.tree_manifest),
        "changes_during_traversal": list(context.tree_changes),
        "manifest": [
            {
                "path": entry.relative_path,
                "kind": entry.kind,
                "size": entry.size,
                "sha256": entry.sha256,
                "mode": entry.mode,
                "uid": entry.uid,
                "gid": entry.gid,
                "metadata_source": entry.metadata_source,
                "hardlink_group": entry.hardlink_group,
                "link_target": entry.link_target,
            }
            for entry in context.tree_manifest
        ],
        "declared_manifest": (
            {
                "path": str(declared.path),
                "sha256": declared.sha256,
                "entries": declared.entry_count,
                "declared_only": declared.declared_only,
                "observed_only": declared.observed_only,
            }
            if declared is not None
            else None
        ),
    }


def _count_kinds(entries: list[Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for entry in entries:
        counts[entry.kind] = counts.get(entry.kind, 0) + 1
    return dict(sorted(counts.items()))


# ──────────────────────────────────────────────
# Loading / upgrading
# ──────────────────────────────────────────────


#: Sections a renderer iterates. Each element must be an object: a document is
#: untrusted input (it may have been produced by another tool), so a string or a
#: list where an object belongs is rejected before a renderer indexes into it.
_LIST_SECTIONS = ("findings", "controls", "stages", "components")
_OBJECT_SECTIONS = (
    "artifact",
    "assessment",
    "outcome",
    "entropy",
    "inventory",
    "risk_score",
    "component_bases",
    "boot",
    "cache",
    "mcu",
)


def _validate_document_shape(document: dict[str, Any]) -> None:
    """Reject a document whose sections have the wrong shape.

    This is deliberately shallow: it checks the containers the renderers walk,
    not every field inside them. A hostile or corrupted document must be
    reported as invalid input (exit 3) instead of reaching a renderer and
    raising ``AttributeError`` from ``.get`` on a string.
    """
    version = document.get("schema_version")
    if not isinstance(version, int) or isinstance(version, bool):
        raise ValueError(f"schema_version must be an integer, not {type(version).__name__}")

    for section in _OBJECT_SECTIONS:
        value = document.get(section)
        if value is not None and not isinstance(value, dict):
            raise ValueError(
                f"section {section!r} must be an object or null, not {type(value).__name__}"
            )

    for section in _LIST_SECTIONS:
        value = document.get(section)
        if value is None:
            continue
        if not isinstance(value, list):
            raise ValueError(
                f"section {section!r} must be a list or null, not {type(value).__name__}"
            )
        for index, entry in enumerate(value):
            if not isinstance(entry, dict):
                raise ValueError(
                    f"section {section!r} entry {index} must be an object, "
                    f"not {type(entry).__name__}"
                )


def load_document(data: dict[str, Any]) -> dict[str, Any]:
    """Return a document at the current schema, upgrading an older one if necessary."""
    if not isinstance(data, dict):
        raise ValueError("report document must be a JSON object")

    raw_version = data.get("schema_version")
    if raw_version is None:
        # An unversioned document is a v1 report -- but only if it has the shape
        # of one. Anything else must not be silently relabelled "legacy".
        if not _looks_like_v1(data):
            raise ValueError("document has no schema_version and does not describe a v1 report")
    elif not isinstance(raw_version, int) or isinstance(raw_version, bool):
        raise ValueError(f"schema_version must be an integer, not {type(raw_version).__name__}")

    if raw_version == SCHEMA_VERSION:
        document = dict(data)
        document.setdefault("findings", [])
        document.setdefault("controls", [])
        document.setdefault("stages", [])
        document.setdefault("components", [])
        document.setdefault("component_bases", None)
        document.setdefault("assessment", {})
        document.setdefault("risk_score", None)
        document.setdefault("boot", None)
        document.setdefault("cache", None)
        document.setdefault("mcu", None)
        _mark_unrecorded_capabilities(document)
        _validate_document_shape(document)
        return document

    if raw_version == 7:
        document = _upgrade_v7(data)
    elif raw_version == 6:
        document = _upgrade_v6(data)
    elif raw_version == 5:
        document = _upgrade_v5(data)
    elif raw_version == 4:
        document = _upgrade_v4(data)
    elif raw_version == 3:
        document = _upgrade_v3(data)
    elif raw_version == 2:
        document = _upgrade_v2(data)
    else:
        document = _upgrade_v1(data)

    # Every readable version gains the sections it never had, as explicit
    # "not recorded" values. An absent section is never read as a negative.
    document.setdefault("boot", None)
    document.setdefault("cache", None)
    document.setdefault("mcu", None)
    _mark_unrecorded_capabilities(document)
    _validate_document_shape(document)
    return document


def _mark_unrecorded_capabilities(document: dict[str, Any]) -> None:
    """Give every document the schema-7 capability keys, absent when unknown.

    A version before 7 did not record how its type label was established, nor
    what the host could use. ``None`` says "not recorded"; an empty capability
    map would read as "nothing was available".
    """
    artifact = document.get("artifact")
    if isinstance(artifact, dict):
        artifact.setdefault("file_type_source", None)
    tool = document.get("tool")
    if isinstance(tool, dict):
        tool.setdefault("capabilities", None)


#: Sections a schema-5 document never recorded.
_V5_SECTIONS = ("component_bases",)


def _upgrade_v7(data: dict[str, Any]) -> dict[str, Any]:
    """Lift a schema-7 document to schema 8 without inventing an address map.

    A v7 document was produced before bare-metal images were decoded. ``mcu`` is
    ``None``: no address map was recorded, which is not an empty one.
    """
    document = dict(data)
    document["schema_version"] = SCHEMA_VERSION
    document["schema_note"] = (
        "upgraded from schema 7; bare-metal address maps were not recorded by that version"
    )
    document.setdefault("mcu", None)
    document.setdefault(
        "migration",
        {
            "from": 7,
            "to": SCHEMA_VERSION,
            "note": (
                "This document was produced before Intel HEX, S-record and UF2 images were "
                "decoded into an address map. The mcu section is absent, not empty."
            ),
        },
    )
    return document


def _upgrade_v6(data: dict[str, Any]) -> dict[str, Any]:
    """Lift a schema-6 document to schema 7 without inventing host capability.

    A v6 document recorded the type label but not how it was produced, and its
    tool section carried a version and nothing else. Those two facts are
    ``None`` here: unknown, not false and not empty.
    """
    document = dict(data)
    document["schema_version"] = SCHEMA_VERSION
    document["schema_note"] = (
        "upgraded from schema 6; how the file type was identified and which host "
        "capabilities were available were not recorded by that version"
    )
    document.setdefault(
        "migration",
        {
            "from": 6,
            "to": SCHEMA_VERSION,
            "note": (
                "This document was produced before the report recorded the source of "
                "its file-type label (libmagic, magic bytes or a filename suffix) and "
                "the parser and helper capabilities of the host that ran the scan. "
                "Those facts are absent, not false."
            ),
        },
    )
    return document


def _upgrade_v5(data: dict[str, Any]) -> dict[str, Any]:
    """Lift a schema-5 document to the current schema without inventing a boot section.

    A v5 document was produced before boot manifests were parsed. Its facts are
    preserved; ``boot`` is ``None`` and ``cache`` is ``None`` because neither
    existed in that version. The schema-7 capability keys are added as ``None``
    by :func:`_mark_unrecorded_capabilities`. No unknown becomes a negative.
    """
    document = dict(data)
    document["schema_version"] = SCHEMA_VERSION
    document["schema_note"] = (
        "upgraded from schema 5; boot-manifest analysis and the repeated-work cache "
        "were not recorded in that version, so those sections are absent rather than empty"
    )
    for section in ("boot", "cache"):
        document.setdefault(section, None)
    document.setdefault(
        "migration",
        {
            "from": 5,
            "to": SCHEMA_VERSION,
            "note": (
                "This document was produced before flattened device trees and U-Boot "
                "FIT images were parsed. Boot integrity, signature presence and "
                "verification are not recorded, not 'not found'."
            ),
        },
    )
    return document


def _upgrade_v4(data: dict[str, Any]) -> dict[str, Any]:
    """Lift a schema-4 document to the current schema without inventing a component basis.

    Every v4 fact is preserved. A v4 component never recorded how its
    vendor/product pair was decided, so ``component_bases`` is ``None`` and each
    component's ``cpe_basis`` is left absent rather than guessed.
    """
    document = dict(data)
    document["schema_version"] = SCHEMA_VERSION
    document["schema_note"] = (
        "upgraded from schema 4; components do not record their naming basis in that "
        "version, so the per-basis counts are absent rather than zero"
    )
    for section in _V5_SECTIONS:
        document.setdefault(section, None)
    document.setdefault(
        "migration",
        {
            "from": 4,
            "to": SCHEMA_VERSION,
            "note": (
                "This document was produced before every installed-package record "
                "became a component and before each component recorded its naming "
                "basis. Those facts are absent, not empty."
            ),
        },
    )
    return document


#: Sections a schema-3 document never recorded.
_V4_SECTIONS = ("ruleset", "advisory")


def _upgrade_v3(data: dict[str, Any]) -> dict[str, Any]:
    """Lift a schema-3 document to the current schema without inventing rule identity.

    Every v3 fact is preserved. The rule set and the advisory assessment were
    never recorded, so they are ``None`` with a migration note; findings keep
    their recorded shape and simply have no ``destination``.
    """
    document = dict(data)
    document["schema_version"] = SCHEMA_VERSION
    document["schema_note"] = (
        "upgraded from schema 3; the rule-set identity and advisory assessment were "
        "not recorded by that version"
    )
    for section in _V4_SECTIONS + _V5_SECTIONS:
        document.setdefault(section, None)
    document.setdefault(
        "migration",
        {
            "from": 3,
            "to": SCHEMA_VERSION,
            "note": (
                "This document was produced before each finding carried a typed "
                "destination, before the compiled rule set was identified by digest, "
                "and before advisory applicability could be assessed offline. Those "
                "sections are absent, not empty."
            ),
        },
    )
    return document


#: Sections a schema-2 document never recorded. They are added as explicit
#: "not recorded" markers so a reader can tell an empty section from an absent
#: capability.
_V3_SECTIONS = ("image_map", "extraction", "input_binding", "opkg", "tree")


def _upgrade_v2(data: dict[str, Any]) -> dict[str, Any]:
    """Lift a schema-2 document to the current schema without inventing evidence.

    Every v2 fact is preserved. The v3 sections are set to ``None`` with a
    migration note, and ``elf`` is added with an empty record list because a v2
    report never recorded ELF structure.
    """
    document = dict(data)
    document["schema_version"] = SCHEMA_VERSION
    document["schema_note"] = (
        "upgraded from schema 2; v3 and v4 evidence sections were not recorded"
    )
    for section in _V3_SECTIONS + _V4_SECTIONS + _V5_SECTIONS:
        document.setdefault(section, None)
    document.setdefault("elf", {"eligible": 0, "parsed": 0, "records": [], "rejected": []})
    for key in ("findings", "controls", "stages", "components"):
        document.setdefault(key, [])
    document.setdefault("assessment", {})
    document.setdefault("risk_score", None)
    document.setdefault(
        "migration",
        {
            "from": 2,
            "to": SCHEMA_VERSION,
            "note": (
                "This document was produced before the image map, ELF records, "
                "installed-package records and input binding existed. Those sections "
                "are absent, not empty."
            ),
        },
    )
    return document


def _looks_like_v1(data: dict[str, Any]) -> bool:
    """Whether an unversioned document can be read as the historical v1 format.

    v1 had no ``schema_version``. Treating *every* unversioned object as v1 would
    let an arbitrary JSON file render as a "legacy report"; the historical shape
    is an artifact record plus at least one of the v1 sections.
    """

    def _section(name: str) -> dict[str, Any]:
        value = data.get(name, {})
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise ValueError(f"section {name!r} must be an object in a v1 document")
        return value

    firmware = _section("firmware")
    for name in ("credentials", "cve", "c2_malware", "risk_score", "sbom"):
        _section(name)
    return bool(firmware) or isinstance(data.get("scan_id"), str)


def _upgrade_v1(data: dict[str, Any]) -> dict[str, Any]:
    """Convert an unversioned v1 document without inventing facts.

    Every section the current document defines from 2.1 onward is present as
    ``None`` ("not recorded"), matching what a v2 upgrade produces. Before P1 a
    v1 replay simply omitted them, so a consumer reading
    ``document["image_map"]`` got ``KeyError`` for v1 and ``None`` for v2 for the
    same absence. The v1 format never had these concepts, and ``None`` is the
    marker for that; no fact is invented, and no empty list stands in for an
    unknown.

    ``outcome`` and ``data_sources`` are not added: they are schema-2 fields a v1
    document never recorded, and the renderers treat their absence as unknown.
    """
    firmware = data.get("firmware") or {}
    findings: list[dict[str, Any]] = []

    for entry in (data.get("credentials") or {}).get("findings", []):
        findings.append(
            {
                "rule_id": entry.get("matched_pattern") or "credential.v1",
                "severity": entry.get("severity", "INFO"),
                "title": f"{(entry.get('category') or 'credential').title()} finding",
                "description": entry.get("context", ""),
                "category": entry.get("category", "credential"),
                "locations": [
                    f"{entry.get('file_path', '')}"
                    + (f":{entry['line_number']}" if entry.get("line_number") else "")
                ],
                "evidence": [],
                "remediation": None,
                "critical_qualified": False,
            }
        )
    for entry in (data.get("cve") or {}).get("findings", []):
        findings.append(
            {
                "rule_id": f"advisory.{entry.get('cve_id', 'unknown')}",
                "severity": entry.get("severity", "INFO"),
                "title": entry.get("cve_id", "advisory"),
                "description": entry.get("description", ""),
                "category": "advisory",
                "locations": [entry.get("affected_product", "")],
                "evidence": [],
                "remediation": None,
                "critical_qualified": False,
            }
        )
    for entry in (data.get("c2_malware") or {}).get("findings", []):
        findings.append(
            {
                "rule_id": f"c2.{entry.get('indicator_type', 'indicator')}",
                "severity": entry.get("severity", "INFO"),
                "title": "C2 indicator",
                "description": entry.get("description", ""),
                "category": "c2_indicator",
                "locations": [entry.get("file_path", "")],
                "evidence": [],
                "remediation": None,
                "critical_qualified": False,
            }
        )

    legacy_grade = None
    if data.get("risk_score"):
        risk = data["risk_score"]
        legacy_grade = {
            "method": "v1-12-control-weighted",
            "total_score": risk.get("total_score"),
            "risk_level": risk.get("risk_level"),
            "executive_summary": risk.get("executive_summary", ""),
            "control_scores": risk.get("control_scores", []),
            "owasp_iot_mapping": risk.get("owasp_iot_mapping", {}),
        }

    return {
        "schema_version": SCHEMA_VERSION,
        "schema_note": "upgraded from an unversioned (v1) report",
        "tool": data.get("tool") or {"name": TOOL_NAME, "version": "1.x"},
        "scan_id": data.get("scan_id"),
        "scan_date": data.get("scan_date"),
        "report_generated": datetime.now(tz=timezone.utc).isoformat(),
        "artifact": {
            "kind": "file",
            "name": firmware.get("name"),
            "path": firmware.get("path"),
            "size": firmware.get("size"),
            "sha256": firmware.get("sha256"),
            "md5": firmware.get("md5"),
            "file_type": firmware.get("file_type"),
            "size_category": firmware.get("size_category"),
            "manifest_entries": None,
        },
        "assessment": {
            "profile": "v1-legacy",
            "profile_version": "1.x",
            "completion": Completion.UNKNOWN.value,
            "coverage": "UNKNOWN",
            "incomplete_reasons": [
                "This document was produced by a version that did not record "
                "stage coverage; what ran and what was omitted is unknown."
            ],
            "missing_required_dependencies": [],
            "limitations": ["Historical report replayed for rendering. Nothing was re-analysed."],
            "check_counts": {},
            "started_at": None,
            "completed_at": None,
        },
        "stages": [],
        "controls": [],
        "findings": findings,
        "inventory": None,
        "entropy": data.get("entropy"),
        "image_map": None,
        "extraction": None,
        "input_binding": None,
        "elf": None,
        "opkg": None,
        "tree": None,
        "ruleset": None,
        "advisory": None,
        "components": (data.get("sbom") or {}).get("components", []),
        "component_bases": None,
        "risk_score": legacy_grade,
        "legacy_grade": legacy_grade,
    }


# ──────────────────────────────────────────────
# Rendering — JSON
# ──────────────────────────────────────────────


def render_json(document: dict[str, Any]) -> str:
    """Serialize the document exactly as stored."""
    return json.dumps(document, indent=2, default=str)


# ──────────────────────────────────────────────
# Rendering — shared helpers
# ──────────────────────────────────────────────


def _completion_line(document: dict[str, Any]) -> str:
    assessment = document.get("assessment") or {}
    completion = assessment.get("completion", "UNKNOWN")
    if completion == Completion.COMPLETE.value:
        return "Assessment: COMPLETE — every required stage ran"
    if completion == Completion.INCOMPLETE.value:
        count = len(assessment.get("incomplete_reasons") or [])
        return f"Assessment: INCOMPLETE — {count} required stage(s) did not finish (listed below)"
    return "Assessment: UNKNOWN — this document does not record which stages ran (legacy report)"


def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        key = str(finding.get("severity", "INFO"))
        counts[key] = counts.get(key, 0) + 1
    return counts


def _file_type_source_suffix(artifact: dict[str, Any]) -> str:
    """How the type label was established, when the document records it."""
    source = artifact.get("file_type_source")
    if not source:
        return ""
    return f" (identified by {source})"


def _identified_line(artifact: dict[str, Any]) -> str:
    """The terminal one-liner for type and provenance, or nothing when unknown."""
    suffix = _file_type_source_suffix(artifact)
    if not suffix:
        return ""
    return f"  type:    {artifact.get('file_type')}{suffix}"


def _capabilities_line(document: dict[str, Any]) -> str:
    """One Markdown line naming what the host could use (schema 7 only).

    ``None`` means the version never recorded capabilities, which is not the same
    as "nothing was available", so an upgraded document gets no line at all.
    """
    tool = document.get("tool") or {}
    capabilities = tool.get("capabilities")
    if not isinstance(capabilities, dict):
        return ""
    parts: list[str] = []
    for name in ("libmagic", "pyelftools", "yara-python"):
        entry = capabilities.get(name)
        if not isinstance(entry, dict):
            continue
        if entry.get("available"):
            version = entry.get("version")
            parts.append(f"{name}" + (f" {version}" if version else ""))
        else:
            detail = entry.get("detail") or "unavailable"
            parts.append(f"{name} **unavailable** ({detail})")
    runtimes = capabilities.get("container_runtime_on_path")
    if isinstance(runtimes, list):
        parts.append("container runtime on PATH: " + (", ".join(runtimes) if runtimes else "none"))
    return "**Host capabilities:** " + "; ".join(parts) if parts else ""


# ──────────────────────────────────────────────
# Rendering — terminal
# ──────────────────────────────────────────────


def render_terminal(document: dict[str, Any]) -> str:
    """Plain-text summary suitable for a terminal or CI log."""
    artifact = document.get("artifact") or {}
    assessment = document.get("assessment") or {}
    findings = document.get("findings") or []
    controls = document.get("controls") or []

    lines = [
        f"Artifact: {artifact.get('name')} ({artifact.get('kind', 'file')})",
        f"  size:    {artifact.get('size')} bytes",
        f"  sha256:  {artifact.get('sha256')}",
        f"  profile: {assessment.get('profile')} v{assessment.get('profile_version')}",
        _completion_line(document),
    ]
    identified = _identified_line(artifact)
    if identified:
        lines.insert(3, identified)

    missing = assessment.get("missing_required_dependencies") or []
    if missing:
        lines.append("Missing required dependencies:")
        lines.extend(f"  - {item}" for item in missing)

    reasons = [
        r
        for r in (assessment.get("incomplete_reasons") or [])
        if not any(dep in r for dep in missing)
    ]
    if reasons and assessment.get("completion") == Completion.INCOMPLETE.value:
        lines.append("Incomplete work:")
        lines.extend(f"  - {item}" for item in reasons)

    counts = _severity_counts(findings)
    if findings:
        summary = ", ".join(f"{k} {v}" for k, v in sorted(counts.items()))
        lines.append(f"Findings: {len(findings)} ({summary})")
        for finding in findings:
            locations = ", ".join(finding.get("locations") or [])
            qualified = "critical" if finding.get("critical_qualified") else "review"
            lines.append(
                f"  [{finding.get('severity')}/{qualified}] {finding.get('rule_id')} — {locations}"
            )
    else:
        lines.append("Findings: none reported")

    if controls:
        performed = sum(1 for c in controls if c.get("status") == "PERFORMED")
        inconclusive = sum(1 for c in controls if c.get("status") == "INCONCLUSIVE")
        omitted = sum(1 for c in controls if c.get("status") == "OMITTED")
        not_applicable = sum(1 for c in controls if c.get("status") == "NOT_APPLICABLE")
        lines.append(
            f"Checks: {performed} performed, {inconclusive} inconclusive, "
            f"{omitted} omitted, {not_applicable} not applicable "
            f"(of {len(controls)})"
        )

    legacy = document.get("legacy_grade") or document.get("risk_score")
    if legacy:
        lines.append(
            f"Legacy grade (v1 method, not comparable to a v2 assessment): "
            f"{legacy.get('total_score')}/100 {legacy.get('risk_level')}"
        )

    entropy = document.get("entropy")
    if entropy:
        scope = "sampled" if entropy.get("sampled") else "whole input"
        lines.append(
            f"Entropy: {entropy.get('overall_entropy')} bits/byte "
            f"over {entropy.get('bytes_analyzed')} bytes ({scope})"
        )

    image_map = document.get("image_map") or {}
    nodes = image_map.get("nodes") or []
    if nodes:
        lines.append("Image map:")
        for node in nodes:
            # A node from an older or partial document may not carry numbers.
            # The absence is printed as "not recorded", never raised over.
            extent_value = node.get("extent_bytes")
            expanded_value = node.get("expanded_bytes")
            length_value = node.get("length")
            extent = f", extent {extent_value:,}" if isinstance(extent_value, int) else ""
            expanded = f" -> {expanded_value:,} decoded" if isinstance(expanded_value, int) else ""
            length = (
                f"{length_value:,} bytes" if isinstance(length_value, int) else "length unrecorded"
            )
            lines.append(
                f"  [{node.get('artifact_id')}] {node.get('format')} "
                f"{node.get('coordinate_system')} {length}{expanded}{extent}"
                f" (decoder {node.get('decoder')}"
                + (f" {node['decoder_version']}" if node.get("decoder_version") else "")
                + ")"
            )

    mcu = document.get("mcu") or {}
    if mcu:
        ranges = mcu.get("ranges") or []
        gaps = mcu.get("gaps") or []
        lines.append(
            f"Bare-metal image: {mcu.get('format')} ({mcu.get('decoder')} "
            f"{mcu.get('decoder_version')}), {mcu.get('records')} record(s)"
        )
        lines.append(f"  payload: {mcu.get('payload_bytes')} byte(s) over {len(ranges)} range(s)")
        for item in ranges[:8]:
            lines.append(
                f"  [{item.get('start_hex')}-{item.get('end_hex')}] "
                f"{item.get('length')} byte(s), records {item.get('source_records')}"
            )
        if gaps:
            lines.append(
                f"  {len(gaps)} unobserved gap(s) (never zero-filled): "
                + ", ".join(f"{i.get('start_hex')}-{i.get('end_hex')}" for i in gaps[:4])
            )
        if mcu.get("family"):
            lines.append(f"  family id {mcu.get('family')}")
        if mcu.get("start_address_hex"):
            lines.append(
                f"  declared start address {mcu.get('start_address_hex')} "
                "(an intention, not the running image)"
            )
        for item in (mcu.get("diagnostics") or [])[:6]:
            lines.append(f"  ! {item.get('kind')}: {item.get('detail')}")

    boot = document.get("boot") or {}
    for artifact in boot.get("artifacts") or []:
        configurations = artifact.get("configurations") or []
        payloads = artifact.get("referenced_payloads") or []
        lines.append(
            f"Boot: {artifact.get('kind')} {artifact.get('locator')} — "
            f"{len(configurations)} configuration(s), default "
            f"{artifact.get('default_config') or 'unknown'}, "
            f"{len(payloads)} payload(s)"
        )
        for payload in payloads:
            signature = payload.get("signature") or {}
            lines.append(
                f"  payload {payload.get('node')} ({payload.get('kind')}): integrity "
                f"{payload.get('integrity')}, signature "
                f"{'present' if signature.get('present') else 'absent'}"
            )
        for configuration in configurations:
            signature = configuration.get("signature") or {}
            if signature.get("present"):
                lines.append(
                    f"  configuration {configuration.get('name')}: signature "
                    f"{signature.get('algo')}, verified "
                    f"{signature.get('verified')} ({signature.get('key_source')})"
                )
        lines.append(
            f"  boot enforcement: {artifact.get('boot_enforcement', 'unknown')} "
            "(a static parser cannot establish it)"
        )
        for note in artifact.get("notes") or []:
            lines.append(f"  note: {note}")

    extraction = document.get("extraction")
    if extraction:
        lines.append(
            f"Extraction: {extraction.get('state')} via {extraction.get('worker')} "
            f"({extraction.get('isolation')})"
            + (
                f", helper {extraction.get('helper_version')}"
                if extraction.get("helper_version")
                else ""
            )
            + (
                f", image {extraction.get('worker_digest')}"
                if extraction.get("worker_digest")
                else ""
            )
        )
        for omission in extraction.get("omissions") or []:
            lines.append(f"  omission: {omission}")

    opkg = document.get("opkg")
    if opkg:
        lines.append(
            f"Packages: {opkg.get('installed')} installed, {opkg.get('held')} held "
            f"from {opkg.get('locator')} (sha256 {str(opkg.get('database_sha256'))[:16]}…)"
        )

    elf = document.get("elf") or {}
    if elf.get("records"):
        lines.append(
            f"ELF: {elf.get('parsed')} of {elf.get('eligible')} eligible file(s) parsed from "
            "their own headers"
        )

    ruleset = document.get("ruleset")
    if ruleset:
        lines.append(
            f"Rule set: {len(ruleset.get('rule_files') or [])} file(s), digest "
            f"{str(ruleset.get('digest'))[:16]}… ({ruleset.get('source')})"
        )
        for error in ruleset.get("compile_errors") or []:
            lines.append(f"  rule gap: {error.get('file')}: {error.get('reason')}")

    advisory = document.get("advisory")
    if advisory:
        snapshot = advisory.get("snapshot") or {}
        lines.append(
            f"Advisory: {advisory.get('state')} — {advisory.get('matched')} match(es), "
            f"{advisory.get('kev_matches')} in KEV, {len(advisory.get('lookups') or [])} "
            f"lookup(s); snapshot {str(snapshot.get('digest_sha256'))[:16]}…"
        )
    elif document.get("stages"):
        lines.append("Advisory: not assessed (no snapshot supplied)")

    binding = document.get("input_binding")
    if binding:
        lines.append(
            f"Input binding: snapshot {'verified' if binding.get('digest_matches') else 'MISMATCH'}"
            f"; source changed after ingest: {'yes' if binding.get('source_changed') else 'no'}"
        )

    return "\n".join(lines)


# ──────────────────────────────────────────────
# Rendering — Markdown
# ──────────────────────────────────────────────


def render_markdown(document: dict[str, Any]) -> str:
    """Human-readable Markdown built from the document."""
    artifact = document.get("artifact") or {}
    assessment = document.get("assessment") or {}
    findings = document.get("findings") or []
    controls = document.get("controls") or []
    stages = document.get("stages") or []

    lines = [f"# IoT Hardware Scanner — {artifact.get('name')}", ""]
    lines.append(f"**Scan ID:** {document.get('scan_id')}")
    lines.append(f"**Scan date:** {document.get('scan_date')}")
    lines.append(f"**Artifact kind:** {artifact.get('kind')}")
    lines.append(f"**SHA-256:** `{artifact.get('sha256')}`")
    lines.append(f"**Size:** {artifact.get('size')} bytes")
    lines.append(f"**File type:** {artifact.get('file_type')}{_file_type_source_suffix(artifact)}")
    lines.append(f"**Profile:** {assessment.get('profile')} v{assessment.get('profile_version')}")
    capabilities_line = _capabilities_line(document)
    if capabilities_line:
        lines.append(capabilities_line)
    lines.append("")

    lines += ["## Assessment", "", f"**Completion:** {assessment.get('completion', 'UNKNOWN')}"]
    if (assessment.get("coverage") or "").upper() == "UNKNOWN":
        lines.append("")
        lines.append(
            "> Coverage unknown: this document does not record which stages ran. "
            "No grade is implied by its absence."
        )
    for reason in assessment.get("incomplete_reasons") or []:
        lines.append(f"- Incomplete: {reason}")
    for item in assessment.get("missing_required_dependencies") or []:
        lines.append(f"- Missing dependency: {item}")
    for limitation in assessment.get("limitations") or []:
        lines.append(f"- Limitation: {limitation}")
    counts = assessment.get("check_counts") or {}
    if counts:
        lines.append(
            "- Checks: " + ", ".join(f"{v} {k.lower()}" for k, v in sorted(counts.items()))
        )
    lines.append("")

    if stages:
        lines += [
            "## Stage coverage",
            "",
            "| Stage | Status | Required | Inspected | Eligible | Reason |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for stage in stages:
            lines.append(
                f"| {stage.get('stage')} | {stage.get('status')} | "
                f"{'yes' if stage.get('required') else 'no'} | "
                f"{_count(stage.get('inspected'))} | {_count(stage.get('eligible'))} | "
                f"{_md_cell(stage.get('reason') or '')} |"
            )
        lines.append("")

    lines += ["## Findings", ""]
    if not findings:
        lines.append("None reported.")
    else:
        lines += [
            "| Severity | Rule | Locations | Review/critical |",
            "| --- | --- | --- | --- |",
        ]
        for finding in findings:
            lines.append(
                f"| {finding.get('severity')} | `{finding.get('rule_id')}` | "
                f"{_md_cell(', '.join(finding.get('locations') or []))} | "
                f"{'critical' if finding.get('critical_qualified') else 'review'} |"
            )
    lines.append("")

    if controls:
        lines += [
            "## Named checks",
            "",
            "| # | Check | Status | Result | Evidence |",
            "| --- | --- | --- | --- | --- |",
        ]
        for control in controls:
            evidence = "; ".join(control.get("evidence") or []) or "—"
            lines.append(
                f"| {control.get('control_id')} | {_md_cell(control.get('control_name', ''))} | "
                f"{control.get('status')} | {control.get('result')} | {_md_cell(evidence)} |"
            )
        lines.append("")

    inventory = document.get("inventory")
    if inventory:
        lines += ["## Inventory", ""]
        lines.append(f"- Files: {inventory.get('files')}")
        lines.append(f"- Directories: {inventory.get('directories')}")
        lines.append(f"- Bytes: {inventory.get('bytes')}")
        lines.append(f"- Metadata source: {inventory.get('metadata_source')}")
        boot = inventory.get("boot_evidence") or []
        if boot:
            lines.append("")
            lines += [
                "| Root | Source | Line | Action | Program | Configured |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
            for entry in boot:
                lines.append(
                    f"| {entry.get('root_id')} | {_md_cell(entry.get('source', ''))} | "
                    f"{entry.get('line')} | {entry.get('action')} | "
                    f"{_md_cell(entry.get('program', ''))} | "
                    f"{'yes' if entry.get('configured') else 'no (commented)'} |"
                )
        lines.append("")

    entropy = document.get("entropy")
    if entropy:
        scope = "sampled" if entropy.get("sampled") else "whole input"
        lines += [
            "## Entropy",
            "",
            f"- Whole-input entropy: {entropy.get('overall_entropy')} bits/byte "
            f"over {entropy.get('bytes_analyzed')} bytes ({scope})",
            f"- Mean of windows: {entropy.get('window_mean_entropy')} bits/byte",
            f"- Window size: {entropy.get('block_size')} bytes",
        ]
        for note in entropy.get("notes") or []:
            lines.append(f"- {note}")
        lines.append("")

    image_map = document.get("image_map") or {}
    if image_map.get("nodes"):
        lines += [
            "## Image map",
            "",
            "| ID | Parent | Format | Coordinates | Offset | Length | Extent | Decoder |",
            "| --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
        for node in image_map["nodes"]:
            decoder = str(node.get("decoder") or "")
            if node.get("decoder_version"):
                decoder += f" {node['decoder_version']}"
            lines.append(
                f"| {node.get('artifact_id')} | {node.get('parent_id') or '—'} | "
                f"{node.get('format')} | {node.get('coordinate_system')} | "
                f"{node.get('offset')} | {node.get('length')} | "
                f"{_count(node.get('extent_bytes'))} | {_md_cell(decoder)} |"
            )
        lines.append("")

    mcu = document.get("mcu") or {}
    if mcu:
        ranges = mcu.get("ranges") or []
        gaps = mcu.get("gaps") or []
        lines += [
            f"## Bare-metal image — {mcu.get('format')}",
            "",
            f"- Decoder: `{mcu.get('decoder')}` {mcu.get('decoder_version')}",
            f"- Records: {mcu.get('records')}",
            f"- Addressed bytes: {mcu.get('payload_bytes')} over {len(ranges)} range(s) "
            f"({mcu.get('declared_bytes')} declared)",
            f"- Payload SHA-256: `{mcu.get('payload_sha256')}` — over the addressed bytes "
            "in ascending order, never over a gap",
            f"- Family id: {mcu.get('family') or '—'}",
            f"- Declared start address: {mcu.get('start_address_hex') or '—'} "
            "(what the producer intended, not what the device runs)",
            "",
            "| Start | End | Bytes | SHA-256 | Records |",
            "| --- | --- | --- | --- | --- |",
        ]
        for item in ranges:
            lines.append(
                f"| `{item.get('start_hex')}` | `{item.get('end_hex')}` | "
                f"{item.get('length')} | `{(item.get('sha256') or '')[:16]}…` | "
                f"{item.get('source_records')} |"
            )
        if gaps:
            lines += [
                "",
                "Unobserved address ranges (never zero-filled):",
                "",
                "| Start | End | Bytes | Observed |",
                "| --- | --- | --- | --- |",
            ]
            for item in gaps:
                lines.append(
                    f"| `{item.get('start_hex')}` | `{item.get('end_hex')}` | "
                    f"{item.get('length')} | no |"
                )
        if mcu.get("diagnostics"):
            lines += ["", "### Structural diagnostics", ""]
            for item in mcu.get("diagnostics") or []:
                lines.append(f"- **{item.get('kind')}** — {_md_cell(str(item.get('detail')))}")
        if mcu.get("notes"):
            lines += ["", "### Encoding notes", ""]
            for note in mcu.get("notes") or []:
                lines.append(f"- {note}")
        lines.append("")

    boot = document.get("boot") or {}
    for artifact in boot.get("artifacts") or []:
        lines += [
            f"## Boot manifest — {artifact.get('kind')}",
            "",
            f"- Locator: `{artifact.get('locator')}`",
            f"- FDT version: {artifact.get('fdt_version')}",
            f"- Compatible: {', '.join(artifact.get('compatible') or []) or '—'}",
            f"- Model: {artifact.get('model') or '—'}",
            f"- Default configuration: {artifact.get('default_config') or 'unknown'}",
            f"- Boot enforcement: **{artifact.get('boot_enforcement', 'unknown')}** "
            "(a declared configuration is not enforcement)",
            "",
            "| Payload | Kind | Integrity | Declared | Observed | Signature |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for payload in artifact.get("referenced_payloads") or []:
            signature = payload.get("signature") or {}
            lines.append(
                f"| {_md_cell(str(payload.get('node')))} | {payload.get('kind')} | "
                f"{payload.get('integrity')} | "
                f"{_md_cell(str(payload.get('digest_declared') or '—'))} | "
                f"{_md_cell(str(payload.get('digest_observed') or '—'))} | "
                f"{'present' if signature.get('present') else 'absent'} |"
            )
        lines.append("")
        for configuration in artifact.get("configurations") or []:
            signature = configuration.get("signature") or {}
            lines.append(
                f"- Configuration `{configuration.get('name')}`: kernel "
                f"`{configuration.get('kernel')}`, fdt `{configuration.get('fdt')}`, "
                f"signature {'present' if signature.get('present') else 'absent'}, "
                f"verified {signature.get('verified')} "
                f"({signature.get('key_source')})"
            )
        for note in artifact.get("notes") or []:
            lines.append(f"- {note}")
        lines.append("")

    extraction = document.get("extraction")
    if extraction:
        lines += ["## Extraction", ""]
        lines.append(f"- State: {extraction.get('state')}")
        lines.append(f"- Worker: {extraction.get('worker')} ({extraction.get('isolation')})")
        if extraction.get("worker_image"):
            lines.append(f"- Worker image: `{extraction.get('worker_image')}`")
        if extraction.get("worker_digest"):
            lines.append(f"- Worker image digest: `{extraction.get('worker_digest')}`")
        if extraction.get("helper_version"):
            lines.append(f"- Helper: {extraction.get('helper')} {extraction.get('helper_version')}")
        limits = extraction.get("limits") or {}
        if limits:
            lines.append(
                "- Budgets: " + ", ".join(f"{key}={value}" for key, value in limits.items())
            )
        for omission in extraction.get("omissions") or []:
            lines.append(f"- Omission: {omission}")
        for error in extraction.get("errors") or []:
            lines.append(f"- Note: {error}")
        lines.append("")

    opkg = document.get("opkg")
    if opkg:
        lines += [
            "## Installed packages",
            "",
            f"- Database: `{opkg.get('locator')}`",
            f"- SHA-256: `{opkg.get('database_sha256')}`",
            f"- Installed records: {opkg.get('installed')} ({opkg.get('held')} held)",
            "",
            "| Package | Version | Architecture | Held | Evidence (bytes) |",
            "| --- | --- | --- | --- | --- |",
        ]
        for record in opkg.get("records") or []:
            span = record.get("evidence") or {}
            lines.append(
                f"| {_md_cell(record.get('name', ''))} | {_md_cell(record.get('version', ''))} | "
                f"{_md_cell(record.get('architecture', ''))} | "
                f"{'yes' if record.get('held') else 'no'} | "
                f"{span.get('start')}-{span.get('end')} (line {span.get('line')}) |"
            )
        lines.append("")

    elf = document.get("elf") or {}
    if elf.get("records"):
        lines += [
            "## ELF records",
            "",
            "| Locator | SHA-256 | Class | Machine | Type | PIE | RELRO | NX | Canary |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
        for record in elf["records"]:
            hardening = record.get("hardening") or {}
            nx = hardening.get("stack_executable")
            lines.append(
                f"| `{_md_cell(record.get('locator', ''))}` | "
                f"`{record.get('digest_sha256') or 'not recorded'}` | "
                f"{record.get('class')} | "
                f"{record.get('machine_name')} ({record.get('machine')}) | {record.get('type')} | "
                f"{_tri(hardening.get('pie'))} | {hardening.get('relro')} | "
                f"{'no' if nx is True else ('yes' if nx is False else 'unknown')} | "
                f"{_tri(hardening.get('canary'))} |"
            )
        lines.append("")
        for record in elf["records"]:
            for unknown in record.get("unknown") or []:
                lines.append(f"- {record.get('locator')}: {unknown}")
        lines.append("")

    binding = document.get("input_binding")
    if binding:
        lines += [
            "## Input binding",
            "",
            f"- Snapshot: `{binding.get('snapshot_path')}` (read-only)",
            f"- Declared SHA-256: `{binding.get('declared_sha256')}`",
            f"- Verified SHA-256: `{binding.get('verified_sha256')}`",
            f"- Original path changed after ingest: "
            f"{'yes' if binding.get('source_changed') else 'no'}",
            "",
        ]

    tree = document.get("tree")
    if tree:
        lines += ["## Staged tree", ""]
        lines.append(f"- Entries: {tree.get('entries')} ({tree.get('by_kind')})")
        for change in tree.get("changes_during_traversal") or []:
            lines.append(f"- Changed while catalogued: {change}")
        declared = tree.get("declared_manifest")
        if declared:
            lines.append(
                f"- Declared manifest: `{declared.get('path')}` "
                f"(sha256 `{declared.get('sha256')}`, {declared.get('entries')} entries)"
            )
            if declared.get("declared_only"):
                lines.append(f"- Declared but not observed: {', '.join(declared['declared_only'])}")
            if declared.get("observed_only"):
                lines.append(
                    f"- Observed but not declared: {len(declared['observed_only'])} file(s)"
                )
        lines.append("")

    ruleset = document.get("ruleset")
    if ruleset:
        lines += [
            "## Rule set",
            "",
            f"- Digest: `{ruleset.get('digest')}`",
            f"- Engine: {ruleset.get('engine')} {ruleset.get('engine_version') or ''}".rstrip(),
            f"- Source: {ruleset.get('source')}",
            f"- Rule files: {len(ruleset.get('rule_files') or [])}",
            "",
            "| Namespace | File | Rules | Destinations | SHA-256 |",
            "| --- | --- | --- | --- | --- |",
        ]
        for record in ruleset.get("rule_files") or []:
            lines.append(
                f"| {_md_cell(record.get('namespace', ''))} | {_md_cell(record.get('name', ''))} | "
                f"{record.get('rule_count')} | {', '.join(record.get('destinations') or [])} | "
                f"`{record.get('sha256')}` |"
            )
        for error in ruleset.get("compile_errors") or []:
            lines.append(f"- Not compiled: {error.get('file')}: {error.get('reason')}")
        lines.append("")

    advisory = document.get("advisory")
    if advisory:
        snapshot = advisory.get("snapshot") or {}
        lines += [
            "## Advisory assessment",
            "",
            f"- State: {advisory.get('state')}",
            f"- Applicable matches: {advisory.get('matched')} "
            f"({advisory.get('kev_matches')} in CISA KEV)",
            f"- Snapshot: `{snapshot.get('path')}` ({snapshot.get('provider')}, "
            f"acquired {snapshot.get('acquired_at')}, {snapshot.get('entries')} entries, "
            f"{snapshot.get('age_days')} day(s) old, stale: "
            f"{'yes' if snapshot.get('stale') else 'no'})",
            f"- Snapshot SHA-256: `{snapshot.get('digest_sha256')}`",
            "",
            "| Component | Version | Lookup state | Matches | Reason |",
            "| --- | --- | --- | --- | --- |",
        ]
        for lookup in advisory.get("lookups") or []:
            lines.append(
                f"| {_md_cell(lookup.get('component', ''))} | "
                f"{_md_cell(lookup.get('version', ''))} | {lookup.get('state')} | "
                f"{lookup.get('matches')} | {_md_cell(lookup.get('reason') or '—')} |"
            )
        for note in advisory.get("notes") or []:
            lines.append(f"- {note}")
        lines.append("")

    components = document.get("components") or []
    if components:
        lines += ["## Components", ""]
        bases = document.get("component_bases") or {}
        counts = bases.get("counts") or {}
        if counts:
            lines += [
                "Basis: "
                + ", ".join(f"{name} {count}" for name, count in counts.items())
                + f" ({bases.get('total', len(components))} component(s))",
                "",
            ]
        lines += [
            "| Vendor | Product | Version | Basis | Source | Method | Confidence | Evidence |",
            "| --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
        for component in components:
            lines.append(
                f"| {_md_cell(component.get('vendor', ''))} | "
                f"{_md_cell(component.get('product', ''))} | "
                f"{_md_cell(component.get('version', ''))} | "
                f"{component.get('cpe_basis') or 'unrecorded'} | "
                f"{_md_cell(component.get('source_file', ''))} | "
                f"{component.get('source_method')} | "
                f"{component.get('confidence')} | "
                f"{_md_cell(component.get('evidence') or '')} |"
            )
        lines.append("")

    legacy = document.get("legacy_grade") or document.get("risk_score")
    if legacy:
        lines += [
            "## Legacy grade (not comparable)",
            "",
            f"- Method: {legacy.get('method')}",
            f"- Historical score: {legacy.get('total_score')}/100 {legacy.get('risk_level')}",
            "",
            "> This grade comes from the retired 12-control weighted method. It is "
            "rendered for continuity only and does not describe this or any new "
            "scan.",
            "",
        ]

    return "\n".join(lines)


def _count(value: Any) -> str:
    return "unknown" if value is None else str(value)


def _tri(value: Any) -> str:
    """Render a tri-state observation without collapsing unknown into false."""
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "unknown"


def _md_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


# ──────────────────────────────────────────────
# Rendering — HTML
# ──────────────────────────────────────────────

_CSS = """
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
       max-width: 960px; margin: 2rem auto; padding: 0 1rem; background: #1a1a2e; color: #e0e0e0; }
h1 { color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: .5rem; }
h2 { color: #7c4dff; margin-top: 2rem; }
table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
th, td { border: 1px solid #333; padding: .5rem .75rem; text-align: left; vertical-align: top; }
th { background: #16213e; color: #00d4ff; }
tr:nth-child(even) { background: #0f3460; }
code { background: #16213e; padding: .1rem .3rem; border-radius: 3px; }
.badge { display: inline-block; padding: .25rem .75rem; border-radius: 4px; font-weight: bold; }
.badge.COMPLETE { background: #2e7d32; color: #fff; }
.badge.INCOMPLETE { background: #c62828; color: #fff; }
.badge.UNKNOWN { background: #616161; color: #fff; }
.note { border-left: 4px solid #7c4dff; padding: .5rem 1rem; background: #16213e; }
"""


def render_html(document: dict[str, Any]) -> str:
    """Standalone HTML, built from the document with every value escaped.

    Nothing here reads a neighbouring Markdown file, and no firmware-derived
    string is interpolated without escaping.
    """
    artifact = document.get("artifact") or {}
    assessment = document.get("assessment") or {}
    completion = str(assessment.get("completion", "UNKNOWN"))
    title = f"IoT Hardware Scanner — {artifact.get('name')}"

    parts: list[str] = []
    parts.append(f"<h1>{html.escape(title)}</h1>")
    parts.append(
        "<table>"
        f"<tr><th>Scan ID</th><td>{html.escape(str(document.get('scan_id')))}</td></tr>"
        f"<tr><th>Scan date</th><td>{html.escape(str(document.get('scan_date')))}</td></tr>"
        f"<tr><th>Artifact</th><td>{html.escape(str(artifact.get('kind')))} "
        f"({html.escape(str(artifact.get('size')))} bytes)</td></tr>"
        f"<tr><th>SHA-256</th><td><code>{html.escape(str(artifact.get('sha256')))}</code></td></tr>"
        f"<tr><th>Profile</th><td>{html.escape(str(assessment.get('profile')))} "
        f"v{html.escape(str(assessment.get('profile_version')))}</td></tr>"
        "</table>"
    )

    parts.append("<h2>Assessment</h2>")
    parts.append(
        f'<p><span class="badge {html.escape(completion)}">{html.escape(completion)}</span></p>'
    )
    if str(assessment.get("coverage", "")).upper() == "UNKNOWN":
        parts.append(
            '<p class="note">Coverage unknown: this document does not record which '
            "stages ran. No grade is implied by its absence.</p>"
        )
    reasons = assessment.get("incomplete_reasons") or []
    if reasons:
        parts.append("<ul>")
        parts.extend(f"<li>{html.escape(str(r))}</li>" for r in reasons)
        parts.append("</ul>")

    stages = document.get("stages") or []
    if stages:
        parts.append("<h2>Stage coverage</h2><table>")
        parts.append(
            "<tr><th>Stage</th><th>Status</th><th>Required</th><th>Inspected</th>"
            "<th>Eligible</th><th>Reason</th></tr>"
        )
        for stage in stages:
            parts.append(
                "<tr>"
                f"<td>{html.escape(str(stage.get('stage')))}</td>"
                f"<td>{html.escape(str(stage.get('status')))}</td>"
                f"<td>{'yes' if stage.get('required') else 'no'}</td>"
                f"<td>{html.escape(_count(stage.get('inspected')))}</td>"
                f"<td>{html.escape(_count(stage.get('eligible')))}</td>"
                f"<td>{html.escape(str(stage.get('reason') or ''))}</td>"
                "</tr>"
            )
        parts.append("</table>")

    findings = document.get("findings") or []
    parts.append("<h2>Findings</h2>")
    if not findings:
        parts.append("<p>None reported.</p>")
    else:
        parts.append(
            "<table><tr><th>Severity</th><th>Rule</th><th>Destination</th>"
            "<th>Locations</th><th>Kind</th></tr>"
        )
        for finding in findings:
            kind = "critical" if finding.get("critical_qualified") else "review"
            parts.append(
                "<tr>"
                f"<td>{html.escape(str(finding.get('severity')))}</td>"
                f"<td><code>{html.escape(str(finding.get('rule_id')))}</code></td>"
                f"<td>{html.escape(str(finding.get('destination') or 'unrecorded'))}</td>"
                f"<td>{html.escape(', '.join(finding.get('locations') or []))}</td>"
                f"<td>{kind}</td>"
                "</tr>"
            )
        parts.append("</table>")

    controls = document.get("controls") or []
    if controls:
        parts.append("<h2>Named checks</h2><table>")
        parts.append(
            "<tr><th>#</th><th>Check</th><th>Status</th><th>Result</th><th>Evidence</th></tr>"
        )
        for control in controls:
            evidence = "; ".join(control.get("evidence") or [])
            parts.append(
                "<tr>"
                f"<td>{html.escape(str(control.get('control_id')))}</td>"
                f"<td>{html.escape(str(control.get('control_name')))}"
                f'<div class="note">{html.escape(str(control.get("question") or ""))}</div></td>'
                f"<td>{html.escape(str(control.get('status')))}</td>"
                f"<td>{html.escape(str(control.get('result')))}</td>"
                f"<td>{html.escape(evidence)}</td>"
                "</tr>"
            )
        parts.append("</table>")

    ruleset = document.get("ruleset")
    if ruleset:
        parts.append("<h2>Rule set</h2><table>")
        parts.append(
            f"<tr><th>Digest</th><td><code>"
            f"{html.escape(str(ruleset.get('digest')))}</code></td></tr>"
        )
        parts.append(
            f"<tr><th>Engine</th><td>{html.escape(str(ruleset.get('engine')))} "
            f"{html.escape(str(ruleset.get('engine_version') or ''))}</td></tr>"
        )
        parts.append(f"<tr><th>Rule files</th><td>{len(ruleset.get('rule_files') or [])}</td></tr>")
        parts.append("</table>")
        for error in ruleset.get("compile_errors") or []:
            parts.append(
                f'<p class="note">Not compiled: {html.escape(str(error.get("file")))}: '
                f"{html.escape(str(error.get('reason')))}</p>"
            )

    advisory = document.get("advisory")
    if advisory:
        snapshot = advisory.get("snapshot") or {}
        parts.append("<h2>Advisory assessment</h2><table>")
        parts.append(
            f"<tr><th>State</th><td>{html.escape(str(advisory.get('state')))}</td></tr>"
            f"<tr><th>Matches</th><td>{html.escape(str(advisory.get('matched')))} "
            f"({html.escape(str(advisory.get('kev_matches')))} in KEV)</td></tr>"
            f"<tr><th>Snapshot</th><td><code>"
            f"{html.escape(str(snapshot.get('digest_sha256')))}</code> "
            f"({html.escape(str(snapshot.get('provider')))}, acquired "
            f"{html.escape(str(snapshot.get('acquired_at')))})</td></tr>"
            "</table><table>"
            "<tr><th>Component</th><th>Version</th><th>Lookup</th><th>Reason</th></tr>"
        )
        for lookup in advisory.get("lookups") or []:
            parts.append(
                "<tr>"
                f"<td>{html.escape(str(lookup.get('component')))}</td>"
                f"<td>{html.escape(str(lookup.get('version')))}</td>"
                f"<td>{html.escape(str(lookup.get('state')))}</td>"
                f"<td>{html.escape(str(lookup.get('reason') or ''))}</td>"
                "</tr>"
            )
        parts.append("</table>")

    inventory = document.get("inventory")
    if inventory:
        parts.append("<h2>Inventory</h2><table>")
        parts.append(f"<tr><th>Files</th><td>{html.escape(str(inventory.get('files')))}</td></tr>")
        parts.append(
            f"<tr><th>Directories</th><td>{html.escape(str(inventory.get('directories')))}</td></tr>"
        )
        parts.append(
            f"<tr><th>Metadata source</th><td>"
            f"{html.escape(str(inventory.get('metadata_source')))}</td></tr>"
        )
        parts.append("</table>")
        boot = inventory.get("boot_evidence") or []
        if boot:
            parts.append("<h3>Configured startup evidence</h3><table>")
            parts.append(
                "<tr><th>Root</th><th>Source</th><th>Line</th><th>Action</th>"
                "<th>Program</th><th>Configured</th></tr>"
            )
            for entry in boot:
                parts.append(
                    "<tr>"
                    f"<td>{html.escape(str(entry.get('root_id')))}</td>"
                    f"<td>{html.escape(str(entry.get('source')))}</td>"
                    f"<td>{html.escape(str(entry.get('line')))}</td>"
                    f"<td>{html.escape(str(entry.get('action')))}</td>"
                    f"<td>{html.escape(str(entry.get('program')))}</td>"
                    f"<td>{'yes' if entry.get('configured') else 'no (commented)'}</td>"
                    "</tr>"
                )
            parts.append("</table>")

    entropy = document.get("entropy")
    if entropy:
        scope = "sampled" if entropy.get("sampled") else "whole input"
        parts.append("<h2>Entropy</h2>")
        parts.append(
            f"<p>{html.escape(str(entropy.get('overall_entropy')))} bits/byte over "
            f"{html.escape(str(entropy.get('bytes_analyzed')))} bytes ({scope})</p>"
        )
        parts.append("<ul>")
        parts.extend(f"<li>{html.escape(str(note))}</li>" for note in entropy.get("notes") or [])
        parts.append("</ul>")

    image_map = document.get("image_map") or {}
    if image_map.get("nodes"):
        parts.append("<h2>Image map</h2><table>")
        parts.append(
            "<tr><th>ID</th><th>Parent</th><th>Format</th><th>Coordinates</th>"
            "<th>Offset</th><th>Length</th><th>Extent</th><th>Decoder</th></tr>"
        )
        for node in image_map["nodes"]:
            decoder = str(node.get("decoder") or "")
            if node.get("decoder_version"):
                decoder += f" {node['decoder_version']}"
            parts.append(
                "<tr>"
                f"<td>{html.escape(str(node.get('artifact_id')))}</td>"
                f"<td>{html.escape(str(node.get('parent_id') or '—'))}</td>"
                f"<td>{html.escape(str(node.get('format')))}</td>"
                f"<td>{html.escape(str(node.get('coordinate_system')))}</td>"
                f"<td>{html.escape(str(node.get('offset')))}</td>"
                f"<td>{html.escape(str(node.get('length')))}</td>"
                f"<td>{html.escape(_count(node.get('extent_bytes')))}</td>"
                f"<td>{html.escape(decoder)}</td>"
                "</tr>"
            )
        parts.append("</table>")

    mcu = document.get("mcu") or {}
    if mcu:
        ranges = mcu.get("ranges") or []
        gaps = mcu.get("gaps") or []
        parts.append("<h2>Bare-metal image</h2>")
        parts.append(
            f"<p>Encoding <strong>{html.escape(str(mcu.get('format')))}</strong>; "
            f"{html.escape(str(mcu.get('records')))} record(s); "
            f"{html.escape(str(mcu.get('payload_bytes')))} addressed byte(s) over "
            f"{len(ranges)} range(s); payload SHA-256 "
            f"<code>{html.escape(str(mcu.get('payload_sha256')))}</code></p>"
        )
        parts.append("<table><tr><th>Start</th><th>End</th><th>Bytes</th><th>Records</th></tr>")
        for item in ranges:
            parts.append(
                f"<tr><td><code>{html.escape(str(item.get('start_hex')))}</code></td>"
                f"<td><code>{html.escape(str(item.get('end_hex')))}</code></td>"
                f"<td>{html.escape(str(item.get('length')))}</td>"
                f"<td>{html.escape(str(item.get('source_records')))}</td></tr>"
            )
        parts.append("</table>")
        if gaps:
            parts.append(
                f"<p>{len(gaps)} unobserved address range(s); they are never zero-filled.</p>"
            )

    boot = document.get("boot") or {}
    for artifact in boot.get("artifacts") or []:
        parts.append("<h2>Boot manifest</h2>")
        parts.append(
            f"<p>{html.escape(str(artifact.get('kind')))}: "
            f"{html.escape(str(artifact.get('locator')))}; default configuration "
            f"{html.escape(str(artifact.get('default_config') or 'unknown'))}; boot "
            f"enforcement <strong>{html.escape(str(artifact.get('boot_enforcement')))}</strong>"
            "</p>"
        )
        parts.append("<table>")
        parts.append(
            "<tr><th>Payload</th><th>Kind</th><th>Integrity</th><th>Declared</th>"
            "<th>Observed</th><th>Signature</th><th>Verified</th></tr>"
        )
        for payload in artifact.get("referenced_payloads") or []:
            signature = payload.get("signature") or {}
            parts.append(
                "<tr>"
                f"<td>{html.escape(str(payload.get('node')))}</td>"
                f"<td>{html.escape(str(payload.get('kind')))}</td>"
                f"<td>{html.escape(str(payload.get('integrity')))}</td>"
                f"<td>{html.escape(str(payload.get('digest_declared') or '—'))}</td>"
                f"<td>{html.escape(str(payload.get('digest_observed') or '—'))}</td>"
                f"<td>{'present' if signature.get('present') else 'absent'}</td>"
                f"<td>{html.escape(str(signature.get('verified')))}</td>"
                "</tr>"
            )
        parts.append("</table>")
        parts.append("<ul>")
        for note in artifact.get("notes") or []:
            parts.append(f"<li>{html.escape(str(note))}</li>")
        parts.append("</ul>")

    extraction = document.get("extraction")
    if extraction:
        parts.append("<h2>Extraction</h2><table>")
        for key in (
            "state",
            "worker",
            "isolation",
            "worker_image",
            "worker_digest",
            "helper_version",
        ):
            parts.append(
                f"<tr><th>{html.escape(key)}</th>"
                f"<td>{html.escape(str(extraction.get(key)))}</td></tr>"
            )
        parts.append("</table>")
        omissions = extraction.get("omissions") or []
        if omissions:
            parts.append("<ul>")
            parts.extend(f"<li>{html.escape(str(item))}</li>" for item in omissions)
            parts.append("</ul>")

    opkg = document.get("opkg")
    if opkg:
        parts.append("<h2>Installed packages</h2>")
        parts.append(
            f"<p>{html.escape(str(opkg.get('installed')))} installed, "
            f"{html.escape(str(opkg.get('held')))} held, from "
            f"<code>{html.escape(str(opkg.get('locator')))}</code></p>"
        )
        parts.append(
            "<table><tr><th>Package</th><th>Version</th><th>Architecture</th>"
            "<th>Held</th><th>Evidence</th></tr>"
        )
        for record in opkg.get("records") or []:
            span = record.get("evidence") or {}
            parts.append(
                "<tr>"
                f"<td>{html.escape(str(record.get('name')))}</td>"
                f"<td>{html.escape(str(record.get('version')))}</td>"
                f"<td>{html.escape(str(record.get('architecture')))}</td>"
                f"<td>{'yes' if record.get('held') else 'no'}</td>"
                f"<td>{html.escape(str(span.get('start')))}-"
                f"{html.escape(str(span.get('end')))}</td>"
                "</tr>"
            )
        parts.append("</table>")

    elf = document.get("elf") or {}
    if elf.get("records"):
        parts.append("<h2>ELF records</h2><table>")
        parts.append(
            "<tr><th>Locator</th><th>Class</th><th>Machine</th><th>Type</th>"
            "<th>PIE</th><th>RELRO</th><th>NX</th><th>Canary</th></tr>"
        )
        for record in elf["records"]:
            hardening = record.get("hardening") or {}
            stack = hardening.get("stack_executable")
            parts.append(
                "<tr>"
                f"<td><code>{html.escape(str(record.get('locator')))}</code></td>"
                f"<td>{html.escape(str(record.get('class')))}</td>"
                f"<td>{html.escape(str(record.get('machine_name')))}</td>"
                f"<td>{html.escape(str(record.get('type')))}</td>"
                f"<td>{_tri(hardening.get('pie'))}</td>"
                f"<td>{html.escape(str(hardening.get('relro')))}</td>"
                f"<td>{'no' if stack is True else ('yes' if stack is False else 'unknown')}</td>"
                f"<td>{_tri(hardening.get('canary'))}</td>"
                "</tr>"
            )
        parts.append("</table>")

    binding = document.get("input_binding")
    if binding:
        parts.append("<h2>Input binding</h2><table>")
        parts.append(
            f"<tr><th>Snapshot</th><td><code>"
            f"{html.escape(str(binding.get('snapshot_path')))}</code></td></tr>"
            f"<tr><th>Declared SHA-256</th><td><code>"
            f"{html.escape(str(binding.get('declared_sha256')))}</code></td></tr>"
            f"<tr><th>Source changed after ingest</th>"
            f"<td>{'yes' if binding.get('source_changed') else 'no'}</td></tr>"
        )
        parts.append("</table>")

    legacy = document.get("legacy_grade") or document.get("risk_score")
    if legacy:
        parts.append("<h2>Legacy grade (not comparable)</h2>")
        parts.append(
            "<table>"
            f"<tr><th>Method</th><td>{html.escape(str(legacy.get('method')))}</td></tr>"
            f"<tr><th>Historical score</th><td>"
            f"{html.escape(str(legacy.get('total_score')))}/100 "
            f"{html.escape(str(legacy.get('risk_level')))}</td></tr>"
            "</table>"
        )
        parts.append(
            '<p class="note">This grade comes from the retired 12-control weighted '
            "method. It is rendered for continuity only.</p>"
        )

    body = "\n".join(parts)
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n<head>\n<meta charset="UTF-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
        f"<title>{html.escape(title)}</title>\n<style>{_CSS}</style>\n"
        f"</head>\n<body>\n{body}\n</body>\n</html>\n"
    )


RENDERERS = {
    "json": render_json,
    "markdown": render_markdown,
    "html": render_html,
    "terminal": render_terminal,
}


def render(document: dict[str, Any], fmt: str) -> str:
    """Render the document in ``fmt``."""
    try:
        renderer = RENDERERS[fmt]
    except KeyError as exc:  # pragma: no cover - guarded by config validation
        raise ValueError(f"unsupported report format: {fmt}") from exc
    return renderer(document)


# ──────────────────────────────────────────────
# Writing
# ──────────────────────────────────────────────


def write_atomic(destination: Path, content: str) -> Path:
    """Write ``content`` to exactly ``destination``, atomically.

    The temporary file is created in the destination directory so ``os.replace``
    is a same-filesystem rename. A failure leaves no partial report behind and
    raises :class:`ReportWriteError`; callers must not announce success before
    this returns.
    """
    destination = Path(destination)
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=str(destination.parent),
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            tmp_path = Path(handle.name)
            try:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            except BaseException:
                handle.close()
                tmp_path.unlink(missing_ok=True)
                raise
        try:
            os.replace(tmp_path, destination)
        except BaseException:
            tmp_path.unlink(missing_ok=True)
            raise
    except OSError as exc:
        raise ReportWriteError(f"cannot write {destination}: {exc}") from exc
    return destination


def default_filename(fmt: str) -> str:
    """The conventional filename for a format."""
    return f"report{_EXTENSIONS.get(fmt, '.txt')}"
