"""Offline release comparison and build-declaration reconciliation (5B, 5D).

A comparison is a **separate document type** — ``ihs-comparison/1`` — built from
two saved scan documents, not from a live scan. Nothing here opens a socket,
runs an extractor or re-reads firmware: the shipped report is the input, so the
comparison says exactly what the two scans recorded and nothing more.

Identity, not proximity
-----------------------
Every match is on a *logical* identity:

* packages — the ``Package`` name in the image's own opkg database. The record
  compared is the package record, not the mapped CPE component: mapping only a
  few names to NIST products is how 193 of 196 records would silently vanish.
  Every occurrence is kept, so two roots with different revisions stay two
  facts.
* components — the ``(vendor, product)`` pair, with every complete version
  string and every occurrence. A component that moved is still the same
  component; its locators are kept and the move is reported.
* layout — content identity: an ELF build ID when the file declares one, else
  the file digest. A file that moved inside the image keeps its identity.
* findings — the rule that produced them, matched location by location on
  trailing path components, so a finding that followed its file is persistent
  and relocated rather than new-and-resolved.

What a comparison refuses to guess
----------------------------------
Before any difference is interpreted, the document states what changed in the
*instruments*: scanner version, profile and profile version, rule-set digest,
advisory snapshot and per-stage coverage. When a detector's question was not
settled on one side — a skipped stage, a changed rule set, a different scanner
version — that detector's previous findings are reported **indeterminate**.
They are never rendered as resolved, because "we did not ask" and "the problem
is gone" are different answers.

Declarations
------------
An OpenWrt target manifest and a supplier CycloneDX 1.4 document are optional
inputs. Each is recorded with its own digest and its binding to the image: a
declaration that carries an image digest is bound only when that digest is the
image's; one that claims another image is recorded unbound and never resolves
anything; one that carries no digest at all is recorded as unclaimed, with the
association stated as scope-based and unverified.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from iot_hardware_scanner.scanner.bounded_reader import (
    BoundedReadLimitError,
    open_bounded,
)
from iot_hardware_scanner.scanner.report_document import SCHEMA_VERSION, load_document

#: Document type for a comparison. It is not a scan document and has its own
#: version, because its fields and its exit contract are different.
COMPARISON_SCHEMA = "ihs-comparison/1"

#: The scan-document schema this comparison knows how to read. A newer scan
#: document is refused rather than half-read.
MAX_SCAN_SCHEMA = SCHEMA_VERSION

#: Bound on any declaration or scan document read into memory.
DEFAULT_BUDGET_BYTES = 256 * 1024 * 1024

#: Where each finding destination's evidence comes from. A destination is
#: comparable only when every stage that can produce it settled on both sides.
DESTINATION_STAGES: dict[str, tuple[str, ...]] = {
    "credential": ("rule_compilation", "credential_scan", "unix_accounts"),
    "service": ("rule_compilation", "service_analysis", "c2_indicators"),
    "crypto": ("rule_compilation", "c2_indicators"),
    "indicator": ("rule_compilation", "c2_indicators"),
    "advisory": ("advisory",),
}

#: Destinations produced by the compiled rule set: a changed digest means the
#: questions themselves changed, so the answers are not comparable.
RULE_BASED_DESTINATIONS = frozenset({"credential", "service", "crypto", "indicator"})

#: A stage that settled either ran over its whole population or had none.
SETTLED_STAGES = frozenset({"COMPLETE", "NOT_APPLICABLE"})

#: Statuses an entry can have.
STATE_NEW = "new"
STATE_REMOVED = "removed"
STATE_CHANGED = "changed"
STATE_PERSISTENT = "persistent"
STATE_INDETERMINATE = "indeterminate"
STATE_UNBOUND = "unbound"

#: Declaration outcome states.
OUTCOME_AGREEMENT = "agreement"
OUTCOME_CONFLICT = "version-conflict"
OUTCOME_UNRESOLVED = "unresolved-revision"
OUTCOME_DECLARED_ONLY = "declared-only"
OUTCOME_OBSERVED_ONLY = "observed-only"


class ComparisonError(ValueError):
    """A document could not be read as a scan, or as a declaration."""


# ──────────────────────────────────────────────
# Reading
# ──────────────────────────────────────────────


def read_json_document(path: Path, *, budget: int = DEFAULT_BUDGET_BYTES) -> dict[str, Any]:
    """Read a JSON object through the bounded reader, or raise ComparisonError."""
    reader = open_bounded(Path(path))
    try:
        data = reader.read_all_bounded(budget)
    except BoundedReadLimitError as exc:  # pragma: no cover - budget is generous
        raise ComparisonError(f"{path} is larger than the {budget}-byte budget: {exc}") from exc
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ComparisonError(f"{path} is not a JSON document: {exc}") from exc
    if not isinstance(payload, dict):
        raise ComparisonError(f"{path} does not contain a JSON object")
    return payload


def load_scan(path: Path) -> dict[str, Any]:
    """Load one saved scan document, upgrading older schemas."""
    payload = read_json_document(path)
    version = payload.get("schema_version")
    if not isinstance(version, int) or version > MAX_SCAN_SCHEMA:
        raise ComparisonError(
            f"{path} is not a scan document this release can compare "
            f"(schema_version {version!r}, this release reads up to {MAX_SCAN_SCHEMA})"
        )
    try:
        document = load_document(payload)
    except (ValueError, KeyError, TypeError) as exc:
        raise ComparisonError(f"{path} is not a readable scan document: {exc}") from exc
    if "artifact" not in document or "assessment" not in document:
        raise ComparisonError(f"{path} is not a scan document: no artifact or assessment")
    return document


# ──────────────────────────────────────────────
# Small helpers
# ──────────────────────────────────────────────


def _split_locator(locator: str) -> tuple[str, str]:
    """Split a locator into its path and its in-file suffix.

    Suffixes are the coordinate systems the scanner uses: ``:12`` for a line,
    ``@37098`` for a byte offset. The suffix is kept apart so ``a/b:1`` and
    ``a/c:1`` match on the trailing path component and the same line.
    """
    text = str(locator)
    for separator in ("@", ":"):
        head, found, tail = text.rpartition(separator)
        if found and head and tail.replace(".", "").isdigit():
            return head, separator + tail
    return text, ""


def _trailing(path: str) -> str:
    """The last path component, i.e. the identity that survives a move."""
    return path.rstrip("/").rsplit("/", 1)[-1]


def _identity_tail(locator: str) -> tuple[str, str]:
    path, suffix = _split_locator(locator)
    return _trailing(path), suffix


def _match_locations(
    base: Iterable[str], target: Iterable[str]
) -> tuple[list[tuple[str, str]], list[str], list[str]]:
    """Pair locations by trailing identity, keeping multiplicity.

    Exact locators are paired first, then same-tail pairs are reported as
    moved. Whatever is left over is genuinely base-only or target-only.
    """
    base_list = [str(item) for item in base]
    target_list = [str(item) for item in target]
    pairs: list[tuple[str, str]] = []
    remaining_target = list(target_list)
    remaining_base: list[str] = []
    for locator in base_list:
        if locator in remaining_target:
            remaining_target.remove(locator)
            pairs.append((locator, locator))
        else:
            remaining_base.append(locator)
    unmatched_base: list[str] = []
    for locator in remaining_base:
        tail = _identity_tail(locator)
        for candidate in remaining_target:
            if _identity_tail(candidate) == tail:
                remaining_target.remove(candidate)
                pairs.append((locator, candidate))
                break
        else:
            unmatched_base.append(locator)
    return pairs, unmatched_base, remaining_target


def _stage_map(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(stage.get("stage")): stage
        for stage in (document.get("stages") or [])
        if isinstance(stage, dict) and stage.get("stage")
    }


def _settled(stages: dict[str, dict[str, Any]], stage_id: str) -> tuple[bool, str]:
    """Whether a stage settled, and why not when it did not."""
    stage = stages.get(stage_id)
    if stage is None:
        return False, f"stage {stage_id} was not recorded"
    status = str(stage.get("status") or "")
    if status in SETTLED_STAGES:
        return True, ""
    reason = str(stage.get("reason") or status.lower())
    return False, f"stage {stage_id} is {status}: {reason}"


def _artifact_identity(document: dict[str, Any]) -> dict[str, Any]:
    artifact = document.get("artifact") or {}
    assessment = document.get("assessment") or {}
    opkg = document.get("opkg") or {}
    ruleset = document.get("ruleset") or {}
    advisory = document.get("advisory") or {}
    snapshot = (advisory.get("snapshot") or {}) if isinstance(advisory, dict) else {}
    extraction = document.get("extraction") or {}
    return {
        "scan_id": document.get("scan_id"),
        "name": artifact.get("name"),
        "sha256": artifact.get("sha256"),
        "size": artifact.get("size"),
        "kind": artifact.get("kind"),
        "scanner_version": (document.get("tool") or {}).get("version"),
        "schema_version": document.get("schema_version"),
        "profile": assessment.get("profile"),
        "profile_version": assessment.get("profile_version"),
        "completion": assessment.get("completion"),
        "ruleset_digest": ruleset.get("digest"),
        "ruleset_files": len(ruleset.get("rule_files") or []),
        "advisory_snapshot_digest": snapshot.get("digest_sha256"),
        "advisory_provider": snapshot.get("provider"),
        "advisory_acquired_at": snapshot.get("acquired_at"),
        "advisory_state": advisory.get("state") if isinstance(advisory, dict) else None,
        "opkg_database_sha256": opkg.get("database_sha256"),
        "opkg_locator": opkg.get("locator"),
        "opkg_installed": opkg.get("installed"),
        "components": len(document.get("components") or []),
        "worker_image": (extraction.get("worker_image") if extraction else None),
        "worker_version": (extraction.get("backend_version") if extraction else None),
    }


# ──────────────────────────────────────────────
# Instrument changes — read before any difference
# ──────────────────────────────────────────────


def _environment_changes(
    base: dict[str, Any], target: dict[str, Any]
) -> tuple[dict[str, Any], list[str]]:
    """What changed in the instruments, and the consequences for comparison."""
    fields = {
        "scanner_version": "scanner version",
        "profile": "scan profile",
        "profile_version": "profile version",
        "ruleset_digest": "rule-set digest",
        "advisory_snapshot_digest": "advisory snapshot digest",
        "advisory_provider": "advisory provider",
        "advisory_acquired_at": "advisory acquisition time",
        "opkg_database_sha256": "opkg database digest",
    }
    comparison: dict[str, Any] = {}
    changed: list[str] = []
    for key, label in fields.items():
        before, after = base.get(key), target.get(key)
        differs = before != after
        comparison[key] = {"base": before, "target": after, "changed": differs}
        if differs:
            changed.append(f"{label}: {before or 'none'} → {after or 'none'}")
    return comparison, changed


def _comparability(
    base_doc: dict[str, Any],
    target_doc: dict[str, Any],
    base: dict[str, Any],
    target: dict[str, Any],
) -> dict[str, Any]:
    """Per-destination comparability, with the reason when it is not."""
    base_stages, target_stages = _stage_map(base_doc), _stage_map(target_doc)
    instruments_differ: list[str] = []
    if base.get("scanner_version") != target.get("scanner_version"):
        instruments_differ.append(
            "the two scans were produced by different scanner versions, so their "
            "findings answer different questions"
        )
    if base.get("profile") != target.get("profile") or base.get("profile_version") != target.get(
        "profile_version"
    ):
        instruments_differ.append(
            "the two scans selected different profiles or profile versions, so their "
            "required work is not the same"
        )
    ruleset_changed = base.get("ruleset_digest") != target.get("ruleset_digest")

    destinations: dict[str, Any] = {}
    for destination, stage_ids in DESTINATION_STAGES.items():
        reasons = list(instruments_differ)
        if destination in RULE_BASED_DESTINATIONS and ruleset_changed:
            reasons.append(
                f"the compiled rule-set digest changed "
                f"({base.get('ruleset_digest') or 'none'} → "
                f"{target.get('ruleset_digest') or 'none'}), so the same match means "
                "something different"
            )
        for stage_id in stage_ids:
            for side, stages in (("base", base_stages), ("target", target_stages)):
                settled, why = _settled(stages, stage_id)
                if not settled:
                    reasons.append(f"{side} scan: {why}")
        # A duplicate reason from two sides is noise; keep the first of each.
        unique = list(dict.fromkeys(reasons))
        destinations[destination] = {
            "comparable": not unique,
            "reasons": unique,
        }

    comparable_destinations = [name for name, entry in destinations.items() if entry["comparable"]]
    if len(comparable_destinations) == len(destinations):
        status = "comparable"
    elif comparable_destinations:
        status = "partial"
    else:
        status = "indeterminate"
    return {
        "status": status,
        "destinations": destinations,
        "comparable_destinations": comparable_destinations,
    }


def _coverage_changes(base_doc: dict[str, Any], target_doc: dict[str, Any]) -> list[dict[str, Any]]:
    """Stages whose status or required flag differs, with both reasons."""
    base_stages, target_stages = _stage_map(base_doc), _stage_map(target_doc)
    changes: list[dict[str, Any]] = []
    for stage_id in sorted(set(base_stages) | set(target_stages)):
        before = base_stages.get(stage_id, {})
        after = target_stages.get(stage_id, {})
        if before.get("status") == after.get("status") and before.get("required") == after.get(
            "required"
        ):
            continue
        changes.append(
            {
                "stage": stage_id,
                "base": {
                    "status": before.get("status"),
                    "required": before.get("required"),
                    "reason": before.get("reason"),
                    "inspected": before.get("inspected"),
                    "eligible": before.get("eligible"),
                },
                "target": {
                    "status": after.get("status"),
                    "required": after.get("required"),
                    "reason": after.get("reason"),
                    "inspected": after.get("inspected"),
                    "eligible": after.get("eligible"),
                },
            }
        )
    return changes


# ──────────────────────────────────────────────
# Packages
# ──────────────────────────────────────────────


def _package_records(document: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Installed records grouped by package name, every occurrence kept."""
    opkg = document.get("opkg") or {}
    grouped: dict[str, list[dict[str, Any]]] = {}
    for record in opkg.get("records") or []:
        if not record.get("installed"):
            continue
        name = str(record.get("name") or "")
        if not name:
            continue
        grouped.setdefault(name, []).append(
            {
                "version": record.get("version"),
                "architecture": record.get("architecture"),
                "held": record.get("held"),
                "locator": opkg.get("locator"),
                "database_sha256": opkg.get("database_sha256"),
                "evidence": record.get("evidence"),
            }
        )
    return grouped


def _package_locators(records: list[dict[str, Any]]) -> set[str]:
    """One locator per record: database locator plus stanza byte range."""
    locators: set[str] = set()
    for record in records:
        evidence = record.get("evidence") or {}
        start = evidence.get("start")
        end = evidence.get("end")
        locators.add(f"{record.get('locator')}:{start}-{end}")
    return locators


def _compare_packages(base_doc: dict[str, Any], target_doc: dict[str, Any]) -> dict[str, Any]:
    base_records = _package_records(base_doc)
    target_records = _package_records(target_doc)
    changed: list[dict[str, Any]] = []
    new: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    relocated: list[dict[str, Any]] = []
    persistent = 0
    seen: set[str] = set()

    for name in sorted(base_records):
        before = base_records[name]
        seen.add(name)
        after = target_records.get(name)
        if after is None:
            removed.append({"name": name, "base": before})
            continue
        before_versions = sorted({str(r["version"]) for r in before})
        after_versions = sorted({str(r["version"]) for r in after})
        if before_versions != after_versions or sorted(
            {str(r["architecture"]) for r in before}
        ) != sorted({str(r["architecture"]) for r in after}):
            changed.append(
                {
                    "name": name,
                    "base_versions": before_versions,
                    "target_versions": after_versions,
                    "base": before,
                    "target": after,
                }
            )
            continue
        persistent += 1
        before_locators = sorted(_package_locators(before))
        after_locators = sorted(_package_locators(after))
        if before_locators != after_locators:
            relocated.append(
                {
                    "name": name,
                    "versions": before_versions,
                    "base": before,
                    "target": after,
                }
            )

    for name in sorted(set(target_records) - seen):
        new.append({"name": name, "target": target_records[name]})

    return {
        "base_records": sum(len(records) for records in base_records.values()),
        "target_records": sum(len(records) for records in target_records.values()),
        "base_names": len(base_records),
        "target_names": len(target_records),
        "persistent": persistent,
        "changed": changed,
        "new": new,
        "removed": removed,
        "relocated": relocated,
        "identity": (
            "the Package name in the image's own opkg database; every occurrence is kept, "
            "so two roots with different revisions remain two facts"
        ),
        "counts": {
            "persistent": persistent,
            "changed": len(changed),
            "new": len(new),
            "removed": len(removed),
            "relocated": len(relocated),
        },
    }


# ──────────────────────────────────────────────
# Components and layout
# ──────────────────────────────────────────────


def _components(document: dict[str, Any]) -> dict[tuple[str, str], list[dict[str, Any]]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for component in document.get("components") or []:
        key = (str(component.get("vendor") or ""), str(component.get("product") or ""))
        grouped.setdefault(key, []).append(component)
    return grouped


def _compare_components(base_doc: dict[str, Any], target_doc: dict[str, Any]) -> dict[str, Any]:
    base_components = _components(base_doc)
    target_components = _components(target_doc)
    changed: list[dict[str, Any]] = []
    new: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    relocated: list[dict[str, Any]] = []
    persistent = 0
    seen: set[tuple[str, str]] = set()

    for key in sorted(base_components):
        seen.add(key)
        before = base_components[key]
        after = target_components.get(key)
        identity = f"{key[0]}:{key[1]}"
        if after is None:
            removed.append({"identity": identity, "base": before})
            continue
        before_versions = sorted({str(c.get("version")) for c in before})
        after_versions = sorted({str(c.get("version")) for c in after})
        if before_versions != after_versions:
            changed.append(
                {
                    "identity": identity,
                    "base_versions": before_versions,
                    "target_versions": after_versions,
                    "base_basis": sorted({str(c.get("cpe_basis")) for c in before}),
                    "target_basis": sorted({str(c.get("cpe_basis")) for c in after}),
                }
            )
            continue
        persistent += 1
        before_locations = sorted(
            str(locator)
            for component in before
            for locator in (component.get("occurrences") or [component.get("source_file")])
        )
        after_locations = sorted(
            str(locator)
            for component in after
            for locator in (component.get("occurrences") or [component.get("source_file")])
        )
        if before_locations != after_locations:
            relocated.append(
                {
                    "identity": identity,
                    "versions": before_versions,
                    "base_locations": before_locations,
                    "target_locations": after_locations,
                }
            )

    for key in sorted(set(target_components) - seen):
        new.append({"identity": f"{key[0]}:{key[1]}", "target": target_components[key]})

    bases: dict[str, dict[str, int]] = {}
    for label, document in (("base", base_doc), ("target", target_doc)):
        counts = (document.get("component_bases") or {}).get("counts") or {}
        bases[label] = {str(name): int(value) for name, value in counts.items()}

    return {
        "base_components": len(base_doc.get("components") or []),
        "target_components": len(target_doc.get("components") or []),
        "persistent": persistent,
        "changed": changed,
        "new": new,
        "removed": removed,
        "relocated": relocated,
        "basis_counts": bases,
        "counts": {
            "persistent": persistent,
            "changed": len(changed),
            "new": len(new),
            "removed": len(removed),
            "relocated": len(relocated),
        },
        "identity": (
            "the (vendor, product) pair; versions and occurrences are compared, and a "
            "component whose locators differ is the same component that moved"
        ),
    }


def _layout_identities(document: dict[str, Any]) -> tuple[str, dict[str, list[str]]]:
    """Content identity → locators, per document, plus which source was used."""
    tree = document.get("tree") or {}
    manifest = tree.get("manifest") or []
    identities: dict[str, list[str]] = {}
    if manifest:
        for entry in manifest:
            if str(entry.get("kind")) != "file":
                continue
            digest = entry.get("sha256")
            key = f"sha256:{digest}" if digest else f"file:{entry.get('size')}"
            identities.setdefault(key, []).append(str(entry.get("path")))
        return "tree-manifest", identities
    elf = document.get("elf") or {}
    for record in elf.get("records") or []:
        build_id = record.get("build_id")
        digest = record.get("digest_sha256")
        key = f"build-id:{build_id}" if build_id else f"sha256:{digest}"
        identities.setdefault(key, []).append(str(record.get("locator")))
    return "elf-records", identities


def _compare_layout(base_doc: dict[str, Any], target_doc: dict[str, Any]) -> dict[str, Any]:
    base_source, base_identities = _layout_identities(base_doc)
    target_source, target_identities = _layout_identities(target_doc)
    relocated: list[dict[str, Any]] = []
    new: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    unchanged = 0
    for key in sorted(base_identities):
        before = sorted(base_identities[key])
        after = target_identities.get(key)
        if after is None:
            removed.append({"identity": key, "base_locations": before})
            continue
        after_sorted = sorted(after)
        if before == after_sorted:
            unchanged += 1
        else:
            relocated.append(
                {
                    "identity": key,
                    "base_locations": before,
                    "target_locations": after_sorted,
                }
            )
    for key in sorted(set(target_identities) - set(base_identities)):
        new.append({"identity": key, "target_locations": sorted(target_identities[key])})

    # The same path carrying different bytes is a rebuild, not a move.
    base_paths = {locator: key for key, locators in base_identities.items() for locator in locators}
    target_paths = {
        locator: key for key, locators in target_identities.items() for locator in locators
    }
    rebuilt = [
        {"locator": path, "base_identity": base_paths[path], "target_identity": target_paths[path]}
        for path in sorted(set(base_paths) & set(target_paths))
        if base_paths[path] != target_paths[path]
    ]

    return {
        "base_source": base_source,
        "target_source": target_source,
        "unchanged": unchanged,
        "relocated": relocated,
        "rebuilt_at_same_path": rebuilt,
        "new": new,
        "removed": removed,
        "counts": {
            "unchanged": unchanged,
            "relocated": len(relocated),
            "rebuilt_at_same_path": len(rebuilt),
            "new": len(new),
            "removed": len(removed),
        },
        "identity": (
            "content identity — an ELF build ID when the file declares one, else the file "
            "digest; a file that moved keeps its identity"
        ),
    }


# ──────────────────────────────────────────────
# Findings
# ──────────────────────────────────────────────


def _finding_groups(document: dict[str, Any]) -> dict[tuple[str, str], list[dict[str, Any]]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for finding in document.get("findings") or []:
        key = (
            str(finding.get("destination") or "unrecorded"),
            str(finding.get("rule_id") or "unknown"),
        )
        grouped.setdefault(key, []).append(finding)
    return grouped


def _finding_members(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One member per location, carrying the finding's own facts."""
    members: list[dict[str, Any]] = []
    for finding in findings:
        for locator in finding.get("locations") or [""]:
            members.append(
                {
                    "rule_id": finding.get("rule_id"),
                    "destination": finding.get("destination"),
                    "severity": finding.get("severity"),
                    "title": finding.get("title"),
                    "location": locator,
                }
            )
    return members


def _compare_findings(
    base_doc: dict[str, Any],
    target_doc: dict[str, Any],
    comparability: dict[str, Any],
) -> dict[str, Any]:
    base_groups = _finding_groups(base_doc)
    target_groups = _finding_groups(target_doc)
    per_destination: dict[str, dict[str, Any]] = {}
    new: list[dict[str, Any]] = []
    persistent: list[dict[str, Any]] = []
    changed: list[dict[str, Any]] = []
    resolved: list[dict[str, Any]] = []
    indeterminate: list[dict[str, Any]] = []

    for key in sorted(set(base_groups) | set(target_groups)):
        destination, _rule_id = key
        entry = comparability["destinations"].get(
            destination, {"comparable": False, "reasons": ["unknown destination"]}
        )
        bucket = per_destination.setdefault(
            destination,
            {
                "comparable": entry["comparable"],
                "reasons": entry["reasons"],
                "base": 0,
                "target": 0,
                STATE_NEW: 0,
                STATE_PERSISTENT: 0,
                STATE_CHANGED: 0,
                STATE_REMOVED: 0,
                STATE_INDETERMINATE: 0,
            },
        )
        before_members = _finding_members(base_groups.get(key, []))
        after_members = _finding_members(target_groups.get(key, []))
        bucket["base"] += len(before_members)
        bucket["target"] += len(after_members)

        if not entry["comparable"]:
            for member in before_members:
                indeterminate.append({**member, "side": "base", "reasons": entry["reasons"]})
                bucket[STATE_INDETERMINATE] += 1
            for member in after_members:
                indeterminate.append({**member, "side": "target", "reasons": entry["reasons"]})
                bucket[STATE_INDETERMINATE] += 1
            continue

        pairs, removed_members, new_members = _match_locations(
            [member["location"] for member in before_members],
            [member["location"] for member in after_members],
        )
        by_location = {member["location"]: member for member in before_members}
        target_by_location = {member["location"]: member for member in after_members}
        for base_location, target_location in pairs:
            before = by_location[base_location]
            after = target_by_location[target_location]
            if before["severity"] != after["severity"]:
                changed.append(
                    {
                        **after,
                        "base_severity": before["severity"],
                        "target_severity": after["severity"],
                        "base_location": base_location,
                        "relocated": base_location != target_location,
                    }
                )
                bucket[STATE_CHANGED] += 1
            else:
                persistent.append(
                    {
                        **after,
                        "base_location": base_location,
                        "relocated": base_location != target_location,
                    }
                )
                bucket[STATE_PERSISTENT] += 1
        for location in removed_members:
            resolved.append({**by_location[location]})
            bucket[STATE_REMOVED] += 1
        for location in new_members:
            new.append({**target_by_location[location]})
            bucket[STATE_NEW] += 1

    return {
        "by_destination": per_destination,
        "new": new,
        "persistent": persistent,
        "changed": changed,
        "resolved": resolved,
        "indeterminate": indeterminate,
        "counts": {
            STATE_NEW: len(new),
            STATE_PERSISTENT: len(persistent),
            STATE_CHANGED: len(changed),
            STATE_REMOVED: len(resolved),
            STATE_INDETERMINATE: len(indeterminate),
        },
        "identity": (
            "the rule that produced the finding, matched location by location on "
            "trailing path components; a finding that followed a moved file is "
            "persistent and relocated, and a detector that did not settle is "
            "indeterminate — never resolved"
        ),
    }


# ──────────────────────────────────────────────
# Declarations (5D)
# ──────────────────────────────────────────────


@dataclass
class Declaration:
    """One declaration input, read and bound to the scan it is compared with."""

    path: Path
    kind: str
    digest_sha256: str
    byte_length: int
    rows: list[dict[str, str]] = field(default_factory=list)
    unparsed_lines: int = 0
    claimed_image_sha256: str | None = None
    spec_version: str | None = None
    notes: list[str] = field(default_factory=list)


def _read_manifest(path: Path, budget: int) -> Declaration:
    reader = open_bounded(Path(path))
    data = reader.read_all_bounded(budget)
    digest = hashlib.sha256(data).hexdigest()
    rows: list[dict[str, str]] = []
    unparsed = 0
    for raw in data.decode("utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        name, separator, version = line.partition(" - ")
        if not separator or not name.strip():
            unparsed += 1
            continue
        rows.append({"name": name.strip(), "version": version.strip()})
    return Declaration(
        path=Path(path),
        kind="openwrt-target-manifest",
        digest_sha256=digest,
        byte_length=len(data),
        rows=rows,
        unparsed_lines=unparsed,
    )


def _declared_image_digest(payload: dict[str, Any]) -> str | None:
    """The image digest a CycloneDX document claims, if it claims one."""
    metadata = payload.get("metadata") or {}
    component = metadata.get("component") or {}
    for entry in component.get("hashes") or []:
        if str(entry.get("alg", "")).upper().replace("-", "") == "SHA256":
            value = str(entry.get("content") or "").lower()
            if len(value) == 64:
                return value
    for prop in metadata.get("properties") or []:
        name = str(prop.get("name") or "").lower()
        value = str(prop.get("value") or "").lower()
        if "sha256" in name and len(value) == 64:
            return value
    return None


def _read_cyclonedx(payload: dict[str, Any], path: Path, digest: str, length: int) -> Declaration:
    rows: list[dict[str, str]] = []
    unparsed = 0
    for component in payload.get("components") or []:
        if not isinstance(component, dict):
            unparsed += 1
            continue
        name = str(component.get("name") or "")
        version = str(component.get("version") or "")
        if not name:
            unparsed += 1
            continue
        rows.append({"name": name, "version": version})
    return Declaration(
        path=path,
        kind="cyclonedx",
        digest_sha256=digest,
        byte_length=length,
        rows=rows,
        unparsed_lines=unparsed,
        claimed_image_sha256=_declared_image_digest(payload),
        spec_version=str(payload.get("specVersion") or ""),
    )


def _read_declaration(path: Path, *, budget: int) -> Declaration:
    reader = open_bounded(Path(path))
    data = reader.read_all_bounded(budget)
    digest = hashlib.sha256(data).hexdigest()
    stripped = data.lstrip()[:1]
    if stripped == b"{":
        try:
            payload = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise ComparisonError(f"{path} is not a readable JSON declaration: {exc}") from exc
        if not isinstance(payload, dict) or payload.get("bomFormat") != "CycloneDX":
            raise ComparisonError(f"{path} is JSON but not a CycloneDX document")
        return _read_cyclonedx(payload, Path(path), digest, len(data))
    # Anything else is read as the line-oriented target manifest, whose format
    # is `name - version`. Unknown lines are counted, never guessed at.
    return _read_manifest(Path(path), budget)


def _observed_records(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    opkg = document.get("opkg") or {}
    observed: dict[str, dict[str, Any]] = {}
    for record in opkg.get("records") or []:
        if not record.get("installed"):
            continue
        observed[str(record.get("name"))] = {
            "version": str(record.get("version") or ""),
            "architecture": record.get("architecture"),
            "held": record.get("held"),
            "evidence": record.get("evidence"),
            "locator": opkg.get("locator"),
            "database_sha256": opkg.get("database_sha256"),
        }
    return observed


def _upstream_version(version: str) -> str:
    """The upstream version of an opkg version string, without the -rN revision."""
    head, separator, tail = version.rpartition("-r")
    if separator and tail.isdigit():
        return head
    return version


def _is_revision_less(declared: str, observed: str) -> bool:
    """Whether the declaration names the version the image records, less detail.

    OpenWrt records two kinds of suffix the upstream version does not carry: a
    package revision (``-rN``) and a build suffix (``~<commit>``). A declaration
    that stops short of either is unresolved at that granularity — not a
    mismatch — while a genuinely different version remains a conflict.
    """
    upstream = _upstream_version(observed)
    if upstream == declared:
        return True
    return any(upstream.startswith(declared + separator) for separator in ("~", "+"))


def _classify_declared(declared: str, observed: str) -> str:
    if declared == observed:
        return OUTCOME_AGREEMENT
    if _is_revision_less(declared, observed):
        return OUTCOME_UNRESOLVED
    return OUTCOME_CONFLICT


def _reconcile(
    declaration: Declaration,
    document: dict[str, Any],
    image_sha256: str,
) -> dict[str, Any]:
    observed = _observed_records(document)
    declared_names: set[str] = set()
    rows: list[dict[str, Any]] = []
    outcomes = {
        OUTCOME_AGREEMENT: 0,
        OUTCOME_UNRESOLVED: 0,
        OUTCOME_CONFLICT: 0,
        OUTCOME_DECLARED_ONLY: 0,
        OUTCOME_OBSERVED_ONLY: 0,
        STATE_UNBOUND: 0,
    }

    claim = declaration.claimed_image_sha256
    if claim is None:
        binding = {
            "status": "unclaimed",
            "claimed_image_sha256": None,
            "note": (
                "the declaration carries no image digest, so its association with this "
                "image is scope-based and unverified; proximity and release name cannot "
                "bind it"
            ),
        }
    elif claim == image_sha256:
        binding = {
            "status": "bound",
            "claimed_image_sha256": claim,
            "note": "the declaration names this image's digest",
        }
    else:
        binding = {
            "status": "mismatched",
            "claimed_image_sha256": claim,
            "note": (
                "the declaration names a different image; its rows are recorded but "
                "never used to resolve anything about this one"
            ),
        }

    for row in declaration.rows:
        name = row["name"]
        declared_names.add(name)
        record: dict[str, Any] = {"name": name, "declared_version": row["version"]}
        if binding["status"] == "mismatched":
            record["state"] = STATE_UNBOUND
            outcomes[STATE_UNBOUND] += 1
        elif name not in observed:
            record["state"] = OUTCOME_DECLARED_ONLY
            outcomes[OUTCOME_DECLARED_ONLY] += 1
        else:
            observation = observed[name]
            record["observed_version"] = observation["version"]
            record["state"] = _classify_declared(row["version"], observation["version"])
            record["evidence"] = observation["evidence"]
            outcomes[record["state"]] += 1
        rows.append(record)

    observed_only = [
        {
            "name": name,
            "observed_version": record["version"],
            "evidence": record["evidence"],
        }
        for name, record in sorted(observed.items())
        if name not in declared_names
    ]
    if binding["status"] == "mismatched":
        outcomes[OUTCOME_OBSERVED_ONLY] = 0
        observed_only = []
    else:
        outcomes[OUTCOME_OBSERVED_ONLY] = len(observed_only)

    return {
        "path": str(declaration.path),
        "kind": declaration.kind,
        "spec_version": declaration.spec_version,
        "digest_sha256": declaration.digest_sha256,
        "byte_length": declaration.byte_length,
        "source": "operator-supplied declaration, read offline",
        "binding": {"image_sha256": image_sha256, **binding},
        "scope": {
            "declared_rows": len(declaration.rows),
            "unparsed_lines": declaration.unparsed_lines,
            "declared_image_sha256": declaration.claimed_image_sha256,
            "observed_rows": len(observed),
        },
        "outcomes": outcomes,
        "rows": rows,
        "observed_only": observed_only,
        "observed_provenance": {
            "opkg_locator": (document.get("opkg") or {}).get("locator"),
            "database_sha256": (document.get("opkg") or {}).get("database_sha256"),
            "installed": (document.get("opkg") or {}).get("installed"),
        },
        "notes": [
            "A declared version that names only the upstream version, while the image "
            "records a package revision, is unresolved at revision granularity; it is "
            "not upgraded to agreement and not reported as a mismatch.",
            "Reconciliation is available independently of any CycloneDX export: it reads "
            "the two documents and the image's own package records.",
        ],
    }


# ──────────────────────────────────────────────
# The comparison document
# ──────────────────────────────────────────────


def compare_documents(
    base_document: dict[str, Any],
    target_document: dict[str, Any],
    *,
    declaration_paths: Iterable[Path] = (),
    budget: int = DEFAULT_BUDGET_BYTES,
    tool_version: str = "unknown",
) -> dict[str, Any]:
    """Build the ``ihs-comparison/1`` document for two saved scans."""
    base = _artifact_identity(base_document)
    target = _artifact_identity(target_document)
    environment, environment_changes = _environment_changes(base, target)
    comparability = _comparability(base_document, target_document, base, target)
    coverage_changes = _coverage_changes(base_document, target_document)

    declarations = [
        _reconcile(
            _read_declaration(Path(path), budget=budget),
            target_document,
            str(target.get("sha256") or ""),
        )
        for path in declaration_paths
    ]

    document: dict[str, Any] = {
        "schema_version": COMPARISON_SCHEMA,
        "tool": {"name": "iot-hardware-scanner", "version": tool_version},
        "generated": datetime.now(tz=timezone.utc).isoformat(),
        "kind": "release-comparison",
        "inputs": {"base": base, "target": target},
        "environment": {
            "comparison": environment,
            "changes": environment_changes,
            "coverage_changes": coverage_changes,
        },
        "comparability": comparability,
        "packages": _compare_packages(base_document, target_document),
        "components": _compare_components(base_document, target_document),
        "layout": _compare_layout(base_document, target_document),
        "findings": _compare_findings(base_document, target_document, comparability),
        "declarations": declarations,
        "notes": [
            "This document compares two saved scans. It issues no request, runs no "
            "extractor and re-reads no firmware: every fact comes from the documents "
            "named in inputs.",
            "Coverage, instruments and rule-set identity are reported before any "
            "difference, because a change in what was asked is not a change in the image.",
            "A finding whose detector did not settle on either side is indeterminate. "
            "It is never counted as resolved.",
        ],
    }
    return document


# ──────────────────────────────────────────────
# Rendering
# ──────────────────────────────────────────────


def _cell(value: Any) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", " ")


def render_comparison_terminal(document: dict[str, Any]) -> str:
    """A compact terminal view: instruments, then what changed."""
    base = document["inputs"]["base"]
    target = document["inputs"]["target"]
    lines = [
        f"Release comparison — {base.get('name')} → {target.get('name')}",
        f"  base   {base.get('sha256')}",
        f"  target {target.get('sha256')}",
        "",
        "Instruments (read before any difference)",
        f"  scanner      {base.get('scanner_version')} → {target.get('scanner_version')}",
        f"  profile      {base.get('profile')} {base.get('profile_version')} → "
        f"{target.get('profile')} {target.get('profile_version')}",
        f"  rule set     {(base.get('ruleset_digest') or 'none')[:16]} → "
        f"{(target.get('ruleset_digest') or 'none')[:16]}",
        f"  advisory     {base.get('advisory_snapshot_digest') or 'none'} → "
        f"{target.get('advisory_snapshot_digest') or 'none'}",
    ]
    for change in document["environment"]["changes"]:
        lines.append(f"  changed: {change}")
    for change in document["environment"]["coverage_changes"]:
        lines.append(
            f"  coverage: {change['stage']} {change['base'].get('status')} → "
            f"{change['target'].get('status')}"
        )
    packages = document["packages"]
    lines += [
        "",
        "Packages",
        f"  {packages['base_names']} → {packages['target_names']} name(s); "
        f"{packages['counts']['changed']} changed, {packages['counts']['new']} new, "
        f"{packages['counts']['removed']} removed, "
        f"{packages['counts']['relocated']} relocated",
    ]
    for entry in packages["changed"]:
        lines.append(
            f"    changed {entry['name']}: {', '.join(entry['base_versions'])} → "
            f"{', '.join(entry['target_versions'])}"
        )
    for entry in packages["removed"]:
        lines.append(f"    removed {entry['name']}")
    for entry in packages["new"]:
        lines.append(f"    new {entry['name']}")
    layout = document["layout"]
    lines += [
        "",
        "Layout",
        f"  {layout['counts']['relocated']} relocated, "
        f"{layout['counts']['rebuilt_at_same_path']} rebuilt at the same path, "
        f"{layout['counts']['new']} new, {layout['counts']['removed']} removed",
    ]
    for entry in layout["relocated"]:
        lines.append(f"    relocated {entry['base_locations']} → {entry['target_locations']}")
    findings = document["findings"]
    lines += [
        "",
        "Findings",
        f"  {findings['counts']['new']} new, {findings['counts']['persistent']} persistent, "
        f"{findings['counts']['changed']} changed, {findings['counts']['removed']} resolved, "
        f"{findings['counts']['indeterminate']} indeterminate",
    ]
    for name, bucket in findings["by_destination"].items():
        state = "comparable" if bucket["comparable"] else "INDETERMINATE"
        lines.append(f"    {name}: {state}")
        if not bucket["comparable"]:
            for reason in bucket["reasons"]:
                lines.append(f"      - {reason}")
    for entry in findings["resolved"]:
        lines.append(f"    resolved {entry['rule_id']} at {entry['location']}")
    for entry in findings["new"]:
        lines.append(f"    new {entry['rule_id']} at {entry['location']}")
    for entry in findings["indeterminate"]:
        lines.append(
            f"    indeterminate {entry['rule_id']} at {entry['location']} ({entry['side']} scan)"
        )
    for declaration in document["declarations"]:
        outcomes = declaration["outcomes"]
        lines += [
            "",
            f"Declaration — {declaration['path']} ({declaration['kind']})",
            f"  binding: {declaration['binding']['status']} ({declaration['binding']['note']})",
            f"  digest: {declaration['digest_sha256']}",
            f"  {declaration['scope']['declared_rows']} declared, "
            f"{declaration['scope']['observed_rows']} observed; "
            + ", ".join(f"{name} {count}" for name, count in outcomes.items() if count),
        ]
        if declaration["binding"]["status"] == "mismatched":
            lines.append("  every row is unbound: this declaration names another image")
    return "\n".join(lines)


def render_comparison_markdown(document: dict[str, Any]) -> str:
    """A Markdown view with the instrument section first, as the plan requires."""
    base = document["inputs"]["base"]
    target = document["inputs"]["target"]
    lines = [
        "# Release comparison",
        "",
        f"- Document: `{document['schema_version']}`",
        f"- Base: `{base.get('name')}` `{base.get('sha256')}`",
        f"- Target: `{target.get('name')}` `{target.get('sha256')}`",
        f"- Generated: {document['generated']}",
        "",
        "## Instruments",
        "",
        "> A change here changes the question, not the answer. Read it before the "
        "differences below.",
        "",
        "| Dimension | Base | Target | Changed |",
        "| --- | --- | --- | --- |",
    ]
    for name, entry in document["environment"]["comparison"].items():
        lines.append(
            f"| {_cell(name)} | {_cell(entry['base'])} | {_cell(entry['target'])} | "
            f"{'yes' if entry['changed'] else 'no'} |"
        )
    if document["environment"]["coverage_changes"]:
        lines += [
            "",
            "### Coverage changes",
            "",
            "| Stage | Base | Target |",
            "| --- | --- | --- |",
        ]
        for change in document["environment"]["coverage_changes"]:
            lines.append(
                f"| {_cell(change['stage'])} | {change['base'].get('status')} | "
                f"{change['target'].get('status')} |"
            )
    lines += [
        "",
        "## Comparability",
        "",
        f"Overall: **{document['comparability']['status']}**",
        "",
        "| Destination | Comparable | Reason |",
        "| --- | --- | --- |",
    ]
    for name, entry in document["comparability"]["destinations"].items():
        lines.append(
            f"| {name} | {'yes' if entry['comparable'] else 'no'} | "
            f"{_cell('; '.join(entry['reasons']))} |"
        )
    packages = document["packages"]
    lines += [
        "",
        "## Packages",
        "",
        f"{packages['base_records']} → {packages['target_records']} installed record(s) "
        f"({packages['base_names']} → {packages['target_names']} name(s)).",
        "",
        "| Change | Package | Base | Target |",
        "| --- | --- | --- | --- |",
    ]
    for entry in packages["changed"]:
        lines.append(
            f"| changed | {_cell(entry['name'])} | "
            f"{_cell(', '.join(entry['base_versions']))} | "
            f"{_cell(', '.join(entry['target_versions']))} |"
        )
    for entry in packages["removed"]:
        versions = sorted({str(r["version"]) for r in entry["base"]})
        lines.append(f"| removed | {_cell(entry['name'])} | {_cell(', '.join(versions))} | — |")
    for entry in packages["new"]:
        versions = sorted({str(r["version"]) for r in entry["target"]})
        lines.append(f"| new | {_cell(entry['name'])} | — | {_cell(', '.join(versions))} |")
    layout = document["layout"]
    lines += [
        "",
        "## Layout",
        "",
        f"{layout['counts']['unchanged']} unchanged content identit(ies), "
        f"{layout['counts']['relocated']} relocated, "
        f"{layout['counts']['rebuilt_at_same_path']} rebuilt at the same path, "
        f"{layout['counts']['new']} new, {layout['counts']['removed']} removed.",
    ]
    for entry in layout["relocated"]:
        lines.append(
            f"- relocated `{_cell(entry['identity'])}`: {_cell(entry['base_locations'])} → "
            f"{_cell(entry['target_locations'])}"
        )
    findings = document["findings"]
    lines += [
        "",
        "## Findings",
        "",
        "| State | Count |",
        "| --- | --- |",
    ]
    for state in ("new", "persistent", "changed", "removed", "indeterminate"):
        lines.append(f"| {state} | {findings['counts'][state]} |")
    for state, key in (("resolved", "resolved"), ("new", "new")):
        for entry in findings[key]:
            lines.append(f"- {state}: `{_cell(entry['rule_id'])}` at `{_cell(entry['location'])}`")
    for entry in findings["indeterminate"]:
        lines.append(
            f"- indeterminate: `{_cell(entry['rule_id'])}` at "
            f"`{_cell(entry['location'])}` ({entry['side']} scan) — "
            f"{_cell('; '.join(entry['reasons']))}"
        )
    for declaration in document["declarations"]:
        lines += [
            "",
            f"## Declaration — `{_cell(declaration['path'])}`",
            "",
            f"- Kind: {declaration['kind']}",
            f"- Digest: `{declaration['digest_sha256']}`",
            f"- Binding: **{declaration['binding']['status']}** — {declaration['binding']['note']}",
            f"- Declared rows: {declaration['scope']['declared_rows']}; "
            f"observed records: {declaration['scope']['observed_rows']}",
            "",
            "| Outcome | Count |",
            "| --- | --- |",
        ]
        for name, count in declaration["outcomes"].items():
            lines.append(f"| {name} | {count} |")
        if declaration["binding"]["status"] != "mismatched":
            for row in declaration["rows"]:
                if row["state"] == OUTCOME_CONFLICT:
                    lines.append(
                        f"- conflict: `{_cell(row['name'])}` declared "
                        f"`{_cell(row['declared_version'])}`, image records "
                        f"`{_cell(row.get('observed_version'))}`"
                    )
            if declaration["observed_only"]:
                names = ", ".join(
                    f"`{_cell(entry['name'])}`" for entry in declaration["observed_only"]
                )
                lines.append(f"- observed-only ({len(declaration['observed_only'])}): {names}")
    lines += [""] + [f"> {note}" for note in document["notes"]]
    return "\n".join(lines)


def render_comparison(document: dict[str, Any], fmt: str) -> str:
    """Render a comparison document in ``fmt``."""
    if fmt == "json":
        return json.dumps(document, indent=2, sort_keys=False)
    if fmt == "markdown":
        return render_comparison_markdown(document)
    if fmt == "terminal":
        return render_comparison_terminal(document)
    raise ValueError(f"unsupported comparison format: {fmt}")


# ──────────────────────────────────────────────
# Exit contract for the compare command
# ──────────────────────────────────────────────

EXIT_COMPARISON_INVALID = 3
EXIT_COMPARISON_INDETERMINATE = 4
EXIT_COMPARISON_DETERMINATE = 2
EXIT_COMPARISON_CLEAN = 0
EXIT_COMPARISON_WRITE_FAILED = 6


def decide_comparison_exit(document: dict[str, Any]) -> tuple[int, str]:
    """The compare command's own exit contract.

    It is deliberately *not* the scan table: a comparison has no findings to
    grade and no required stages to complete. Precedence is:

    3  an input could not be read as a scan document (decided before this point)
    6  the requested output could not be written (decided before this point)
    2  the comparison was determinate and something differs — in the image, in
       the findings, or between a declaration and the image
    4  nothing differs, but something could not be concluded: a detector that
       produced findings did not settle, or a declaration row is unresolved or
       unbound
    0  nothing differs and nothing was left unresolved

    A detector that was never asked and produced no findings on either side is
    recorded in the document as a coverage gap and does not change the exit: it
    cannot have hidden a resolution that was never claimed.
    """
    comparability = document["comparability"]
    findings = document["findings"]

    packages = document["packages"]["counts"]
    layout = document["layout"]["counts"]
    differences = (
        packages["changed"]
        + packages["new"]
        + packages["removed"]
        + layout["relocated"]
        + layout["rebuilt_at_same_path"]
        + layout["new"]
        + layout["removed"]
        + findings["counts"]["new"]
        + findings["counts"]["changed"]
        + findings["counts"]["removed"]
    )
    totals = {
        "version-conflict": 0,
        "declared-only": 0,
        "observed-only": 0,
        "unresolved-revision": 0,
        "unbound": 0,
    }
    for declaration in document["declarations"]:
        for name in totals:
            totals[name] += int(declaration["outcomes"].get(name, 0))
    declaration_differences = (
        totals["version-conflict"] + totals["declared-only"] + totals["observed-only"]
    )
    declaration_unresolved = totals["unresolved-revision"] + totals["unbound"]

    if differences or declaration_differences:
        return EXIT_COMPARISON_DETERMINATE, "comparison complete: differences recorded"

    uncomparable_with_findings = any(
        not bucket["comparable"] and (bucket["base"] or bucket["target"])
        for bucket in findings["by_destination"].values()
    )
    if comparability["status"] == "indeterminate" or findings["counts"]["indeterminate"]:
        return (
            EXIT_COMPARISON_INDETERMINATE,
            "comparison indeterminate: a detector that produced findings did not settle",
        )
    if declaration_unresolved:
        return (
            EXIT_COMPARISON_INDETERMINATE,
            "comparison incomplete: a declaration row is unresolved or unbound",
        )
    if uncomparable_with_findings:
        return (
            EXIT_COMPARISON_INDETERMINATE,
            "comparison incomplete: a detector with findings was not comparable",
        )
    return EXIT_COMPARISON_CLEAN, "comparison complete: no differences"
