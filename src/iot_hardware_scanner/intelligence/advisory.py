"""Offline advisory applicability (slice 4C).

The scanner never fetches advisory data during a scan. This module applies a
**local snapshot** — a JSON document the operator acquired in a separate,
explicit refresh operation — to the components the scanner actually observed.

What it preserves, because losing any of it turns an advisory into a guess:

* the provider's own applicability statement: the CPE names, the version
  bounds (``version_start_including`` and friends) and any excluded versions;
* the provider's score and vector, and when the provider last modified the
  record;
* KEV membership and public exploit availability as **separate** facts from
  applicability and from each other;
* one lookup state per component, so "no match" can be told apart from "the
  snapshot did not cover this component" and from "the snapshot is stale".

Rules this module enforces:

* A keyword-sourced candidate is only a finding when the advisory's own
  product/vendor evidence matches the component. A keyword hit on its own is a
  candidate, counted and rejected, never reported as applicable.
* A clean result (``KNOWN_EMPTY`` everywhere) is a fact. Anything else —
  ``UNAVAILABLE``, ``STALE``, ``PARTIAL`` — is a stated gap, and the control
  that consumes it cannot pass.
* Offline means zero requests: nothing here opens a socket, and the snapshot
  is read once, bounded, with its digest recorded.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from iot_hardware_scanner.models import (
    AdvisoryAssessment,
    AdvisoryLookup,
    AdvisorySnapshotInfo,
    CVEFinding,
    Severity,
    SoftwareComponent,
)

logger = logging.getLogger(__name__)

#: The only snapshot schema this release reads.
SNAPSHOT_SCHEMA = "ihs-advisory-snapshot/1"

#: A snapshot whose acquisition time is older than this is reported stale.
DEFAULT_MAX_AGE_DAYS = 30

#: Bound on the number of advisories one snapshot may contain.
MAX_SNAPSHOT_ENTRIES = 200_000

_VERSION_TOKEN = re.compile(r"(\d+|[A-Za-z]+|[^0-9A-Za-z]+)")


class AdvisorySnapshotError(ValueError):
    """The supplied snapshot is not readable as one."""


# ──────────────────────────────────────────────
# Version comparison
# ──────────────────────────────────────────────


def version_key(version: str) -> tuple:
    """A comparable key for a version string such as ``1.36.1-r2``.

    Numbers compare numerically and before letters, so ``1.9`` < ``1.36`` <
    ``1.36.1`` < ``1.36.1-r2``. A distribution that backports a fix keeps the
    version string, so a version comparison is evidence about *what the package
    database says*, never proof that a fix is absent.
    """
    tokens: list[tuple[int, Any]] = []
    for match in _VERSION_TOKEN.findall(version.strip()):
        if match.isdigit():
            tokens.append((1, int(match)))
        elif match.isalpha():
            tokens.append((0, match.lower()))
        # separators carry no ordering information
    return tuple(tokens)


def _compare(left: str, right: str) -> int:
    """``-1``, ``0`` or ``1`` comparing two version strings."""
    a, b = version_key(left), version_key(right)
    return (a > b) - (a < b)


# ──────────────────────────────────────────────
# CPE handling
# ──────────────────────────────────────────────


def cpe_parts(cpe: str) -> list[str]:
    """The components of a CPE 2.3 formatted string, unescaped and lowercased."""
    body = cpe.strip()
    if body.lower().startswith("cpe:2.3:"):
        body = body[len("cpe:2.3:") :]
    elif body.lower().startswith("cpe:/"):
        body = body[len("cpe:/") :]
    return [part.replace("\\", "").lower() for part in body.split(":")]


# ──────────────────────────────────────────────
# Snapshot loading
# ──────────────────────────────────────────────


def load_snapshot(path: Path, max_bytes: int = 64 * 1024 * 1024) -> tuple[dict, str]:
    """Read a snapshot document and its digest, bounded.

    The digest is computed over the bytes that were parsed, so the report can
    name exactly the data the conclusion rests on.
    """
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise AdvisorySnapshotError(f"{path} cannot be read: {exc}") from exc
    if size > max_bytes:
        raise AdvisorySnapshotError(
            f"{path} is {size:,} bytes, beyond the {max_bytes:,}-byte snapshot budget"
        )
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise AdvisorySnapshotError(f"{path} cannot be read: {exc}") from exc
    digest = hashlib.sha256(payload).hexdigest()
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdvisorySnapshotError(f"{path} is not a JSON document: {exc}") from exc
    if not isinstance(document, dict):
        raise AdvisorySnapshotError(f"{path} does not contain a JSON object")
    schema = str(document.get("schema", ""))
    if schema != SNAPSHOT_SCHEMA:
        raise AdvisorySnapshotError(
            f"{path} declares schema {schema or '<none>'}; this release reads "
            f"{SNAPSHOT_SCHEMA} only"
        )
    entries = document.get("advisories")
    if not isinstance(entries, list):
        raise AdvisorySnapshotError(f"{path} has no 'advisories' list")
    if len(entries) > MAX_SNAPSHOT_ENTRIES:
        raise AdvisorySnapshotError(
            f"{path} carries {len(entries):,} advisories, beyond the {MAX_SNAPSHOT_ENTRIES:,} bound"
        )
    return document, digest


def describe_snapshot(
    document: dict, digest: str, path: Path, max_age_days: int = DEFAULT_MAX_AGE_DAYS
) -> AdvisorySnapshotInfo:
    """Identity, provenance and freshness of a loaded snapshot."""
    acquired_raw = str(document.get("acquired_at", ""))
    age_days = -1.0
    stale = True
    acquired = _parse_time(acquired_raw)
    if acquired is not None:
        age_days = max(0.0, (datetime.now(tz=timezone.utc) - acquired).total_seconds() / 86400)
        stale = age_days > max_age_days
    kev = document.get("kev") or {}
    return AdvisorySnapshotInfo(
        path=str(path),
        digest_sha256=digest,
        schema=str(document.get("schema", "")),
        provider=str(document.get("provider", "unrecorded")),
        acquired_at=acquired_raw,
        entries=len(document.get("advisories") or []),
        age_days=round(age_days, 2),
        stale=stale,
        includes_kev=bool(kev.get("cves")),
        sample=bool(document.get("sample", False)),
    )


def _parse_time(value: str) -> datetime | None:
    if not value:
        return None
    text = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


# ──────────────────────────────────────────────
# Applicability
# ──────────────────────────────────────────────


def _range_match(advisory: dict, version: str) -> bool:
    """Whether ``version`` falls inside the advisory's declared bounds."""
    declared_bounds = advisory.get("version_bounds")
    # The bounds may be nested (an advisory-level statement) or written directly
    # on the recorded CPE match, which is how a provider response carries them.
    bounds = declared_bounds if isinstance(declared_bounds, dict) else advisory
    excluded = advisory.get("excluded_versions") or []
    if isinstance(version, str) and version in excluded:
        return False
    checks = {
        "version_start_including": lambda value: _compare(version, value) >= 0,
        "version_start_excluding": lambda value: _compare(version, value) > 0,
        "version_end_including": lambda value: _compare(version, value) <= 0,
        "version_end_excluding": lambda value: _compare(version, value) < 0,
    }
    declared = {key: bounds[key] for key in checks if bounds.get(key)}
    if not declared:
        return False
    return all(checks[key](str(value)) for key, value in declared.items())


#: Index of each attribute inside a CPE 2.3 formatted string, after the
#: ``cpe:2.3:`` prefix is removed: part, vendor, product, version, update, ...
_CPE_VENDOR = 1
_CPE_PRODUCT = 2
_CPE_VERSION = 3


def _entry_matches(entry: dict, product: str, version: str, excluded: list | None = None) -> bool:
    """Whether one recorded CPE match names this product and includes this version."""
    parts = cpe_parts(str(entry.get("cpe", "")))
    if len(parts) <= _CPE_PRODUCT:
        return False
    if parts[_CPE_PRODUCT] not in (product.lower(), "*", "-", ""):
        return False
    concrete = parts[_CPE_VERSION] if len(parts) > _CPE_VERSION else ""
    if concrete and concrete not in ("*", "-"):
        return concrete == version.lower()
    return _range_match({**entry, "excluded_versions": excluded or []}, version)


def _cpe_matches(advisory: dict, component: SoftwareComponent) -> str | None:
    """How an advisory's own CPE statement matches a component, if it does.

    Returns ``cpe-exact``, ``version-range`` or ``None``. A recorded CPE with a
    concrete version is an exact statement; a CPE with version bounds is a range
    statement. Both are the provider's words, transcribed.
    """
    exact = False
    ranged = False
    excluded = advisory.get("excluded_versions") or []
    for entry in advisory.get("matches") or []:
        if not isinstance(entry, dict):
            continue
        parts = cpe_parts(str(entry.get("cpe", "")))
        if len(parts) <= _CPE_PRODUCT:
            continue
        if parts[_CPE_PRODUCT] not in (component.product.lower(), "*", "-", ""):
            continue
        if not _entry_matches(entry, component.product, component.version, excluded):
            continue
        concrete = parts[_CPE_VERSION] if len(parts) > _CPE_VERSION else ""
        if concrete and concrete not in ("*", "-"):
            exact = True
        else:
            ranged = True
    if exact:
        return "cpe-exact"
    if ranged:
        return "version-range"
    return None


def _keyword_matches(advisory: dict, component: SoftwareComponent) -> bool:
    """Whether a keyword-sourced candidate names this product *and* version.

    A keyword search is a query, not a finding. It becomes applicable only when
    the advisory itself names the product and its version statement includes the
    shipped version.
    """
    declared = list(advisory.get("products") or [])
    if advisory.get("product"):
        declared.append(str(advisory["product"]))
    products = {str(value).lower() for value in declared if value}
    if not products:
        return False
    if component.product.lower() not in products and component.vendor.lower() not in products:
        return False
    if _declares_version(advisory, component.version):
        return True
    excluded = advisory.get("excluded_versions") or []
    return any(
        isinstance(entry, dict)
        and _entry_matches(entry, component.product, component.version, excluded)
        for entry in advisory.get("matches") or []
    )


def _declares_version(advisory: dict, version: str) -> bool:
    versions = {str(value) for value in advisory.get("versions") or []}
    return version in versions


# ──────────────────────────────────────────────
# Assessment
# ──────────────────────────────────────────────


def assess(
    document: dict,
    snapshot: AdvisorySnapshotInfo,
    components: list[SoftwareComponent],
) -> tuple[list[CVEFinding], AdvisoryAssessment]:
    """Apply one snapshot to the observed components.

    Returns the findings and the assessment, where every component has exactly
    one lookup whose state says whether its question was answered.
    """
    advisories = [entry for entry in document.get("advisories") or [] if isinstance(entry, dict)]
    kev = document.get("kev") or {}
    kev_cves = {str(value) for value in kev.get("cves") or []}
    provider = str(document.get("provider", "unrecorded"))

    findings: list[CVEFinding] = []
    lookups: list[AdvisoryLookup] = []
    rejected_keywords = 0

    seen: dict[tuple[str, str], CVEFinding] = {}

    for component in components:
        state = "KNOWN_EMPTY"
        reason = ""
        matched = 0

        for advisory in advisories:
            cve_id = str(advisory.get("cve_id", ""))
            if not cve_id:
                continue

            applicability: str
            if advisory.get("keyword_search"):
                if not _keyword_matches(advisory, component):
                    declared = {str(value).lower() for value in advisory.get("products") or []}
                    if (
                        _declares_version(advisory, component.version)
                        or component.product.lower() in declared
                    ):
                        rejected_keywords += 1
                    continue
                applicability = "keyword-unverified"
            else:
                matched_by = _cpe_matches(advisory, component)
                if matched_by is None:
                    continue
                applicability = matched_by

            matched += 1
            state = "MATCHED"
            key = (cve_id, component.product.lower())
            existing = seen.get(key)
            location = f"{component.product} {component.version}"
            if existing is not None:
                if location not in existing.occurrences:
                    existing.occurrences.append(location)
                continue

            provider_score = advisory.get("provider_score")
            score = float(provider_score) if provider_score is not None else None
            finding = CVEFinding(
                cve_id=cve_id,
                severity=_severity_for(score, cve_id in kev_cves),
                cvss_v3_score=score,
                cvss_v3_vector=advisory.get("provider_vector"),
                description=str(advisory.get("description", "")),
                affected_product=component.product,
                affected_version=component.version,
                published_date=str(advisory.get("published", "")),
                references=[str(url) for url in advisory.get("references") or []],
                is_in_kev=cve_id in kev_cves,
                exploit_available=bool(advisory.get("exploit_available_public", False)),
                applicability=applicability,
                provider_score=score,
                provider=str(advisory.get("provider", provider)),
                last_modified=str(advisory.get("last_modified", "")),
                occurrences=[location],
                vendor_backport_uncertain=bool(advisory.get("vendor_backport_uncertain", False)),
                stale=snapshot.stale,
            )
            seen[key] = finding
            findings.append(finding)

        recorded = _recorded_state(document, component)
        if recorded is not None and state == "KNOWN_EMPTY":
            state = recorded
        if snapshot.stale and state in ("MATCHED", "KNOWN_EMPTY"):
            state = "STALE"
            reason = (
                f"the snapshot was acquired {snapshot.age_days:.0f} day(s) ago; "
                "a clean or reviewed result from it is not current"
            )
        elif recorded == "PARTIAL":
            reason = "the snapshot's own record for this query is incomplete"
        elif recorded == "UNAVAILABLE":
            reason = "the snapshot records that this query could not be answered"

        lookups.append(
            AdvisoryLookup(
                component=component.product,
                version=component.version,
                cpe=component.cpe_string,
                state=state,
                matches=matched,
                reason=reason,
            )
        )

    if not lookups:
        overall = "UNAVAILABLE"
    elif snapshot.stale:
        overall = "STALE"
    elif any(lookup.state in ("UNAVAILABLE", "PARTIAL") for lookup in lookups):
        overall = "PARTIAL"
    else:
        overall = "ASSESSED"

    assessment = AdvisoryAssessment(
        snapshot=snapshot,
        lookups=lookups,
        state=overall,
        matched=len(findings),
        kev_matches=sum(1 for finding in findings if finding.is_in_kev),
        keyword_candidates_rejected=rejected_keywords,
        kev_source=str(kev.get("source", "")) if kev_cves else "",
    )
    logger.info(
        "Advisory assessment: %d component(s), %d match(es), "
        "%d keyword candidate(s) rejected, state %s",
        len(lookups),
        len(findings),
        rejected_keywords,
        overall,
    )
    return findings, assessment


def _recorded_state(document: dict, component: SoftwareComponent) -> str | None:
    """A lookup state the snapshot recorded for this component, if any."""
    for entry in document.get("lookups") or []:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("component", "")).lower() != component.product.lower():
            continue
        if str(entry.get("version", "")) != component.version:
            continue
        state = str(entry.get("state", "")).upper()
        if state in ("UNAVAILABLE", "PARTIAL", "KNOWN_EMPTY", "MATCHED"):
            return state
    return None


def _severity_for(score: float | None, in_kev: bool) -> Severity:
    """Severity from the provider's score; KEV membership is a separate fact.

    KEV membership is recorded on the finding and read by the control. It does
    not rewrite the provider's severity, because "known exploited" and "this
    image is affected" are different statements.
    """
    if score is None:
        return Severity.MEDIUM
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO
