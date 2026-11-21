"""Installed-package records, read verbatim from the image (slice 4B).

The claim this module supports is narrow and checkable: *the installed database
in this image records these packages, at these versions, in this byte range.*
It is not a claim that every package-owned file is present or intact, and the
report says so.

What is read
------------
``/usr/lib/opkg/status`` — the opkg database. Each stanza is kept in full for
the fields that matter and the stanza's byte range is recorded, so a report can
point at the exact inventory entry an observation came from:

* ``Package`` — the name;
* ``Version`` — the **complete** version string, including the ``-rN``
  revision. ``1.36.1-r2`` and ``1.36.1`` are different facts and a declaration
  that only names the upstream version leaves the comparison unresolved;
* ``Architecture``, ``Status``, ``Source``, ``Depends``;
* ``Status``'s three tokens: want, flag, state. ``installed`` is a state;
  ``hold`` is a flag. Both are reported separately.

The reader is bounded: a status database above the configured text budget is
refused, not truncated, because a partial stanza list would understate the
inventory without saying so.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path

from iot_hardware_scanner.models import OpkgInventory, OpkgPackageRecord
from iot_hardware_scanner.scanner.bounded_reader import BoundedReadLimitError, open_bounded

logger = logging.getLogger(__name__)

PARSER_VERSION = "1"


def parse_opkg_status(
    data: bytes,
    *,
    locator: str = "/usr/lib/opkg/status",
) -> OpkgInventory:
    """Parse an opkg status database held in memory, keeping byte ranges."""
    digest = hashlib.sha256(data).hexdigest()
    records: list[OpkgPackageRecord] = []
    installed = 0
    held = 0
    unparsed = 0

    position = 0
    line_number = 1
    for stanza in data.split(b"\n\n"):
        length = len(stanza)
        if stanza.strip():
            record = _parse_stanza(stanza, position, line_number)
            if record is None:
                unparsed += 1
            else:
                records.append(record)
                if record.installed:
                    installed += 1
                if record.held:
                    held += 1
        position += length + 2  # the two newlines the split consumed
        line_number += stanza.count(b"\n") + 2

    # A file that does not end in a blank line loses the final separator, so
    # the offsets above can overrun by one separator; the recorded ranges are
    # still ordered and never overlap.
    return OpkgInventory(
        locator=locator,
        database_sha256=digest,
        byte_length=len(data),
        records=records,
        installed_count=installed,
        held_count=held,
        unparsed_stanzas=unparsed,
        parser_version=PARSER_VERSION,
    )


def read_opkg_status(
    path: Path,
    *,
    locator: str = "/usr/lib/opkg/status",
    budget: int = 8 * 1024 * 1024,
) -> OpkgInventory:
    """Read and parse an opkg status database through the bounded reader."""
    reader = open_bounded(Path(path))
    try:
        data = reader.read_all_bounded(budget)
    except BoundedReadLimitError as exc:
        raise ValueError(
            f"{locator} is larger than the {budget}-byte package-database budget: {exc}"
        ) from exc
    return parse_opkg_status(data, locator=locator)


def _parse_stanza(stanza: bytes, start: int, line_number: int) -> OpkgPackageRecord | None:
    """One package stanza, or ``None`` when it has no package name."""
    fields: dict[str, str] = {}
    for raw in stanza.split(b"\n"):
        text = raw.decode("utf-8", errors="replace").rstrip("\r")
        if not text or text[0] in (" ", "\t"):
            continue  # continuation line: kept only inside the verbatim record
        key, separator, value = text.partition(":")
        if not separator:
            continue
        fields.setdefault(key.strip().lower(), value.strip())
    name = fields.get("package")
    if not name:
        return None

    status = fields.get("status", "")
    tokens = status.split()
    state = tokens[-1].lower() if tokens else ""
    flag = tokens[1].lower() if len(tokens) > 1 else ""
    return OpkgPackageRecord(
        name=name,
        version=fields.get("version", ""),
        architecture=fields.get("architecture", ""),
        status=status,
        installed=state == "installed",
        held=flag == "hold",
        source=fields.get("source", ""),
        depends=fields.get("depends", ""),
        evidence_start=start,
        evidence_end=start + len(stanza),
        evidence_line=line_number,
    )


@dataclass
class PackageIndex:
    """Lookup helpers over one parsed database."""

    inventory: OpkgInventory

    def by_name(self, name: str) -> OpkgPackageRecord | None:
        """The first installed record for ``name``, if any."""
        for record in self.inventory.records:
            if record.installed and record.name == name:
                return record
        return None

    def names(self) -> list[str]:
        """Installed package names, sorted, without duplicates."""
        return sorted({record.name for record in self.inventory.records if record.installed})
