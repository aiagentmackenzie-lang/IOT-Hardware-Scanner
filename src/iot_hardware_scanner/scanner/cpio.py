"""CPIO initramfs archives (slice 3A, part 3).

An initramfs is a filesystem that has not been mounted. It arrives as a CPIO
archive, usually inside the kernel image or behind a gzip wrapper, and until
this module existed the scanner called it an opaque blob — the same wrong
question 2.9.0 stopped asking of disk images.

Three rules, the same three the rest of the map follows:

* **Every range is validated before it is read.** A record whose name or data
  does not fit in the file is a truncated archive, which is incomplete work:
  it raises :class:`CpioError` rather than producing a tree with holes in it.
* **A name is data, not a path.** A member name is checked against traversal
  before anything is written; an unsafe name refuses the *archive*, because a
  tree that cannot be materialised is not a tree this scanner can inventory.
* **A hard link is one file with several names.** In ``newc`` the bytes are
  carried by one member of the group and every other member declares the same
  inode with a zero length. Emitting those zero lengths as empty files would
  turn ``/etc/shadow`` into a 0-byte file and report a weaker finding than the
  artifact supports, so the group is resolved and the data is attributed to
  every name.

Formats decoded here are the three ASCII ones: ``newc`` (``070701``), ``crc``
(``070702``) and ``odc`` (``070707``). The old *binary* format (magic
``0xC7 0x71``) is recognised and refused by name rather than misparsed as
``odc``, which shares its magic's decimal spelling but not its layout.

Nothing here writes outside the destination directory, follows a symlink, or
materialises a device node, FIFO or socket: those are recorded as metadata with
their archive mode, exactly as the SquashFS worker's tar path already does.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import stat
from collections.abc import Iterator
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from iot_hardware_scanner.scanner.bounded_reader import BoundedReader, BoundedReadLimitError

logger = logging.getLogger(__name__)

#: ``newc`` and ``crc`` differ only in what the check field means.
CPIO_NEWC_MAGIC = b"070701"
CPIO_CRC_MAGIC = b"070702"
#: Old *portable ASCII*. Same decimal spelling as the binary magic, different
#: bytes — the binary form stores 0o070707 as a word, i.e. ``0xC7 0x71``.
CPIO_ODC_MAGIC = b"070707"
CPIO_BINARY_MAGIC = b"\xc7\x71"
CPIO_TRAILER_NAME = "TRAILER!!!"

CPIO_NEWC = "newc"
CPIO_CRC = "crc"
CPIO_ODC = "odc"
CPIO_BINARY = "binary"

#: 6-byte magic + 13 eight-digit hex fields, or 6 + 70 octal digits.
HEADER_BYTES = {CPIO_NEWC: 110, CPIO_CRC: 110, CPIO_ODC: 76}
#: ``newc`` pads the name and the data so every header starts on a 4-byte
#: boundary; ``odc`` has no padding at all. This is the whole difference that
#: makes one of them misparse as the other.
ALIGNMENT = {CPIO_NEWC: 4, CPIO_CRC: 4, CPIO_ODC: 1}
#: ``newc``: ino mode uid gid nlink mtime filesize devmajor devminor rdevmajor
#: rdevminor namesize check.
_FIELDS_NEWC = (
    "ino",
    "mode",
    "uid",
    "gid",
    "nlink",
    "mtime",
    "filesize",
    "devmajor",
    "devminor",
    "rdevmajor",
    "rdevminor",
    "namesize",
    "check",
)
#: ``odc``: dev ino mode uid gid nlink rdev mtime namesize filesize.
_FIELDS_ODC = ("dev", "ino", "mode", "uid", "gid", "nlink", "rdev", "mtime", "namesize", "filesize")
_FIELD_WIDTHS_ODC = (6, 6, 6, 6, 6, 6, 6, 11, 6, 11)

CPIO_DECODER_NAME = "ihs-cpio"
CPIO_DECODER_VERSION = "1"

#: ``S_IFMT`` -> the word this report uses. Anything else keeps ``other``.
_MODE_KINDS = {
    stat.S_IFREG: "file",
    stat.S_IFDIR: "dir",
    stat.S_IFLNK: "symlink",
    stat.S_IFCHR: "char",
    stat.S_IFBLK: "block",
    stat.S_IFIFO: "fifo",
    stat.S_IFSOCK: "socket",
}

#: A symlink target is a path, not content: this is a sanity bound, not a budget.
_MAX_SYMLINK_TARGET = 4096
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
_OCTAL_DIGITS = frozenset("01234567")


class CpioError(Exception):
    """An archive that cannot be read as an archive.

    Every message names the record it was reading and why it stopped, because
    "the initramfs is truncated" is a fact the operator can act on and a
    traceback is not.
    """


# ──────────────────────────────────────────────
# Records
# ──────────────────────────────────────────────


@dataclass(frozen=True)
class CpioMember:
    """One header of an archive, with the byte range its data occupies.

    ``data_offset``/``data_length`` are offsets **in the container**, validated
    against the file before the member exists. A hard link's member may declare
    a zero length while its group carries the bytes; :func:`resolve_hardlinks`
    is what decides which member owns them.
    """

    index: int
    name: str
    header_offset: int
    data_offset: int
    data_length: int
    ino: int
    mode: int
    uid: int
    gid: int
    nlink: int
    mtime: int
    dev_major: int
    dev_minor: int
    rdev_major: int
    rdev_minor: int
    check: int | None = None

    @property
    def kind(self) -> str:
        """What the mode says this record is."""
        return _MODE_KINDS.get(stat.S_IFMT(self.mode), "other")

    @property
    def inode_key(self) -> tuple[int, int, int]:
        """The identity a hard-link group shares: device, inode, and nlink > 1."""
        return (self.dev_major, self.dev_minor, self.ino)

    @property
    def is_hardlink_member(self) -> bool:
        """Whether this record is one name of a multiply-linked inode."""
        return self.kind == "file" and self.nlink > 1


@dataclass
class CpioArchive:
    """A decoded archive: every record, and what the walk concluded.

    ``archive_length`` is the span the archive occupies, ending with the
    ``TRAILER!!!`` record. ``trailing_bytes`` is what follows it — block
    padding, or a second archive — and is reported rather than decoded, because
    a concatenated initramfs is two proposed states and this release does not
    claim to merge them.
    """

    format: str
    members: list[CpioMember] = field(default_factory=list)
    archive_length: int = 0
    trailing_bytes: int = 0
    diagnostics: list[str] = field(default_factory=list)
    total_data_bytes: int = 0
    #: True when another archive follows the trailer: the tree this release
    #: decoded is a *part* of the initramfs, and the stage must say so.
    incomplete: bool = False

    @property
    def member_names(self) -> list[str]:
        """Names in archive order."""
        return [member.name for member in self.members]

    def as_dict(self) -> dict[str, Any]:
        """The fields the report records for the container node."""
        by_kind: dict[str, int] = {}
        for member in self.members:
            by_kind[member.kind] = by_kind.get(member.kind, 0) + 1
        return {
            "cpio_format": self.format,
            "member_count": len(self.members),
            "member_kinds": dict(sorted(by_kind.items())),
            "data_bytes": self.total_data_bytes,
            "archive_bytes": self.archive_length,
            "trailing_bytes": self.trailing_bytes,
            "diagnostics": list(self.diagnostics),
        }


def detect_cpio_format(head: bytes) -> str | None:
    """Name the CPIO variant whose magic starts ``head``, or ``None``.

    ``binary`` is returned so a caller can refuse it by name; it is a real
    format this release does not decode.
    """
    if head.startswith(CPIO_NEWC_MAGIC):
        return CPIO_NEWC
    if head.startswith(CPIO_CRC_MAGIC):
        return CPIO_CRC
    if head.startswith(CPIO_ODC_MAGIC):
        return CPIO_ODC
    if head.startswith(CPIO_BINARY_MAGIC):
        return CPIO_BINARY
    return None


# ──────────────────────────────────────────────
# Header parsing
# ──────────────────────────────────────────────


def _parse_field(raw: bytes, digits: frozenset[str], base: int, field_name: str) -> int:
    text = raw.decode("ascii", errors="replace")
    if not text or any(char not in digits for char in text):
        raise CpioError(f"the {field_name} field {text!r} is not a {base}-base integer")
    return int(text, base)


def _parse_newc_header(raw: bytes, index: int, header_offset: int) -> tuple[CpioMember, int]:
    values = {}
    cursor = 6
    for name in _FIELDS_NEWC:
        values[name] = _parse_field(raw[cursor : cursor + 8], _HEX_DIGITS, 16, name)
        cursor += 8
    member = CpioMember(
        index=index,
        name="",
        header_offset=header_offset,
        data_offset=0,
        data_length=values["filesize"],
        ino=values["ino"],
        mode=values["mode"],
        uid=values["uid"],
        gid=values["gid"],
        nlink=values["nlink"],
        mtime=values["mtime"],
        dev_major=values["devmajor"],
        dev_minor=values["devminor"],
        rdev_major=values["rdevmajor"],
        rdev_minor=values["rdevminor"],
        check=values["check"],
    )
    return member, values["namesize"]


def _parse_odc_header(raw: bytes, index: int, header_offset: int) -> tuple[CpioMember, int]:
    values = {}
    cursor = 6
    for name, width in zip(_FIELDS_ODC, _FIELD_WIDTHS_ODC, strict=True):
        values[name] = _parse_field(raw[cursor : cursor + width], _OCTAL_DIGITS, 8, name)
        cursor += width
    # ``odc`` carries one 6-digit device number where newc carries a major and
    # a minor. It is kept whole: splitting it would invent a layout.
    dev = values["dev"]
    rdev = values["rdev"]
    member = CpioMember(
        index=index,
        name="",
        header_offset=header_offset,
        data_offset=0,
        data_length=values["filesize"],
        ino=values["ino"],
        mode=values["mode"],
        uid=values["uid"],
        gid=values["gid"],
        nlink=values["nlink"],
        mtime=values["mtime"],
        dev_major=dev,
        dev_minor=0,
        # The old 16-bit pair, as the format itself defines it.
        rdev_major=(rdev >> 8) & 0xFF,
        rdev_minor=rdev & 0xFF,
        check=None,
    )
    return member, values["namesize"]


def _member_name(raw: bytes) -> str:
    """A member name must be NUL-terminated inside its own field."""
    if not raw or raw[-1] != 0:
        raise CpioError("a member name is not NUL-terminated inside its declared length")
    return raw[:-1].decode("utf-8", errors="backslashreplace")


# ──────────────────────────────────────────────
# Name safety
# ──────────────────────────────────────────────


def safe_relative_name(name: str) -> str:
    """Normalise a member name, or refuse it.

    A name is data that becomes a path, so it is checked before anything is
    written: no absolute path, no ``..`` component, no NUL, no drive letter.
    ``.`` and a leading ``./`` are how archives spell the root, and are
    normalised away rather than refused.
    """
    if "\x00" in name:
        raise CpioError("a member name contains a NUL byte")
    cleaned = name.replace("\\", "/")
    if cleaned.startswith("/"):
        raise CpioError(f"the member name {name!r} is an absolute path")
    parts = [part for part in cleaned.split("/") if part not in ("", ".")]
    if any(part == ".." for part in parts):
        raise CpioError(f"the member name {name!r} leaves the extraction root")
    return "/".join(parts)


# ──────────────────────────────────────────────
# The walk
# ──────────────────────────────────────────────


def decode_cpio(
    reader: BoundedReader,
    *,
    max_members: int = 200_000,
    max_data_bytes: int = 1024 * 1024 * 1024,
    offset: int = 0,
) -> CpioArchive:
    """Walk the headers of an archive without reading any member's data.

    Every jump is validated against the file before it is taken, so a record
    that declares more bytes than exist is a truncation error, not a short read
    that later looks like a small file.
    """
    head = reader.read_at(offset, min(6, max(reader.size - offset, 0)))
    archive_format = detect_cpio_format(head)
    if archive_format is None:
        raise CpioError("no CPIO magic (070701, 070702 or 070707) at this offset")
    if archive_format == CPIO_BINARY:
        raise CpioError(
            "this is a binary CPIO archive (magic 0xC7 0x71); this release decodes "
            "newc, crc and odc only"
        )

    header_bytes = HEADER_BYTES[archive_format]
    alignment = ALIGNMENT[archive_format]
    archive = CpioArchive(format=archive_format)
    cursor = offset
    seen_names: set[str] = set()

    while True:
        if cursor + header_bytes > reader.size:
            raise CpioError(
                f"the archive ends at byte {cursor} without a {CPIO_TRAILER_NAME} record: "
                "it is truncated"
            )
        raw = reader.read_at(cursor, header_bytes)
        member_format = detect_cpio_format(raw[:6])
        if member_format != archive_format:
            raise CpioError(
                f"a record at byte {cursor} carries magic {raw[:6]!r}, not the "
                f"{archive_format} magic the archive started with"
            )
        if archive_format == CPIO_ODC:
            member, raw_namesize = _parse_odc_header(raw, len(archive.members), cursor)
        else:
            member, raw_namesize = _parse_newc_header(raw, len(archive.members), cursor)

        name_offset = cursor + header_bytes
        if member.index >= max_members:
            raise CpioError(
                f"the archive holds more than {max_members:,} records, over the entry budget"
            )

            raise CpioError(f"a record at byte {cursor} declares an empty name field")
        if name_offset + raw_namesize > reader.size:
            raise CpioError(f"the name field of the record at byte {cursor} runs past the input")
        name = _member_name(reader.read_at(name_offset, raw_namesize))
        # A name is data that becomes a path, so it is checked here — before the
        # member exists, before the map has a locator for it, and before any
        # caller could write it. Normalising here is what makes every later
        # offset and digest refer to the same record.
        name = safe_relative_name(name) if name != CPIO_TRAILER_NAME else name

        # ``newc`` pads (header + name) to a 4-byte boundary; ``odc`` does not.
        unpadded = header_bytes + raw_namesize
        padding = (-unpadded) % alignment
        data_offset = name_offset + raw_namesize + padding
        if data_offset + member.data_length > reader.size:
            raise CpioError(
                f"the record {name!r} declares {member.data_length} data byte(s) at "
                f"{data_offset}, past the end of the {reader.size}-byte input"
            )

        if name == CPIO_TRAILER_NAME:
            if member.data_length != 0:
                raise CpioError(
                    f"the {CPIO_TRAILER_NAME} record declares {member.data_length} data byte(s)"
                )
            archive.archive_length = data_offset - offset
            archive.trailing_bytes = reader.size - data_offset
            if archive.trailing_bytes:
                following = reader.read_at(data_offset, min(6, archive.trailing_bytes))
                note = (
                    "a second archive follows the first (a concatenated initramfs); "
                    "only the first is decoded"
                    if detect_cpio_format(following)
                    else "block padding or trailing bytes after the trailer"
                )
                archive.incomplete = bool(detect_cpio_format(following))
                archive.diagnostics.append(
                    f"{archive.trailing_bytes} byte(s) after {CPIO_TRAILER_NAME}: {note}"
                )
            break

        if not name:
            # The archive's own root (``.`` or ``./``) normalises to nothing and
            # is created when its children are; only a *file* with no path is an
            # error.
            if member.kind != "dir":
                raise CpioError(f"the record at byte {cursor} is not a directory and has no name")
            name = "."
        if member.kind == "symlink" and member.data_length > _MAX_SYMLINK_TARGET:
            raise CpioError(
                f"the symlink {name!r} declares a {member.data_length}-byte target, "
                f"over the {_MAX_SYMLINK_TARGET}-byte sanity bound"
            )
        archive.total_data_bytes += member.data_length
        if archive.total_data_bytes > max_data_bytes:
            raise CpioError(
                f"the archive declares more than {max_data_bytes:,} data bytes, "
                "over the decoded-data budget"
            )
        if name in seen_names:
            archive.diagnostics.append(f"the member name {name!r} appears more than once")
        seen_names.add(name)

        member = replace(member, name=name, data_offset=data_offset)
        archive.members.append(member)
        cursor = data_offset + member.data_length
        cursor += (-member.data_length) % alignment

    logger.info(
        "cpio %s archive: %d member(s), %d data byte(s), %d trailing byte(s)",
        archive_format,
        len(archive.members),
        archive.total_data_bytes,
        archive.trailing_bytes,
    )
    return archive


def resolve_hardlinks(
    archive: CpioArchive,
) -> tuple[dict[int, CpioMember], list[str]]:
    """Decide which member of each hard-link group carries the bytes.

    Returns ``{member_index: carrier}`` for members whose data lives in another
    record, plus the diagnostics that resolution produced. A group where **no**
    member carries data is genuinely a set of empty files, and is left alone:
    an empty file is a fact, and inventing content for it would not be one.
    """
    groups: dict[tuple[int, int, int], list[CpioMember]] = {}
    for member in archive.members:
        if member.is_hardlink_member:
            groups.setdefault(member.inode_key, []).append(member)

    resolved: dict[int, CpioMember] = {}
    diagnostics: list[str] = []
    for key, members in groups.items():
        carriers = [member for member in members if member.data_length > 0]
        if not carriers:
            continue
        if len(carriers) > 1:
            diagnostics.append(
                f"inode {key[2]} is carried by {len(carriers)} member(s) "
                f"({', '.join(member.name for member in carriers)}); "
                "the first in archive order is used"
            )
        carrier = carriers[0]
        for member in members:
            if member is carrier:
                continue
            resolved[member.index] = carrier
    return resolved, diagnostics


# ──────────────────────────────────────────────
# Extraction
# ──────────────────────────────────────────────


@dataclass
class CpioExtraction:
    """What one archive produced on disk, with the manifest the scanner reads."""

    rootfs: Path
    entries: list[dict[str, Any]] = field(default_factory=list)
    files: int = 0
    directories: int = 0
    bytes_written: int = 0
    omissions: list[str] = field(default_factory=list)
    digests: dict[int, str] = field(default_factory=dict)
    checks_verified: int = 0

    @property
    def metadata(self) -> dict[str, dict[str, Any]]:
        """Manifest entries keyed by root-relative path, as the scanner wants them."""
        return {
            str(entry["path"]): entry for entry in self.entries if entry.get("path") is not None
        }


def _cpio_checksum(data: bytes) -> int:
    """``crc`` CPIO's check field: the sum of the data bytes, modulo 2**32.

    The format calls it a CRC; it is a byte sum, and calling it one is the
    difference between verifying it and believing a name.
    """
    return sum(data) & 0xFFFFFFFF


def _write_manifest(destination: Path, archive: CpioArchive, extraction: CpioExtraction) -> None:
    payload = {
        "decoder": CPIO_DECODER_NAME,
        "decoder_version": CPIO_DECODER_VERSION,
        "worker": None,
        "worker_digest": None,
        "cpio_format": archive.format,
        "archive_bytes": archive.archive_length,
        "diagnostics": list(archive.diagnostics),
        "entries": extraction.entries,
    }
    (destination / "extract-manifest.json").write_text(
        json.dumps(payload, indent=2), encoding="utf-8"
    )


def extract_cpio(
    reader: BoundedReader,
    archive: CpioArchive,
    destination: Path,
    *,
    max_data_bytes: int = 1024 * 1024 * 1024,
) -> CpioExtraction:
    """Materialise the archive into ``destination``/``rootfs`` and hash each member.

    Two passes over the decoded records, no second read of the container: the
    first writes the bytes and hashes them (verifying ``crc`` sums as it goes),
    the second builds one manifest entry per record so a hard link can name the
    member that actually carries its bytes even when that member came later.
    """
    rootfs = destination / "rootfs"
    rootfs.mkdir(parents=True, exist_ok=True)
    resolved, resolution_notes = resolve_hardlinks(archive)
    extraction = CpioExtraction(rootfs=rootfs, omissions=list(archive.diagnostics))
    extraction.omissions.extend(resolution_notes)
    skipped_kinds: dict[str, int] = {}

    # ── Pass 1: bytes on disk ──
    for member in archive.members:
        relative = safe_relative_name(member.name)
        kind = member.kind
        if kind == "dir":
            if relative:
                (rootfs / relative).mkdir(parents=True, exist_ok=True)
            continue
        if member.index in resolved or kind != "file":
            # A hard link's bytes belong to its carrier; a symlink, device node,
            # FIFO or socket is recorded as metadata and not materialised.
            skipped_kinds[kind] = skipped_kinds.get(kind, 0) + 1
            continue
        if not relative:
            raise CpioError(f"the member {member.name!r} is a file with an empty path")
        target = rootfs / relative
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise CpioError(f"the member {member.name!r} cannot be created: {exc}") from exc
        hasher = hashlib.sha256()
        written = 0
        checksum = 0
        try:
            with target.open("wb") as out:
                for window in reader.iter_windows(
                    min(1024 * 1024, max(member.data_length, 1)),
                    budget=member.data_length,
                    start=member.data_offset,
                ):
                    if written + window.length > member.data_length:
                        raise CpioError(
                            f"the member {member.name!r} produced more bytes than it declares"
                        )
                    out.write(window.data)
                    hasher.update(window.data)
                    checksum = (checksum + _cpio_checksum(window.data)) & 0xFFFFFFFF
                    written += window.length
        except BoundedReadLimitError as exc:  # pragma: no cover - decode proved the range
            raise CpioError(f"the member {member.name!r} could not be read: {exc}") from exc
        except BaseException:
            target.unlink(missing_ok=True)
            raise
        if written != member.data_length:
            target.unlink(missing_ok=True)
            raise CpioError(
                f"the member {member.name!r} declares {member.data_length} byte(s), "
                f"{written} could be read"
            )
        if archive.format == CPIO_CRC and member.check is not None:
            if checksum & 0xFFFFFFFF != member.check:
                raise CpioError(
                    f"the member {member.name!r} fails its own checksum: the record declares "
                    f"{member.check}, the bytes sum to {checksum & 0xFFFFFFFF}"
                )
            extraction.checks_verified += 1
        try:
            os.chmod(target, stat.S_IMODE(member.mode))
        except OSError:  # pragma: no cover - a read-only filesystem
            extraction.omissions.append(
                f"{member.name}: mode {stat.S_IMODE(member.mode):04o} could not be applied"
            )
        extraction.digests[member.index] = hasher.hexdigest()
        extraction.files += 1
        extraction.bytes_written += written

    # ── Pass 2: one manifest entry per record ──
    for member in archive.members:
        relative = safe_relative_name(member.name)
        kind = member.kind
        base: dict[str, Any] = {
            "path": relative,
            "kind": kind,
            "mode": member.mode,
            "uid": member.uid,
            "gid": member.gid,
            "mtime": member.mtime,
            "metadata_source": "image",
        }
        if kind == "dir":
            extraction.directories += 1
            extraction.entries.append({**base, "size": 0})
            continue
        if member.index in resolved:
            carrier = resolved[member.index]
            carrier_relative = safe_relative_name(carrier.name)
            # A hard link is materialised as a *real* link, not as an empty file
            # and not as a copy: both names then exist, and the scanner's inode
            # reconciliation still knows they are one file.
            try:
                (rootfs / relative).parent.mkdir(parents=True, exist_ok=True)
                if not (rootfs / relative).exists():
                    os.link(rootfs / carrier_relative, rootfs / relative)
            except OSError as exc:
                extraction.omissions.append(
                    f"{relative}: hard link to {carrier_relative} could not be created ({exc})"
                )
            carrier_digest = extraction.digests.get(carrier.index, "")
            # The link's bytes *are* the carrier's bytes, so the link has a
            # digest too: a map node with an empty digest would read as "hashed
            # and found empty", which is the false evidence this row exists to
            # prevent.
            if carrier_digest:
                extraction.digests[member.index] = carrier_digest
            extraction.entries.append(
                {
                    **base,
                    "kind": "hardlink",
                    "link_target": carrier_relative,
                    "size": carrier.data_length,
                    "sha256": carrier_digest,
                }
            )
            continue
        if kind == "file":
            extraction.entries.append(
                {
                    **base,
                    "size": member.data_length,
                    "sha256": extraction.digests.get(member.index, ""),
                }
            )
            continue
        if kind == "symlink":
            raw = reader.read_at(member.data_offset, member.data_length)
            extraction.entries.append(
                {
                    **base,
                    "size": 0,
                    "link_target": raw.decode("utf-8", errors="backslashreplace"),
                }
            )
            continue
        extraction.entries.append(
            {
                **base,
                "size": 0,
                "rdev": f"{member.rdev_major}:{member.rdev_minor}",
            }
        )

    extraction.omissions.extend(
        f"{count} {kind}(s) recorded as metadata only"
        for kind, count in sorted(skipped_kinds.items())
        if kind in {"symlink", "char", "block", "fifo", "socket", "other"}
    )
    extraction.omissions = list(dict.fromkeys(extraction.omissions))
    _write_manifest(destination, archive, extraction)
    logger.info(
        "cpio %s extraction: %d file(s), %d dir(s), %d byte(s)",
        archive.format,
        extraction.files,
        extraction.directories,
        extraction.bytes_written,
    )
    return extraction


# ──────────────────────────────────────────────
# A streaming view for callers that only want the bytes
# ──────────────────────────────────────────────


def iter_member_data(reader: BoundedReader, member: CpioMember) -> Iterator[bytes]:
    """Yield one member's data in bounded windows.

    Kept separate from extraction so a caller can hash or scan a member without
    writing it to disk — the same discipline that stops a 50 MiB blob from
    becoming a 200 MiB string.
    """
    if member.data_length == 0:
        return
    for window in reader.iter_windows(
        min(1024 * 1024, member.data_length),
        budget=member.data_length,
        start=member.data_offset,
    ):
        yield window.data
