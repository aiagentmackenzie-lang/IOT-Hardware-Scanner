"""Disk-image partition tables (slice 3A, part 2).

A file is not always one filesystem. A flash dump, an SD-card image or an
OpenWrt sysupgrade artifact is often a **disk**: an MBR or GPT table naming
partitions, each of which may hold its own root filesystem. Until this module
existed the scanner called such a file an opaque blob, because the bytes at
offset zero are a boot sector, not a SquashFS superblock.

Two rules, the same two the rest of the map follows:

* **Every range is validated before it is read.** A table that points past the
  end of the file is a truncated image, which is incomplete work: it raises
  :class:`PartitionError` rather than producing a partition slice full of holes.
* **A record is what the table declares, not what the image happens to contain.**
  A partition is emitted with its declared offset and length and a type from the
  table; what is *inside* it is decided later by its own magic bytes. An unknown
  type id is reported by id, never guessed into a filesystem.

The decoders here do no I/O of their own beyond reading bounded ranges through
:class:`~iot_hardware_scanner.scanner.bounded_reader.BoundedReader`, so a
32 GiB disk image costs the entry array, not the disk.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field
from typing import Any

from iot_hardware_scanner.scanner.bounded_reader import BoundedReader

#: Everything here is LBAs of 512 bytes. A 4Kn disk is not claimed.
SECTOR_SIZE = 512
MBR_SIGNATURE = b"\x55\xaa"
MBR_SIGNATURE_OFFSET = 510
MBR_ENTRY_OFFSET = 446
MBR_ENTRY_SIZE = 16
MBR_PRIMARY_ENTRIES = 4
MBR_BOOTABLE = 0x80
#: Extended-partition containers: traversed, never emitted as a filesystem.
MBR_EXTENDED_TYPES = frozenset({0x05, 0x0F, 0x85})
#: The MBR type that only means "look at LBA 1 for the real table".
MBR_PROTECTIVE_TYPE = 0xEE

GPT_SIGNATURE = b"EFI PART"
GPT_HEADER_SIZE = 92
GPT_MIN_ENTRY_SIZE = 128
GPT_MAX_ENTRIES = 4096
#: 4096 entries x 128 bytes is the maximum entry array any table can ask for.
GPT_MAX_ENTRY_BYTES = GPT_MAX_ENTRIES * GPT_MIN_ENTRY_SIZE
#: A logical-partition chain longer than this is a loop, not a layout.
EBR_MAX_DEPTH = 8

SCHEME_MBR = "mbr"
SCHEME_GPT = "gpt"

#: A stated subset of the MBR type ids. An id outside it is reported as
#: ``raw-0xNN``: a name that says exactly how much is known.
MBR_TYPE_NAMES = {
    0x00: "empty",
    0x05: "extended",
    0x07: "ntfs-or-hfs",
    0x0B: "fat32-chs",
    0x0C: "fat32-lba",
    0x0E: "fat16-lba",
    0x0F: "extended-lba",
    0x82: "linux-swap",
    0x83: "linux",
    0x85: "extended-linux",
    0x8E: "linux-lvm",
    0xA5: "freebsd",
    0xEE: "gpt-protective",
    0xEF: "efi-system",
    0xFD: "linux-raid",
}

#: The GUIDs a firmware image actually uses. Others are reported by GUID.
GPT_TYPE_NAMES = {
    "c12a7328-f81f-11d2-ba4b-00a0c93ec93b": "efi-system",
    "0fc63daf-8483-4772-8e79-3d69d8477de4": "linux-filesystem",
    "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f": "linux-swap",
    "e6d6d379-f507-44c2-a23c-238f2a3df928": "linux-lvm",
    "a19d880f-05fc-4d3b-a006-743f0f84911e": "linux-raid",
    "9293e1ff-cee4-4658-88be-898ec863944f": "linux-root-x86",
    "44479540-f297-41b2-9af7-d131d5f0458a": "linux-root-x86",
    "4f68bce3-e8cd-4db1-96e7-fbcaf984b709": "linux-root-x86-64",
    "b921b045-1df0-41c3-af44-4c6f280d3fae": "linux-root-arm64",
}


class PartitionError(Exception):
    """A partition table that cannot be read as one.

    Malformed, truncated or self-contradictory tables land here. The caller
    records a FAILED stage: a table that describes sectors the file does not
    contain is incomplete work, not an empty disk.
    """


@dataclass
class PartitionRecord:
    """One partition as the table declares it.

    ``offset`` and ``length`` are byte coordinates in the **container** (the
    file that was scanned), not inside any filesystem. ``index`` is the number a
    disk tool would show.
    """

    index: int
    scheme: str
    label: str
    type_id: str
    type_name: str
    offset: int
    length: int
    bootable: bool = False
    logical: bool = False
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def end(self) -> int:
        return self.offset + self.length

    def to_details(self) -> dict[str, Any]:
        """Serialisable form, merged into the artifact node's ``details``."""
        payload = {
            "scheme": self.scheme,
            "partition_index": self.index,
            "label": self.label,
            "type_id": self.type_id,
            "type_name": self.type_name,
            "bootable": self.bootable,
            "logical": self.logical,
            "start_hex": f"0x{self.offset:08x}",
            "end_hex": f"0x{self.end:08x}",
        }
        payload.update(self.details)
        return payload

    def as_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "scheme": self.scheme,
            "label": self.label,
            "type_id": self.type_id,
            "type_name": self.type_name,
            "offset": self.offset,
            "length": self.length,
            "bootable": self.bootable,
            "logical": self.logical,
            **self.details,
        }


# ──────────────────────────────────────────────
# Recognition
# ──────────────────────────────────────────────


def looks_like_partition_table(head: bytes) -> bool:
    """Whether these first bytes carry an MBR/GPT table *and* an entry.

    A bare ``0x55aa`` at offset 510 is extremely common at the end of binaries,
    and a file that happens to end in it is not a disk. The check therefore
    requires a signature **and** at least one plausible non-empty entry, or the
    GPT header at LBA 1. It is a hint that says "try to decode this"; the
    decoder still validates every field and every range.
    """
    if len(head) < MBR_SIGNATURE_OFFSET + 2:
        return False
    if head[MBR_SIGNATURE_OFFSET : MBR_SIGNATURE_OFFSET + 2] != MBR_SIGNATURE:
        return False
    if len(head) >= 2 * SECTOR_SIZE and head[SECTOR_SIZE : SECTOR_SIZE + 8] == GPT_SIGNATURE:
        return True
    for entry in range(MBR_PRIMARY_ENTRIES):
        start = MBR_ENTRY_OFFSET + entry * MBR_ENTRY_SIZE
        chunk = head[start : start + MBR_ENTRY_SIZE]
        if len(chunk) < MBR_ENTRY_SIZE:
            return False
        if _plausible_mbr_entry(chunk):
            return True
    return False


def _plausible_mbr_entry(entry: bytes) -> bool:
    status = entry[0]
    part_type = entry[4]
    start_lba, sectors = struct.unpack("<II", entry[8:16])
    return status in (0x00, MBR_BOOTABLE) and part_type not in (0, 0xEE) and start_lba and sectors


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────


def decode_partition_table(reader: BoundedReader) -> tuple[str, list[PartitionRecord]]:
    """Decode the table at the start of ``reader``.

    Returns:
        ``(scheme, records)``. ``scheme`` is ``mbr`` or ``gpt``.

    Raises:
        PartitionError: when the table is not decodable, or when any declared
            range lies outside the file.
    """
    if reader.size < SECTOR_SIZE:
        raise PartitionError(
            f"a partition table needs at least one {SECTOR_SIZE}-byte sector; "
            f"the input is {reader.size} bytes"
        )
    sector_zero = reader.read_at(0, SECTOR_SIZE)
    if sector_zero[MBR_SIGNATURE_OFFSET : MBR_SIGNATURE_OFFSET + 2] != MBR_SIGNATURE:
        raise PartitionError("no 0x55aa boot signature at offset 510; no MBR to read")

    lba_one = reader.read_at(SECTOR_SIZE, 8) if reader.size >= 2 * SECTOR_SIZE else b""
    if lba_one == GPT_SIGNATURE:
        scheme, records = SCHEME_GPT, _decode_gpt(reader)
    else:
        scheme, records = SCHEME_MBR, _decode_mbr(reader)

    for record in records:
        _validate_range(record, reader.size)
    return scheme, records


def _validate_range(record: PartitionRecord, size: int) -> None:
    if record.length <= 0:
        raise PartitionError(f"partition {record.index} declares no length")
    if record.offset < 0 or record.offset >= size:
        raise PartitionError(
            f"partition {record.index} starts at {record.offset:#x}, outside the "
            f"{size:#x}-byte image"
        )
    if record.end > size:
        raise PartitionError(
            f"partition {record.index} ends at {record.end:#x}, past the end of the "
            f"{size:#x}-byte image; the image is truncated"
        )


# ──────────────────────────────────────────────
# MBR
# ──────────────────────────────────────────────


def _mbr_entries(sector: bytes) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for slot in range(MBR_PRIMARY_ENTRIES):
        start = MBR_ENTRY_OFFSET + slot * MBR_ENTRY_SIZE
        raw = sector[start : start + MBR_ENTRY_SIZE]
        status = raw[0]
        part_type = raw[4]
        start_lba, sectors = struct.unpack("<II", raw[8:16])
        entries.append(
            {
                "slot": slot,
                "status": status,
                "type": part_type,
                "start_lba": start_lba,
                "sectors": sectors,
            }
        )
    return entries


def _decode_mbr(reader: BoundedReader) -> list[PartitionRecord]:
    sector_zero = reader.read_at(0, SECTOR_SIZE)
    records: list[PartitionRecord] = []
    index = 0
    extended: list[dict[str, Any]] = []
    for entry in _mbr_entries(sector_zero):
        part_type = entry["type"]
        if part_type == 0 or entry["sectors"] == 0:
            continue
        if part_type == MBR_PROTECTIVE_TYPE:
            # The real table is at LBA 1 but LBA 1 does not say GPT: the image is
            # a protective MBR with no GPT behind it, which is a broken image.
            raise PartitionError("the MBR has a GPT protective entry but no GPT header at LBA 1")
        if part_type in MBR_EXTENDED_TYPES:
            extended.append(entry)
            continue
        index += 1
        records.append(
            PartitionRecord(
                index=index,
                scheme=SCHEME_MBR,
                label=f"partition {index}",
                type_id=f"0x{part_type:02x}",
                type_name=MBR_TYPE_NAMES.get(part_type, f"raw-0x{part_type:02x}"),
                offset=entry["start_lba"] * SECTOR_SIZE,
                length=entry["sectors"] * SECTOR_SIZE,
                bootable=entry["status"] == MBR_BOOTABLE,
                details={"slot": entry["slot"], "start_lba": entry["start_lba"]},
            )
        )
    for container in extended:
        records.extend(_decode_ebr_chain(reader, container, start_index=len(records) + 1))
    if not records:
        raise PartitionError("the MBR declares no non-empty partition")
    return records


def _decode_ebr_chain(
    reader: BoundedReader, container: dict[str, Any], *, start_index: int
) -> list[PartitionRecord]:
    """Follow the extended-partition chain, bounded and cycle-safe."""
    base = container["start_lba"] * SECTOR_SIZE
    limit = base + container["sectors"] * SECTOR_SIZE
    records: list[PartitionRecord] = []
    seen: set[int] = set()
    current = base
    depth = 0
    while current and depth < EBR_MAX_DEPTH:
        if current in seen:
            raise PartitionError(f"extended-partition chain loops at {current:#x}")
        seen.add(current)
        if current + SECTOR_SIZE > reader.size or current + SECTOR_SIZE > limit:
            raise PartitionError(
                f"extended partition boot record at {current:#x} lies outside the image"
            )
        sector = reader.read_at(current, SECTOR_SIZE)
        if sector[MBR_SIGNATURE_OFFSET : MBR_SIGNATURE_OFFSET + 2] != MBR_SIGNATURE:
            raise PartitionError(f"extended boot record at {current:#x} has no signature")
        entries = _mbr_entries(sector)
        logical = entries[0]
        if logical["type"] and logical["sectors"]:
            records.append(
                PartitionRecord(
                    index=start_index + len(records),
                    scheme=SCHEME_MBR,
                    label=f"logical {len(records) + 1}",
                    type_id=f"0x{logical['type']:02x}",
                    type_name=MBR_TYPE_NAMES.get(logical["type"], f"raw-0x{logical['type']:02x}"),
                    offset=current + logical["start_lba"] * SECTOR_SIZE,
                    length=logical["sectors"] * SECTOR_SIZE,
                    bootable=logical["status"] == MBR_BOOTABLE,
                    logical=True,
                    details={"ebr_offset": current},
                )
            )
        chained = entries[1]
        current = base + chained["start_lba"] * SECTOR_SIZE if chained["sectors"] else 0
        depth += 1
    if depth >= EBR_MAX_DEPTH:
        raise PartitionError(
            f"extended-partition chain exceeded {EBR_MAX_DEPTH} links; not following it further"
        )
    return records


# ──────────────────────────────────────────────
# GPT
# ──────────────────────────────────────────────


def _decode_gpt(reader: BoundedReader) -> list[PartitionRecord]:
    header = _read_gpt_header(reader, SECTOR_SIZE)
    entries = _read_gpt_entries(reader, header)
    records: list[PartitionRecord] = []
    for slot, entry in enumerate(entries):
        if entry["type_guid"] == "00000000-0000-0000-0000-000000000000":
            continue
        first, last = entry["first_lba"], entry["last_lba"]
        if last < first:
            raise PartitionError(f"GPT entry {slot + 1} ends before it starts ({first}..{last})")
        name = GPT_TYPE_NAMES.get(entry["type_guid"], entry["type_guid"])
        records.append(
            PartitionRecord(
                index=slot + 1,
                scheme=SCHEME_GPT,
                label=entry["name"] or f"partition {slot + 1}",
                type_id=entry["type_guid"],
                type_name=name,
                offset=first * SECTOR_SIZE,
                length=(last - first + 1) * SECTOR_SIZE,
                details={
                    "slot": slot,
                    "first_lba": first,
                    "last_lba": last,
                    "unique_guid": entry["unique_guid"],
                    "attributes": entry["attributes"],
                },
            )
        )
    if not records:
        raise PartitionError("the GPT declares no non-empty partition")
    return records


def _read_gpt_header(reader: BoundedReader, offset: int) -> dict[str, Any]:
    # One sector is enough for any legal header (92..512 bytes) and is the
    # smallest range that can be CRC-checked without re-reading.
    raw = reader.read_at(offset, SECTOR_SIZE)
    if len(raw) < GPT_HEADER_SIZE or not raw.startswith(GPT_SIGNATURE):
        raise PartitionError(f"no GPT header at {offset:#x}")
    header_size = struct.unpack("<I", raw[12:16])[0]
    if not GPT_HEADER_SIZE <= header_size <= SECTOR_SIZE:
        raise PartitionError(f"GPT header size {header_size} is not between 92 and 512")
    stated_crc = struct.unpack("<I", raw[16:20])[0]
    zeroed = bytearray(raw[:header_size])
    zeroed[16:20] = b"\x00\x00\x00\x00"
    if zlib.crc32(bytes(zeroed)) & 0xFFFFFFFF != stated_crc:
        raise PartitionError(f"GPT header CRC32 0x{stated_crc:08x} does not describe the header")
    entry_lba = struct.unpack("<Q", raw[72:80])[0]
    entry_count = struct.unpack("<I", raw[80:84])[0]
    entry_size = struct.unpack("<I", raw[84:88])[0]
    entries_crc = struct.unpack("<I", raw[88:92])[0]
    if not 0 < entry_count <= GPT_MAX_ENTRIES:
        raise PartitionError(f"GPT declares {entry_count} entries, outside 1..{GPT_MAX_ENTRIES}")
    if entry_size < GPT_MIN_ENTRY_SIZE or entry_size % GPT_MIN_ENTRY_SIZE:
        raise PartitionError(
            f"GPT entry size {entry_size} is not a multiple of {GPT_MIN_ENTRY_SIZE}"
        )
    if entry_count * entry_size > GPT_MAX_ENTRY_BYTES:
        raise PartitionError(
            f"GPT entry array of {entry_count * entry_size} bytes is above the "
            f"{GPT_MAX_ENTRY_BYTES}-byte maximum"
        )
    return {
        "revision": struct.unpack("<I", raw[8:12])[0],
        "header_size": header_size,
        "current_lba": struct.unpack("<Q", raw[24:32])[0],
        "backup_lba": struct.unpack("<Q", raw[32:40])[0],
        "first_usable": struct.unpack("<Q", raw[40:48])[0],
        "last_usable": struct.unpack("<Q", raw[48:56])[0],
        "disk_guid": _guid(raw[56:72]),
        "entry_lba": entry_lba,
        "entry_count": entry_count,
        "entry_size": entry_size,
        "entries_crc": entries_crc,
    }


def _read_gpt_entries(reader: BoundedReader, header: dict[str, Any]) -> list[dict[str, Any]]:
    offset = header["entry_lba"] * SECTOR_SIZE
    total = header["entry_count"] * header["entry_size"]
    if offset + total > reader.size:
        raise PartitionError(
            f"GPT entry array at {offset:#x} ({total} bytes) runs past the end of the "
            f"{reader.size:#x}-byte image"
        )
    raw = reader.read_at(offset, total)
    if len(raw) != total:
        raise PartitionError("GPT entry array could not be read in full")
    if zlib.crc32(raw) & 0xFFFFFFFF != header["entries_crc"]:
        raise PartitionError("GPT entry-array CRC32 does not describe the entries")
    entries: list[dict[str, Any]] = []
    size = header["entry_size"]
    for slot in range(header["entry_count"]):
        chunk = raw[slot * size : (slot + 1) * size]
        first, last, attributes = struct.unpack("<QQQ", chunk[32:56])
        entries.append(
            {
                "type_guid": _guid(chunk[0:16]),
                "unique_guid": _guid(chunk[16:32]),
                "first_lba": first,
                "last_lba": last,
                "attributes": attributes,
                "name": chunk[56:128].decode("utf-16-le", errors="replace").split("\x00")[0],
            }
        )
    return entries


def _guid(raw: bytes) -> str:
    """A GPT GUID in the mixed-endian form the specification prints."""
    first, second, third = struct.unpack("<IHH", raw[0:8])
    return f"{first:08x}-{second:04x}-{third:04x}-{raw[8:10].hex()}-{raw[10:16].hex()}"
