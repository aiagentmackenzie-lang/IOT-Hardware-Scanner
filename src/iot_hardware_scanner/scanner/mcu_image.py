"""Bare-metal images as sparse address spaces (slice 3C).

Intel HEX, Motorola S-record and UF2 are three encodings of one thing: a
**sparse set of byte ranges in a device's address space**. This module decodes
all three into that single representation and applies one set of rules to it, so
a fact recorded from an S-record and the same fact recorded from a UF2 block are
the same fact.

Two rules shape every line of it
--------------------------------
* **An address is a device address, never a file offset.** The file offset of a
  record is a property of the encoding; the address it writes to is a property
  of the device. Both are kept, and they are never confused.
* **The address space is never allocated.** A record may name 0xFFFF_FFF0; that
  costs a dictionary entry, not four gigabytes. Only bytes that were actually
  declared are held, and the payload budget is enforced as they are added.

What "equivalent payloads" means
--------------------------------
The same bytes at the same addresses must yield the same
:attr:`~iot_hardware_scanner.models.McuAnalysis.payload_sha256` whether they
arrived as Intel HEX, S-record or UF2. Records are therefore merged into
ascending, contiguous ranges and the digest is computed over::

    for each merged range, in ascending address order:
        b"IHS-MCU-1 <start:016x> <length:016x>\\n" + payload bytes

Nothing encoding-specific enters the digest: not the record count, not the
checksum syntax, not the gap layout. A gap is never zero-filled — filling it
would invent bytes the artifact did not carry, so a gap stays unobserved and the
digest is explicitly a digest of what was present.

Conflicts are not resolved silently. If two records write different bytes to the
same address the range is kept (first declaration in address order wins, which is
deterministic) and a ``conflict`` diagnostic names the address and the records,
because the artifact does not describe one payload and the report must not imply
that it does.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

from iot_hardware_scanner.models import (
    McuAnalysis,
    McuDiagnostic,
    McuGap,
    McuRange,
)
from iot_hardware_scanner.scanner.bounded_reader import BoundedReader

#: Decoder version. Bump when a decode result would change for the same bytes.
DECODER_VERSION = "1"

FORMAT_INTEL_HEX = "intel-hex"
FORMAT_SREC = "srec"
FORMAT_UF2 = "uf2"
MCU_FORMATS = (FORMAT_INTEL_HEX, FORMAT_SREC, FORMAT_UF2)

#: The largest address any of the three encodings can express.
MAX_ADDRESS = 0xFFFF_FFFF
#: A record may not be larger than this; Intel HEX and S-record caps are smaller.
MAX_RECORD_BYTES = 512
#: Default ceiling on decoded payload bytes (overridable through the config).
DEFAULT_MAX_PAYLOAD_BYTES = 64 * 1024 * 1024
#: Default ceiling on records/blocks read.
DEFAULT_MAX_RECORDS = 500_000
#: UF2 block layout.
UF2_BLOCK = 512
UF2_MAGIC_START0 = 0x0A324655
UF2_MAGIC_START1 = 0x9E5D5157
UF2_MAGIC_END = 0x0AB16F30
UF2_FLAG_NOT_MAIN_FLASH = 0x00000001
UF2_FLAG_FILE_CONTAINER = 0x00001000
UF2_FLAG_FAMILY_PRESENT = 0x00002000
UF2_FLAG_MD5_PRESENT = 0x00004000
UF2_FLAG_EXTENSION_TAGS = 0x00008000

#: How a payload digest is framed. Part of the contract: a change here changes
#: every MCU digest, so it is versioned in the prefix.
_DIGEST_PREFIX = b"IHS-MCU-1"

_INTEL_HEX_LINE = re.compile(r"^:[0-9A-Fa-f]+$")
_SREC_LINE = re.compile(r"^S[0-9][0-9A-Fa-f]+$")

#: Extension hints. Content is always tried first; these only name the decoder
#: to attempt when the sniff is inconclusive, and the decoder still validates.
_EXTENSIONS = {
    ".hex": FORMAT_INTEL_HEX,
    ".ihex": FORMAT_INTEL_HEX,
    ".ihx": FORMAT_INTEL_HEX,
    ".s19": FORMAT_SREC,
    ".s28": FORMAT_SREC,
    ".s37": FORMAT_SREC,
    ".srec": FORMAT_SREC,
    ".mot": FORMAT_SREC,
    ".uf2": FORMAT_UF2,
}


class McuFormatError(Exception):
    """The artifact does not decode as the format it claims to be.

    A malformed or truncated encoding is *incomplete work*, not an empty
    result: the caller records a FAILED stage and exits 4.
    """


# ──────────────────────────────────────────────
# Recognition
# ──────────────────────────────────────────────


def looks_like_uf2(head: bytes) -> bool:
    """Whether the first bytes carry the UF2 magic pair."""
    if len(head) < 8:
        return False
    start0 = int.from_bytes(head[0:4], "little")
    start1 = int.from_bytes(head[4:8], "little")
    return start0 == UF2_MAGIC_START0 and start1 == UF2_MAGIC_START1


def _first_text_line(head: bytes) -> str:
    """The first non-empty, non-whitespace line of a bounded head."""
    text = head.decode("latin-1", errors="replace").lstrip("\ufeff")
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return ""


def identify_mcu_format(head: bytes) -> str | None:
    """Name the encoding from the artifact's own content, or ``None``.

    Content decides; a filename is only consulted by :func:`format_hint` when
    the content is inconclusive, and the decoder still has to accept the bytes.
    """
    if looks_like_uf2(head):
        return FORMAT_UF2
    line = _first_text_line(head)
    if _INTEL_HEX_LINE.match(line):
        return FORMAT_INTEL_HEX
    if _SREC_LINE.match(line):
        return FORMAT_SREC
    return None


def format_hint(suffix: str) -> str | None:
    """The encoding a filename suffix suggests, or ``None``."""
    return _EXTENSIONS.get(suffix.lower())


# ──────────────────────────────────────────────
# Accumulation
# ──────────────────────────────────────────────


@dataclass
class _Chunk:
    address: int
    data: bytes
    record: int


@dataclass
class _Accumulator:
    """Collect records as address ranges, bounded and never address-allocated."""

    max_payload_bytes: int = DEFAULT_MAX_PAYLOAD_BYTES
    max_records: int = DEFAULT_MAX_RECORDS
    chunks: list[_Chunk] = field(default_factory=list)
    payload_bytes: int = 0
    records: int = 0
    out_of_order: int = 0
    last_address: int | None = None

    def add(self, address: int, data: bytes, record: int) -> None:
        """Record one declared range, enforcing the payload and address bounds."""
        if not data:
            return
        length = len(data)
        if address < 0 or address > MAX_ADDRESS:
            raise McuFormatError(f"record {record}: address {address:#x} is outside 32 bits")
        if address + length - 1 > MAX_ADDRESS:
            raise McuFormatError(
                f"record {record}: range {address:#x}+{length} runs past the 32-bit address space"
            )
        if length > MAX_RECORD_BYTES:
            raise McuFormatError(
                f"record {record}: {length} byte(s) declared in one record, above the "
                f"{MAX_RECORD_BYTES}-byte maximum"
            )
        if self.records >= self.max_records:
            raise McuFormatError(
                f"record ceiling reached at {self.max_records} records; the image was not "
                "decoded further, so its address map is incomplete"
            )
        if self.payload_bytes + length > self.max_payload_bytes:
            raise McuFormatError(
                f"decoded payload exceeds the {self.max_payload_bytes}-byte budget "
                f"at record {record}; the image was not decoded further"
            )
        if self.last_address is not None and address < self.last_address:
            self.out_of_order += 1
        self.last_address = address
        self.payload_bytes += length
        self.records += 1
        self.chunks.append(_Chunk(address=address, data=bytes(data), record=record))

    def finish(
        self,
    ) -> tuple[list[McuRange], list[McuGap], list[McuDiagnostic], str, int, list]:
        """Merge into ascending contiguous ranges and hash what was declared."""
        diagnostics: list[McuDiagnostic] = []
        if self.out_of_order and self.chunks:
            diagnostics.append(
                McuDiagnostic(
                    kind="out-of-order",
                    detail=(
                        f"{self.out_of_order} record(s) declared a lower address than the "
                        "record before them; the address map is ordered by address, not by "
                        "file position"
                    ),
                )
            )

        ordered = sorted(self.chunks, key=lambda chunk: (chunk.address, chunk.record))
        merged: list[list[Any]] = []  # [start, bytearray, [record ids]]
        for chunk in ordered:
            if merged:
                start, data, ids = merged[-1]
                end = start + len(data)
                if chunk.address < end:
                    # Overlap. Same bytes are a duplicate; different bytes are a
                    # conflict the report must state rather than resolve.
                    overlap = min(end, chunk.address + len(chunk.data)) - chunk.address
                    existing = bytes(data[chunk.address - start : chunk.address - start + overlap])
                    incoming = chunk.data[:overlap]
                    kind = "duplicate" if existing == incoming else "conflict"
                    diagnostics.append(
                        McuDiagnostic(
                            kind=kind,
                            detail=(
                                f"record {chunk.record} rewrites {overlap} byte(s) already "
                                f"declared at {chunk.address:#x} with "
                                + (
                                    "identical content"
                                    if kind == "duplicate"
                                    else "different content; the first declaration in address "
                                    "order is kept, so the digest describes that declaration"
                                )
                            ),
                            address=chunk.address,
                            length=overlap,
                            records=[*ids, chunk.record],
                        )
                    )
                    # Keep any tail that extends past the existing range.
                    tail_start = end - chunk.address
                    if tail_start < len(chunk.data):
                        data.extend(chunk.data[tail_start:])
                        ids.append(chunk.record)
                    continue
                if chunk.address == end:
                    data.extend(chunk.data)
                    ids.append(chunk.record)
                    continue
            merged.append([chunk.address, bytearray(chunk.data), [chunk.record]])

        ranges: list[McuRange] = []
        payload_ranges: list[tuple[int, bytes]] = []
        unique_bytes = 0
        hasher = hashlib.sha256()
        previous_end: int | None = None
        gaps: list[McuGap] = []
        for start, data, ids in merged:
            if previous_end is not None and start > previous_end:
                gaps.append(McuGap(start=previous_end, end=start, length=start - previous_end))
            payload = bytes(data)
            hasher.update(_DIGEST_PREFIX + f" {start:016x} {len(payload):016x}\n".encode())
            hasher.update(payload)
            ranges.append(
                McuRange(
                    start=start,
                    end=start + len(payload),
                    length=len(payload),
                    sha256=hashlib.sha256(payload).hexdigest(),
                    source_records=_summarise_records(ids),
                )
            )
            previous_end = start + len(payload)
            unique_bytes += len(payload)
            payload_ranges.append((start, payload))
        return ranges, gaps, diagnostics, hasher.hexdigest(), unique_bytes, payload_ranges


def _summarise_records(ids: list[int]) -> str:
    """A compact, human-readable record span: ``"1-4"`` or ``"1,3,9"``."""
    if not ids:
        return ""
    unique = sorted(set(ids))
    if len(unique) == 1:
        return str(unique[0])
    if unique[-1] - unique[0] + 1 == len(unique):
        return f"{unique[0]}-{unique[-1]}"
    return ",".join(str(value) for value in unique[:8]) + (",…" if len(unique) > 8 else "")


# ──────────────────────────────────────────────
# Intel HEX
# ──────────────────────────────────────────────


def _decode_hex_bytes(field_text: str, record: int, what: str) -> bytes:
    if len(field_text) % 2:
        raise McuFormatError(f"record {record}: odd-length {what} field")
    try:
        return bytes.fromhex(field_text)
    except ValueError as exc:
        raise McuFormatError(f"record {record}: {what} is not hexadecimal ({exc})") from exc


def decode_intel_hex(
    reader: BoundedReader, accumulator: _Accumulator, *, budget: int
) -> dict[str, Any]:
    """Decode Intel HEX into the shared representation.

    Record types handled: 00 (data), 01 (EOF), 02 (extended segment address),
    03 (start segment address), 04 (extended linear address), 05 (start linear
    address). Anything else is named, not ignored.
    """
    base = 0
    record = 0
    start_address: int | None = None
    diagnostics: list[McuDiagnostic] = []
    saw_eof = False
    notes: list[str] = []

    for line in reader.iter_lines(budget=budget):
        text = line.text.strip()
        if not text:
            continue
        record += 1
        if not text.startswith(":"):
            raise McuFormatError(
                f"record {record}: line {line.number} does not start with ':' "
                "(not an Intel HEX record)"
            )
        payload = _decode_hex_bytes(text[1:], record, "record")
        if len(payload) < 5:
            raise McuFormatError(
                f"record {record}: {len(payload)} byte(s), below the 5-byte minimum"
            )
        body, checksum = payload[:-1], payload[-1]
        if sum(payload) & 0xFF:
            raise McuFormatError(
                f"record {record}: checksum 0x{checksum:02x} does not satisfy the record"
            )
        declared = body[0]
        if declared != len(body) - 4:
            raise McuFormatError(
                f"record {record}: declares {declared} data byte(s), carries {len(body) - 4}"
            )
        offset = int.from_bytes(body[1:3], "big")
        kind = body[3]
        data = body[4:]
        if kind == 0x00:
            accumulator.add(base + offset, data, record)
        elif kind == 0x01:
            saw_eof = True
            break
        elif kind == 0x02:
            if len(data) != 2:
                raise McuFormatError(f"record {record}: extended segment address needs 2 bytes")
            base = int.from_bytes(data, "big") << 4
        elif kind == 0x04:
            if len(data) != 2:
                raise McuFormatError(f"record {record}: extended linear address needs 2 bytes")
            base = int.from_bytes(data, "big") << 16
        elif kind == 0x03:
            start_address = (int.from_bytes(data[0:2], "big") << 4) + int.from_bytes(
                data[2:4], "big"
            )
            notes.append(
                f"record {record} declares a start segment address {start_address:#x}; "
                "a start address is what the producer intends, not what the device runs"
            )
        elif kind == 0x05:
            start_address = int.from_bytes(data, "big")
            notes.append(
                f"record {record} declares a start linear address {start_address:#x}; "
                "a start address is what the producer intends, not what the device runs"
            )
        else:
            diagnostics.append(
                McuDiagnostic(
                    kind="unknown-record-type",
                    detail=(
                        f"record {record}: type 0x{kind:02x} has no meaning in Intel HEX and "
                        "was not interpreted"
                    ),
                    length=len(data),
                )
            )

    if not saw_eof:
        diagnostics.append(
            McuDiagnostic(
                kind="missing-eof",
                detail=(
                    "no end-of-file record (type 01) was found; every record that was present "
                    "was decoded, but the producer's own terminator is absent"
                ),
            )
        )
    return {
        "start_address": start_address,
        "diagnostics": diagnostics,
        "notes": notes,
        "header": None,
    }


# ──────────────────────────────────────────────
# Motorola S-record
# ──────────────────────────────────────────────

#: Address width in bytes for each S-record type that carries data.
_SREC_DATA_ADDRESS_BYTES = {1: 2, 2: 3, 3: 4}
_SREC_START_TYPES = {7: 4, 8: 3, 9: 2}
_SREC_COUNT_TYPES = {5: 2, 6: 3}


def decode_srec(reader: BoundedReader, accumulator: _Accumulator, *, budget: int) -> dict[str, Any]:
    """Decode Motorola S-record into the shared representation.

    S0 (header), S1/S2/S3 (data), S5/S6 (declared record count) and S7/S8/S9
    (start address) are interpreted. A count record that disagrees with the
    number of data records is a diagnostic, not a silent correction.
    """
    record = 0
    start_address: int | None = None
    header: str | None = None
    declared_count: int | None = None
    data_records = 0
    diagnostics: list[McuDiagnostic] = []
    notes: list[str] = []

    for line in reader.iter_lines(budget=budget):
        text = line.text.strip()
        if not text:
            continue
        record += 1
        if len(text) < 4 or text[0] not in "Ss" or not text[1].isdigit():
            raise McuFormatError(
                f"record {record}: line {line.number} is not an S-record "
                "(expected 'S' followed by a type digit)"
            )
        kind = int(text[1])
        payload = _decode_hex_bytes(text[2:], record, "record")
        count, body = payload[0], payload[1:]
        if count != len(body):
            raise McuFormatError(
                f"record {record}: declares {count} byte(s) after the count field, "
                f"carries {len(body)}"
            )
        if sum(payload) & 0xFF != 0xFF:
            raise McuFormatError(
                f"record {record}: checksum 0x{body[-1]:02x} does not satisfy the record"
            )

        if kind in _SREC_DATA_ADDRESS_BYTES:
            width = _SREC_DATA_ADDRESS_BYTES[kind]
            if len(body) < width + 1:
                raise McuFormatError(
                    f"record {record}: S{kind} is too short for a {width}-byte address"
                )
            address = int.from_bytes(body[:width], "big")
            accumulator.add(address, body[width:-1], record)
            data_records += 1
        elif kind == 0:
            header = body[:-1].decode("latin-1", errors="replace").strip("\x00 ")
        elif kind in _SREC_COUNT_TYPES:
            declared_count = int.from_bytes(body[: _SREC_COUNT_TYPES[kind]], "big")
        elif kind in _SREC_START_TYPES:
            start_address = int.from_bytes(body[: _SREC_START_TYPES[kind]], "big")
            notes.append(
                f"record {record} declares a start address {start_address:#x}; a start "
                "address is what the producer intends, not what the device runs"
            )
        else:
            diagnostics.append(
                McuDiagnostic(
                    kind="unknown-record-type",
                    detail=(
                        f"record {record}: S{kind} has no meaning the decoder knows and was "
                        "not interpreted"
                    ),
                    length=len(body),
                )
            )

    if declared_count is not None and declared_count != data_records:
        diagnostics.append(
            McuDiagnostic(
                kind="record-count-mismatch",
                detail=(
                    f"the count record declares {declared_count} data record(s); the file "
                    f"contains {data_records}. The bytes that are present were decoded"
                ),
            )
        )
    return {
        "start_address": start_address,
        "diagnostics": diagnostics,
        "notes": notes,
        "header": header,
    }


# ──────────────────────────────────────────────
# UF2
# ──────────────────────────────────────────────


def decode_uf2(reader: BoundedReader, accumulator: _Accumulator, *, budget: int) -> dict[str, Any]:
    """Decode UF2 blocks into the shared representation. (3C, third encoding.)"""
    if reader.size % UF2_BLOCK:
        raise McuFormatError(
            f"UF2 input is {reader.size} bytes, which is not a whole number of "
            f"{UF2_BLOCK}-byte blocks; the last block is truncated"
        )
    diagnostics: list[McuDiagnostic] = []
    notes: list[str] = []
    family: str | None = None
    target_address: int | None = None
    total_blocks: int | None = None
    seen: set[int] = set()

    for window in reader.iter_windows(UF2_BLOCK, budget=budget):
        block = window.offset // UF2_BLOCK
        data = window.data
        if len(data) != UF2_BLOCK:
            raise McuFormatError(f"block {block}: {len(data)} byte(s), expected {UF2_BLOCK}")
        start0 = int.from_bytes(data[0:4], "little")
        start1 = int.from_bytes(data[4:8], "little")
        end_magic = int.from_bytes(data[508:512], "little")
        if (start0, start1, end_magic) != (UF2_MAGIC_START0, UF2_MAGIC_START1, UF2_MAGIC_END):
            raise McuFormatError(f"block {block}: magic words do not match a UF2 block")
        flags = int.from_bytes(data[8:12], "little")
        address = int.from_bytes(data[12:16], "little")
        payload_size = int.from_bytes(data[16:20], "little")
        block_no = int.from_bytes(data[20:24], "little")
        num_blocks = int.from_bytes(data[24:28], "little")
        if payload_size > 476:
            raise McuFormatError(
                f"block {block}: declares {payload_size} payload byte(s), above the 476-byte "
                "maximum"
            )
        if num_blocks == 0:
            raise McuFormatError(f"block {block}: declares zero total blocks")
        if block_no >= num_blocks:
            raise McuFormatError(
                f"block {block}: block number {block_no} is not below the declared count "
                f"{num_blocks}"
            )
        if total_blocks is None:
            total_blocks = num_blocks
        elif num_blocks != total_blocks:
            raise McuFormatError(
                f"block {block}: declares {num_blocks} total blocks, earlier blocks declared "
                f"{total_blocks}"
            )
        if block_no in seen:
            diagnostics.append(
                McuDiagnostic(
                    kind="duplicate-block",
                    detail=f"block number {block_no} appears more than once",
                    address=address,
                    length=payload_size,
                    records=[block_no],
                )
            )
        seen.add(block_no)
        if flags & UF2_FLAG_FAMILY_PRESENT:
            family = f"0x{int.from_bytes(data[28:32], 'little'):08x}"
            if flags & UF2_FLAG_MD5_PRESENT:
                notes.append(
                    f"block {block}: the family id occupies the field its own flag also marks "
                    "as an MD5 checksum; the family id was used and no MD5 was verified"
                )
        if flags & UF2_FLAG_FILE_CONTAINER:
            notes.append(
                f"block {block}: this block is a file container, not main flash; its payload "
                "was decoded but it is not device memory"
            )
        if flags & UF2_FLAG_NOT_MAIN_FLASH:
            notes.append(
                f"block {block}: marked not-main-flash; the address it names is not main "
                "flash memory"
            )
        if flags & UF2_FLAG_EXTENSION_TAGS:
            notes.append(
                f"block {block}: carries extension tags, which this decoder does not interpret"
            )
        if target_address is None:
            target_address = address
        accumulator.add(address, data[32 : 32 + payload_size], block_no + 1)

    missing = [index for index in range(total_blocks or 0) if index not in seen]
    if missing:
        diagnostics.append(
            McuDiagnostic(
                kind="missing-block",
                detail=(
                    f"{len(missing)} of {total_blocks} block(s) are absent "
                    f"(first missing: {missing[0]}); the payload those blocks carry is "
                    "unobserved, not zeros"
                ),
                length=len(missing),
                records=missing[:16],
            )
        )
    return {
        "start_address": None,
        "target_address": target_address,
        "family": family,
        "diagnostics": diagnostics,
        "notes": notes,
        "header": None,
    }


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────

_DECODERS = {
    FORMAT_INTEL_HEX: decode_intel_hex,
    FORMAT_SREC: decode_srec,
    FORMAT_UF2: decode_uf2,
}


def analyse_mcu(
    reader: BoundedReader,
    *,
    format: str,  # noqa: A002 - the report field is named `format`
    locator: str,
    digest: str,
    max_payload_bytes: int = DEFAULT_MAX_PAYLOAD_BYTES,
    max_records: int | None = None,
    text_budget: int | None = None,
    max_line: int = 1024,
) -> McuAnalysis:
    """Decode one bare-metal image into an address map.

    Raises:
        McuFormatError: when the bytes do not decode, or when the declared
            payload budget is exceeded. The caller records a FAILED stage; a
            partial map would present unobserved bytes as absent ones.
    """
    if format not in _DECODERS:
        raise McuFormatError(f"unsupported MCU format {format!r}")
    accumulator = _Accumulator(
        max_payload_bytes=max_payload_bytes,
        max_records=max_records or DEFAULT_MAX_RECORDS,
    )
    if format == FORMAT_UF2:
        # Every block must be read: a missing block is a gap in the map, not a
        # reason to stop early.
        budget = reader.size
    else:
        # Hex text is at least twice the bytes it carries, plus address and
        # checksum fields; the payload ceiling is the number that matters.
        budget = text_budget or min(max_payload_bytes * 4, 256 * 1024 * 1024)
    decoded = _DECODERS[format](reader, accumulator, budget=budget)

    if accumulator.records == 0 and not accumulator.chunks:
        raise McuFormatError(
            "no data records were found; an image with no payload is not an empty payload"
        )

    (
        ranges,
        gaps,
        merge_diagnostics,
        payload_sha256,
        unique_bytes,
        payload_ranges,
    ) = accumulator.finish()
    diagnostics = [*decoded["diagnostics"], *merge_diagnostics]
    notes = list(decoded["notes"])
    if gaps:
        notes.append(
            f"{len(gaps)} unobserved gap(s) between declared ranges; they are reported as "
            "unobserved and were never zero-filled"
        )
    return McuAnalysis(
        format=format,
        decoder="ihs-mcu",
        decoder_version=DECODER_VERSION,
        locator=locator,
        digest=digest,
        ranges=ranges,
        gaps=gaps,
        payload_bytes=unique_bytes,
        declared_bytes=accumulator.payload_bytes,
        payload_sha256=payload_sha256,
        records=accumulator.records,
        start_address=decoded["start_address"],
        target_address=decoded.get("target_address"),
        family=decoded.get("family"),
        header=decoded.get("header"),
        diagnostics=diagnostics,
        notes=notes,
        payload_ranges=payload_ranges,
    )
