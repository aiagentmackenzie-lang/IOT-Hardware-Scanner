"""Generated MBR/GPT disk images (slice 3A, part 2).

Written from the published layouts, byte by byte, so the expected offsets are
known before the decoder runs and nothing here shares code with it. A CRC is
computed the same way a real tool computes it, which is what makes the
"corrupt header" cases meaningful rather than accidental.
"""

from __future__ import annotations

import struct
import zlib

#: First LBA a fixture partition uses: past the GPT header and entry array.
BASE_LBA = 64
#: One 2 MiB disk by default.
DISK_SECTORS = 4096

LINUX_GUID = "0fc63daf-8483-4772-8e79-3d69d8477de4"
EFI_GUID = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
UNKNOWN_GUID = "12345678-1234-1234-1234-1234567890ab"


def guid_bytes(text: str) -> bytes:
    """The on-disk mixed-endian form of a GUID string."""
    first, second, third, fourth, fifth = text.split("-")
    return (
        struct.pack("<IHH", int(first, 16), int(second, 16), int(third, 16))
        + bytes.fromhex(fourth)
        + bytes.fromhex(fifth)
    )


def mbr_entry(status: int, part_type: int, start_lba: int, sectors: int) -> bytes:
    """One 16-byte MBR partition entry (CHS fields zeroed)."""
    return bytes([status, 0, 0, 0, part_type, 0, 0, 0]) + struct.pack("<II", start_lba, sectors)


def mbr_image(
    primaries: list[tuple[int, int, int]],
    *,
    logical: list[tuple[int, int, int]] | None = None,
    bootable: bool = False,
    sectors: int = DISK_SECTORS,
    extended_start: int | None = None,
) -> bytes:
    """An MBR image: ``(start_lba, sectors, type)`` primaries, optional logicals."""
    image = bytearray(sectors * 512)
    entries: list[bytes] = [
        mbr_entry(0x80 if (bootable and slot == 0) else 0, part_type, start, count)
        for slot, (start, count, part_type) in enumerate(primaries)
    ]
    logical = logical or []
    if logical:
        ext_start = extended_start or (max(start + count for start, count, _type in primaries) + 4)
        entries.append(mbr_entry(0, 0x05, ext_start, 256))
        for slot, (start, count, part_type) in enumerate(logical):
            ebr_lba = ext_start + slot
            next_ebr = ext_start + slot + 1 if slot + 1 < len(logical) else 0
            ebr = bytearray(512)
            # Entry 1 is relative to the EBR's own sector; entry 2 (the chain
            # link) is relative to the extended container's start.
            ebr[446:462] = mbr_entry(0, part_type, start - ebr_lba, count)
            if next_ebr:
                ebr[462:478] = mbr_entry(0, 0x05, next_ebr - ext_start, 1)
            ebr[510:512] = b"\x55\xaa"
            image[ebr_lba * 512 : (ebr_lba + 1) * 512] = ebr
    for slot, entry in enumerate(entries):
        image[446 + slot * 16 : 446 + (slot + 1) * 16] = entry
    image[510:512] = b"\x55\xaa"
    return bytes(image)


def gpt_image(
    entries: list[tuple[int, int, str, str]],
    *,
    sectors: int = DISK_SECTORS,
    entry_count: int = 128,
    entry_size: int = 128,
    disk_guid: str = "deadbeef-0000-4000-8000-000000000001",
) -> bytes:
    """A GPT image: ``(first_lba, sectors, type_guid, label)`` entries.

    A protective MBR is written first, then the header at LBA 1 and the entry
    array at LBA 2, with both CRCs computed over the real bytes.
    """
    image = bytearray(sectors * 512)
    image[446:462] = mbr_entry(0, 0xEE, 1, min(sectors - 1, 0xFFFFFFFF))
    image[510:512] = b"\x55\xaa"

    entry_lba = 2
    array = bytearray(entry_count * entry_size)
    for slot, (first, count, type_guid, label) in enumerate(entries):
        chunk = bytearray(entry_size)
        chunk[0:16] = guid_bytes(type_guid)
        chunk[16:32] = guid_bytes(f"aaaaaaaa-0000-4000-8000-{slot + 1:012x}")
        struct.pack_into("<QQQ", chunk, 32, first, first + count - 1, 0)
        name = label.encode("utf-16-le")[:72]
        chunk[56 : 56 + len(name)] = name
        array[slot * entry_size : (slot + 1) * entry_size] = chunk
    image[entry_lba * 512 : entry_lba * 512 + len(array)] = array

    header = bytearray(512)
    header[0:8] = b"EFI PART"
    struct.pack_into("<I", header, 8, 0x00010000)  # revision 1.0
    struct.pack_into("<I", header, 12, 92)  # header size
    struct.pack_into("<I", header, 20, 0)  # reserved
    struct.pack_into("<Q", header, 24, 1)  # current LBA
    struct.pack_into("<Q", header, 32, sectors - 1)  # backup LBA
    struct.pack_into("<Q", header, 40, BASE_LBA)  # first usable LBA
    struct.pack_into("<Q", header, 48, sectors - 2)  # last usable LBA
    header[56:72] = guid_bytes(disk_guid)
    struct.pack_into("<Q", header, 72, entry_lba)
    struct.pack_into("<I", header, 80, entry_count)
    struct.pack_into("<I", header, 84, entry_size)
    struct.pack_into("<I", header, 88, zlib.crc32(bytes(array)) & 0xFFFFFFFF)
    struct.pack_into("<I", header, 16, zlib.crc32(bytes(header[:92])) & 0xFFFFFFFF)
    image[512:1024] = header
    return bytes(image)


def reseal_gpt_entries(image: bytearray) -> None:
    """Recompute the entry-array CRC, then the header CRC that covers it."""
    entry_count, entry_size = struct.unpack_from("<II", image, 512 + 80)
    entry_lba = struct.unpack_from("<Q", image, 512 + 72)[0]
    start = entry_lba * 512
    array = bytes(image[start : start + entry_count * entry_size])
    struct.pack_into("<I", image, 512 + 88, zlib.crc32(array) & 0xFFFFFFFF)
    reseal_gpt_header(image)


def reseal_gpt_header(image: bytearray) -> None:
    """Recompute the header CRC with its own field zeroed."""
    header = bytearray(image[512 : 512 + 92])
    header[16:20] = b"\x00\x00\x00\x00"
    struct.pack_into("<I", image, 512 + 16, zlib.crc32(bytes(header)) & 0xFFFFFFFF)
