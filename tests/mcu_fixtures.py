"""Generated bare-metal fixtures (slice 3C).

Three encoders written by hand from their published layouts, so the expected
address map is known before the decoder runs and no oracle shares code with the
module under test. Shared by the decoder tests and the profile tests.
"""

from __future__ import annotations

import struct

BASE = 0x0800_0000
SECOND = BASE + 0x200
FAMILY = 0xE48BFF56


# ──────────────────────────────────────────────
# Encoders (independent of the decoder)
# ──────────────────────────────────────────────


def ihex_record(kind: int, address: int, data: bytes) -> str:
    body = bytes([len(data), (address >> 8) & 0xFF, address & 0xFF, kind]) + data
    checksum = (-sum(body)) & 0xFF
    return ":" + (body + bytes([checksum])).hex().upper()


def encode_ihex(ranges: list[tuple[int, bytes]], *, chunk: int = 32) -> bytes:
    """Intel HEX, one extended-linear-address record per 64 KiB page."""
    lines: list[str] = []
    page: int | None = None
    for address, payload in ranges:
        for offset in range(0, len(payload), chunk):
            current = address + offset
            if current >> 16 != page:
                page = current >> 16
                lines.append(ihex_record(0x04, 0, page.to_bytes(2, "big")))
            lines.append(ihex_record(0x00, current & 0xFFFF, payload[offset : offset + chunk]))
    lines.append(ihex_record(0x05, 0, BASE.to_bytes(4, "big")))
    lines.append(ihex_record(0x01, 0, b""))
    return ("\r\n".join(lines) + "\r\n").encode()


def srec_record(kind: int, address: int, data: bytes, address_bytes: int) -> str:
    body = address.to_bytes(address_bytes, "big") + data
    count = len(body) + 1
    payload = bytes([count]) + body
    checksum = (~sum(payload)) & 0xFF
    return f"S{kind}" + (payload + bytes([checksum])).hex().upper()


def encode_srec(ranges: list[tuple[int, bytes]], *, chunk: int = 32) -> bytes:
    """Motorola S-record: S0 header, S3 data, S5 count, S7 start address."""
    lines = [srec_record(0, 0, b"board-fixture", 2)]
    count = 0
    for address, payload in ranges:
        for offset in range(0, len(payload), chunk):
            lines.append(srec_record(3, address + offset, payload[offset : offset + chunk], 4))
            count += 1
    lines.append(srec_record(5, count, b"", 2))
    lines.append(srec_record(7, BASE, b"", 4))
    return ("\n".join(lines) + "\n").encode()


def encode_uf2(ranges: list[tuple[int, bytes]], *, block_payload: int = 476) -> bytes:
    """UF2: 512-byte blocks, family id present, addresses as target addresses."""
    blocks: list[tuple[int, bytes]] = []
    for address, payload in ranges:
        for offset in range(0, len(payload), block_payload):
            blocks.append((address + offset, payload[offset : offset + block_payload]))
    output = b""
    for number, (address, chunk) in enumerate(blocks):
        header = struct.pack(
            "<IIIIIIII",
            0x0A324655,
            0x9E5D5157,
            0x00002000,  # family id present
            address,
            len(chunk),
            number,
            len(blocks),
            FAMILY,
        )
        output += header + chunk.ljust(476, b"\x00") + struct.pack("<I", 0x0AB16F30)
    return output


def payload_ranges() -> list[tuple[int, bytes]]:
    """Two ranges with a deliberate hole between them."""
    first = bytes((index * 7 + 3) & 0xFF for index in range(300))
    second = bytes((index * 11 + 5) & 0xFF for index in range(200))
    return [(BASE, first), (SECOND, second)]
