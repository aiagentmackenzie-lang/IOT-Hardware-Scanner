"""Deterministic hostile artifacts for the adversarial-input gate (slice 2E).

Nothing here needs a worker, a corpus or a network: a hostile input is generated
from bytes on demand. Every builder is pure, so the same fixture can be asserted
by a property test and driven through the installed CLI.

Two rules this gate enforces:

* hostile input is rejected with a **documented** exit status (3/4/5) or parsed
  successfully — never a traceback;
* a rejected input never contributes a fact: the stage that could not read it is
  ``FAILED``/``UNAVAILABLE`` with a reason, and the assessment is ``INCOMPLETE``.

The fixtures are deliberately small. Each one isolates a single lie the parser
must not believe: a declared size that is larger than the bytes, an offset
outside the artifact, a version it does not decode, more nesting than the bound.
"""

from __future__ import annotations

import gzip
import io
import struct
import tarfile

from fdt_fixtures import Node, board_dtb, build_fdt, build_fit

# ──────────────────────────────────────────────
# gzip wrapper
# ──────────────────────────────────────────────


def gzip_truncated_header() -> bytes:
    """Three bytes of a gzip member: shorter than any valid header."""
    return b"\x1f\x8b\x08"


def gzip_corrupt_body() -> bytes:
    """A valid gzip header followed by bytes that cannot inflate."""
    header = gzip.compress(b"x" * 64)[:10]
    return header + b"\x00\xff" * 32 + b"\x00\x00\x00\x00"


def gzip_isize_lie() -> bytes:
    """A valid gzip member whose trailer declares a different decoded size."""
    member = bytearray(gzip.compress(b"hello world", mtime=0))
    member[-4:] = struct.pack("<I", 0xFFFFFF)
    return bytes(member)


# ──────────────────────────────────────────────
# SquashFS superblock
# ──────────────────────────────────────────────

SQUASHFS_MAGIC = b"hsqs"


def squashfs_superblock(
    *,
    bytes_used: int = 4096,
    version_major: int = 4,
    version_minor: int = 0,
    block_size: int = 262144,
    inode_count: int = 1,
) -> bytes:
    """A SquashFS v4 superblock with caller-chosen declarations."""
    header = struct.pack(
        "<IIIIIHHHHHHQQ",
        int.from_bytes(SQUASHFS_MAGIC, "little"),
        inode_count,
        0,
        block_size,
        0,
        1,  # gzip
        17,
        0,
        1,
        version_major,
        version_minor,
        0,
        bytes_used,
    )
    return header


def squashfs_huge_extent() -> bytes:
    """Declares ~4 GiB used in a 200-byte file."""
    return squashfs_superblock(bytes_used=0xFFFFFFF0) + b"\x00" * 152


def squashfs_future_version() -> bytes:
    """A version this release does not decode."""
    return squashfs_superblock(version_major=5) + b"\x00" * 152


def squashfs_zero_block_size() -> bytes:
    """A block size of zero, which no reader can use."""
    return squashfs_superblock(block_size=0) + b"\x00" * 152


def squashfs_magic_only() -> bytes:
    """The magic and nothing else: shorter than the 96-byte superblock."""
    return SQUASHFS_MAGIC


# ──────────────────────────────────────────────
# CPIO archives (slice 3A, part 3)
# ──────────────────────────────────────────────


def _newc_record(name: str, payload: bytes, *, filesize: int | None = None) -> bytes:
    """One ``newc`` record, with an optional lie about its data length."""
    declared = len(payload) if filesize is None else filesize
    body = name.encode() + b"\x00"
    header = b"070701" + b"".join(
        f"{value:08x}".encode()
        for value in (
            1,  # ino
            0o100644,  # mode
            0,  # uid
            0,  # gid
            1,  # nlink
            1_700_000_000,  # mtime
            declared,  # filesize
            1,  # devmajor
            2,  # devminor
            0,  # rdevmajor
            0,  # rdevminor
            len(body),  # namesize
            0,  # check
        )
    )
    padded = header + body
    padded += b"\x00" * ((-len(padded)) % 4)
    return padded + payload + b"\x00" * ((-len(payload)) % 4)


def cpio_data_size_lie() -> bytes:
    """A record that declares 64 KiB of data and carries twelve bytes."""
    return _newc_record("etc/shadow", b"root::0:0:", filesize=0x10000)


def cpio_traversal_name() -> bytes:
    """A member whose name would write outside the extraction root."""
    return _newc_record("../../etc/shadow", b"root::0:0:")


def cpio_no_trailer() -> bytes:
    """A well-formed record set with no ``TRAILER!!!``: truncated, not empty."""
    return _newc_record("etc/passwd", b"root:x:0:0:root:/root:/bin/sh\n")


def cpio_binary_magic() -> bytes:
    """The old binary format, whose magic is decimal 070707 stored as a word."""
    return b"\xc7\x71" + b"\x00" * 24


# ──────────────────────────────────────────────
# Flattened device tree (FDT)
# ──────────────────────────────────────────────


def _patch_header(data: bytes, field_offset: int, value: int) -> bytes:
    patched = bytearray(data)
    patched[field_offset : field_offset + 4] = struct.pack(">I", value)
    return bytes(patched)


def fdt_totalsize_lie() -> bytes:
    """Declares a total size far beyond the bytes that exist."""
    return _patch_header(board_dtb(), 4, 0xFFFFFFF0)


def fdt_struct_offset_lie() -> bytes:
    """Points the structure block past the declared total size."""
    data = board_dtb()
    totalsize = struct.unpack(">I", data[4:8])[0]
    return _patch_header(data, 8, totalsize + 4096)


def fdt_header_only() -> bytes:
    """A valid magic followed by a truncated header."""
    return board_dtb()[:24]


def fdt_deep_nesting(depth: int = 40) -> bytes:
    """A structurally valid FDT nested deeper than the parser's bound (32)."""
    root = Node("")
    cursor = root
    for index in range(depth):
        child = Node(f"n{index}")
        cursor.child(child)
        cursor = child
    root.add_str("compatible", "deep,test")
    return build_fdt(root)


# ──────────────────────────────────────────────
# U-Boot FIT
# ──────────────────────────────────────────────


def fit_out_of_bounds() -> bytes:
    """A FIT whose payload range is declared beyond the artifact."""
    return build_fit(out_of_bounds=True).data


def fit_truncated() -> bytes:
    """A valid FIT cut in half: the declared payloads no longer exist."""
    data = build_fit().data
    return data[: len(data) // 2]


# ──────────────────────────────────────────────
# opkg status databases
# ──────────────────────────────────────────────


def opkg_oversized(mebibytes: int = 9) -> bytes:
    """A package database larger than the 8 MiB parse budget."""
    stanza = b"Package: pkg\nVersion: 1.0\nStatus: install user installed\nArchitecture: all\n\n"
    return stanza * ((mebibytes * 1024 * 1024) // len(stanza) + 1)


def opkg_binary_garbage() -> bytes:
    """NULs and invalid UTF-8 around one readable stanza."""
    body = b"\x00\xff\xfe\x80garbage\n"
    stanza = b"Package: base-files\nVersion: 1\nStatus: install user installed\n"
    return body + stanza + body


# ──────────────────────────────────────────────
# Streamed tar members (the extraction worker's return path)
# ──────────────────────────────────────────────


def tar_with_member(name: str, payload: bytes = b"data") -> bytes:
    """One tar member with an arbitrary name, used to test member validation."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        info = tarfile.TarInfo(name=name)
        info.size = len(payload)
        info.mode = 0o644
        archive.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


# ──────────────────────────────────────────────
# Saved documents (report / comparison / SBOM input)
# ──────────────────────────────────────────────


def hostile_documents() -> list[tuple[str, object]]:
    """Saved-document inputs that must be invalid input (exit 3), not crashes."""
    return [
        ("findings-is-a-string", {"schema_version": 6, "findings": "nope"}),
        ("assessment-is-a-string", {"schema_version": 6, "assessment": "nope"}),
        ("stages-contain-a-string", {"schema_version": 6, "stages": ["ingest"]}),
        ("components-contain-null", {"schema_version": 6, "components": [None]}),
        ("controls-contain-a-list", {"schema_version": 6, "controls": [[]]}),
        ("schema-version-is-a-string", {"schema_version": "6"}),
        ("schema-version-is-a-bool", {"schema_version": True}),
        ("schema-version-missing", {"artifact": {}}),
        ("cache-is-a-list", {"schema_version": 6, "cache": []}),
        ("boot-is-a-string", {"schema_version": 6, "boot": "d00dfeed"}),
        ("unversioned-and-not-v1", {"firmware": "nope"}),
    ]


def deeply_nested_json(depth: int = 5000) -> bytes:
    """JSON nested past CPython's recursion limit, written without recursion."""
    return b'{"a":' * depth + b"1" + b"}" * depth


def nested_object(depth: int = 200) -> dict[str, object]:
    """A Python object nested past a shallow validator, for property tests."""
    value: dict[str, object] = {}
    cursor = value
    for _ in range(depth):
        child: dict[str, object] = {}
        cursor["a"] = child
        cursor = child
    return value
