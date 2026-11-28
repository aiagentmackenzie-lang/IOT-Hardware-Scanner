"""CPIO archives, built byte by byte (slice 3A, part 3).

These fixtures are written here rather than produced by a ``cpio`` binary, for
the same reason the partition fixtures are: the row must prove the *layout*
(padding, octal fields, the trailer, a hard link's zero-length member) rather
than trust whatever producer happens to be installed on the machine running
the suite.

The three ASCII formats differ in ways that are easy to get wrong and cheap to
test:

* ``newc``/``crc`` — 110-byte header, eight hex digits per field, name and data
  padded so the next header starts on a 4-byte boundary;
* ``odc`` — 76-byte header, six octal digits per field (eleven for mtime and
  filesize), and **no padding at all**.

A reader that assumes one layout for the other produces a plausible-looking
tree of nonsense, which is exactly the failure these fixtures exist to catch.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

NEWC = "newc"
CRC = "crc"
ODC = "odc"

MAGIC = {NEWC: b"070701", CRC: b"070702", ODC: b"070707"}
TRAILER = "TRAILER!!!"

S_IFREG = 0o100000
S_IFDIR = 0o040000
S_IFLNK = 0o120000
S_IFCHR = 0o020000
S_IFBLK = 0o060000
S_IFIFO = 0o010000
S_IFSOCK = 0o140000


@dataclass(frozen=True)
class Member:
    """One record to write: exactly the fields a header carries."""

    name: str
    mode: int = S_IFREG | 0o644
    data: bytes = b""
    ino: int = 1
    nlink: int = 1
    uid: int = 0
    gid: int = 0
    mtime: int = 1_700_000_000
    dev_major: int = 1
    dev_minor: int = 2
    rdev_major: int = 0
    rdev_minor: int = 0
    #: ``crc`` checksum. ``None`` means "the sum of ``data``", which is what a
    #: real producer writes.
    check: int | None = None


def _newc_header(member: Member, archive_format: str) -> bytes:
    check = member.check
    if check is None:
        check = sum(member.data) & 0xFFFFFFFF
    if archive_format == NEWC:
        check = 0
    return MAGIC[archive_format] + b"".join(
        f"{value:08x}".encode()
        for value in (
            member.ino,
            member.mode,
            member.uid,
            member.gid,
            member.nlink,
            member.mtime,
            len(member.data),
            member.dev_major,
            member.dev_minor,
            member.rdev_major,
            member.rdev_minor,
            len(member.name.encode()) + 1,
            check,
        )
    )


def _odc_header(member: Member) -> bytes:
    dev = ((member.dev_major & 0xFF) << 8) | (member.dev_minor & 0xFF)
    rdev = ((member.rdev_major & 0xFF) << 8) | (member.rdev_minor & 0xFF)
    return (
        MAGIC[ODC]
        + (
            f"{dev:06o}{member.ino:06o}{member.mode:06o}{member.uid:06o}{member.gid:06o}"
            f"{member.nlink:06o}{rdev:06o}{member.mtime:011o}"
            f"{len(member.name.encode()) + 1:06o}{len(member.data):011o}"
        ).encode()
    )


def _pad(data: bytes, alignment: int) -> bytes:
    return data + b"\x00" * ((-len(data)) % alignment)


def build(
    members: list[Member],
    *,
    archive_format: str = NEWC,
    trailer: bool = True,
    trailing: bytes = b"",
) -> bytes:
    """Serialise ``members`` as one archive, optionally followed by ``trailing``."""
    if archive_format == ODC:
        alignment = 1
        header = _odc_header
    else:
        alignment = 4
        header = lambda member: _newc_header(member, archive_format)  # noqa: E731

    out = bytearray()
    for member in members:
        name = member.name.encode() + b"\x00"
        raw_header = header(member)
        out += raw_header
        out += _pad(raw_header + name, alignment)[len(raw_header) :]
        out += member.data
        out += b"\x00" * ((-len(member.data)) % alignment)
    if trailer:
        end = Member(name=TRAILER, mode=S_IFREG, data=b"", ino=0, nlink=1)
        raw_header = header(end)
        name = end.name.encode() + b"\x00"
        out += raw_header
        out += _pad(raw_header + name, alignment)[len(raw_header) :]
    return bytes(out) + trailing


def initramfs(
    *,
    shadow: bytes = b"root:*:19000:0:99999:7:::\n",
    archive_format: str = NEWC,
    **kwargs: object,
) -> bytes:
    """A minimal initramfs: ``/etc/passwd``, ``/etc/shadow`` and a helper.

    The shadow line is the one switch: an empty password field is what the
    credential rules must find, and a locked field is what they must not.
    """
    return build(
        [
            Member(name=".", mode=S_IFDIR | 0o755, ino=1, nlink=3),
            Member(name="etc", mode=S_IFDIR | 0o755, ino=2, nlink=2),
            Member(
                name="etc/passwd",
                data=b"root:x:0:0:root:/root:/bin/sh\n",
                ino=3,
            ),
            Member(name="etc/shadow", mode=S_IFREG | 0o600, data=shadow, ino=4),
            Member(name="bin", mode=S_IFDIR | 0o755, ino=5, nlink=2),
            Member(
                name="bin/sh",
                mode=S_IFREG | 0o755,
                data=b"#!/bin/sh\nexec /bin/busybox sh\n",
                ino=6,
                nlink=2,
            ),
            Member(
                name="bin/busybox.sh",
                mode=S_IFREG | 0o755,
                data=b"",
                ino=6,
                nlink=2,
            ),
        ],
        archive_format=archive_format,
        **kwargs,
    )


def hardlink_pair(
    carrier: str,
    link: str,
    data: bytes,
    *,
    ino: int = 42,
    mode: int = S_IFREG | 0o600,
) -> list[Member]:
    """Two names of one inode: the zero-length member first, the bytes second.

    That is the order a real producer writes: the data lives in the last member
    of the group. A reader that treats the zero length as an empty file reports
    a 0-byte ``/etc/shadow`` and a weaker finding than the artifact supports.
    """
    return [
        Member(name=link, mode=mode, data=b"", ino=ino, nlink=2),
        Member(name=carrier, mode=mode, data=data, ino=ino, nlink=2),
    ]


def with_check(member: Member, *, forged: int) -> Member:
    """A ``crc`` member whose declared check deliberately disagrees with its data."""
    return replace(member, check=forged)
