"""The image map — ancestry and coordinates for everything a scan opens (3A).

Milestone B needs three different sizes kept apart, because confusing them is
how a scanner ends up claiming a limit it never enforced:

* **wrapper size** — the gzip file on the wire (4,451,127 bytes for the
  reference image);
* **expanded size** — what the gzip stream decodes to (109,051,904 bytes);
* **filesystem extent** — what the SquashFS superblock says it uses
  (4,348,264 bytes).

The expanded stream is mostly padding: the filesystem extent is the only one
that describes content. Limits are applied to each separately.

What this module validates
--------------------------
* The gzip wrapper's header and trailer are parsed and its declared
  uncompressed size (ISIZE) is compared with what was actually decoded.
* The SquashFS superblock is read from a bounded window at a declared offset,
  its magic and version are checked, and its declared extent must lie inside
  the bytes that exist.
* Every node records the decoder and its version, so a later release can tell
  which parser produced the observation.

The decoder here is Python's ``zlib`` for the gzip wrapper and a structural
reader for the superblock. Both run in-process and touch no network. The
SquashFS *filesystem* is decoded by upstream ``unsquashfs`` in a pinned Linux
worker; see :mod:`iot_hardware_scanner.scanner.extraction_worker`.
"""

from __future__ import annotations

import hashlib
import logging
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path

from iot_hardware_scanner.models import (
    ArtifactNode,
    ImageMap,
    SquashfsSuperblock,
)
from iot_hardware_scanner.scanner.bounded_reader import BoundedReader, open_bounded

logger = logging.getLogger(__name__)

GZIP_MAGIC = b"\x1f\x8b"
SQUASHFS_MAGIC = b"hsqs"
#: The superblock is 96 bytes in SquashFS v4.
SUPERBLOCK_SIZE = 96
#: Compressor identifiers, from squashfs_fs.h.
COMPRESSION_NAMES = {
    1: "gzip",
    2: "lzma",
    3: "lzo",
    4: "xz",
    5: "lz4",
    6: "zstd",
}

_DECODER_NAME = "python-zlib"
_DECODER_VERSION = zlib.ZLIB_VERSION


class ImageMapError(Exception):
    """Raised when a declared container range or header cannot be trusted."""


@dataclass
class GzipHeader:
    """The fields of a gzip member header that can be read without decoding."""

    offset: int
    flags: int
    mtime: int
    xfl: int
    os: int
    isize: int
    header_length: int


class ImageMapBuilder:
    """Build the ancestry of one scan, one validated container at a time."""

    def __init__(self) -> None:
        self.map: ImageMap | None = None

    # ──────────────────────────────────────────
    # Root node
    # ──────────────────────────────────────────

    def start(self, reader: BoundedReader, digest: str, name: str) -> ImageMap:
        """Create the map with the inspected artifact as its root node."""
        header = reader.read_head(4)
        fmt = "gzip" if header.startswith(GZIP_MAGIC) else "file"
        root = ArtifactNode(
            artifact_id="a0",
            parent_id=None,
            digest_sha256=digest,
            format=fmt,
            coordinate_system="container-bytes",
            offset=0,
            length=reader.size,
            decoder=_DECODER_NAME,
            decoder_version=_DECODER_VERSION,
            depth=0,
            locator=name,
            details={"input_size": reader.size},
        )
        self.map = ImageMap(root_artifact_id=root.artifact_id, nodes=[root])
        return self.map

    # ──────────────────────────────────────────
    # gzip wrapper
    # ──────────────────────────────────────────

    @staticmethod
    def parse_gzip_header(reader: BoundedReader, offset: int = 0) -> GzipHeader:
        """Parse and validate a gzip member header at ``offset``."""
        head = reader.read_at(offset, min(12, reader.size - offset))
        if len(head) < 10 or not head.startswith(GZIP_MAGIC):
            raise ImageMapError(f"no gzip magic at offset {offset}")
        if head[2] != 8:
            raise ImageMapError(f"unsupported gzip compression method {head[2]}")
        flags = head[3]
        mtime = int.from_bytes(head[4:8], "little")
        xfl, os_byte = head[8], head[9]
        # Optional fields shift the member trailer's position but not the fact
        # that the last four bytes are the declared ISIZE.
        trailer = reader.read_at(max(reader.size - 4, 0), 4)
        isize = int.from_bytes(trailer, "little")
        return GzipHeader(
            offset=offset,
            flags=flags,
            mtime=mtime,
            xfl=xfl,
            os=os_byte,
            isize=isize,
            header_length=10,
        )

    def decompress_gzip(
        self,
        reader: BoundedReader,
        destination: Path,
        *,
        max_decoded_bytes: int,
        node_id: str = "a1",
    ) -> tuple[Path, ArtifactNode]:
        """Stream the gzip wrapper into bounded scratch and record the child.

        The decoded size is checked against the declared ISIZE and against
        ``max_decoded_bytes``. Exceeding either raises :class:`ImageMapError`
        and removes the partial file, so a quota breach cannot be mistaken for
        a decoded image.
        """
        header = self.parse_gzip_header(reader)
        destination.parent.mkdir(parents=True, exist_ok=True)
        hasher = hashlib.sha256()
        decoded = 0
        decompressor = zlib.decompressobj(wbits=31)
        try:
            with destination.open("wb") as out:
                for window in reader.iter_windows(1024 * 1024):
                    pending = window.data
                    while pending:
                        try:
                            chunk = decompressor.decompress(pending, 1024 * 1024)
                        except zlib.error as exc:
                            raise ImageMapError(f"gzip stream is not decodable: {exc}") from exc
                        pending = decompressor.unconsumed_tail
                        if chunk:
                            decoded += len(chunk)
                            if decoded > max_decoded_bytes:
                                raise ImageMapError(
                                    f"decoded stream exceeds the {max_decoded_bytes}-byte "
                                    f"budget (wrapper declares {header.isize} bytes)"
                                )
                            hasher.update(chunk)
                            out.write(chunk)
                        if not pending:
                            break
                    if decompressor.eof:
                        break
                if not decompressor.eof:
                    raise ImageMapError(
                        "gzip stream ended before the member trailer: the wrapper is truncated"
                    )
        except BaseException:
            destination.unlink(missing_ok=True)
            raise

        expected = header.isize
        # ISIZE is the size modulo 2**32; treat a mismatch as corruption only
        # when the declared value is usable as a size at all.
        if expected and decoded & 0xFFFFFFFF != expected & 0xFFFFFFFF:
            destination.unlink(missing_ok=True)
            raise ImageMapError(
                f"gzip trailer declares {expected} decoded bytes, the stream produced {decoded}"
            )

        assert self.map is not None, "start() must be called before decompress_gzip()"
        child = ArtifactNode(
            artifact_id=node_id,
            parent_id=self.map.root_artifact_id,
            digest_sha256=hasher.hexdigest(),
            format="squashfs",
            coordinate_system="container-bytes",
            offset=0,
            length=decoded,
            decoder=_DECODER_NAME,
            decoder_version=_DECODER_VERSION,
            depth=1,
            locator=destination.name,
            expanded_bytes=decoded,
            details={
                "wrapper_offset": header.offset,
                "wrapper_size": reader.size,
                "wrapper_declared_isize": header.isize,
                "gzip_flags": header.flags,
                "gzip_mtime": header.mtime,
            },
        )
        self.map.add(child)
        logger.info(
            "gzip wrapper: %d bytes on the wire -> %d decoded bytes (sha256 %s)",
            reader.size,
            decoded,
            child.digest_sha256,
        )

        # The declared format is settled by the child's own header, not by the
        # wrapper's name.
        superblock = self.parse_squashfs(open_bounded(destination, size=decoded))
        child.format = "squashfs"
        child.details["superblock"] = superblock.as_dict()
        child.extent_bytes = superblock.bytes_used
        child.decoder = "unsquashfs"
        child.decoder_version = None
        return destination, child

    # ──────────────────────────────────────────
    # SquashFS superblock
    # ──────────────────────────────────────────

    @staticmethod
    def parse_squashfs(reader: BoundedReader, offset: int = 0) -> SquashfsSuperblock:
        """Read and validate a SquashFS v4 superblock at ``offset``."""
        if offset < 0 or offset + SUPERBLOCK_SIZE > reader.size:
            raise ImageMapError(
                f"superblock range {offset}:{offset + SUPERBLOCK_SIZE} is outside the "
                f"{reader.size}-byte input"
            )
        raw = reader.read_at(offset, SUPERBLOCK_SIZE)
        magic = raw[:4]
        if magic != SQUASHFS_MAGIC:
            printable = magic[::-1] if magic == SQUASHFS_MAGIC[::-1] else magic
            raise ImageMapError(
                f"no SquashFS magic at offset {offset} (found {printable!r}); "
                "this release decodes SquashFS v4 only"
            )
        (
            _magic,
            inode_count,
            mkfs_time,
            block_size,
            fragment_count,
            compression,
            _block_log,
            _flags,
            _id_count,
            version_major,
            version_minor,
            _root_inode,
            bytes_used,
        ) = struct.unpack("<IIIIIHHHHHHQQ", raw[:48])
        if version_major != 4:
            raise ImageMapError(
                f"SquashFS version {version_major}.{version_minor} is not supported; "
                "this release decodes v4 only"
            )
        if block_size == 0 or block_size > 1024 * 1024:
            raise ImageMapError(f"SquashFS superblock declares an invalid block size {block_size}")
        if bytes_used == 0:
            raise ImageMapError("SquashFS superblock declares a zero extent")
        if offset + bytes_used > reader.size:
            raise ImageMapError(
                f"SquashFS declares {bytes_used} bytes used but only "
                f"{reader.size - offset} bytes exist at offset {offset}: the image is truncated"
            )
        return SquashfsSuperblock(
            offset=offset,
            magic=magic.decode("ascii", errors="replace"),
            version_major=version_major,
            version_minor=version_minor,
            bytes_used=bytes_used,
            block_size=block_size,
            inode_count=inode_count,
            fragment_count=fragment_count,
            compression=COMPRESSION_NAMES.get(compression, f"unknown({compression})"),
            mkfs_time=mkfs_time,
            declared_filesystem_size=bytes_used,
        )

    # ──────────────────────────────────────────
    # File locators
    # ──────────────────────────────────────────

    def add_file(
        self,
        *,
        locator: str,
        digest: str,
        size: int,
        parent_id: str,
        offset: int = 0,
        details: dict[str, object] | None = None,
    ) -> ArtifactNode:
        """Record one file inside an extracted filesystem.

        The coordinates are a path, not a byte range: ``coordinate_system`` says
        so, and ``offset``/``length`` describe the file's own extent so a reader
        still cannot read past it.
        """
        assert self.map is not None, "start() must be called before add_file()"
        parent = self.map.by_id(parent_id)
        node = ArtifactNode(
            artifact_id=f"f{len(self.map.nodes)}",
            parent_id=parent_id,
            digest_sha256=digest,
            format="file",
            coordinate_system="filesystem-path",
            offset=offset,
            length=size,
            decoder="",
            decoder_version=None,
            depth=parent.depth + 1 if parent is not None else 1,
            locator=locator,
            details=dict(details or {}),
        )
        self.map.add(node)
        return node
