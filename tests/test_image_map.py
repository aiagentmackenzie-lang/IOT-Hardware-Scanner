"""Image map (3A): wrapper, expanded size and filesystem extent stay separate."""

from __future__ import annotations

import gzip
import struct
from pathlib import Path

import pytest

from iot_hardware_scanner.models import ImageMap
from iot_hardware_scanner.scanner.bounded_reader import open_bounded
from iot_hardware_scanner.scanner.image_map import (
    GzipHeader,
    ImageMapBuilder,
    ImageMapError,
)

PAYLOAD = b"hsqs" + b"\x00" * 92  # a superblock-shaped stub, 96 bytes


def squashfs_stub(
    *,
    magic: bytes = b"hsqs",
    version: tuple[int, int] = (4, 0),
    bytes_used: int = 96,
    block_size: int = 262144,
    inodes: int = 1622,
    fragments: int = 59,
    compression: int = 4,
    total: int = 96,
) -> bytes:
    """A superblock with the fields this scanner validates, plus padding."""
    # magic + inodes, mkfs_time, block_size, fragments, compression, block_log,
    # flags, id_count, major, minor, root_inode, bytes_used
    header = struct.pack(
        "<IIIIHHHHHHQQ",
        inodes,
        1700000000,
        block_size,
        fragments,
        compression,
        17,
        0,
        2,
        version[0],
        version[1],
        0x1234,
        bytes_used,
    )
    body = magic + header
    assert len(body) == 48
    return body.ljust(total, b"\x00")


@pytest.fixture
def gzip_image(tmp_path: Path) -> Path:
    path = tmp_path / "rootfs.img.gz"
    path.write_bytes(gzip.compress(squashfs_stub(total=4096), mtime=0))
    return path


class TestGzipWrapper:
    def test_header_fields_are_parsed(self, gzip_image: Path) -> None:
        builder = ImageMapBuilder()
        header = builder.parse_gzip_header(open_bounded(gzip_image))
        assert isinstance(header, GzipHeader)
        assert header.flags & 0x08 == 0
        assert header.isize == 4096

    def test_non_gzip_input_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "plain.bin"
        path.write_bytes(b"\x00" * 128)
        with pytest.raises(ImageMapError):
            ImageMapBuilder().parse_gzip_header(open_bounded(path))

    def test_root_node_records_the_wrapper(self, gzip_image: Path) -> None:
        builder = ImageMapBuilder()
        image_map = builder.start(open_bounded(gzip_image), "a" * 64, "rootfs.img.gz")
        assert isinstance(image_map, ImageMap)
        root = image_map.nodes[0]
        assert root.format == "gzip"
        assert root.coordinate_system == "container-bytes"
        assert root.length == gzip_image.stat().st_size
        assert root.decoder == "python-zlib"

    def test_decompression_records_the_child_in_both_coordinates(
        self, gzip_image: Path, tmp_path: Path
    ) -> None:
        builder = ImageMapBuilder()
        reader = open_bounded(gzip_image)
        builder.start(reader, "a" * 64, "rootfs.img.gz")
        decoded, child = builder.decompress_gzip(
            reader, tmp_path / "decoded" / "root.squashfs", max_decoded_bytes=1 << 20
        )

        assert decoded.read_bytes() == squashfs_stub(total=4096)
        assert child.expanded_bytes == 4096
        assert child.extent_bytes == 96
        assert child.details["wrapper_size"] == gzip_image.stat().st_size
        assert child.details["wrapper_declared_isize"] == 4096
        assert child.details["superblock"]["bytes_used"] == 96
        assert child.details["superblock"]["compression"] == "xz"
        assert child.parent_id == "a0"

        # Three different numbers, kept apart.
        assert child.expanded_bytes != child.extent_bytes
        assert child.details["wrapper_size"] != child.expanded_bytes

    def test_decoded_budget_is_enforced_and_nothing_is_left(
        self, gzip_image: Path, tmp_path: Path
    ) -> None:
        builder = ImageMapBuilder()
        reader = open_bounded(gzip_image)
        builder.start(reader, "a" * 64, "rootfs.img.gz")
        destination = tmp_path / "decoded" / "root.squashfs"

        with pytest.raises(ImageMapError) as excinfo:
            builder.decompress_gzip(reader, destination, max_decoded_bytes=512)
        assert "budget" in str(excinfo.value)
        assert not destination.exists()

    def test_corrupt_stream_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "broken.img.gz"
        raw = bytearray(gzip.compress(b"x" * 4096, mtime=0))
        raw[20:40] = b"\xff" * 20  # corrupt the deflate stream
        path.write_bytes(bytes(raw))

        builder = ImageMapBuilder()
        reader = open_bounded(path)
        builder.start(reader, "a" * 64, "broken.img.gz")
        with pytest.raises(ImageMapError) as excinfo:
            builder.decompress_gzip(reader, tmp_path / "out.bin", max_decoded_bytes=1 << 20)
        assert "decodable" in str(excinfo.value) or "trailer" in str(excinfo.value)

    def test_truncated_stream_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "cut.img.gz"
        raw = gzip.compress(b"y" * 65536, mtime=0)
        path.write_bytes(raw[: len(raw) // 2])

        builder = ImageMapBuilder()
        reader = open_bounded(path)
        builder.start(reader, "a" * 64, "cut.img.gz")
        with pytest.raises(ImageMapError):
            builder.decompress_gzip(reader, tmp_path / "out.bin", max_decoded_bytes=1 << 20)


class TestSquashfsSuperblock:
    def test_valid_superblock_is_read(self, tmp_path: Path) -> None:
        path = tmp_path / "root.squashfs"
        path.write_bytes(squashfs_stub(total=4096))
        block = ImageMapBuilder.parse_squashfs(open_bounded(path))
        assert (block.magic, block.version_major, block.version_minor) == ("hsqs", 4, 0)
        assert block.bytes_used == 96
        assert block.block_size == 262144
        assert block.inode_count == 1622
        assert block.fragment_count == 59
        assert block.compression == "xz"
        assert block.as_dict()["version"] == "4.0"

    def test_wrong_magic_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "not-squashfs.bin"
        path.write_bytes(b"\x00" * 4096)
        with pytest.raises(ImageMapError) as excinfo:
            ImageMapBuilder.parse_squashfs(open_bounded(path))
        assert "magic" in str(excinfo.value)

    def test_unsupported_version_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "v3.squashfs"
        path.write_bytes(squashfs_stub(version=(3, 1), total=4096))
        with pytest.raises(ImageMapError) as excinfo:
            ImageMapBuilder.parse_squashfs(open_bounded(path))
        assert "version 3.1" in str(excinfo.value)

    def test_declared_extent_beyond_the_file_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "short.squashfs"
        path.write_bytes(squashfs_stub(bytes_used=1_000_000, total=4096))
        with pytest.raises(ImageMapError) as excinfo:
            ImageMapBuilder.parse_squashfs(open_bounded(path))
        assert "truncated" in str(excinfo.value)

    def test_absurd_block_size_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "blocks.squashfs"
        path.write_bytes(squashfs_stub(block_size=8 * 1024 * 1024, total=4096))
        with pytest.raises(ImageMapError) as excinfo:
            ImageMapBuilder.parse_squashfs(open_bounded(path))
        assert "block size" in str(excinfo.value)

    def test_superblock_outside_the_input_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "tiny.squashfs"
        path.write_bytes(b"hsqs")
        with pytest.raises(ImageMapError) as excinfo:
            ImageMapBuilder.parse_squashfs(open_bounded(path))
        assert "outside" in str(excinfo.value)


class TestAncestry:
    def test_file_locators_hang_from_their_parent(self, tmp_path: Path) -> None:
        builder = ImageMapBuilder()
        path = tmp_path / "root.squashfs"
        path.write_bytes(b"\x00" * 32)
        builder.start(open_bounded(path), "b" * 64, "root.squashfs")
        node = builder.add_file(
            locator="rootfs/bin/busybox",
            digest="c" * 64,
            size=32,
            parent_id="a0",
            details={"sha256": "c" * 64},
        )
        assert node.artifact_id == "f1"
        assert node.coordinate_system == "filesystem-path"
        assert node.depth == 1
        assert node.parent_id == "a0"
        assert builder.map is not None
        assert builder.map.children("a0") == [node]
        assert builder.map.by_id("f1") is node
        assert builder.map.by_id("nope") is None
        assert builder.map.root_artifact_id == "a0"
