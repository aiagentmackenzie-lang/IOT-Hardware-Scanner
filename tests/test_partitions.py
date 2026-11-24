"""Slice 3A, part 2 — partition tables.

The plan's acceptance row:

> a generated partitioned image with two distinct root filesystems maps both into
> the report, all physical ranges stay in bounds, and identical paths in different
> partitions remain distinguishable.

These tests build the tables byte by byte, so the expected offsets are known
before the decoder runs, and they cover the failure the row is really about: a
table that points past the end of a truncated image must be refused, not turned
into an empty partition.

The end-to-end half of the row (two SquashFS roots, distinguishable paths) needs
the pinned worker image and runs in the qualified CI job; see
`tests/test_installed_image_cli.py::TestPartitionedImage`.
"""

from __future__ import annotations

import struct
from pathlib import Path

import partition_fixtures as fixtures
import pytest

from iot_hardware_scanner.scanner.bounded_reader import open_bounded
from iot_hardware_scanner.scanner.image_map import ImageMapBuilder, ImageMapError
from iot_hardware_scanner.scanner.partitions import (
    SCHEME_GPT,
    SCHEME_MBR,
    PartitionError,
    decode_partition_table,
    looks_like_partition_table,
)


def decode(tmp_path: Path, blob: bytes, name: str = "disk.img"):
    path = tmp_path / name
    path.write_bytes(blob)
    return decode_partition_table(open_bounded(path))


class TestRecognition:
    def test_an_mbr_with_one_entry_is_recognised(self) -> None:
        image = fixtures.mbr_image([(fixtures.BASE_LBA, 8, 0x83)])

        assert looks_like_partition_table(image[:1024]) is True

    def test_a_signature_alone_is_not_a_disk(self) -> None:
        """``0x55aa`` at 510 is common; a table needs an entry to be one."""
        blob = bytearray(4096)
        blob[510:512] = b"\x55\xaa"
        assert looks_like_partition_table(bytes(blob)) is False

    def test_a_gpt_header_behind_a_protective_mbr_is_recognised(self) -> None:
        image = fixtures.gpt_image([(fixtures.BASE_LBA, 8, fixtures.LINUX_GUID, "root")])

        assert looks_like_partition_table(image[:1024]) is True

    def test_a_short_file_cannot_carry_a_sector(self, tmp_path: Path) -> None:
        path = tmp_path / "tiny.bin"
        path.write_bytes(b"\x00" * 100)
        with pytest.raises(PartitionError, match="512-byte sector"):
            decode_partition_table(open_bounded(path))


class TestMbr:
    def test_primary_entries_become_records_with_byte_coordinates(self, tmp_path: Path) -> None:
        image = fixtures.mbr_image(
            [(fixtures.BASE_LBA, 16, 0x83), (fixtures.BASE_LBA + 16, 8, 0x0C)]
        )
        scheme, records = decode(tmp_path, image)

        assert scheme == SCHEME_MBR
        assert [record.index for record in records] == [1, 2]
        assert records[0].type_name == "linux"
        assert records[0].offset == fixtures.BASE_LBA * 512
        assert records[0].length == 16 * 512
        assert records[1].type_name == "fat32-lba"
        assert records[1].offset == (fixtures.BASE_LBA + 16) * 512
        # Every record's end is inside the image: that is what "in bounds" means.
        for record in records:
            assert record.end <= len(image)

    def test_the_bootable_flag_is_carried(self, tmp_path: Path) -> None:
        image = fixtures.mbr_image([(fixtures.BASE_LBA, 8, 0x83)], bootable=True)
        _scheme, records = decode(tmp_path, image)

        assert records[0].bootable is True

    def test_an_unknown_type_is_named_by_id_not_guessed(self, tmp_path: Path) -> None:
        image = fixtures.mbr_image([(fixtures.BASE_LBA, 8, 0x7F)])
        _scheme, records = decode(tmp_path, image)

        assert records[0].type_name == "raw-0x7f"
        assert records[0].type_id == "0x7f"

    def test_an_extended_chain_is_followed(self, tmp_path: Path) -> None:
        # The extended container starts after the primary, so the logical
        # partition can sit inside it (its start is relative to the EBR sector).
        image = fixtures.mbr_image(
            [(fixtures.BASE_LBA, 16, 0x83)],
            logical=[(fixtures.BASE_LBA + 32, 8, 0x83)],
            extended_start=fixtures.BASE_LBA + 16,
        )
        _scheme, records = decode(tmp_path, image)

        assert len(records) == 2
        logical = records[1]
        assert logical.logical is True
        assert logical.offset == (fixtures.BASE_LBA + 32) * 512
        assert logical.details["ebr_offset"]
        # The extended container itself is traversed, never emitted.
        assert all(record.type_name != "extended" for record in records)

    def test_a_table_with_no_entries_is_refused(self, tmp_path: Path) -> None:
        image = fixtures.mbr_image([])
        with pytest.raises(PartitionError, match="no non-empty partition"):
            decode(tmp_path, image)

    def test_a_protective_mbr_without_a_gpt_is_refused(self, tmp_path: Path) -> None:
        image = fixtures.mbr_image([(1, 8, 0xEE)])
        with pytest.raises(PartitionError, match="no GPT header"):
            decode(tmp_path, image)


class TestGpt:
    def test_entries_become_records_with_labels_and_guids(self, tmp_path: Path) -> None:
        image = fixtures.gpt_image(
            [
                (fixtures.BASE_LBA, 16, fixtures.LINUX_GUID, "rootfs-a"),
                (fixtures.BASE_LBA + 16, 16, fixtures.LINUX_GUID, "rootfs-b"),
            ]
        )
        scheme, records = decode(tmp_path, image)

        assert scheme == SCHEME_GPT
        assert [record.label for record in records] == ["rootfs-a", "rootfs-b"]
        assert all(record.type_name == "linux-filesystem" for record in records)
        assert records[0].offset == fixtures.BASE_LBA * 512
        assert records[1].offset == (fixtures.BASE_LBA + 16) * 512
        for record in records:
            assert record.end <= len(image)

    def test_a_gpt_type_outside_the_known_set_is_reported_by_guid(self, tmp_path: Path) -> None:
        image = fixtures.gpt_image([(fixtures.BASE_LBA, 8, fixtures.UNKNOWN_GUID, "x")])
        _scheme, records = decode(tmp_path, image)

        assert records[0].type_name == fixtures.UNKNOWN_GUID
        assert records[0].type_id == fixtures.UNKNOWN_GUID

    def test_a_corrupt_header_crc_is_refused(self, tmp_path: Path) -> None:
        image = bytearray(fixtures.gpt_image([(fixtures.BASE_LBA, 8, fixtures.LINUX_GUID, "r")]))
        image[512 + 24] ^= 0xFF  # a byte inside the CRC-covered header
        with pytest.raises(PartitionError, match="header CRC32"):
            decode(tmp_path, bytes(image))

    def test_a_corrupt_entry_crc_is_refused(self, tmp_path: Path) -> None:
        image = bytearray(fixtures.gpt_image([(fixtures.BASE_LBA, 8, fixtures.LINUX_GUID, "r")]))
        entry_offset = 2 * 512 + 56  # the first entry's name field
        image[entry_offset] ^= 0xFF
        with pytest.raises(PartitionError, match="entry-array CRC32"):
            decode(tmp_path, bytes(image))

    def test_an_entry_array_past_the_end_is_refused(self, tmp_path: Path) -> None:
        image = bytearray(fixtures.gpt_image([(fixtures.BASE_LBA, 8, fixtures.LINUX_GUID, "r")]))
        # Claim the entry array lives far beyond the image, and re-seal the header.
        struct.pack_into("<Q", image, 512 + 72, 4096)
        fixtures.reseal_gpt_header(image)
        with pytest.raises(PartitionError, match="runs past the end"):
            decode(tmp_path, bytes(image))

    def test_an_entry_that_ends_before_it_starts_is_refused(self, tmp_path: Path) -> None:
        image = bytearray(fixtures.gpt_image([(fixtures.BASE_LBA, 8, fixtures.LINUX_GUID, "r")]))
        struct.pack_into("<Q", image, 2 * 512 + 40, 1)  # last LBA below first LBA
        fixtures.reseal_gpt_entries(image)
        with pytest.raises(PartitionError, match="ends before it starts"):
            decode(tmp_path, bytes(image))


class TestBounds:
    def test_a_partition_past_the_end_of_a_truncated_image_is_refused(self, tmp_path: Path) -> None:
        # A partition that starts inside the image and ends past the cut: this is
        # the truncation case, not the "starts outside" case.
        image = fixtures.mbr_image([(1024, 3000, 0x83)])
        truncated = image[: int(len(image) * 0.6)]

        with pytest.raises(PartitionError, match="truncated"):
            decode(tmp_path, truncated, name="truncated.img")

    def test_a_partition_starting_outside_the_image_is_refused(self, tmp_path: Path) -> None:
        image = fixtures.mbr_image([(fixtures.DISK_SECTORS + 10_000, 8, 0x83)])

        with pytest.raises(PartitionError, match="outside"):
            decode(tmp_path, image)


class TestImageMap:
    def test_partition_nodes_carry_offsets_parents_and_the_byte_coordinate_system(
        self, tmp_path: Path
    ) -> None:
        image = fixtures.mbr_image(
            [(fixtures.BASE_LBA, 16, 0x83), (fixtures.BASE_LBA + 16, 8, 0x83)]
        )
        path = tmp_path / "disk.img"
        path.write_bytes(image)
        reader = open_bounded(path)
        builder = ImageMapBuilder()
        image_map = builder.start(reader, "d" * 64, "disk")
        nodes = builder.add_partitions(reader)

        assert image_map.nodes[0].format == "disk"
        assert image_map.nodes[0].details["partition_scheme"] == SCHEME_MBR
        assert len(nodes) == 2
        expected = [(fixtures.BASE_LBA, 16), (fixtures.BASE_LBA + 16, 8)]
        for node, record in zip(nodes, expected, strict=True):
            assert node.parent_id == image_map.root_artifact_id
            assert node.format == "partition"
            assert node.coordinate_system == "container-bytes"
            assert node.offset == record[0] * 512
            assert node.length == record[1] * 512
            assert node.decoder == "ihs-partitions"
            assert node.details["type_name"] == "linux"

    def test_slicing_a_partition_copies_exactly_its_bytes_and_hashes_them(
        self, tmp_path: Path
    ) -> None:
        image = bytearray(fixtures.mbr_image([(fixtures.BASE_LBA, 16, 0x83)]))
        start = fixtures.BASE_LBA * 512
        image[start : start + 16 * 512] = bytes(range(256)) * 32
        path = tmp_path / "disk.img"
        path.write_bytes(bytes(image))
        reader = open_bounded(path)
        builder = ImageMapBuilder()
        builder.start(reader, "d" * 64, "disk")
        (node,) = builder.add_partitions(reader)

        sliced = builder.slice_partition(reader, node, tmp_path / "scratch" / "p1.img")

        assert sliced.read_bytes() == bytes(image)[start : start + 16 * 512]
        assert (
            node.digest_sha256
            == __import__("hashlib").sha256(bytes(image)[start : start + 16 * 512]).hexdigest()
        )

    def test_slicing_refuses_a_node_that_is_not_a_partition(self, tmp_path: Path) -> None:
        path = tmp_path / "disk.img"
        path.write_bytes(fixtures.mbr_image([(fixtures.BASE_LBA, 8, 0x83)]))
        reader = open_bounded(path)
        builder = ImageMapBuilder()
        image_map = builder.start(reader, "d" * 64, "disk")

        with pytest.raises(ImageMapError, match="not a partition"):
            builder.slice_partition(reader, image_map.nodes[0], tmp_path / "x.img")
