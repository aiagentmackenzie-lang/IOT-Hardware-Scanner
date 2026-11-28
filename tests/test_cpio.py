"""CPIO archives: the layout, the traps, and the extraction (slice 3A, part 3).

Each case here fails for a reason a reader could plausibly get wrong: a
zero-length hard link read as an empty file, an ``odc`` archive parsed with
``newc`` padding, a trailer that is missing rather than merely last, a name that
would write outside the extraction root, a checksum that nobody checked.

None of these need a container runtime. That is the point of the slice: an
initramfs is decoded in-process, so a firmware class that used to require the
pinned worker can now be qualified on any host.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cpio_fixtures
from cpio_fixtures import CRC, ODC, Member, build, hardlink_pair, initramfs

from iot_hardware_scanner.scanner.bounded_reader import open_bounded
from iot_hardware_scanner.scanner.cpio import (
    CPIO_BINARY,
    CPIO_CRC,
    CPIO_NEWC,
    CPIO_ODC,
    CpioError,
    decode_cpio,
    detect_cpio_format,
    extract_cpio,
    iter_member_data,
    safe_relative_name,
)

# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────


def decoded(tmp_path: Path, payload: bytes, **kwargs: object):
    """Write ``payload`` and decode it, the way the scan does."""
    path = tmp_path / "image.cpio"
    path.write_bytes(payload)
    return decode_cpio(open_bounded(path), **kwargs)  # type: ignore[arg-type]


def extracted(tmp_path: Path, payload: bytes):
    """Decode and materialise one archive into ``tmp_path/out``."""
    path = tmp_path / "image.cpio"
    path.write_bytes(payload)
    reader = open_bounded(path)
    archive = decode_cpio(reader)
    return archive, extract_cpio(reader, archive, tmp_path / "out")


def names(archive) -> list[str]:
    return archive.member_names


# ──────────────────────────────────────────────
# Format identification
# ──────────────────────────────────────────────


@pytest.mark.parametrize(
    ("magic", "expected"),
    [
        (b"070701", CPIO_NEWC),
        (b"070702", CPIO_CRC),
        (b"070707", CPIO_ODC),
        (b"\xc7\x71", CPIO_BINARY),
        (b"hsqs", None),
        (b"\x1f\x8b\x08", None),
    ],
)
def test_each_magic_is_named_and_a_binary_archive_is_not_odc(magic, expected) -> None:
    """The binary magic is decimal 070707 stored as a word, not the text."""
    assert detect_cpio_format(magic) == expected


def test_a_binary_archive_is_refused_by_name(tmp_path: Path) -> None:
    path = tmp_path / "image.cpio"
    path.write_bytes(b"\xc7\x71" + b"\x00" * 24)
    with pytest.raises(CpioError, match="binary CPIO archive"):
        decode_cpio(open_bounded(path))


# ──────────────────────────────────────────────
# newc: the layout
# ──────────────────────────────────────────────


def test_newc_records_carry_their_own_offsets_and_metadata(tmp_path: Path) -> None:
    archive = decoded(tmp_path, initramfs())

    assert archive.format == CPIO_NEWC
    assert names(archive) == [
        ".",
        "etc",
        "etc/passwd",
        "etc/shadow",
        "bin",
        "bin/sh",
        "bin/busybox.sh",
    ]
    shadow = archive.members[3]
    assert shadow.kind == "file"
    assert shadow.mode == 0o100600
    assert shadow.data_length == len(b"root:*:19000:0:99999:7:::\n")
    # 110 header bytes + name, padded so the data starts on a 4-byte boundary.
    unpadded = 110 + len("etc/shadow") + 1
    assert shadow.data_offset == shadow.header_offset + unpadded + (-unpadded % 4)
    assert archive.members[0].kind == "dir"
    assert archive.members[0].nlink == 3


def test_newc_pads_the_name_and_the_data_to_a_four_byte_boundary(tmp_path: Path) -> None:
    archive = decoded(
        tmp_path,
        build([Member(name="a", data=b"xyz"), Member(name="bbbb", data=b"12345678")]),
    )
    first, second = archive.members
    # 110 + 2 name bytes -> padded to 112; data is 3 bytes -> padded to 4.
    assert first.data_offset == 112
    assert second.header_offset == 116
    assert second.data_offset == 116 + 110 + 5 + (-(110 + 5) % 4)


# ──────────────────────────────────────────────
# odc: no padding, octal, and a wider mtime
# ──────────────────────────────────────────────


def test_odc_is_read_without_padding_and_its_own_field_widths(tmp_path: Path) -> None:
    """An ``odc`` archive read as ``newc`` produces names full of garbage."""
    archive = decoded(
        tmp_path,
        build(
            [Member(name="etc", mode=0o040755), Member(name="etc/hosts", data=b"127.0.0.1\n")],
            archive_format=ODC,
        ),
    )

    assert archive.format == CPIO_ODC
    assert names(archive) == ["etc", "etc/hosts"]
    first, second = archive.members
    # No padding at all: the next header starts where the name ended.
    assert first.data_offset == 76 + 4
    assert second.header_offset == 76 + 4
    # odc writes mode as six octal digits; the permission bits must survive.
    assert first.mode == 0o040755


def test_odc_mtime_uses_its_eleven_digit_field(tmp_path: Path) -> None:
    """The namesize field sits at byte 59, not where newc puts it."""
    mtime = 4_000_000_000
    archive = decoded(
        tmp_path,
        build([Member(name="late", data=b"x", mtime=mtime)], archive_format=ODC),
    )
    assert archive.members[0].mtime == mtime
    assert archive.members[0].name == "late"


def test_a_newc_record_inside_an_odc_archive_is_refused(tmp_path: Path) -> None:
    """Mixed magics mean the offsets cannot all be right, so the walk stops."""
    payload = build([Member(name="etc", mode=0o040755)], archive_format=ODC, trailer=False)
    payload += cpio_fixtures.build([Member(name="etc/hosts", data=b"x")])
    with pytest.raises(CpioError, match="not the odc magic"):
        decoded(tmp_path, payload)


# ──────────────────────────────────────────────
# The trailer, truncation and declared ranges
# ──────────────────────────────────────────────


def test_a_missing_trailer_is_a_truncated_archive(tmp_path: Path) -> None:
    with pytest.raises(CpioError, match="without a TRAILER"):
        decoded(tmp_path, build([Member(name="etc/passwd")], trailer=False))


def test_a_data_range_past_the_end_names_the_member(tmp_path: Path) -> None:
    """The header is intact and the trailer follows; the *data* it declares does not."""
    payload = build([Member(name="etc/passwd", data=b"short")])
    # ``filesize`` is the seventh field of a ``newc`` header: bytes 54..62.
    forged = payload[:54] + b"00001000" + payload[62:]
    with pytest.raises(CpioError, match="etc/passwd"):
        decoded(tmp_path, forged)


def test_a_truncated_name_field_is_refused(tmp_path: Path) -> None:
    payload = build([Member(name="a-rather-long-name", data=b"x")])
    # ``namesize`` is the twelfth field: bytes 94..102. Claim more than exists.
    forged = payload[:94] + b"00010000" + payload[102:]
    with pytest.raises(CpioError, match="runs past the input"):
        decoded(tmp_path, forged)


def test_trailing_block_padding_is_reported_not_decoded(tmp_path: Path) -> None:
    archive = decoded(tmp_path, initramfs(trailing=b"\x00" * 512))
    assert archive.trailing_bytes == 512
    assert archive.incomplete is False
    assert "block padding" in archive.diagnostics[0]


def test_a_second_archive_makes_the_stage_incomplete(tmp_path: Path) -> None:
    """A concatenated initramfs is two proposed states; only the first is read."""
    archive = decoded(tmp_path, initramfs(trailing=initramfs()))
    assert archive.incomplete is True
    assert "a second archive follows" in archive.diagnostics[0]


# ──────────────────────────────────────────────
# Names are data that become paths
# ──────────────────────────────────────────────


@pytest.mark.parametrize(
    "name",
    ["../etc/shadow", "/etc/shadow", "etc/../../shadow", "a/../../b"],
)
def test_a_name_that_leaves_the_root_refuses_the_archive(tmp_path: Path, name: str) -> None:
    with pytest.raises(CpioError, match=r"leaves the extraction root|absolute path"):
        decoded(tmp_path, build([Member(name=name, data=b"x")]))


def test_a_nul_inside_a_name_is_refused() -> None:
    with pytest.raises(CpioError, match="NUL"):
        safe_relative_name("etc/sha\x00dow")


@pytest.mark.parametrize(
    ("raw", "clean"),
    [
        ("./etc/shadow", "etc/shadow"),
        ("etc//shadow", "etc/shadow"),
        ("./", ""),
        ("etc/./x", "etc/x"),
    ],
)
def test_the_root_spelling_and_repeated_slashes_are_normalised(raw: str, clean: str) -> None:
    assert safe_relative_name(raw) == clean


# ──────────────────────────────────────────────
# Hard links: one file, several names
# ──────────────────────────────────────────────


def test_a_hard_link_is_not_an_empty_file(tmp_path: Path) -> None:
    """The whole point: the zero-length member carries no bytes, the group does."""
    payload = build(hardlink_pair("etc/shadow", "var/shadow", b"root::0:0:99999:7:::\n", ino=7))
    archive, extraction = extracted(tmp_path, payload)

    assert [member.data_length for member in archive.members] == [0, 21]
    shadow = extraction.rootfs / "etc/shadow"
    linked = extraction.rootfs / "var/shadow"
    assert shadow.read_bytes() == b"root::0:0:99999:7:::\n"
    # A real link, not a copy and not an empty file: same inode, same bytes.
    assert linked.stat().st_ino == shadow.stat().st_ino
    entries = {entry["path"]: entry for entry in extraction.entries}
    assert entries["var/shadow"]["kind"] == "hardlink"
    assert entries["var/shadow"]["link_target"] == "etc/shadow"
    assert entries["var/shadow"]["sha256"] == entries["etc/shadow"]["sha256"]
    assert entries["var/shadow"]["size"] == 21


def test_a_group_with_no_carrier_is_a_set_of_genuinely_empty_files(tmp_path: Path) -> None:
    """An empty file is a fact; inventing content for it would not be one."""
    payload = build(
        [
            Member(name="a", data=b"", ino=9, nlink=2),
            Member(name="b", data=b"", ino=9, nlink=2),
        ]
    )
    _archive, extraction = extracted(tmp_path, payload)
    assert (extraction.rootfs / "a").read_bytes() == b""
    assert (extraction.rootfs / "b").read_bytes() == b""
    assert {entry["kind"] for entry in extraction.entries} == {"file"}


# ──────────────────────────────────────────────
# Kinds that are recorded, not materialised
# ──────────────────────────────────────────────


def test_a_symlink_is_recorded_with_its_target_and_never_followed(tmp_path: Path) -> None:
    payload = build(
        [
            Member(name="etc", mode=cpio_fixtures.S_IFDIR | 0o755),
            Member(
                name="etc/localtime",
                mode=cpio_fixtures.S_IFLNK | 0o777,
                data=b"/usr/share/zoneinfo/UTC",
            ),
        ]
    )
    _archive, extraction = extracted(tmp_path, payload)
    entry = next(item for item in extraction.entries if item["path"] == "etc/localtime")
    assert entry["kind"] == "symlink"
    assert entry["link_target"] == "/usr/share/zoneinfo/UTC"
    assert not (extraction.rootfs / "etc/localtime").exists()
    assert any("symlink(s) recorded as metadata only" in note for note in extraction.omissions)


def test_a_device_node_is_recorded_with_its_numbers_and_not_created(tmp_path: Path) -> None:
    payload = build(
        [
            Member(
                name="dev/console",
                mode=cpio_fixtures.S_IFCHR | 0o600,
                rdev_major=5,
                rdev_minor=1,
            )
        ]
    )
    _archive, extraction = extracted(tmp_path, payload)
    entry = next(item for item in extraction.entries if item["path"] == "dev/console")
    assert entry["kind"] == "char"
    assert entry["rdev"] == "5:1"
    assert not (extraction.rootfs / "dev/console").exists()


# ──────────────────────────────────────────────
# crc: the check field is checked
# ──────────────────────────────────────────────


def test_crc_archives_have_their_checksum_verified(tmp_path: Path) -> None:
    """Three records carry data (the fourth file is a hard link: no bytes of its own)."""
    archive, extraction = extracted(tmp_path, initramfs(archive_format=CRC))
    assert archive.format == CPIO_CRC
    assert extraction.checks_verified == 3


def test_a_failing_checksum_refuses_the_member(tmp_path: Path) -> None:
    good = Member(name="etc/shadow", data=b"root:*:0:0:99999:7:::\n")
    forged = cpio_fixtures.with_check(good, forged=good.check or 0xDEADBEEF)
    payload = build([cpio_fixtures.with_check(good, forged=1)], archive_format=CRC)
    path = tmp_path / "image.cpio"
    path.write_bytes(payload)
    reader = open_bounded(path)
    archive = decode_cpio(reader)
    with pytest.raises(CpioError, match="fails its own checksum"):
        extract_cpio(reader, archive, tmp_path / "out")
    assert forged.check is not None


# ──────────────────────────────────────────────
# Budgets
# ──────────────────────────────────────────────


def test_the_member_budget_stops_a_wide_archive(tmp_path: Path) -> None:
    payload = build([Member(name=f"f{index}") for index in range(5)])
    with pytest.raises(CpioError, match="more than 3"):
        decoded(tmp_path, payload, max_members=3)


def test_the_data_budget_stops_a_large_archive(tmp_path: Path) -> None:
    payload = build([Member(name="blob", data=b"x" * 4096)])
    with pytest.raises(CpioError, match="decoded-data budget"):
        decoded(tmp_path, payload, max_data_bytes=1024)


# ──────────────────────────────────────────────
# Extraction details
# ──────────────────────────────────────────────


def test_the_archive_mode_is_applied_and_hashed(tmp_path: Path) -> None:
    archive, extraction = extracted(tmp_path, initramfs())
    shadow = extraction.rootfs / "etc/shadow"
    assert oct(os.stat(shadow).st_mode & 0o777) == "0o600"
    entry = next(item for item in extraction.entries if item["path"] == "etc/shadow")
    assert entry["sha256"] == __import__("hashlib").sha256(shadow.read_bytes()).hexdigest()
    assert entry["metadata_source"] == "image"
    assert entry["uid"] == 0
    assert archive.members[3].uid == 0


def test_the_manifest_is_written_where_the_pipeline_reads_it(tmp_path: Path) -> None:
    _archive, extraction = extracted(tmp_path, initramfs())
    manifest = (tmp_path / "out" / "extract-manifest.json").read_text()
    assert '"cpio_format": "newc"' in manifest
    assert '"worker": null' in manifest
    assert extraction.metadata["etc/passwd"]["kind"] == "file"


def test_a_duplicate_name_is_reported_rather_than_resolved_silently(tmp_path: Path) -> None:
    payload = build(
        [
            Member(name="etc/motd", data=b"first\n", ino=1),
            Member(name="etc/motd", data=b"second\n", ino=2),
        ]
    )
    archive, extraction = extracted(tmp_path, payload)
    assert any("appears more than once" in note for note in archive.diagnostics)
    # The later record is what a mounted filesystem would show.
    assert (extraction.rootfs / "etc/motd").read_bytes() == b"second\n"
    assert len([entry for entry in extraction.entries if entry["path"] == "etc/motd"]) == 2


def test_member_data_streams_in_bounded_windows(tmp_path: Path) -> None:
    payload = build([Member(name="blob", data=b"abcdef")])
    path = tmp_path / "image.cpio"
    path.write_bytes(payload)
    reader = open_bounded(path)
    archive = decode_cpio(reader)
    assert b"".join(iter_member_data(reader, archive.members[0])) == b"abcdef"
    empty = decode_cpio(open_bounded(path))  # a second walk is independent
    assert empty.members[0].data_length == 6


# ──────────────────────────────────────────────
# The map: coordinates and digests
# ──────────────────────────────────────────────


def test_the_map_gives_every_member_a_byte_range_and_a_digest(tmp_path: Path) -> None:
    from hashlib import sha256

    from iot_hardware_scanner.scanner.image_map import ImageMapBuilder

    raw = initramfs()
    plain = tmp_path / "plain.cpio"
    plain.write_bytes(raw)

    builder = ImageMapBuilder()
    reader = open_bounded(plain)
    image_map = builder.start(reader, "digest", "initramfs.cpio")
    assert image_map.nodes[0].format == "cpio"
    archive = builder.add_cpio_members(
        reader, image_map.nodes[0], max_members=100, max_data_bytes=1 << 20
    )
    extraction = builder.extract_cpio_members(
        reader, image_map.nodes[0], archive, tmp_path / "out", max_data_bytes=1 << 20
    )

    nodes = {node.locator: node for node in image_map.nodes[1:]}
    shadow = nodes["etc/shadow"]
    shadow_bytes = b"root:*:19000:0:99999:7:::\n"
    assert shadow.coordinate_system == "container-bytes"
    assert plain.read_bytes()[shadow.offset : shadow.offset + shadow.length] == shadow_bytes
    assert shadow.digest_sha256 == sha256(shadow_bytes).hexdigest()
    assert nodes["etc"].format == "dir"
    # Three records carry bytes; the fourth name is a hard link to bin/sh.
    assert extraction.files == 3
    assert image_map.nodes[0].extent_bytes == archive.archive_length
