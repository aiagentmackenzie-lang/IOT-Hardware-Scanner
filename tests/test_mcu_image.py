"""Slice 3C — three encodings, one address space, one payload digest.

The plan's acceptance rows:

* equivalent generated payloads in all three encodings yield the same address
  map and payload hash;
* a gap stays unobserved;
* a bare-metal scan completes with a profile appropriate to an image without a
  Linux root filesystem.

The fixtures here are *generated*, so the expected map is known before the
decoder runs, and each oracle is independent of the code under test: the
encoders write the formats by hand from their published layout.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from mcu_fixtures import (
    BASE,
    FAMILY,
    SECOND,
    encode_ihex,
    encode_srec,
    encode_uf2,
    ihex_record,
    payload_ranges,
    srec_record,
)

from iot_hardware_scanner.scanner.bounded_reader import open_bounded
from iot_hardware_scanner.scanner.mcu_image import (
    FORMAT_INTEL_HEX,
    FORMAT_SREC,
    FORMAT_UF2,
    McuFormatError,
    analyse_mcu,
    format_hint,
    identify_mcu_format,
)

ENCODERS = {
    FORMAT_INTEL_HEX: encode_ihex,
    FORMAT_SREC: encode_srec,
    FORMAT_UF2: encode_uf2,
}


def analyse(tmp_path: Path, mcu_format: str, blob: bytes, **kwargs):
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / f"image-{mcu_format}.bin"
    path.write_bytes(blob)
    return analyse_mcu(
        open_bounded(path),
        format=mcu_format,
        locator=path.name,
        digest="d" * 64,
        **kwargs,
    )


# ──────────────────────────────────────────────
# The acceptance rows
# ──────────────────────────────────────────────


@pytest.mark.parametrize("mcu_format", sorted(ENCODERS))
def test_recognition_is_by_content_not_by_name(tmp_path: Path, mcu_format: str) -> None:
    blob = ENCODERS[mcu_format](payload_ranges())

    assert identify_mcu_format(blob[:4096]) == mcu_format
    # The name is not needed: a file with no suffix is still recognised.
    unnamed = tmp_path / "board"
    unnamed.write_bytes(blob)
    assert identify_mcu_format(open_bounded(unnamed).read_head(4096)) == mcu_format


@pytest.mark.parametrize("mcu_format", sorted(ENCODERS))
def test_equivalent_payloads_yield_the_same_address_map_and_digest(
    tmp_path: Path, mcu_format: str
) -> None:
    analysis = analyse(tmp_path, mcu_format, ENCODERS[mcu_format](payload_ranges()))

    expected = payload_ranges()
    assert [(item.start, item.length) for item in analysis.ranges] == [
        (address, len(payload)) for address, payload in expected
    ]
    assert analysis.payload_bytes == sum(len(payload) for _address, payload in expected)
    assert analysis.declared_bytes == analysis.payload_bytes

    # The digest is the contract: it does not depend on the encoding at all.
    baseline = analyse(
        tmp_path / "baseline", FORMAT_INTEL_HEX, encode_ihex(payload_ranges())
    ).payload_sha256
    assert analysis.payload_sha256 == baseline


def test_all_three_encodings_agree(tmp_path: Path) -> None:
    """One payload, three encodings: one map, one digest, one gap."""
    analyses = {
        name: analyse(tmp_path / name, name, encoder(payload_ranges()))
        for name, encoder in ENCODERS.items()
    }
    digests = {item.payload_sha256 for item in analyses.values()}
    ranges = {
        tuple((segment.start, segment.length) for segment in item.ranges)
        for item in analyses.values()
    }
    gaps = {tuple((gap.start, gap.length) for gap in item.gaps) for item in analyses.values()}

    assert len(digests) == 1, digests
    assert len(ranges) == 1, ranges
    assert len(gaps) == 1, gaps
    # The payload each encoding carries is the same bytes in the same places.
    for name, item in analyses.items():
        assert [payload for _start, payload in item.payload_ranges] == [
            payload for _address, payload in payload_ranges()
        ], name


@pytest.mark.parametrize("mcu_format", sorted(ENCODERS))
def test_a_gap_stays_unobserved(tmp_path: Path, mcu_format: str) -> None:
    analysis = analyse(tmp_path, mcu_format, ENCODERS[mcu_format](payload_ranges()))

    assert len(analysis.gaps) == 1
    gap = analysis.gaps[0]
    assert (gap.start, gap.end) == (BASE + 300, SECOND)
    assert gap.as_dict()["observed"] is False
    # No range covers the hole, and the payload count excludes it.
    for segment in analysis.ranges:
        assert not (segment.start <= gap.start < segment.end)
    assert analysis.payload_bytes == 500
    # Nothing zero-filled the hole into the digest: the digest of the same
    # payload with the hole filled in is a different digest.
    filled = analyse(
        tmp_path / "filled",
        FORMAT_INTEL_HEX,
        encode_ihex([(BASE, payload_ranges()[0][1] + b"\x00" * 0x200 + payload_ranges()[1][1])]),
    )
    assert filled.payload_sha256 != analysis.payload_sha256


def test_the_digest_is_over_addresses_not_record_boundaries(tmp_path: Path) -> None:
    """Re-chunking the same payload must not change the digest."""
    address, payload = BASE, bytes(range(256)) * 2
    coarse = analyse(
        tmp_path / "coarse", FORMAT_INTEL_HEX, encode_ihex([(address, payload)], chunk=128)
    )
    fine = analyse(tmp_path / "fine", FORMAT_INTEL_HEX, encode_ihex([(address, payload)], chunk=16))

    assert coarse.payload_sha256 == fine.payload_sha256
    assert coarse.ranges[0].length == fine.ranges[0].length == len(payload)
    assert coarse.records != fine.records  # the encodings really differ


# ──────────────────────────────────────────────
# Structural diagnostics
# ──────────────────────────────────────────────


def test_a_conflicting_rewrite_is_named_and_the_digest_stays_deterministic(
    tmp_path: Path,
) -> None:
    first = b"\x11" * 32
    second = b"\x22" * 32
    lines = [
        ihex_record(0x04, 0, (BASE >> 16).to_bytes(2, "big")),
        ihex_record(0x00, 0, first),
        ihex_record(0x00, 0, second),
        ihex_record(0x01, 0, b""),
    ]
    analysis = analyse(tmp_path, FORMAT_INTEL_HEX, ("\n".join(lines) + "\n").encode())

    conflict = [item for item in analysis.diagnostics if item.kind == "conflict"]
    assert len(conflict) == 1
    assert conflict[0].address == BASE
    assert conflict[0].length == 32
    assert conflict[0].records == [2, 3]
    # First declaration in address order wins, so the result is reproducible.
    assert analysis.payload_ranges[0][1] == first
    again = analyse(tmp_path / "again", FORMAT_INTEL_HEX, ("\n".join(lines) + "\n").encode())
    assert again.payload_sha256 == analysis.payload_sha256


def test_an_identical_rewrite_is_a_duplicate_not_a_conflict(tmp_path: Path) -> None:
    block = b"\x33" * 32
    lines = [
        ihex_record(0x04, 0, (BASE >> 16).to_bytes(2, "big")),
        ihex_record(0x00, 0, block),
        ihex_record(0x00, 0, block),
        ihex_record(0x01, 0, b""),
    ]
    analysis = analyse(tmp_path, FORMAT_INTEL_HEX, ("\n".join(lines) + "\n").encode())

    kinds = [item.kind for item in analysis.diagnostics]
    assert "duplicate" in kinds
    assert "conflict" not in kinds
    assert analysis.payload_bytes == len(block)
    assert analysis.declared_bytes == 2 * len(block)


def test_out_of_order_records_are_reported_but_still_mapped(tmp_path: Path) -> None:
    lines = [
        ihex_record(0x04, 0, (BASE >> 16).to_bytes(2, "big")),
        ihex_record(0x00, 0x20, b"\xaa" * 8),
        ihex_record(0x00, 0x00, b"\xbb" * 8),
        ihex_record(0x01, 0, b""),
    ]
    analysis = analyse(tmp_path, FORMAT_INTEL_HEX, ("\n".join(lines) + "\n").encode())

    assert [item.kind for item in analysis.diagnostics].count("out-of-order") == 1
    assert [(item.start, item.length) for item in analysis.ranges] == [
        (BASE, 8),
        (BASE + 0x20, 8),
    ]


def test_a_missing_eof_makes_the_record_stream_unverified(tmp_path: Path) -> None:
    lines = [
        ihex_record(0x04, 0, (BASE >> 16).to_bytes(2, "big")),
        ihex_record(0x00, 0, b"\x44" * 16),
    ]
    analysis = analyse(tmp_path, FORMAT_INTEL_HEX, ("\n".join(lines) + "\n").encode())

    assert "missing-eof" in [item.kind for item in analysis.diagnostics]
    # What was present is still mapped; nothing is invented.
    assert analysis.payload_bytes == 16


def test_srec_declared_count_that_disagrees_is_a_diagnostic(tmp_path: Path) -> None:
    blob = encode_srec([(BASE, b"\x55" * 64)], chunk=32)
    lines = blob.decode().splitlines()
    lines[-2] = srec_record(5, 99, b"", 2)  # declares 99 data records, file has 2
    analysis = analyse(tmp_path, FORMAT_SREC, ("\n".join(lines) + "\n").encode())

    mismatch = [item for item in analysis.diagnostics if item.kind == "record-count-mismatch"]
    assert len(mismatch) == 1
    assert "declares 99" in mismatch[0].detail
    assert analysis.payload_bytes == 64


def test_uf2_missing_block_is_unobserved_not_zero_filled(tmp_path: Path) -> None:
    blob = bytearray(encode_uf2([(BASE, bytes(1000))]))
    # Drop the second 512-byte block by rewriting the stream without it.
    blocks = [bytes(blob[index : index + 512]) for index in range(0, len(blob), 512)]
    assert len(blocks) == 3
    del blocks[1]
    analysis = analyse(tmp_path, FORMAT_UF2, b"".join(blocks))

    missing = [item for item in analysis.diagnostics if item.kind == "missing-block"]
    assert len(missing) == 1
    assert missing[0].records == [1]
    assert analysis.payload_bytes < 1000
    assert len(analysis.gaps) >= 1


def test_uf2_keeps_family_and_target_address(tmp_path: Path) -> None:
    analysis = analyse(tmp_path, FORMAT_UF2, encode_uf2([(BASE, b"\x66" * 476)]))

    assert analysis.family == f"0x{FAMILY:08x}"
    assert analysis.target_address == BASE
    assert analysis.records == 1


def test_srec_and_ihex_keep_the_declared_start_address(tmp_path: Path) -> None:
    for mcu_format, encoder in ((FORMAT_SREC, encode_srec), (FORMAT_INTEL_HEX, encode_ihex)):
        analysis = analyse(tmp_path / mcu_format, mcu_format, encoder([(BASE, b"\x77" * 32)]))
        assert analysis.start_address == BASE
        assert any("start address" in note for note in analysis.notes)


# ──────────────────────────────────────────────
# Malformed input is incomplete work, never a traceback
# ──────────────────────────────────────────────


@pytest.mark.parametrize(
    "mcu_format,blob",
    [
        (FORMAT_INTEL_HEX, b":10000000AABBCC\n"),
        (FORMAT_INTEL_HEX, b":0000000\n"),
        (FORMAT_SREC, b"S3\n"),
        (FORMAT_SREC, b"S30700000000FF\n"),
        (FORMAT_UF2, b"\x00" * 512),
        (FORMAT_UF2, b"\x00" * 100),
    ],
)
def test_a_malformed_artifact_is_a_named_error(
    tmp_path: Path, mcu_format: str, blob: bytes
) -> None:
    with pytest.raises(McuFormatError):
        analyse(tmp_path, mcu_format, blob)


def test_a_bad_checksum_is_named(tmp_path: Path) -> None:
    good = ihex_record(0x00, 0, b"\x88" * 8)
    broken = good[:-2] + "00"
    with pytest.raises(McuFormatError, match="checksum"):
        analyse(tmp_path, FORMAT_INTEL_HEX, broken.encode() + b"\n")


def test_the_payload_budget_stops_the_decode(tmp_path: Path) -> None:
    blob = encode_ihex([(BASE, bytes(4096))])
    with pytest.raises(McuFormatError, match="budget"):
        analyse(tmp_path, FORMAT_INTEL_HEX, blob, max_payload_bytes=1024)


def test_the_record_ceiling_stops_the_decode(tmp_path: Path) -> None:
    blob = encode_ihex([(BASE, bytes(4096))], chunk=16)
    with pytest.raises(McuFormatError, match="ceiling"):
        analyse(tmp_path, FORMAT_INTEL_HEX, blob, max_records=4)


def test_an_address_that_overflows_32_bits_is_refused(tmp_path: Path) -> None:
    lines = [
        ihex_record(0x04, 0, b"\xff\xff"),
        ihex_record(0x00, 0xFFF0, b"\x99" * 32),
        ihex_record(0x01, 0, b""),
    ]
    with pytest.raises(McuFormatError, match="32-bit"):
        analyse(tmp_path, FORMAT_INTEL_HEX, ("\n".join(lines) + "\n").encode())


def test_an_image_with_no_data_records_is_not_an_empty_payload(tmp_path: Path) -> None:
    blob = (ihex_record(0x01, 0, b"") + "\n").encode()
    with pytest.raises(McuFormatError, match="no data records"):
        analyse(tmp_path, FORMAT_INTEL_HEX, blob)


# ──────────────────────────────────────────────
# Property: whatever the chunking, the bytes survive
# ──────────────────────────────────────────────


@given(
    payload=st.binary(min_size=1, max_size=512),
    chunk=st.integers(min_value=1, max_value=32),
)
@settings(max_examples=25, deadline=None)
def test_intel_hex_round_trips_any_payload(payload: bytes, chunk: int) -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "board.hex"
        path.write_bytes(encode_ihex([(BASE, payload)], chunk=chunk))
        analysis = analyse_mcu(
            open_bounded(path),
            format=FORMAT_INTEL_HEX,
            locator="board.hex",
            digest="d" * 64,
        )
    assert analysis.payload_ranges[0][1] == payload


@given(payload=st.binary(min_size=1, max_size=512), chunk=st.integers(min_value=1, max_value=32))
@settings(max_examples=25, deadline=None)
def test_srec_round_trips_any_payload(payload: bytes, chunk: int) -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "board.s19"
        path.write_bytes(encode_srec([(BASE, payload)], chunk=chunk))
        analysis = analyse_mcu(
            open_bounded(path),
            format=FORMAT_SREC,
            locator="board.s19",
            digest="d" * 64,
        )
    assert analysis.payload_ranges[0][1] == payload


def test_extension_hints_only_name_a_decoder() -> None:
    assert format_hint(".hex") == FORMAT_INTEL_HEX
    assert format_hint(".S19") == FORMAT_SREC
    assert format_hint(".uf2") == FORMAT_UF2
    assert format_hint(".bin") is None
    # A hint is not evidence: these bytes are not a record stream.
    assert identify_mcu_format(b"\x00\x01\x02\x03") is None
