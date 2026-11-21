"""Bounded reader: original offsets, budgets and truncation that is stated."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from iot_hardware_scanner.scanner.bounded_reader import (
    BoundedReadLimitError,
    BudgetedStream,
    file_size,
    open_bounded,
)


@pytest.fixture
def data_file(tmp_path: Path) -> Path:
    path = tmp_path / "artifact.bin"
    path.write_bytes(bytes(range(256)) * 8)  # 2048 deterministic bytes
    return path


class TestWindows:
    def test_windows_cover_the_input_and_keep_offsets(self, data_file: Path) -> None:
        reader = open_bounded(data_file)
        scan = reader.scan_windows(512)
        assert [w.offset for w in scan.windows] == [0, 512, 1024, 1536]
        assert [w.length for w in scan.windows] == [512, 512, 512, 512]
        assert scan.bytes_read == 2048
        assert not scan.sampled
        assert scan.gaps() == []

    def test_last_window_is_not_padded(self, tmp_path: Path) -> None:
        path = tmp_path / "odd.bin"
        path.write_bytes(b"\x00" * 129)
        scan = open_bounded(path).scan_windows(128)
        assert [(w.offset, w.length) for w in scan.windows] == [(0, 128), (128, 1)]

    def test_budget_truncates_and_reports_the_gap(self, data_file: Path) -> None:
        scan = open_bounded(data_file).scan_windows(512, budget=700)
        assert scan.bytes_read == 512
        assert scan.truncated
        assert scan.sampled
        assert scan.gaps() == [(512, 2048)]
        assert scan.omissions and "1536" in scan.omissions[0]

    def test_stride_keeps_original_coordinates(self, tmp_path: Path) -> None:
        path = tmp_path / "sampled.bin"
        path.write_bytes(bytes(range(256)) * 16)  # 4096 bytes
        scan = open_bounded(path).scan_windows(256, stride=1024)
        assert [w.offset for w in scan.windows] == [0, 1024, 2048, 3072]
        # Windows are never concatenated, so the gaps between them stay visible.
        assert scan.gaps() == [(256, 1024), (1280, 2048), (2304, 3072), (3328, 4096)]

    def test_invalid_window_size_is_refused(self, data_file: Path) -> None:
        with pytest.raises(BoundedReadLimitError):
            open_bounded(data_file).scan_windows(0)

    def test_stride_smaller_than_window_is_refused(self, data_file: Path) -> None:
        with pytest.raises(BoundedReadLimitError):
            open_bounded(data_file).scan_windows(512, stride=100)


class TestRangedReads:
    def test_read_at_past_the_end_is_refused(self, data_file: Path) -> None:
        reader = open_bounded(data_file)
        with pytest.raises(BoundedReadLimitError):
            reader.read_at(2000, 100)
        with pytest.raises(BoundedReadLimitError):
            reader.read_at(-1, 10)

    def test_read_head_is_clipped_to_the_file(self, tmp_path: Path) -> None:
        path = tmp_path / "tiny.bin"
        path.write_bytes(b"abc")
        assert open_bounded(path).read_head(4096) == b"abc"

    def test_declared_size_cannot_be_widened(self, data_file: Path) -> None:
        reader = open_bounded(data_file, size=100)
        assert reader.size == 100
        with pytest.raises(BoundedReadLimitError):
            reader.read_at(0, 101)

    def test_read_all_bounded_refuses_rather_than_truncating(self, data_file: Path) -> None:
        reader = open_bounded(data_file)
        with pytest.raises(BoundedReadLimitError):
            reader.read_all_bounded(1024)
        assert len(reader.read_all_bounded(2048)) == 2048


class TestLines:
    def test_lines_carry_numbers_and_byte_offsets(self, tmp_path: Path) -> None:
        path = tmp_path / "text.conf"
        path.write_text("first=1\nsecond=22\nthird=333\n")
        lines = list(open_bounded(path).iter_lines())
        assert [(line.number, line.offset, line.text) for line in lines] == [
            (1, 0, "first=1"),
            (2, 8, "second=22"),
            (3, 18, "third=333"),
        ]

    def test_budget_stops_the_pass(self, tmp_path: Path) -> None:
        path = tmp_path / "big.log"
        path.write_text("".join(f"line-{index:04d}\n" for index in range(1000)))
        lines = list(open_bounded(path).iter_lines(budget=100))
        assert 0 < len(lines) < 1000

    def test_overlong_line_is_not_decoded_but_offsets_stay_exact(self, tmp_path: Path) -> None:
        path = tmp_path / "banner.bin"
        path.write_bytes(b"a" * 300 + b"\n" + b"short\n")
        lines = list(open_bounded(path).iter_lines(max_line=64))
        assert [line.text for line in lines] == ["", "short"]
        assert lines[1].offset == 301

    def test_unterminated_tail_is_yielded(self, tmp_path: Path) -> None:
        path = tmp_path / "tail.txt"
        path.write_bytes(b"no newline at end")
        lines = list(open_bounded(path).iter_lines())
        assert len(lines) == 1
        assert lines[0].text == "no newline at end"

    def test_read_text_bounded_reports_truncation(self, tmp_path: Path) -> None:
        path = tmp_path / "text.txt"
        path.write_text("x" * 100)
        text, truncated = open_bounded(path).read_text_bounded(10)
        assert text == "x" * 10
        assert truncated


class TestBudgetedStream:
    def test_stream_stops_at_the_budget(self) -> None:
        source = io.BufferedReader(io.BytesIO(b"z" * 4096))
        stream = BudgetedStream(source, 2048)
        buffer = bytearray(1024)
        assert stream.readinto(buffer) == 1024
        assert stream.readinto(buffer) == 1024
        with pytest.raises(BoundedReadLimitError):
            stream.readinto(buffer)

    def test_stream_returns_zero_at_eof(self) -> None:
        source = io.BufferedReader(io.BytesIO(b"abc"))
        stream = BudgetedStream(source, 10)
        buffer = bytearray(16)
        assert stream.readinto(buffer) == 3
        assert stream.readinto(buffer) == 0
        assert stream.readable()


def test_file_size_of_a_directory_is_refused(tmp_path: Path) -> None:
    with pytest.raises(OSError):
        file_size(tmp_path)
    path = tmp_path / "f"
    path.write_bytes(b"12345")
    assert file_size(path) == 5
