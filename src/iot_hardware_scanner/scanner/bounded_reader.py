"""Bounded readers — every byte this scanner reads goes through here.

The rule this module exists to enforce: **no ``read()`` of an arbitrary-size
input into memory**. A firmware image is untrusted and often larger than the
machine's RAM, so a detector that says ``handle.read()`` is a denial-of-service
waiting for the first hostile artifact.

What a bound is
---------------
Every call states the maximum number of bytes it may consume. When that budget
runs out the reader stops and *says so*: :class:`BoundedReadLimitError` is raised, or
the pass is returned with ``truncated=True`` and the unread ranges listed. A
truncated read is never silently presented as a complete one.

Coordinate discipline
---------------------
Windows keep their **original offsets** in the underlying file and are yielded
in ascending order. Sampled windows are never concatenated, so a later
histogram or detector can tell a gap from an adjacency. Text lines carry the
byte offset of the line as well as the line number, so a finding can be quoted
back to a physical range.

Deliberate non-goals
--------------------
This module does not decompress, decode a filesystem or interpret a container.
Those live in :mod:`iot_hardware_scanner.scanner.image_map` and
:mod:`iot_hardware_scanner.scanner.extraction_worker`.
"""

from __future__ import annotations

import io
import os
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

#: Default window for a streaming pass over an artifact.
DEFAULT_WINDOW_SIZE = 1024 * 1024
#: Default ceiling for a text file parsed line by line.
DEFAULT_TEXT_BUDGET = 8 * 1024 * 1024
#: A single "line" longer than this is treated as noise, not as a line.
DEFAULT_MAX_LINE = 64 * 1024
#: Chunk size used by the line reader.
_CHUNK = 64 * 1024


class BoundedReadLimitError(Exception):
    """Raised when a reader is asked to exceed its declared budget."""


@dataclass
class SampleWindow:
    """One window of an artifact, with the coordinates it came from."""

    offset: int
    length: int
    data: bytes

    @property
    def end(self) -> int:
        """Exclusive end offset in the original artifact."""
        return self.offset + self.length


@dataclass
class WindowScan:
    """The windows read by one pass, plus what the pass could not cover."""

    windows: list[SampleWindow] = field(default_factory=list)
    bytes_read: int = 0
    input_size: int = 0
    truncated: bool = False
    omissions: list[str] = field(default_factory=list)

    @property
    def sampled(self) -> bool:
        """Whether the pass covered less than the whole artifact."""
        return self.truncated or self.bytes_read < self.input_size

    def gaps(self) -> list[tuple[int, int]]:
        """Half-open ``(start, end)`` ranges that were never read."""
        gaps: list[tuple[int, int]] = []
        cursor = 0
        for window in self.windows:
            if window.offset > cursor:
                gaps.append((cursor, window.offset))
            cursor = max(cursor, window.end)
        if cursor < self.input_size:
            gaps.append((cursor, self.input_size))
        return gaps


@dataclass
class TextLine:
    """One line of text, with the byte offset and line number it came from."""

    number: int
    offset: int
    text: str


class BoundedReader:
    """A read-only file view that cannot be asked for more than it declares.

    The reader re-opens the file for each pass, so it holds no descriptor
    between passes: it is safe over a snapshot that another process made
    read-only before the scan started.
    """

    def __init__(self, path: Path, *, size: int | None = None) -> None:
        self._path = Path(path)
        self._size = os.stat(self._path).st_size if size is None else int(size)

    # ──────────────────────────────────────────
    # Metadata
    # ──────────────────────────────────────────

    @property
    def path(self) -> Path:
        """Path this reader was opened on."""
        return self._path

    @property
    def size(self) -> int:
        """Size of the underlying file in bytes."""
        return self._size

    def exists(self) -> bool:
        """Whether the underlying file is still present."""
        return self._path.is_file()

    # ──────────────────────────────────────────
    # Whole-artifact passes
    # ──────────────────────────────────────────

    def iter_windows(
        self,
        window_size: int = DEFAULT_WINDOW_SIZE,
        *,
        budget: int | None = None,
        stride: int | None = None,
        start: int = 0,
    ) -> Iterator[SampleWindow]:
        """Yield windows in ascending original-offset order from ``start``.

        ``budget`` caps the total number of bytes yielded. ``stride`` skips
        ahead between windows, which is how a sampled pass keeps original
        coordinates instead of joining separate regions into one buffer.
        ``start`` begins a pass at an offset, so a sampled measurement can read
        the middle and the end of a large file without ever holding it.
        """
        if window_size <= 0:
            raise BoundedReadLimitError(f"window size must be positive, got {window_size}")
        if stride is not None and stride < window_size:
            raise BoundedReadLimitError(
                f"stride {stride} must be at least the window size {window_size}"
            )
        step = stride if stride is not None else window_size
        if start < 0 or start > self._size:
            raise BoundedReadLimitError(f"start offset {start} is outside the input")
        available = self._size - start
        remaining = available if budget is None else min(budget, available)
        offset = start
        with self._path.open("rb") as handle:
            while offset < self._size and remaining > 0:
                available = self._size - offset
                if remaining < window_size and available >= window_size:
                    # The budget ran out mid-window. Emitting a short window here
                    # would look like a genuine tail window and skew any
                    # histogram built from these samples, so the pass stops.
                    break
                length = min(window_size, remaining, available)
                handle.seek(offset)
                data = handle.read(length)
                if not data:
                    break
                yield SampleWindow(offset=offset, length=len(data), data=data)
                remaining -= len(data)
                offset += step

    def scan_windows(
        self,
        window_size: int = DEFAULT_WINDOW_SIZE,
        *,
        budget: int | None = None,
        stride: int | None = None,
        start: int = 0,
    ) -> WindowScan:
        """Collect :meth:`iter_windows` into a :class:`WindowScan`."""
        result = WindowScan(input_size=self._size)
        for window in self.iter_windows(window_size, budget=budget, stride=stride, start=start):
            result.windows.append(window)
            result.bytes_read += window.length
        if result.bytes_read < self._size:
            result.truncated = True
            result.omissions.append(
                f"{self._size - result.bytes_read} of {self._size} byte(s) were not read"
            )
        return result

    def read_at(self, offset: int, length: int) -> bytes:
        """Read ``length`` bytes at ``offset``, refusing to leave the file."""
        if offset < 0 or length < 0:
            raise BoundedReadLimitError(f"negative range: offset={offset} length={length}")
        if length > self._size or offset + length > self._size:
            raise BoundedReadLimitError(
                f"range {offset}:{offset + length} exceeds the {self._size}-byte input"
            )
        with self._path.open("rb") as handle:
            handle.seek(offset)
            return handle.read(length)

    def read_head(self, length: int = 4096) -> bytes:
        """Read the first ``length`` bytes (never more than the file holds)."""
        return self.read_at(0, min(length, self._size))

    def read_all_bounded(self, budget: int) -> bytes:
        """Read the whole file only when it is known to fit in ``budget``.

        This is the only whole-file read in the scanner. It exists for small,
        structurally validated inputs (a package database, a config file) and
        raises rather than truncating, because a truncated parse produces a
        wrong answer instead of a short one.
        """
        if self._size > budget:
            raise BoundedReadLimitError(
                f"{self._path.name} is {self._size} bytes, over the {budget}-byte budget"
            )
        return self.read_at(0, self._size)

    # ──────────────────────────────────────────
    # Text passes
    # ──────────────────────────────────────────

    def iter_lines(
        self,
        *,
        budget: int = DEFAULT_TEXT_BUDGET,
        max_line: int = DEFAULT_MAX_LINE,
        encoding: str = "utf-8",
    ) -> Iterator[TextLine]:
        """Yield decoded lines with their line number and byte offset.

        The read stops at ``budget`` bytes. A line longer than ``max_line`` is
        not decoded; it is yielded with empty text so that a binary blob cannot
        turn into one enormous "line". Offsets stay exact either way.
        """
        consumed = 0
        line_no = 0
        line_start = 0
        buffer = b""
        dropped = 0
        with self._path.open("rb") as handle:
            while consumed < budget:
                chunk = handle.read(min(_CHUNK, budget - consumed))
                if not chunk:
                    break
                consumed += len(chunk)
                cursor = 0
                while True:
                    newline = chunk.find(b"\n", cursor)
                    if newline < 0:
                        tail = chunk[cursor:]
                        combined = buffer + tail
                        if len(combined) <= max_line:
                            buffer = combined
                        else:
                            dropped += len(combined) - max_line
                            buffer = combined[:max_line]
                        break
                    part = buffer + chunk[cursor:newline]
                    line_no += 1
                    long_line = bool(dropped) or len(part) > max_line
                    yield TextLine(
                        number=line_no,
                        offset=line_start,
                        text="" if long_line else part.decode(encoding, errors="replace"),
                    )
                    line_start += len(part) + dropped + 1
                    buffer = b""
                    dropped = 0
                    cursor = newline + 1
        if buffer or dropped:
            line_no += 1
            yield TextLine(
                number=line_no,
                offset=line_start,
                text=""
                if dropped or len(buffer) > max_line
                else buffer.decode(encoding, errors="replace"),
            )

    def read_text_bounded(
        self,
        budget: int = DEFAULT_TEXT_BUDGET,
        *,
        encoding: str = "utf-8",
    ) -> tuple[str, bool]:
        """Read up to ``budget`` bytes as text; returns ``(text, truncated)``."""
        data = self.read_head(budget)
        return data.decode(encoding, errors="replace"), self._size > budget


def open_bounded(path: Path, *, size: int | None = None) -> BoundedReader:
    """Open ``path`` for bounded reading.

    ``size`` may be supplied when the caller already knows the length (for
    example from a validated container extent) so that later reads cannot be
    widened by a file that grew underneath.
    """
    return BoundedReader(path, size=size)


class BudgetedStream(io.RawIOBase):
    """A read-only stream that fails once ``budget`` bytes have been consumed.

    Used to bound a subprocess pipe: the extractor stops the worker as soon as
    its output exceeds the declared budget, instead of writing an unbounded
    tree to disk.
    """

    def __init__(self, source: io.BufferedReader, budget: int) -> None:
        self._source = source
        self._budget = budget
        self.consumed = 0

    def readable(self) -> bool:
        """This stream is read-only and readable."""
        return True

    def readinto(self, buffer: bytearray | memoryview) -> int:  # type: ignore[override]
        """Fill ``buffer`` from the worker, refusing to exceed the budget."""
        chunk = self._source.read(min(len(buffer), _CHUNK))
        if not chunk:
            return 0
        if self.consumed + len(chunk) > self._budget:
            raise BoundedReadLimitError(
                f"worker output exceeded its {self._budget}-byte budget "
                f"({self.consumed} bytes already consumed)"
            )
        self.consumed += len(chunk)
        buffer[: len(chunk)] = chunk
        return len(chunk)


def file_size(path: Path) -> int:
    """Size of a regular file, raising ``OSError`` if it is not one."""
    path = Path(path)
    if not path.is_file():
        raise OSError(f"not a regular file: {path}")
    return os.stat(path).st_size
