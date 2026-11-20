"""Entropy analyzer — Phase 3a.

Measures the Shannon entropy of byte distributions over a firmware image.

Units are explicit and fixed: **bits per byte, 0.0-8.0**. A constant run is
0.0, two equally likely symbols are 1.0, and 256 equally frequent byte values
are 8.0. The earlier implementation returned the same number but compared it
against 0-1 thresholds, so an ordinary block of bytes could be announced as
"encrypted".

What entropy does not tell you
------------------------------
Entropy describes how evenly bytes are distributed. Compressed data, encrypted
data, packed executables, JPEGs and any well-mixed binary all look alike. A
high-entropy region is therefore reported as ``high_entropy`` and nothing more:
it is never called encrypted, never called unreadable, and never passes or
fails a security control on its own. Format evidence (a SquashFS or LUKS header,
an operator-supplied manifest) is what identifies a container.

Coordinate discipline
---------------------
Every window keeps its **original** offset and its **true** length. Windows
from sampled files are never concatenated into one buffer, and regions are only
joined across genuinely adjacent windows, so a gap stays a gap. For a 129-byte
input with 128-byte windows the last window is offset 128, length 1, and the
region's exclusive end is 129.
"""

from __future__ import annotations

import logging
import math
from pathlib import Path

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.models import (
    EntropyBlock,
    EntropyProfile,
    EntropyRegion,
)

logger = logging.getLogger(__name__)

#: Smallest window that produces a meaningful measurement.
MIN_BLOCK_SIZE = 16
#: Largest window; beyond this a single window is too coarse to locate anything.
MAX_BLOCK_SIZE = 16 * 1024 * 1024

# Classification bands, in bits/byte. These describe distribution shape only.
_BANDS: tuple[tuple[float, str], ...] = (
    (2.4, "padding"),
    (4.0, "structured"),
    (5.6, "code"),
    (6.8, "mixed"),
    (8.01, "high_entropy"),
)


class EntropyAnalyzer:
    """Measure byte-distribution entropy with explicit units and coordinates."""

    def __init__(self, config: ScannerConfig) -> None:
        self.config = config

    # ──────────────────────────────────────────
    # Validation
    # ──────────────────────────────────────────

    @staticmethod
    def validate_block_size(block_size: int | None) -> None:
        """Reject window sizes that cannot produce a bounded measurement.

        Raises:
            ValueError: when the size is not an integer in the supported range.
        """
        if block_size is None:
            return
        if not isinstance(block_size, int) or isinstance(block_size, bool):
            raise ValueError(f"block size must be an integer, got {block_size!r}")
        if block_size < MIN_BLOCK_SIZE:
            raise ValueError(
                f"block size {block_size} is below the minimum of {MIN_BLOCK_SIZE} bytes"
            )
        if block_size > MAX_BLOCK_SIZE:
            raise ValueError(
                f"block size {block_size} exceeds the maximum of {MAX_BLOCK_SIZE} bytes"
            )

    # ──────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────

    def analyze(self, data: bytes, block_size: int | None = None) -> EntropyProfile:
        """Measure entropy over an in-memory byte string."""
        self.validate_block_size(block_size)
        if block_size is None:
            block_size = self._auto_block_size(len(data))

        if not data:
            return self._empty_profile(Path(""), block_size)

        return self._profile(
            firmware_path=Path(""),
            ranges=[(0, data)],
            block_size=block_size,
            sampled=False,
            input_size=len(data),
        )

    def analyze_file(self, path: Path, block_size: int | None = None) -> EntropyProfile:
        """Measure entropy over a file, sampling only when it exceeds the budget.

        A sampled measurement keeps the original offset of every window and is
        labelled ``bytes_sampled=True``; it is never presented as whole-input.
        """
        path = Path(path)
        size = path.stat().st_size
        effective_block = block_size
        if effective_block is None:
            effective_block = self._auto_block_size(size)
        self.validate_block_size(effective_block)

        if size == 0:
            profile = self._empty_profile(path, effective_block)
            return profile

        max_bytes = self.config.max_entropy_scan_size_mb * 1024 * 1024
        ranges: list[tuple[int, bytes]] = []

        with path.open("rb") as handle:
            if size <= max_bytes:
                ranges.append((0, handle.read()))
                sampled = False
            else:
                window = max_bytes // 3
                starts = [0, max(0, size // 2 - window // 2), max(0, size - window)]
                seen: set[int] = set()
                for start in starts:
                    if start in seen:
                        continue
                    seen.add(start)
                    handle.seek(start)
                    ranges.append((start, handle.read(window)))
                sampled = True
                logger.warning(
                    "Entropy sampling: read %d of %d bytes in %d window(s)",
                    sum(len(chunk) for _start, chunk in ranges),
                    size,
                    len(ranges),
                )

        return self._profile(path, ranges, effective_block, sampled, size)

    def find_high_entropy_regions(
        self, profile: EntropyProfile, threshold: float = 7.2
    ) -> list[EntropyRegion]:
        """Regions whose mean entropy is at or above ``threshold`` bits/byte."""
        return [r for r in profile.regions if r.avg_entropy >= threshold]

    def find_low_entropy_regions(
        self, profile: EntropyProfile, threshold: float = 2.4
    ) -> list[EntropyRegion]:
        """Regions whose mean entropy is at or below ``threshold`` bits/byte."""
        return [r for r in profile.regions if r.avg_entropy <= threshold]

    # ──────────────────────────────────────────
    # Internals
    # ──────────────────────────────────────────

    def _profile(
        self,
        firmware_path: Path,
        ranges: list[tuple[int, bytes]],
        block_size: int,
        sampled: bool,
        input_size: int,
    ) -> EntropyProfile:
        blocks: list[EntropyBlock] = []
        combined: dict[int, int] = {}
        total_bytes = 0

        for start, data in ranges:
            offset = start
            for chunk_start in range(0, len(data), block_size):
                chunk = data[chunk_start : chunk_start + block_size]
                entropy, distribution = self._shannon_entropy(chunk)
                blocks.append(
                    EntropyBlock(
                        offset=offset + chunk_start,
                        entropy=round(entropy, 4),
                        byte_distribution=distribution,
                        length=len(chunk),
                    )
                )
                total_bytes += len(chunk)
                for byte, count in distribution.items():
                    combined[byte] = combined.get(byte, 0) + count

        regions = self._classify_regions(blocks)

        overall = 0.0
        if total_bytes:
            for count in combined.values():
                p = count / total_bytes
                overall -= p * math.log2(p)

        window_mean = sum(b.entropy for b in blocks) / len(blocks) if blocks else 0.0

        profile = EntropyProfile(
            firmware_path=firmware_path,
            total_blocks=len(blocks),
            block_size=block_size,
            blocks=blocks,
            regions=regions,
            overall_entropy=round(overall, 4),
            window_mean_entropy=round(window_mean, 4),
            bytes_analyzed=total_bytes,
            bytes_sampled=sampled or total_bytes < input_size,
            # No format evidence was examined, so neither flag can be set.
            has_encrypted_regions=False,
            has_compressed_regions=False,
            firmware_partially_readable=True,
        )

        logger.info(
            "Entropy: %d window(s) of %d B over %d byte(s) (%.2f bits/byte)%s",
            profile.total_blocks,
            block_size,
            total_bytes,
            profile.overall_entropy,
            " [sampled]" if profile.bytes_sampled else "",
        )
        return profile

    def _empty_profile(self, path: Path, block_size: int) -> EntropyProfile:
        return EntropyProfile(
            firmware_path=path,
            total_blocks=0,
            block_size=block_size,
            overall_entropy=0.0,
            window_mean_entropy=0.0,
            bytes_analyzed=0,
        )

    def _auto_block_size(self, file_size: int) -> int:
        """Pick a window size from the input size, clamped to the valid range."""
        if file_size <= 0:
            return 512
        raw = file_size / 2048
        block = max(128, int(round(raw / 1024) * 1024))
        return min(max(block, MIN_BLOCK_SIZE), MAX_BLOCK_SIZE)

    @staticmethod
    def _shannon_entropy(data: bytes) -> tuple[float, dict[int, int]]:
        """Shannon entropy in bits/byte for one window."""
        if not data:
            return 0.0, {}

        distribution: dict[int, int] = {}
        for byte in data:
            distribution[byte] = distribution.get(byte, 0) + 1

        length = len(data)
        entropy = 0.0
        for count in distribution.values():
            p = count / length
            entropy -= p * math.log2(p)

        return entropy, distribution

    @staticmethod
    def classify(entropy: float) -> str:
        """Distribution band for one entropy value, in bits/byte."""
        for ceiling, label in _BANDS:
            if entropy < ceiling:
                return label
        return "high_entropy"

    def _classify_regions(self, blocks: list[EntropyBlock]) -> list[EntropyRegion]:
        """Group adjacent windows with the same band into regions."""
        if not blocks:
            return []

        regions: list[EntropyRegion] = []
        group: list[EntropyBlock] = [blocks[0]]

        def flush() -> None:
            regions.append(self._build_region(group))

        for block in blocks[1:]:
            previous = group[-1]
            contiguous = previous.offset + previous.length == block.offset
            same_band = self.classify(block.entropy) == self.classify(group[0].entropy)
            if contiguous and same_band:
                group.append(block)
            else:
                flush()
                group = [block]
        flush()
        return regions

    def _build_region(self, blocks: list[EntropyBlock]) -> EntropyRegion:
        avg = sum(b.entropy for b in blocks) / len(blocks)
        start = blocks[0].offset
        end = blocks[-1].offset + blocks[-1].length
        classification = self.classify(avg)
        confidence = {
            "padding": 0.8,
            "structured": 0.6,
            "code": 0.6,
            "mixed": 0.5,
            "high_entropy": 0.5,
        }.get(classification, 0.5)
        return EntropyRegion(
            start_offset=start,
            end_offset=end,
            size=end - start,
            avg_entropy=round(avg, 4),
            classification=classification,
            confidence=confidence,
        )
