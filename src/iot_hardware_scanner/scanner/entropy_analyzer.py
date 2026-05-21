"""Entropy Analyzer — Phase 3a.

Computes Shannon entropy across firmware images to identify
compressed, encrypted, and structured regions.

SDR §9.1 — Entropy & Binary Intelligence

Three-tier analysis:
- Fast: binwalk-compatible block size (overview)
- Standard: 512B blocks (firmware < 100MB)
- Detailed: 128B blocks (partition boundaries)

Classification ranges (research-backed):
- 0.00-0.30: padding/null regions
- 0.30-0.50: headers, structured data, configs
- 0.50-0.70: code, mixed data
- 0.70-0.85: compressed (squashfs, gzip, LZMA)
- 0.85-0.93: high-compression payloads
- 0.93+: encrypted or random data
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


class EntropyAnalyzer:
    """Compute Shannon entropy across firmware images.

    Identifies compressed, encrypted, code, and padding regions
    to support security analysis decisions.
    """

    def __init__(self, config: ScannerConfig) -> None:
        self.config = config

    def analyze(self, data: bytes, block_size: int | None = None) -> EntropyProfile:
        """Compute entropy across the firmware image.

        Args:
            data: Raw firmware bytes.
            block_size: Block size for sliding window. None = auto-compute.

        Returns:
            EntropyProfile with per-block entropy and region classification.
        """
        if not data:
            return EntropyProfile(
                firmware_path=Path(""),
                total_blocks=0,
                block_size=block_size or 512,
                blocks=[],
                regions=[],
                overall_entropy=0.0,
                has_encrypted_regions=False,
                has_compressed_regions=False,
                firmware_partially_readable=True,
            )

        if block_size is None:
            block_size = self._auto_block_size(len(data))

        blocks = self._compute_blocks(data, block_size)
        regions = self._classify_regions(blocks, block_size)

        overall = sum(b.entropy for b in blocks) / len(blocks) if blocks else 0.0

        has_encrypted = any(r.classification == "encrypted" for r in regions)
        has_compressed = any(r.classification == "compressed" for r in regions)

        # If fully encrypted (only encrypted regions), firmware is not readable
        # If encrypted alongside other data, firmware is still partially readable
        fully_encrypted = (
            has_encrypted
            and not has_compressed
            and all(r.classification == "encrypted" for r in regions)
        )
        firmware_partially_readable = not fully_encrypted

        profile = EntropyProfile(
            firmware_path=Path(""),
            total_blocks=len(blocks),
            block_size=block_size,
            blocks=blocks,
            regions=regions,
            overall_entropy=round(overall, 4),
            has_encrypted_regions=has_encrypted,
            has_compressed_regions=has_compressed,
            firmware_partially_readable=firmware_partially_readable,
        )

        logger.info(
            "Entropy analysis complete: %d blocks, %d regions, "
            "overall=%.4f, encrypted=%s, compressed=%s",
            profile.total_blocks,
            len(profile.regions),
            profile.overall_entropy,
            profile.has_encrypted_regions,
            profile.has_compressed_regions,
        )
        return profile

    def analyze_file(self, path: Path, block_size: int | None = None) -> EntropyProfile:
        """Analyze entropy of a file on disk.

        Uses memory-mapped I/O for large files to avoid OOM.
        Files larger than max_entropy_scan_size_mb are sampled
        at regular intervals instead of being fully loaded.
        """
        file_size = path.stat().st_size
        max_bytes = self.config.max_entropy_scan_size_mb * 1024 * 1024

        if file_size <= max_bytes:
            data = path.read_bytes()
        else:
            # Memory-map and sample for large files
            import mmap

            logger.warning(
                "Large file (%s): using mmap sampling instead of full load",
                self._fmt_size(file_size),
            )
            data = bytearray()
            with path.open("rb") as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    # Sample first MB, last MB, and evenly-spaced chunks
                    sample_size = min(max_bytes, file_size)
                    if sample_size >= file_size:
                        data = mm[:].tobytes()
                    else:
                        # First chunk
                        data.extend(mm[: sample_size // 3])
                        # Middle chunk
                        mid_start = file_size // 2 - sample_size // 6
                        data.extend(mm[mid_start : mid_start + sample_size // 3])
                        # Last chunk
                        data.extend(mm[-sample_size // 3 :])
                        data = bytes(data)

        profile = self.analyze(data, block_size)
        profile.firmware_path = path
        return profile

    @staticmethod
    def _fmt_size(n: int) -> str:
        """Format byte count as human-readable size."""
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1024:
                return f"{n:.1f} {unit}"
            n //= 1024  # Use integer division to avoid type: ignore
        return f"{n:.1f} TB"

    def find_high_entropy_regions(
        self, profile: EntropyProfile, threshold: float = 0.85
    ) -> list[EntropyRegion]:
        """Identify regions with entropy above threshold (likely encrypted/compressed)."""
        return [r for r in profile.regions if r.avg_entropy >= threshold]

    def find_low_entropy_regions(
        self, profile: EntropyProfile, threshold: float = 0.30
    ) -> list[EntropyRegion]:
        """Identify regions with entropy below threshold (likely headers/padding/configs)."""
        return [r for r in profile.regions if r.avg_entropy <= threshold]

    # ──────────────────────────────────────────
    # Private
    # ──────────────────────────────────────────

    def _auto_block_size(self, file_size: int) -> int:
        """Auto-compute block size based on file size.

        Binwalk-compatible: file_size / 2048, rounded to nearest 1024.
        Minimum block size: 128 bytes.
        """
        if file_size == 0:
            return 512
        raw = file_size / 2048
        block_size = max(128, int(round(raw / 1024) * 1024))
        return block_size

    def _compute_blocks(self, data: bytes, block_size: int) -> list[EntropyBlock]:
        """Compute Shannon entropy for each block."""
        blocks: list[EntropyBlock] = []
        offset = 0

        while offset < len(data):
            chunk = data[offset : offset + block_size]
            entropy, distribution = self._shannon_entropy(chunk)
            blocks.append(
                EntropyBlock(
                    offset=offset,
                    entropy=round(entropy, 4),
                    byte_distribution=distribution,
                )
            )
            offset += block_size

        return blocks

    def _shannon_entropy(self, data: bytes) -> tuple[float, dict[int, int]]:
        """Compute Shannon entropy of a byte sequence.

        H = -Σ p(xi) * log2(p(xi))

        Returns:
            Tuple of (entropy_value, byte_distribution)
        """
        if not data:
            return 0.0, {}

        distribution: dict[int, int] = {}
        for b in data:
            distribution[b] = distribution.get(b, 0) + 1

        length = len(data)
        entropy = 0.0
        for count in distribution.values():
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)

        return entropy, distribution

    def _classify_regions(self, blocks: list[EntropyBlock], block_size: int) -> list[EntropyRegion]:
        """Classify contiguous blocks into entropy regions.

        SDR §9.1 interpretation table:
        - 0.00-0.30: padding
        - 0.30-0.50: data/headers
        - 0.50-0.70: code
        - 0.70-0.85: compressed
        - 0.85-0.93: high-compression payload (still compressed)
        - 0.93+: encrypted or random
        """
        if not blocks:
            return []

        regions: list[EntropyRegion] = []
        region_start = 0
        current_class = self._entropy_to_classification(blocks[0].entropy)

        for i in range(1, len(blocks)):
            block_class = self._entropy_to_classification(blocks[i].entropy)
            if block_class != current_class:
                region = self._build_region(blocks, region_start, i, block_size, current_class)
                regions.append(region)
                region_start = i
                current_class = block_class

        # Final region
        if region_start < len(blocks):
            region = self._build_region(
                blocks,
                region_start,
                len(blocks),
                block_size,
                current_class,
            )
            regions.append(region)

        return regions

    def _entropy_to_classification(self, entropy: float) -> str:
        """Map entropy value to region classification."""
        if entropy < 0.30:
            return "padding"
        elif entropy < 0.50:
            return "data"
        elif entropy < 0.70:
            return "code"
        elif entropy < 0.93:
            return "compressed"
        else:
            return "encrypted"

    def _build_region(
        self,
        blocks: list[EntropyBlock],
        start_idx: int,
        end_idx: int,
        block_size: int,
        classification: str,
    ) -> EntropyRegion:
        """Build an EntropyRegion from a range of blocks."""
        region_blocks = blocks[start_idx:end_idx]
        avg_entropy = sum(b.entropy for b in region_blocks) / len(region_blocks)

        # Confidence based on how clearly the classification applies
        if classification == "encrypted":
            confidence = min(1.0, (avg_entropy - 0.93) / 0.07) if avg_entropy > 0.93 else 0.5
        elif classification == "compressed":
            confidence = 0.7
        elif classification == "code":
            confidence = 0.6
        else:
            confidence = 0.8

        return EntropyRegion(
            start_offset=blocks[start_idx].offset,
            end_offset=blocks[end_idx - 1].offset + block_size,
            size=(end_idx - start_idx) * block_size,
            avg_entropy=round(avg_entropy, 4),
            classification=classification,
            confidence=round(confidence, 2),
        )
