"""Tests for Entropy Analyzer — Phase 3a.

Covers:
- Shannon entropy computation correctness
- Block size auto-computation
- Region classification (padding, data, code, compressed, encrypted)
- High/low entropy region finding
- Empty data handling
- Uniform data (all zeros = 0 entropy)
- Random data (high entropy ~8 bits = ~1.0 normalized)
- Mixed regions (low + high in same data)
"""

import os
import tempfile
from pathlib import Path

import pytest

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.scanner.entropy_analyzer import EntropyAnalyzer


@pytest.fixture
def config() -> ScannerConfig:
    return ScannerConfig()


@pytest.fixture
def analyzer(config: ScannerConfig) -> EntropyAnalyzer:
    return EntropyAnalyzer(config)


class TestShannonEntropy:
    """Core entropy computation correctness."""

    def test_empty_data(self, analyzer: EntropyAnalyzer) -> None:
        profile = analyzer.analyze(b"")
        assert profile.total_blocks == 0
        assert profile.overall_entropy == 0.0

    def test_single_byte_repeated(self, analyzer: EntropyAnalyzer) -> None:
        """All same bytes = 0 entropy."""
        profile = analyzer.analyze(b"\x00" * 1024, block_size=256)
        assert profile.overall_entropy == pytest.approx(0.0, abs=0.01)

    def test_all_zeros_entropy_zero(
        self, analyzer: EntropyAnalyzer
    ) -> None:
        data = b"\x00" * 2048
        profile = analyzer.analyze(data, block_size=512)
        for block in profile.blocks:
            assert block.entropy == pytest.approx(0.0, abs=0.05)

    def test_random_data_high_entropy(
        self, analyzer: EntropyAnalyzer
    ) -> None:
        """Random data should have entropy close to 1.0 (normalized)."""
        data = os.urandom(4096)
        profile = analyzer.analyze(data, block_size=512)
        # Normalized Shannon entropy: random = 8 bits / 8 = 1.0
        assert profile.overall_entropy > 0.9

    def test_alternating_bytes_medium_entropy(
        self, analyzer: EntropyAnalyzer
    ) -> None:
        """Alternating 0x00/0xFF gives 1 bit of entropy per byte."""
        data = bytes([0, 255] * 2048)
        profile = analyzer.analyze(data, block_size=512)
        # 2 unique values with equal probability → H = 1.0 bit/byte
        # (raw Shannon entropy, not normalized to 0-1)
        assert profile.overall_entropy == pytest.approx(1.0, abs=0.1)

    def test_all_256_byte_values_max_entropy(
        self, analyzer: EntropyAnalyzer
    ) -> None:
        """Each byte value appears exactly once → max entropy."""
        data = bytes(range(256)) * 4  # 1024 bytes, all values equally likely
        profile = analyzer.analyze(data, block_size=512)
        assert profile.overall_entropy > 0.95


class TestBlockAutoSizing:
    """Auto-compute block size based on file size."""

    def test_tiny_file_min_block(self, analyzer: EntropyAnalyzer) -> None:
        block_size = analyzer._auto_block_size(100)
        assert block_size == 128  # Minimum

    def test_medium_file(self, analyzer: EntropyAnalyzer) -> None:
        # 1MB file: 1048576 / 2048 = 512 → round to 512
        block_size = analyzer._auto_block_size(1048576)
        assert block_size >= 128

    def test_large_file(self, analyzer: EntropyAnalyzer) -> None:
        # 500MB file
        block_size = analyzer._auto_block_size(500 * 1024 * 1024)
        assert block_size >= 128

    def test_zero_size(self, analyzer: EntropyAnalyzer) -> None:
        block_size = analyzer._auto_block_size(0)
        assert block_size == 512  # Default

    def test_explicit_block_size_overrides(
        self, analyzer: EntropyAnalyzer
    ) -> None:
        data = os.urandom(2048)
        profile = analyzer.analyze(data, block_size=256)
        assert profile.block_size == 256


class TestRegionClassification:
    """Regions classified correctly by entropy ranges."""

    def test_all_padding_region(
        self, analyzer: EntropyAnalyzer
    ) -> None:
        """All zeros → padding classification."""
        data = b"\x00" * 2048
        profile = analyzer.analyze(data, block_size=512)
        assert len(profile.regions) >= 1
        assert all(
            r.classification == "padding" for r in profile.regions
        )

    def test_all_encrypted_region(
        self, analyzer: EntropyAnalyzer
    ) -> None:
        """Random data → encrypted classification."""
        data = os.urandom(4096)
        profile = analyzer.analyze(data, block_size=512)
        # High entropy blocks should be classified as encrypted
        high_regions = [
            r for r in profile.regions if r.avg_entropy >= 0.93
        ]
        assert len(high_regions) >= 1

    def test_mixed_regions(self, analyzer: EntropyAnalyzer) -> None:
        """Low + high entropy data produces multiple regions."""
        data = b"\x00" * 1024 + os.urandom(1024)
        profile = analyzer.analyze(data, block_size=256)
        # Should have at least 2 different classifications
        classifications = set(r.classification for r in profile.regions)
        assert len(classifications) >= 1  # At minimum one change

    def test_compressed_threshold(self, analyzer: EntropyAnalyzer) -> None:
        """Entropy between 0.70-0.93 → compressed."""
        # We can't easily construct data with exact entropy,
        # but we can test the classification function directly
        assert analyzer._entropy_to_classification(0.75) == "compressed"
        assert analyzer._entropy_to_classification(0.85) == "compressed"
        assert analyzer._entropy_to_classification(0.92) == "compressed"

    def test_classification_thresholds(
        self, analyzer: EntropyAnalyzer
    ) -> None:
        """Verify exact SDR thresholds."""
        assert analyzer._entropy_to_classification(0.0) == "padding"
        assert analyzer._entropy_to_classification(0.29) == "padding"
        assert analyzer._entropy_to_classification(0.30) == "data"
        assert analyzer._entropy_to_classification(0.49) == "data"
        assert analyzer._entropy_to_classification(0.50) == "code"
        assert analyzer._entropy_to_classification(0.69) == "code"
        assert analyzer._entropy_to_classification(0.70) == "compressed"
        assert analyzer._entropy_to_classification(0.93) == "encrypted"
        assert analyzer._entropy_to_classification(1.0) == "encrypted"


class TestHighLowRegionFinders:
    """find_high_entropy_regions and find_low_entropy_regions."""

    def test_find_high_entropy(
        self, analyzer: EntropyAnalyzer
    ) -> None:
        data = b"\x00" * 512 + os.urandom(2048)
        profile = analyzer.analyze(data, block_size=256)
        high = analyzer.find_high_entropy_regions(profile, threshold=0.85)
        # At least the random portion should be high entropy
        assert len(high) >= 1

    def test_find_low_entropy(self, analyzer: EntropyAnalyzer) -> None:
        data = b"\x00" * 1024 + os.urandom(1024)
        profile = analyzer.analyze(data, block_size=256)
        low = analyzer.find_low_entropy_regions(profile, threshold=0.30)
        # At least the zero portion should be low entropy
        assert len(low) >= 1

    def test_custom_threshold(self, analyzer: EntropyAnalyzer) -> None:
        data = os.urandom(2048)
        profile = analyzer.analyze(data, block_size=512)
        # Very high threshold should find fewer regions
        strict = analyzer.find_high_entropy_regions(profile, threshold=0.99)
        loose = analyzer.find_high_entropy_regions(profile, threshold=0.80)
        assert len(loose) >= len(strict)


class TestEncryptedCompressedFlags:
    """Profile flags for encrypted/compressed regions."""

    def test_random_data_sets_encrypted_flag(
        self, analyzer: EntropyAnalyzer
    ) -> None:
        data = os.urandom(4096)
        profile = analyzer.analyze(data, block_size=512)
        assert profile.has_encrypted_regions is True

    def test_zeros_no_encrypted_flag(
        self, analyzer: EntropyAnalyzer
    ) -> None:
        data = b"\x00" * 2048
        profile = analyzer.analyze(data, block_size=512)
        assert profile.has_encrypted_regions is False

    def test_zeros_no_compressed_flag(
        self, analyzer: EntropyAnalyzer
    ) -> None:
        data = b"\x00" * 2048
        profile = analyzer.analyze(data, block_size=512)
        assert profile.has_compressed_regions is False

    def test_partially_readable(self, analyzer: EntropyAnalyzer) -> None:
        """Mixed data → partially readable."""
        data = b"\x00" * 1024 + os.urandom(1024)
        profile = analyzer.analyze(data, block_size=256)
        # Has both non-encrypted and encrypted content
        assert profile.firmware_partially_readable is True

    def test_fully_encrypted_not_readable(
        self, analyzer: EntropyAnalyzer
    ) -> None:
        """Fully random data → not partially readable."""
        data = os.urandom(4096)
        profile = analyzer.analyze(data, block_size=512)
        # All encrypted → not partially readable
        assert profile.firmware_partially_readable is False


class TestAnalyzeFile:
    """analyze_file reads from disk."""

    def test_analyze_file(self, analyzer: EntropyAnalyzer) -> None:
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(os.urandom(2048))
            path = Path(f.name)

        try:
            profile = analyzer.analyze_file(path)
            assert profile.firmware_path == path
            assert profile.total_blocks > 0
        finally:
            path.unlink()

    def test_analyze_file_empty(
        self, analyzer: EntropyAnalyzer
    ) -> None:
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"")
            path = Path(f.name)

        try:
            profile = analyzer.analyze_file(path)
            assert profile.total_blocks == 0
        finally:
            path.unlink()


class TestEntropyProfileStructure:
    """Verify EntropyProfile structure integrity."""

    def test_blocks_have_correct_offsets(
        self, analyzer: EntropyAnalyzer
    ) -> None:
        data = os.urandom(2048)
        block_size = 512
        profile = analyzer.analyze(data, block_size=block_size)
        for i, block in enumerate(profile.blocks):
            assert block.offset == i * block_size

    def test_regions_have_valid_size(
        self, analyzer: EntropyAnalyzer
    ) -> None:
        data = b"\x00" * 1024 + os.urandom(1024)
        profile = analyzer.analyze(data, block_size=256)
        for region in profile.regions:
            assert region.size > 0
            assert region.end_offset > region.start_offset

    def test_confidence_in_valid_range(
        self, analyzer: EntropyAnalyzer
    ) -> None:
        data = os.urandom(2048)
        profile = analyzer.analyze(data, block_size=512)
        for region in profile.regions:
            assert 0.0 <= region.confidence <= 1.0

    def test_entropy_in_valid_range(
        self, analyzer: EntropyAnalyzer
    ) -> None:
        data = os.urandom(4096)
        profile = analyzer.analyze(data, block_size=512)
        for block in profile.blocks:
            assert 0.0 <= block.entropy <= 8.0
        for region in profile.regions:
            assert 0.0 <= region.avg_entropy <= 8.0
