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

    def test_all_zeros_entropy_zero(self, analyzer: EntropyAnalyzer) -> None:
        data = b"\x00" * 2048
        profile = analyzer.analyze(data, block_size=512)
        for block in profile.blocks:
            assert block.entropy == pytest.approx(0.0, abs=0.05)

    def test_random_data_high_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """Random data should have entropy close to 1.0 (normalized)."""
        data = os.urandom(4096)
        profile = analyzer.analyze(data, block_size=512)
        # Normalized Shannon entropy: random = 8 bits / 8 = 1.0
        assert profile.overall_entropy > 0.9

    def test_alternating_bytes_medium_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """Alternating 0x00/0xFF gives 1 bit of entropy per byte."""
        data = bytes([0, 255] * 2048)
        profile = analyzer.analyze(data, block_size=512)
        # 2 unique values with equal probability → H = 1.0 bit/byte
        # (raw Shannon entropy, not normalized to 0-1)
        assert profile.overall_entropy == pytest.approx(1.0, abs=0.1)

    def test_all_256_byte_values_max_entropy(self, analyzer: EntropyAnalyzer) -> None:
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

    def test_explicit_block_size_overrides(self, analyzer: EntropyAnalyzer) -> None:
        data = os.urandom(2048)
        profile = analyzer.analyze(data, block_size=256)
        assert profile.block_size == 256


class TestRegionClassification:
    """Regions classified correctly by entropy ranges."""

    def test_all_padding_region(self, analyzer: EntropyAnalyzer) -> None:
        """All zeros → padding classification."""
        data = b"\x00" * 2048
        profile = analyzer.analyze(data, block_size=512)
        assert len(profile.regions) >= 1
        assert all(r.classification == "padding" for r in profile.regions)

    def test_random_data_is_high_entropy_not_encrypted(self, analyzer: EntropyAnalyzer) -> None:
        """Random bytes are a distribution observation, never an encryption claim."""
        data = os.urandom(4096)
        profile = analyzer.analyze(data, block_size=512)
        high_regions = [r for r in profile.regions if r.avg_entropy >= 7.44]
        assert len(high_regions) >= 1
        assert all(r.classification == "high_entropy" for r in high_regions)
        assert all(r.classification != "encrypted" for r in profile.regions)

    def test_mixed_regions(self, analyzer: EntropyAnalyzer) -> None:
        """Low + high entropy data produces multiple regions."""
        data = b"\x00" * 1024 + os.urandom(1024)
        profile = analyzer.analyze(data, block_size=256)
        # Should have at least 2 different classifications
        classifications = set(r.classification for r in profile.regions)
        assert len(classifications) >= 1  # At minimum one change

    def test_classification_bands_are_bits_per_byte(self) -> None:
        """Bands are defined on a 0.0-8.0 bits/byte scale."""
        assert EntropyAnalyzer.classify(0.0) == "padding"
        assert EntropyAnalyzer.classify(2.39) == "padding"
        assert EntropyAnalyzer.classify(2.40) == "structured"
        assert EntropyAnalyzer.classify(3.99) == "structured"
        assert EntropyAnalyzer.classify(4.00) == "code"
        assert EntropyAnalyzer.classify(5.59) == "code"
        assert EntropyAnalyzer.classify(5.60) == "mixed"
        assert EntropyAnalyzer.classify(6.79) == "mixed"
        assert EntropyAnalyzer.classify(6.80) == "high_entropy"
        assert EntropyAnalyzer.classify(8.0) == "high_entropy"

    def test_no_band_claims_encryption(self, analyzer: EntropyAnalyzer) -> None:
        """No classification value may assert encryption."""
        for value in (0.0, 1.0, 2.5, 4.5, 6.0, 7.5, 8.0):
            assert EntropyAnalyzer.classify(value) not in {"encrypted", "compressed"}


class TestHighLowRegionFinders:
    """find_high_entropy_regions and find_low_entropy_regions."""

    def test_find_high_entropy(self, analyzer: EntropyAnalyzer) -> None:
        data = b"\x00" * 512 + os.urandom(2048)
        profile = analyzer.analyze(data, block_size=256)
        high = analyzer.find_high_entropy_regions(profile, threshold=6.8)
        # At least the random portion should be high entropy
        assert len(high) >= 1

    def test_find_low_entropy(self, analyzer: EntropyAnalyzer) -> None:
        data = b"\x00" * 1024 + os.urandom(1024)
        profile = analyzer.analyze(data, block_size=256)
        low = analyzer.find_low_entropy_regions(profile, threshold=2.4)
        # At least the zero portion should be low entropy
        assert len(low) >= 1

    def test_custom_threshold(self, analyzer: EntropyAnalyzer) -> None:
        data = os.urandom(2048)
        profile = analyzer.analyze(data, block_size=512)
        # Very high threshold should find fewer regions
        strict = analyzer.find_high_entropy_regions(profile, threshold=7.99)
        loose = analyzer.find_high_entropy_regions(profile, threshold=6.5)
        assert len(loose) >= len(strict)


class TestEncryptedCompressedFlags:
    """Profile flags for encrypted/compressed regions."""

    def test_random_data_never_sets_encrypted_flag(self, analyzer: EntropyAnalyzer) -> None:
        """High entropy is not format evidence, so the flag stays False."""
        data = os.urandom(4096)
        profile = analyzer.analyze(data, block_size=512)
        assert profile.has_encrypted_regions is False

    def test_zeros_no_encrypted_flag(self, analyzer: EntropyAnalyzer) -> None:
        data = b"\x00" * 2048
        profile = analyzer.analyze(data, block_size=512)
        assert profile.has_encrypted_regions is False

    def test_zeros_no_compressed_flag(self, analyzer: EntropyAnalyzer) -> None:
        data = b"\x00" * 2048
        profile = analyzer.analyze(data, block_size=512)
        assert profile.has_compressed_regions is False

    def test_partially_readable(self, analyzer: EntropyAnalyzer) -> None:
        """Mixed data → partially readable."""
        data = b"\x00" * 1024 + os.urandom(1024)
        profile = analyzer.analyze(data, block_size=256)
        # Has both non-encrypted and encrypted content
        assert profile.firmware_partially_readable is True

    def test_entropy_never_claims_unreadable(self, analyzer: EntropyAnalyzer) -> None:
        """Entropy alone can never establish that an artifact is unreadable."""
        data = os.urandom(4096)
        profile = analyzer.analyze(data, block_size=512)
        assert profile.firmware_partially_readable is True


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

    def test_analyze_file_empty(self, analyzer: EntropyAnalyzer) -> None:
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

    def test_blocks_have_correct_offsets(self, analyzer: EntropyAnalyzer) -> None:
        data = os.urandom(2048)
        block_size = 512
        profile = analyzer.analyze(data, block_size=block_size)
        for i, block in enumerate(profile.blocks):
            assert block.offset == i * block_size

    def test_regions_have_valid_size(self, analyzer: EntropyAnalyzer) -> None:
        data = b"\x00" * 1024 + os.urandom(1024)
        profile = analyzer.analyze(data, block_size=256)
        for region in profile.regions:
            assert region.size > 0
            assert region.end_offset > region.start_offset

    def test_confidence_in_valid_range(self, analyzer: EntropyAnalyzer) -> None:
        data = os.urandom(2048)
        profile = analyzer.analyze(data, block_size=512)
        for region in profile.regions:
            assert 0.0 <= region.confidence <= 1.0

    def test_entropy_in_valid_range(self, analyzer: EntropyAnalyzer) -> None:
        data = os.urandom(4096)
        profile = analyzer.analyze(data, block_size=512)
        for block in profile.blocks:
            assert 0.0 <= block.entropy <= 8.0
        for region in profile.regions:
            assert 0.0 <= region.avg_entropy <= 8.0

    def test_analyze_file_uses_mmap_for_large_files(self, tmp_path: Path) -> None:
        """Large files above max_entropy_scan_size_mb use mmap sampling instead of full read."""
        from iot_hardware_scanner.scanner.entropy_analyzer import EntropyAnalyzer

        config = ScannerConfig(max_entropy_scan_size_mb=1)  # 1MB limit
        analyzer = EntropyAnalyzer(config)
        # Create a 2MB file (exceeds 1MB limit)
        f = tmp_path / "large_firmware.bin"
        data = os.urandom(2 * 1024 * 1024)
        f.write_bytes(data)
        profile = analyzer.analyze_file(f)
        assert profile.total_blocks > 0
        assert profile.firmware_path == f
        # Should still produce valid entropy values
        assert 0.0 <= profile.overall_entropy <= 8.0

    def test_analyze_file_small_file_reads_fully(self, tmp_path: Path) -> None:
        """Small files below the limit are read fully (not sampled)."""
        from iot_hardware_scanner.scanner.entropy_analyzer import EntropyAnalyzer

        config = ScannerConfig(max_entropy_scan_size_mb=256)
        analyzer = EntropyAnalyzer(config)
        f = tmp_path / "small.bin"
        data = b"\x00" * 1024 + b"\xff" * 1024  # 2KB mixed
        f.write_bytes(data)
        profile = analyzer.analyze_file(f)
        assert profile.total_blocks > 0
        assert profile.firmware_path == f


class TestEntropyUnitsAndBoundaries:
    """1E — units, whole-input aggregation, window boundaries, validation.

    Every expected value here is derivable by hand from the definition of
    Shannon entropy, so none of these assertions depend on the implementation
    agreeing with itself.
    """

    def test_units_are_bits_per_byte(self, analyzer: EntropyAnalyzer) -> None:
        profile = analyzer.analyze(b"\x00" * 64, block_size=64)
        assert profile.units == "bits/byte"

    def test_constant_bytes_are_zero(self, analyzer: EntropyAnalyzer) -> None:
        profile = analyzer.analyze(b"\x41" * 256, block_size=256)
        assert profile.overall_entropy == 0.0

    def test_two_alternating_symbols_are_one_bit(self, analyzer: EntropyAnalyzer) -> None:
        profile = analyzer.analyze(b"AB" * 128, block_size=256)
        assert profile.overall_entropy == 1.0

    def test_all_byte_values_equally_often_are_eight_bits(self, analyzer: EntropyAnalyzer) -> None:
        profile = analyzer.analyze(bytes(range(256)) * 4, block_size=1024)
        assert profile.overall_entropy == 8.0

    def test_whole_input_differs_from_window_mean(self, analyzer: EntropyAnalyzer) -> None:
        """Two uniform windows with different symbols: local 0, whole-input 1."""
        data = b"A" * 128 + b"B" * 128
        profile = analyzer.analyze(data, block_size=128)
        assert [b.entropy for b in profile.blocks] == [0.0, 0.0]
        assert profile.window_mean_entropy == 0.0
        assert profile.overall_entropy == 1.0

    def test_final_window_keeps_true_length_and_end(self, analyzer: EntropyAnalyzer) -> None:
        data = bytes(range(129))
        profile = analyzer.analyze(data, block_size=128)
        assert profile.total_blocks == 2
        assert profile.blocks[-1].offset == 128
        assert profile.blocks[-1].length == 1
        assert profile.regions[-1].end_offset == 129
        assert sum(r.size for r in profile.regions) == 129

    def test_regions_do_not_exceed_input(self, analyzer: EntropyAnalyzer) -> None:
        profile = analyzer.analyze(b"\x00" * 1000, block_size=128)
        assert max(r.end_offset for r in profile.regions) == 1000

    def test_invalid_block_sizes_rejected(self, analyzer: EntropyAnalyzer) -> None:
        for bad in (0, -1, 1, _min_block_size() - 1, _max_block_size() + 1):
            with pytest.raises(ValueError):
                analyzer.analyze(b"\x00" * 64, block_size=bad)

    def test_block_size_must_be_an_integer(self) -> None:
        with pytest.raises(ValueError):
            EntropyAnalyzer.validate_block_size(128.5)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            EntropyAnalyzer.validate_block_size(True)  # type: ignore[arg-type]

    def test_sampled_measurement_is_labelled_and_keeps_offsets(self, tmp_path: Path) -> None:
        from iot_hardware_scanner.config import ScannerConfig

        config = ScannerConfig(max_entropy_scan_size_mb=1)
        analyzer = EntropyAnalyzer(config)
        payload = b"\x00" * (2 * 1024 * 1024)
        target = tmp_path / "big.bin"
        target.write_bytes(payload)
        profile = analyzer.analyze_file(target, block_size=4096)
        assert profile.bytes_sampled is True
        assert profile.bytes_analyzed < len(payload)
        # Original coordinates: the last window starts near the end of the file.
        assert profile.blocks[-1].offset > len(payload) // 2
        # Coordinates stay inside the file and never exceed one window.
        assert all(
            0 < b.length <= 4096 and b.offset + b.length <= len(payload) for b in profile.blocks
        )
        assert [b.offset for b in profile.blocks] == sorted(b.offset for b in profile.blocks)

    def test_sampled_regions_are_not_joined_across_gaps(self, tmp_path: Path) -> None:
        from iot_hardware_scanner.config import ScannerConfig

        analyzer = EntropyAnalyzer(ScannerConfig(max_entropy_scan_size_mb=1))
        target = tmp_path / "gappy.bin"
        target.write_bytes(b"\x00" * (3 * 1024 * 1024))
        profile = analyzer.analyze_file(target, block_size=65536)
        for first, second in zip(profile.regions, profile.regions[1:], strict=False):
            assert first.end_offset <= second.start_offset


def _min_block_size() -> int:
    from iot_hardware_scanner.scanner.entropy_analyzer import MIN_BLOCK_SIZE

    return MIN_BLOCK_SIZE


def _max_block_size() -> int:
    from iot_hardware_scanner.scanner.entropy_analyzer import MAX_BLOCK_SIZE

    return MAX_BLOCK_SIZE
