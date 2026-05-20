"""Tests for Firmware Ingest — Phase 1.

Covers:
- Happy path ingestion (valid firmware)
- Validation errors (missing, empty, too large, unreadable, path traversal)
- Hash computation correctness
- File type identification
- Size classification
- Output directory creation
- ScanContext structure validation
"""

import hashlib
import os
import tempfile
from pathlib import Path

import pytest

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.exceptions import (
    FirmwareEmptyError,
    FirmwareNotFoundError,
    FirmwarePathTraversalError,
    FirmwareTooLargeError,
    FirmwareUnreadableError,
)
from iot_hardware_scanner.models import FirmwareSizeCategory, ScanContext
from iot_hardware_scanner.scanner.firmware_ingest import FirmwareIngest

# ──────────────────────────────────────────────
# Happy path
# ──────────────────────────────────────────────


class TestIngestHappyPath:
    """Test successful firmware ingestion."""

    def test_ingest_small_firmware(
        self, small_firmware: Path, output_config: ScannerConfig
    ) -> None:
        """Ingest a small firmware file successfully."""
        ingest = FirmwareIngest(output_config)
        context = ingest.ingest(small_firmware)

        assert isinstance(context, ScanContext)
        assert context.firmware_path == small_firmware.resolve()
        assert context.firmware_name == "test_firmware"
        assert context.file_size == 1024
        assert context.size_category == FirmwareSizeCategory.SMALL
        assert len(context.file_hash_sha256) == 64
        assert len(context.file_hash_md5) == 32
        assert context.output_dir.exists()
        assert context.scan_id  # UUID is non-empty
        assert context.started_at is not None

    def test_ingest_medium_firmware(
        self, medium_firmware: Path, output_config: ScannerConfig
    ) -> None:
        """Ingest a medium firmware file."""
        ingest = FirmwareIngest(output_config)
        context = ingest.ingest(medium_firmware)

        assert context.file_size == 100 * 1024
        assert context.size_category == FirmwareSizeCategory.SMALL

    def test_hash_computation(self, small_firmware: Path, output_config: ScannerConfig) -> None:
        """Verify SHA-256 and MD5 hashes are computed correctly."""
        # Compute expected hashes
        expected_sha256 = hashlib.sha256(small_firmware.read_bytes()).hexdigest()
        expected_md5 = hashlib.md5(small_firmware.read_bytes()).hexdigest()

        ingest = FirmwareIngest(output_config)
        context = ingest.ingest(small_firmware)

        assert context.file_hash_sha256 == expected_sha256
        assert context.file_hash_md5 == expected_md5

    def test_output_directory_created(self, small_firmware: Path, temp_dir: Path) -> None:
        """Output directory is created automatically."""
        config = ScannerConfig(output_dir=temp_dir / "scan_output")
        ingest = FirmwareIngest(config)
        context = ingest.ingest(small_firmware)

        assert context.output_dir.exists()
        assert context.output_dir.is_dir()
        # Directory should be under the configured output path
        assert str(context.output_dir).startswith(str(temp_dir / "scan_output"))

    def test_output_directory_auto_fallback(self, small_firmware: Path) -> None:
        """When no output_dir configured, uses CWD/reports/."""
        config = ScannerConfig()  # No output_dir
        ingest = FirmwareIngest(config)
        context = ingest.ingest(small_firmware)

        assert context.output_dir.exists()
        # Cleanup
        import shutil

        if context.output_dir.parent.name == "reports":
            shutil.rmtree(context.output_dir.parent, ignore_errors=True)


# ──────────────────────────────────────────────
# Validation errors
# ──────────────────────────────────────────────


class TestIngestValidation:
    """Test firmware validation and error handling."""

    def test_file_not_found(self, output_config: ScannerConfig) -> None:
        """Raise FirmwareNotFoundError for non-existent file."""
        ingest = FirmwareIngest(output_config)
        with pytest.raises(FirmwareNotFoundError):
            ingest.ingest(Path("/nonexistent/firmware.bin"))

    def test_empty_file(self, empty_firmware: Path, output_config: ScannerConfig) -> None:
        """Raise FirmwareEmptyError for 0-byte file."""
        ingest = FirmwareIngest(output_config)
        with pytest.raises(FirmwareEmptyError):
            ingest.ingest(empty_firmware)

    def test_file_too_large(self, large_firmware_name: Path) -> None:
        """Raise FirmwareTooLargeError when file exceeds limit."""
        # Create a file that exceeds 1MB limit
        import os

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(os.urandom(2 * 1024 * 1024))  # 2 MB
            big_file = Path(f.name)
        try:
            config = ScannerConfig(max_file_size_mb=1)
            ingest = FirmwareIngest(config)
            with pytest.raises(FirmwareTooLargeError):
                ingest.ingest(big_file)
        finally:
            big_file.unlink(missing_ok=True)

    def test_directory_instead_of_file(self, temp_dir: Path, output_config: ScannerConfig) -> None:
        """Raise FirmwareNotFoundError when given a directory."""
        ingest = FirmwareIngest(output_config)
        with pytest.raises(FirmwareNotFoundError):
            ingest.ingest(temp_dir)

    def test_symlink_instead_of_file(
        self, small_firmware: Path, temp_dir: Path, output_config: ScannerConfig
    ) -> None:
        """Raise FirmwareNotFoundError when given a symlink."""
        symlink = temp_dir / "firmware_link.bin"
        symlink.symlink_to(small_firmware)

        ingest = FirmwareIngest(output_config)
        with pytest.raises(FirmwareNotFoundError, match=r"(?i)symlink"):
            ingest.ingest(symlink)

    def test_path_traversal_dotdot(self, output_config: ScannerConfig) -> None:
        """Raise FirmwarePathTraversalError for .. in path."""
        ingest = FirmwareIngest(output_config)
        # Use a raw string with .. that will be a path component
        # Path.parts won't show .. after normalization, so we test the string check
        with pytest.raises(FirmwarePathTraversalError):
            # This path has .. as a component before resolve
            ingest.ingest(Path("../etc/passwd"))

    def test_path_traversal_null_byte(self, output_config: ScannerConfig) -> None:
        """Raise FirmwarePathTraversalError for null byte in path."""
        ingest = FirmwareIngest(output_config)
        with pytest.raises(FirmwarePathTraversalError):
            ingest.ingest(Path("/tmp/firmware\x00.bin"))


# ──────────────────────────────────────────────
# Size classification
# ──────────────────────────────────────────────


class TestSizeClassification:
    """Test firmware size categorization."""

    def test_small_firmware(self, output_config: ScannerConfig, temp_dir: Path) -> None:
        """< 50 MB = SMALL."""
        firmware = temp_dir / "small.bin"
        firmware.write_bytes(os.urandom(1024))  # 1 KB
        ingest = FirmwareIngest(output_config)
        context = ingest.ingest(firmware)
        assert context.size_category == FirmwareSizeCategory.SMALL

    def test_medium_firmware(self, output_config: ScannerConfig, temp_dir: Path) -> None:
        """50-500 MB = MEDIUM."""
        # Create a 60MB file (too slow to actually create, so test the internal method)
        ingest = FirmwareIngest(output_config)
        category = ingest._classify_size(60 * 1024 * 1024)
        assert category == FirmwareSizeCategory.MEDIUM

    def test_large_firmware(self, output_config: ScannerConfig) -> None:
        """500 MB - 2 GB = LARGE."""
        ingest = FirmwareIngest(output_config)
        category = ingest._classify_size(600 * 1024 * 1024)
        assert category == FirmwareSizeCategory.LARGE


# ──────────────────────────────────────────────
# File type detection
# ──────────────────────────────────────────────


class TestFileTypeDetection:
    """Test file type identification."""

    def test_extension_fallback(self, output_config: ScannerConfig, temp_dir: Path) -> None:
        """Extension-based fallback works when python-magic unavailable."""
        firmware = temp_dir / "test.elf"
        firmware.write_bytes(os.urandom(256))

        ingest = FirmwareIngest(output_config)
        file_type = ingest._identify_by_extension(firmware)
        assert "ELF" in file_type

    def test_known_extensions(self, output_config: ScannerConfig) -> None:
        """All supported extensions have descriptions."""
        ingest = FirmwareIngest(output_config)

        assert "binary" in ingest._identify_by_extension(Path("firmware.bin")).lower()
        assert "U-Boot" in ingest._identify_by_extension(Path("image.img"))
        assert "ELF" in ingest._identify_by_extension(Path("app.elf"))
        assert "Intel HEX" in ingest._identify_by_extension(Path("mcu.hex"))
        assert "UF2" in ingest._identify_by_extension(Path("boot.uf2"))
        assert "SquashFS" in ingest._identify_by_extension(Path("rootfs.squashfs"))


# ──────────────────────────────────────────────
# get_metadata (lightweight path)
# ──────────────────────────────────────────────


class TestGetMetadata:
    """Test the lightweight metadata extraction path."""

    def test_metadata_from_valid_file(
        self, small_firmware: Path, output_config: ScannerConfig
    ) -> None:
        """Extract metadata without creating ScanContext."""
        from iot_hardware_scanner.models import FirmwareMetadata

        ingest = FirmwareIngest(output_config)
        meta = ingest.get_metadata(small_firmware)

        assert isinstance(meta, FirmwareMetadata)
        assert meta.name == "test_firmware"
        assert meta.size_bytes == 1024
        assert meta.size_category == FirmwareSizeCategory.SMALL
        assert len(meta.sha256) == 64
        assert len(meta.md5) == 32
        assert meta.extension == ".bin"
        assert meta.is_regular_file is True
        assert meta.is_readable is True

    def test_metadata_nonexistent_file(self, output_config: ScannerConfig) -> None:
        """Metadata raises for non-existent file."""
        ingest = FirmwareIngest(output_config)
        with pytest.raises(FirmwareNotFoundError):
            ingest.get_metadata(Path("/nonexistent.bin"))

    def test_metadata_path_traversal_dotdot(self, output_config: ScannerConfig) -> None:
        """get_metadata rejects .. before resolve()."""
        ingest = FirmwareIngest(output_config)
        with pytest.raises(FirmwarePathTraversalError):
            ingest.get_metadata(Path("../etc/passwd"))

    def test_metadata_symlink(self, output_config: ScannerConfig, small_firmware: Path) -> None:
        """get_metadata rejects symlinks."""
        symlink = small_firmware.parent / "meta_link.bin"
        symlink.symlink_to(small_firmware)
        ingest = FirmwareIngest(output_config)
        try:
            with pytest.raises(FirmwareNotFoundError, match=r"(?i)symlink"):
                ingest.get_metadata(symlink)
        finally:
            symlink.unlink(missing_ok=True)


# ──────────────────────────────────────────────
# Determinism
# ──────────────────────────────────────────────


class TestDeterminism:
    """Same input must always produce same output (SDR Design Principle 2)."""

    def test_deterministic_hashes(self, small_firmware: Path, output_config: ScannerConfig) -> None:
        """Same file always produces same hashes."""
        ingest = FirmwareIngest(output_config)
        ctx1 = ingest.ingest(small_firmware)
        ctx2 = ingest.ingest(small_firmware)

        assert ctx1.file_hash_sha256 == ctx2.file_hash_sha256
        assert ctx1.file_hash_md5 == ctx2.file_hash_md5

    def test_deterministic_size_category(
        self, small_firmware: Path, output_config: ScannerConfig
    ) -> None:
        """Same file always classifies to same size category."""
        ingest = FirmwareIngest(output_config)
        ctx1 = ingest.ingest(small_firmware)
        ctx2 = ingest.ingest(small_firmware)

        assert ctx1.size_category == ctx2.size_category


# ──────────────────────────────────────────────
# Exit codes
# ──────────────────────────────────────────────


class TestExitCodes:
    """Verify exception exit codes match SDR §15 specification."""

    def test_not_found_exit_code(self) -> None:
        assert FirmwareNotFoundError.exit_code == 3

    def test_empty_exit_code(self) -> None:
        assert FirmwareEmptyError.exit_code == 3

    def test_too_large_exit_code(self) -> None:
        assert FirmwareTooLargeError.exit_code == 3

    def test_unreadable_exit_code(self) -> None:
        assert FirmwareUnreadableError.exit_code == 3

    def test_path_traversal_exit_code(self) -> None:
        assert FirmwarePathTraversalError.exit_code == 2
