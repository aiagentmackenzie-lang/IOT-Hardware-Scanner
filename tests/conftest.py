"""Shared test fixtures for IoT Hardware Scanner."""

import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.models import FirmwareSizeCategory, ScanContext


@pytest.fixture
def config() -> ScannerConfig:
    """Default scanner config for testing."""
    return ScannerConfig()


@pytest.fixture
def temp_dir() -> Path:
    """Create a temporary directory for test outputs."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def output_config(temp_dir: Path) -> ScannerConfig:
    """Scanner config with a temporary output directory."""
    return ScannerConfig(output_dir=temp_dir / "reports")


@pytest.fixture
def small_firmware(temp_dir: Path) -> Path:
    """Create a small test firmware file (~1KB)."""
    firmware = temp_dir / "test_firmware.bin"
    firmware.write_bytes(os.urandom(1024))
    return firmware


@pytest.fixture
def medium_firmware(temp_dir: Path) -> Path:
    """Create a medium test firmware file (~100KB)."""
    firmware = temp_dir / "medium_firmware.bin"
    firmware.write_bytes(os.urandom(100 * 1024))
    return firmware


@pytest.fixture
def empty_firmware(temp_dir: Path) -> Path:
    """Create an empty firmware file."""
    firmware = temp_dir / "empty.bin"
    firmware.write_bytes(b"")
    return firmware


@pytest.fixture
def large_firmware_name(temp_dir: Path) -> Path:
    """Return a path for a firmware file that exceeds size limits.

    We don't actually create a large file — just test the size check
    with a very low max_file_size_mb.
    """
    firmware = temp_dir / "large.bin"
    firmware.write_bytes(os.urandom(2048))  # 2KB file
    return firmware


@pytest.fixture
def sample_scan_context(temp_dir: Path) -> ScanContext:
    """Create a sample ScanContext for testing later phases."""
    return ScanContext(
        scan_id="test-scan-001",
        firmware_path=temp_dir / "test.bin",
        output_dir=temp_dir / "output",
        file_hash_sha256="a" * 64,
        file_hash_md5="b" * 32,
        file_size=1024,
        file_type="ELF 32-bit LSB executable, MIPS",
        firmware_name="test",
        size_category=FirmwareSizeCategory.SMALL,
        started_at=datetime.now(timezone.utc),
    )
