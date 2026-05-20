"""Firmware Ingest Module — Phase 1.

Validates, catalogs, and prepares firmware images for analysis.
This is the first module in the pipeline — every subsequent phase
depends on the ScanContext it produces.

SDR §7 — Core Infrastructure & Firmware Ingestion
"""

from __future__ import annotations

import hashlib
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.exceptions import (
    FirmwareEmptyError,
    FirmwareNotFoundError,
    FirmwarePathTraversalError,
    FirmwareTooLargeError,
    FirmwareUnreadableError,
)
from iot_hardware_scanner.models import (
    FirmwareMetadata,
    FirmwareSizeCategory,
    ScanContext,
)

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# Supported firmware extensions (SDR Appendix A)
# ──────────────────────────────────────────────

SUPPORTED_EXTENSIONS: set[str] = {
    ".bin",
    ".img",
    ".elf",
    ".hex",
    ".ihex",
    ".uf2",
    ".fw",
    ".uimg",
    ".squashfs",
    ".jffs2",
    ".ubifs",
    ".cpio",
    ".zip",
    ".tar",
    ".gz",
    ".tgz",
    ".bz2",
    ".xz",
    ".vmdk",
    ".srec",
    ".s19",
}


class FirmwareIngest:
    """Validate and catalog firmware images for analysis.

    This module is responsible for:
    1. Validating the firmware file (exists, readable, non-empty, size limits)
    2. Computing cryptographic hashes (SHA-256, MD5)
    3. Identifying file type via python-magic
    4. Creating the per-scan output directory
    5. Initializing the ScanContext object
    """

    def __init__(self, config: ScannerConfig) -> None:
        self.config = config

    def ingest(self, firmware_path: Path) -> ScanContext:
        """Validate and catalog the firmware image.

        Args:
            firmware_path: Path to the firmware file.

        Returns:
            ScanContext with firmware metadata populated.

        Raises:
            FirmwareNotFoundError: Path does not exist.
            FirmwareEmptyError: File is 0 bytes.
            FirmwareTooLargeError: File exceeds max_file_size_mb.
            FirmwareUnreadableError: Permission denied.
            FirmwarePathTraversalError: Path contains traversal sequences.
        """
        # ── Step 0: Safety checks (must be before Path.resolve()) ──
        original_path = Path(firmware_path)
        firmware_str = str(original_path)
        if "\x00" in firmware_str:
            raise FirmwarePathTraversalError(
                f"Path contains null byte: {firmware_str.split(chr(0))[0]}"
            )
        # Check for .. in original path before resolve() normalizes it
        if ".." in original_path.parts:
            raise FirmwarePathTraversalError(
                f"Path contains traversal sequence '..': {firmware_path}"
            )
        # Reject symlinks — check original path, not resolved
        if original_path.is_symlink():
            raise FirmwareNotFoundError(
                f"Symlinks are not accepted: {original_path}. "
                f"Provide the actual firmware file path."
            )

        firmware_path = Path(firmware_path).resolve()
        logger.info("Ingesting firmware: %s", firmware_path)

        # ── Step 2: File existence ──
        if not firmware_path.exists():
            raise FirmwareNotFoundError(f"Firmware file not found: {firmware_path}")

        # ── Step 3: Regular file check (no dirs or devices) ──
        if not firmware_path.is_file():
            raise FirmwareNotFoundError(
                f"Path is not a regular file: {firmware_path}. "
                f"Directories and device files are not accepted."
            )

        # ── Step 4: Readability check ──
        if not os.access(firmware_path, os.R_OK):
            raise FirmwareUnreadableError(f"Permission denied: {firmware_path}")

        # ── Step 5: Non-empty check ──
        file_size = firmware_path.stat().st_size
        if file_size == 0:
            raise FirmwareEmptyError(f"Firmware file is empty (0 bytes): {firmware_path}")

        # ── Step 6: Size limit check ──
        max_bytes = self.config.max_file_size_mb * 1024 * 1024
        if file_size > max_bytes:
            raise FirmwareTooLargeError(
                f"Firmware file too large: {file_size:,} bytes "
                f"(limit: {self.config.max_file_size_mb} MB). "
                f"Increase --max-size to allow larger files."
            )

        # ── Step 7: Compute hashes ──
        sha256, md5 = self._compute_hashes(firmware_path)
        logger.info("SHA-256: %s", sha256)
        logger.info("MD5:     %s", md5)

        # ── Step 8: Identify file type ──
        file_type = self._identify_file_type(firmware_path)
        logger.info("File type: %s", file_type)

        # ── Step 9: Determine size category ──
        size_category = self._classify_size(file_size)

        # ── Step 10: Create output directory ──
        firmware_name = firmware_path.stem
        scan_id = str(uuid.uuid4())
        output_dir = self._create_output_dir(firmware_name, scan_id)
        logger.info("Output directory: %s", output_dir)

        # ── Step 11: Build ScanContext ──
        context = ScanContext(
            scan_id=scan_id,
            firmware_path=firmware_path,
            output_dir=output_dir,
            file_hash_sha256=sha256,
            file_hash_md5=md5,
            file_size=file_size,
            file_type=file_type,
            firmware_name=firmware_name,
            size_category=size_category,
            started_at=datetime.now(timezone.utc),
        )

        logger.info(
            "Ingestion complete: %s (%s, %s)",
            firmware_name,
            file_type,
            size_category.value,
        )
        return context

    def get_metadata(self, firmware_path: Path) -> FirmwareMetadata:
        """Extract metadata without creating a full ScanContext.

        Useful for quick inspection and validation checks
        without the overhead of output directory creation.
        """
        original_path = Path(firmware_path)
        firmware_str = str(original_path)
        if "\x00" in firmware_str:
            raise FirmwarePathTraversalError(
                f"Path contains null byte: {firmware_str.split(chr(0))[0]}"
            )
        if ".." in original_path.parts:
            raise FirmwarePathTraversalError(
                f"Path contains traversal sequence '..': {firmware_path}"
            )
        if original_path.is_symlink():
            raise FirmwareNotFoundError(
                f"Symlinks are not accepted: {original_path}. "
                f"Provide the actual firmware file path."
            )

        firmware_path = Path(firmware_path).resolve()

        if not firmware_path.exists():
            raise FirmwareNotFoundError(f"Firmware file not found: {firmware_path}")
        if not firmware_path.is_file():
            raise FirmwareNotFoundError(f"Not a regular file: {firmware_path}")
        if not os.access(firmware_path, os.R_OK):
            raise FirmwareUnreadableError(f"Permission denied: {firmware_path}")

        file_size = firmware_path.stat().st_size
        if file_size == 0:
            raise FirmwareEmptyError(f"Firmware file is empty: {firmware_path}")

        sha256, md5 = self._compute_hashes(firmware_path)
        file_type = self._identify_file_type(firmware_path)

        return FirmwareMetadata(
            path=firmware_path,
            name=firmware_path.stem,
            size_bytes=file_size,
            size_category=self._classify_size(file_size),
            sha256=sha256,
            md5=md5,
            file_type=file_type,
            extension=firmware_path.suffix.lower(),
            is_regular_file=firmware_path.is_file(),
            is_readable=os.access(firmware_path, os.R_OK),
        )

    # ──────────────────────────────────────────
    # Private helpers
    # ──────────────────────────────────────────

    def _validate_path_safety(self, path: Path) -> None:
        """Check for path traversal sequences.

        SDR §7.1 Validation Rule 5: Filename must not contain
        path traversal sequences (..).

        Checks are performed on the raw input path BEFORE resolve(),
        because Path.resolve() normalizes away traversal sequences.
        Null bytes are checked in ingest() before resolve() is called.
        """
        for part in path.parts:
            if part == "..":
                raise FirmwarePathTraversalError(f"Path contains traversal sequence '..': {path}")

    def _compute_hashes(self, path: Path) -> tuple[str, str]:
        """Compute SHA-256 and MD5 hashes of the firmware file.

        Reads in 64KB chunks to handle large files without
        loading the entire file into memory.
        """
        sha256_hasher = hashlib.sha256()
        md5_hasher = hashlib.md5()

        with open(path, "rb") as f:
            while True:
                chunk = f.read(65536)  # 64 KB
                if not chunk:
                    break
                sha256_hasher.update(chunk)
                md5_hasher.update(chunk)

        return sha256_hasher.hexdigest(), md5_hasher.hexdigest()

    def _identify_file_type(self, path: Path) -> str:
        """Identify file type using python-magic or fallback to extension.

        python-magic reads magic bytes from the file header,
        which is far more reliable than extension-based detection.
        Falls back to extension matching if magic is unavailable.
        """
        try:
            import magic

            file_type = magic.from_file(str(path), mime=True)
            # Also get the descriptive type for richer output
            desc_type = magic.from_file(str(path))
            return f"{desc_type} ({file_type})"
        except ImportError:
            logger.warning(
                "python-magic not installed. Falling back to extension-based detection. "
                "Install python-magic for accurate file type identification."
            )
            return self._identify_by_extension(path)
        except Exception as exc:
            logger.warning("Magic detection failed (%s). Falling back to extension.", exc)
            return self._identify_by_extension(path)

    def _identify_by_extension(self, path: Path) -> str:
        """Fallback file type identification by extension."""
        ext = path.suffix.lower()
        ext_map = {
            ".bin": "Raw binary firmware image",
            ".img": "U-Boot/disk image",
            ".elf": "ELF executable",
            ".hex": "Intel HEX microcontroller firmware",
            ".ihex": "Intel HEX microcontroller firmware",
            ".uf2": "USB Flashing Format (UF2)",
            ".fw": "Generic firmware package",
            ".squashfs": "SquashFS filesystem",
            ".jffs2": "JFFS2 filesystem",
            ".ubifs": "UBIFS filesystem",
            ".cpio": "CPIO archive (initramfs)",
            ".zip": "ZIP archive",
            ".tar": "TAR archive",
            ".gz": "Gzip compressed archive",
            ".vmdk": "VMware virtual disk",
        }
        return ext_map.get(ext, f"Unknown file type (extension: {ext})")

    def _classify_size(self, size_bytes: int) -> FirmwareSizeCategory:
        """Classify firmware by size for analysis strategy selection.

        SDR §7.1 File Size Limits:
        - SMALL:  < 50 MB   → full analysis, small block size
        - MEDIUM: 50-500 MB → full analysis, adaptive block size
        - LARGE:  500 MB-2GB → selective analysis, larger block size
        - > 2GB: rejected by size limit check
        """
        mb = size_bytes / (1024 * 1024)
        if mb < 50:
            return FirmwareSizeCategory.SMALL
        elif mb < 500:
            return FirmwareSizeCategory.MEDIUM
        else:
            return FirmwareSizeCategory.LARGE

    def _create_output_dir(self, firmware_name: str, scan_id: str) -> Path:
        """Create per-scan output directory.

        Pattern: <base_output_dir>/scan-<date>-<short_id>/
        If no output_dir configured, use CWD/reports/.
        """
        base = self.config.output_dir or Path.cwd() / "reports"
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        short_id = scan_id[:8]
        output_dir = base / f"scan-{timestamp}-{short_id}"
        output_dir.mkdir(parents=True, exist_ok=True)
        return output_dir
