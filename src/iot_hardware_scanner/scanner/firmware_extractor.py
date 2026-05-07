"""Firmware Extractor — Phase 2a.

Extracts embedded filesystems from firmware images using binwalk.

SDR §8.1 — Extraction Engine

Security safeguards:
- Disk space check (3x firmware size) before extraction
- Post-extraction symlink audit (Zip-Slip mitigation)
- Timeout enforcement (default 300s)
- Path traversal protection on extracted paths
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.exceptions import (
    BinwalkNotFoundError,
    DiskSpaceError,
    ExtractionFailedError,
)
from iot_hardware_scanner.models import ExtractionResult, SignatureResult

logger = logging.getLogger(__name__)


class FirmwareExtractor:
    """Extract embedded filesystems from firmware using binwalk.

    Uses pybinwalk (native Python API) when available, falls back
    to subprocess invocation of the binwalk CLI.

    Security:
    - Validates disk space before extraction (SDR §8.1: 3x firmware size)
    - Audits extracted filesystem for dangerous symlinks (Zip-Slip mitigation)
    - Enforces extraction timeout (default 300s)
    """

    def __init__(self, config: ScannerConfig) -> None:
        self.config = config
        self._binwalk_available = self._check_binwalk()

    def _check_binwalk(self) -> bool:
        """Check if binwalk is available on the system."""
        try:
            import pybinwalk  # noqa: F401

            return True
        except ImportError:
            pass
        return shutil.which("binwalk") is not None

    def scan(self, firmware_path: Path) -> list[SignatureResult]:
        """Identify embedded files/data via binwalk signature scan (no extraction).

        Raises:
            BinwalkNotFoundError: binwalk not installed.
        """
        if not self._binwalk_available:
            raise BinwalkNotFoundError("binwalk not found. Install pybinwalk or binwalk CLI.")

        signatures: list[SignatureResult] = []
        try:
            import pybinwalk

            results = pybinwalk.scan(str(firmware_path))
            for r in results:
                signatures.append(
                    SignatureResult(
                        offset=r.offset,
                        description=r.description,
                        size=getattr(r, "size", None),
                        filesystem_type=self._classify_filesystem(r.description),
                    )
                )
        except ImportError:
            result = subprocess.run(
                ["binwalk", str(firmware_path)],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode != 0:
                logger.warning("binwalk scan returned non-zero: %s", result.stderr)
            signatures = self._parse_binwalk_output(result.stdout)

        logger.info(
            "Binwalk scan: %d signatures found in %s",
            len(signatures),
            firmware_path.name,
        )
        return signatures

    def extract(self, firmware_path: Path, output_dir: Path) -> ExtractionResult:
        """Extract embedded filesystems recursively.

        Args:
            firmware_path: Path to firmware image.
            output_dir: Directory for extracted contents.

        Returns:
            ExtractionResult with paths to all extracted root filesystems.

        Raises:
            BinwalkNotFoundError: binwalk not installed.
            ExtractionFailedError: extraction failed.
            DiskSpaceError: insufficient disk space.
        """
        if not self._binwalk_available:
            raise BinwalkNotFoundError("binwalk not found. Install pybinwalk or binwalk CLI.")

        firmware_path = Path(firmware_path).resolve()
        firmware_size = firmware_path.stat().st_size

        # ── Disk space check (SDR §8.1: 3x firmware size) ──
        self._check_disk_space(firmware_size, output_dir)

        extraction_dir = output_dir / f"_{firmware_path.name}.extracted"
        extraction_dir.mkdir(parents=True, exist_ok=True)

        errors: list[str] = []
        signatures: list[SignatureResult] = []

        try:
            import pybinwalk

            results = pybinwalk.extract(str(firmware_path), str(extraction_dir))
            for r in results or []:
                signatures.append(
                    SignatureResult(
                        offset=r.offset,
                        description=r.description,
                        filesystem_type=self._classify_filesystem(r.description),
                    )
                )
        except ImportError:
            # Fallback subprocess extraction
            try:
                result = subprocess.run(
                    [
                        "binwalk",
                        "-e",
                        "-C",
                        str(extraction_dir),
                        str(firmware_path),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=self.config.extraction_timeout_seconds,
                )
            except subprocess.TimeoutExpired:
                raise ExtractionFailedError(
                    f"binwalk extraction timed out after {self.config.extraction_timeout_seconds}s"
                ) from None

            if result.returncode != 0 and not extraction_dir.exists():
                raise ExtractionFailedError(f"binwalk extraction failed: {result.stderr}") from None
            if result.returncode != 0:
                errors.append(f"binwalk returned code {result.returncode}: {result.stderr[:200]}")
            signatures = self._parse_binwalk_output(result.stdout)
        except Exception as exc:
            raise ExtractionFailedError(f"Extraction failed: {exc}") from exc

        # ── Post-extraction symlink audit (Zip-Slip mitigation) ──
        removed_symlinks = self._audit_symlinks(extraction_dir)
        if removed_symlinks:
            errors.append(f"Removed {removed_symlinks} symlinks pointing outside extraction root")

        # ── Find extracted root filesystems ──
        root_filesystems = self.get_root_filesystems(extraction_dir)

        # ── Count extracted files and total size ──
        file_count = 0
        total_size = 0
        if extraction_dir.exists():
            for f in extraction_dir.rglob("*"):
                if f.is_file() and not f.is_symlink():
                    file_count += 1
                    total_size += f.stat().st_size

        logger.info(
            "Extraction complete: %d files, %d root filesystems, %d bytes extracted",
            file_count,
            len(root_filesystems),
            total_size,
        )

        return ExtractionResult(
            success=True,
            extraction_dir=extraction_dir,
            root_filesystems=root_filesystems,
            file_count=file_count,
            total_size=total_size,
            signatures_detected=signatures,
            extraction_errors=errors,
        )

    def get_root_filesystems(self, extraction_dir: Path) -> list[Path]:
        """Return paths to all extracted root filesystem directories."""
        root_fs_names = {
            "squashfs-root",
            "jffs2-root",
            "ubifs-root",
            "cpio-root",
            "rootfs",
        }
        found: list[Path] = []

        if not extraction_dir.exists():
            return found

        for d in extraction_dir.rglob("*"):
            if d.is_dir() and d.name in root_fs_names:
                found.append(d)

        # Also look for squashfs-root inside numbered extraction dirs
        for d in extraction_dir.rglob("*.squashfs"):
            parent = d.parent
            if parent.is_dir() and parent not in found:
                found.append(parent)

        return found

    def _check_disk_space(self, firmware_size: int, output_dir: Path) -> None:
        """Verify sufficient disk space for extraction.

        SDR §8.1: Requires at least 3x firmware file size free.
        """
        multiplier = self.config.disk_space_multiplier
        required = int(firmware_size * multiplier)
        output_dir.mkdir(parents=True, exist_ok=True)

        disk_usage = shutil.disk_usage(str(output_dir))
        free_space = disk_usage.free

        if free_space < required:
            raise DiskSpaceError(
                f"Insufficient disk space: {free_space:,} bytes free, "
                f"{required:,} bytes required "
                f"({multiplier}x firmware size of {firmware_size:,} bytes)"
            )

        logger.info(
            "Disk space check passed: %s free, %s required",
            _fmt_size(free_space),
            _fmt_size(required),
        )

    def _audit_symlinks(self, extraction_dir: Path) -> int:
        """Remove symlinks pointing outside the extraction root.

        Zip-Slip mitigation: prevents malicious firmware from creating
        symlinks that escape the extraction sandbox.
        """
        removed = 0
        if not extraction_dir.exists():
            return removed

        root = extraction_dir.resolve()

        for item in extraction_dir.rglob("*"):
            if item.is_symlink():
                try:
                    target = item.resolve()
                    # Check if target escapes extraction root
                    try:
                        target.relative_to(root)
                    except ValueError:
                        logger.warning(
                            "Removing unsafe symlink: %s -> %s (escapes extraction root)",
                            item,
                            target,
                        )
                        item.unlink()
                        removed += 1
                except OSError:
                    # Broken symlink
                    item.unlink()
                    removed += 1

        return removed

    def _classify_filesystem(self, description: str) -> str | None:
        """Classify filesystem type from binwalk description."""
        desc_lower = description.lower()
        fs_types = {
            "squashfs": "SquashFS",
            "jffs2": "JFFS2",
            "ubifs": "UBIFS",
            "cramfs": "CramFS",
            "cpio": "CPIO",
            "romfs": "ROMFS",
            "yaffs": "YAFFS2",
            "gzip": "gzip",
            "lzma": "LZMA",
            "u-boot": "U-Boot",
        }
        for key, fs_type in fs_types.items():
            if key in desc_lower:
                return fs_type
        return None

    def _parse_binwalk_output(self, output: str) -> list[SignatureResult]:
        """Parse binwalk CLI text output into SignatureResult objects."""
        signatures: list[SignatureResult] = []
        for line in output.strip().splitlines():
            line = line.strip()
            if not line or line.startswith("DECIMAL") or line.startswith("0x"):
                continue
            parts = line.split(None, 2)
            if len(parts) >= 2:
                try:
                    offset = int(parts[0], 0) if parts[0].startswith("0x") else int(parts[0])
                    desc = parts[2] if len(parts) > 2 else parts[1]
                    signatures.append(
                        SignatureResult(
                            offset=offset,
                            description=desc,
                            filesystem_type=self._classify_filesystem(desc),
                        )
                    )
                except (ValueError, IndexError):
                    continue
        return signatures


def _fmt_size(n: int) -> str:
    """Format byte count as human-readable size."""
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024  # type: ignore[assignment]
    return f"{n:.1f} TB"
