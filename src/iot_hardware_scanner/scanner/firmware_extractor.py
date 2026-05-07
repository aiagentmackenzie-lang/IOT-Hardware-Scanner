"""Firmware Extractor — Phase 2a.

Extracts embedded filesystems from firmware images using binwalk.

SDR §8.1 — Extraction Engine
"""

from __future__ import annotations

import logging
from pathlib import Path

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.exceptions import BinwalkNotFoundError, ExtractionFailedError
from iot_hardware_scanner.models import ExtractionResult, SignatureResult

logger = logging.getLogger(__name__)


class FirmwareExtractor:
    """Extract embedded filesystems from firmware using binwalk.

    Uses pybinwalk (native Python API) when available, falls back
    to subprocess invocation of the binwalk CLI.
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
        try:
            import shutil

            return shutil.which("binwalk") is not None
        except Exception:
            return False

    def scan(self, firmware_path: Path) -> list[SignatureResult]:
        """Identify embedded files/data via binwalk signature scan (no extraction)."""
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
            # Fallback to subprocess
            import subprocess

            result = subprocess.run(
                ["binwalk", str(firmware_path)],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode != 0:
                logger.warning("binwalk scan returned non-zero: %s", result.stderr)
            signatures = self._parse_binwalk_output(result.stdout)

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
        """
        if not self._binwalk_available:
            raise BinwalkNotFoundError("binwalk not found. Install pybinwalk or binwalk CLI.")

        extraction_dir = output_dir / f"_{firmware_path.name}.extracted"
        extraction_dir.mkdir(parents=True, exist_ok=True)

        try:
            import pybinwalk

            results = pybinwalk.extract(str(firmware_path), str(extraction_dir))
            signatures = [
                SignatureResult(
                    offset=r.offset,
                    description=r.description,
                    filesystem_type=self._classify_filesystem(r.description),
                )
                for r in (results or [])
            ]
        except ImportError:
            # Fallback subprocess extraction
            import subprocess

            result = subprocess.run(
                ["binwalk", "-e", "-C", str(extraction_dir), str(firmware_path)],
                capture_output=True,
                text=True,
                timeout=self.config.extraction_timeout_seconds,
            )
            if result.returncode != 0 and not extraction_dir.exists():
                raise ExtractionFailedError(
                    f"binwalk extraction failed: {result.stderr}"
                ) from None
            signatures = self._parse_binwalk_output(result.stdout)
        except Exception as exc:
            raise ExtractionFailedError(f"Extraction failed: {exc}") from exc

        # Find extracted root filesystems
        root_filesystems = self.get_root_filesystems(extraction_dir)

        # Count extracted files
        file_count = 0
        total_size = 0
        if extraction_dir.exists():
            for f in extraction_dir.rglob("*"):
                if f.is_file():
                    file_count += 1
                    total_size += f.stat().st_size

        return ExtractionResult(
            success=True,
            extraction_dir=extraction_dir,
            root_filesystems=root_filesystems,
            file_count=file_count,
            total_size=total_size,
            signatures_detected=signatures,
        )

    def get_root_filesystems(self, extraction_dir: Path) -> list[Path]:
        """Return paths to all extracted root filesystem directories."""
        root_fs_names = {"squashfs-root", "jffs2-root", "ubifs-root", "cpio-root", "rootfs"}
        found: list[Path] = []

        if not extraction_dir.exists():
            return found

        for d in extraction_dir.rglob("*"):
            if d.is_dir() and d.name in root_fs_names:
                found.append(d)

        # Also look for common patterns like *.extracted/*/squashfs-root
        for d in extraction_dir.rglob("*.squashfs"):
            parent = d.parent
            if parent.is_dir() and parent not in found:
                found.append(parent)

        return found

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
