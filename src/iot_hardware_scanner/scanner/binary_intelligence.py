"""Binary Intelligence — Phase 3b.

Extract metadata from ELF/PE/Mach-O binaries found in firmware.
Checks binary hardening and extracts version strings.

SDR §9.2 — Binary Intelligence
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.models import (
    BinaryHardening,
    BinaryIntelligenceResult,
    BinaryMetadata,
    ScanContext,
    SoftwareComponent,
)

logger = logging.getLogger(__name__)

# SDR §9.2 Version String Extraction Patterns
VERSION_PATTERNS: dict[str, re.Pattern] = {
    "busybox": re.compile(r"BusyBox\s+v?([\d.]+)"),
    "openssl": re.compile(r"OpenSSL\s+([\d.]+[a-z]?)"),
    "dropbear": re.compile(r"Dropbear\s+ssh\s+([\d.]+)"),
    "dnsmasq": re.compile(r"dnsmasq\s+([\d.]+)"),
    "nginx": re.compile(r"nginx/([\d.]+)"),
    "lighttpd": re.compile(r"lighttpd/([\d.]+)"),
    "linux_kernel": re.compile(r"Linux\s+version\s+([\d.]+)"),
    "u_boot": re.compile(r"U-Boot\s+([\d.]+)"),
    "curl": re.compile(r"libcurl/([\d.]+)"),
    "openssh": re.compile(r"OpenSSH_([\d.]+p\d+)"),
    "zlib": re.compile(r"zlib\s+([\d.]+)"),
    "sqlite": re.compile(r"SQLite\s+version\s+([\d.]+)"),
}

# CPE vendor/product mapping
CPE_MAP: dict[str, tuple[str, str]] = {
    "busybox": ("busybox", "busybox"),
    "openssl": ("openssl", "openssl"),
    "dropbear": ("matt_johnston", "dropbear_ssh"),
    "dnsmasq": ("thekelleys", "dnsmasq"),
    "nginx": ("f5", "nginx"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "linux_kernel": ("linux", "linux_kernel"),
    "u_boot": ("denx", "u-boot"),
    "curl": ("haxx", "curl"),
    "openssh": ("openbsd", "openssh"),
    "zlib": ("zlib", "zlib"),
    "sqlite": ("sqlite", "sqlite"),
}


class BinaryIntelligence:
    """Extract metadata and hardening info from firmware binaries."""

    def __init__(self, config: ScannerConfig) -> None:
        self.config = config

    def analyze(self, context: ScanContext) -> BinaryIntelligenceResult:
        """Analyze all binaries found in the firmware.

        Extracts architecture, hardening checks, and version strings.
        Version strings feed into the CVE scanner (Phase 5).
        """
        binaries: list[BinaryMetadata] = []
        components: list[SoftwareComponent] = []

        # Get list of binary files to analyze
        if context.filesystem_inventory:
            binary_findings = context.filesystem_inventory.categories.get(
                # Will look at CRITICAL_BINARY category
                # Import the enum
                __import__(
                    "iot_hardware_scanner.models", fromlist=["FileCategory"]
                ).FileCategory.CRITICAL_BINARY,
                [],
            )
            for finding in binary_findings:
                meta = self._analyze_binary(finding.absolute_path, finding.path)
                if meta:
                    binaries.append(meta)
                    # Extract version strings → software components
                    for product, version in meta.version_strings.items():
                        if product in CPE_MAP:
                            vendor, prod = CPE_MAP[product]
                            components.append(
                                SoftwareComponent(
                                    vendor=vendor,
                                    product=prod,
                                    version=version,
                                    cpe_string=f"cpe:2.3:a:{vendor}:{prod}:{version}",
                                    source_file=finding.path,
                                    source_method="string_extraction",
                                )
                            )
        else:
            # No filesystem inventory — scan the raw firmware
            meta = self._analyze_raw_firmware(context.firmware_path)
            if meta:
                binaries.append(meta)

        # Also scan raw firmware for version strings (catches embedded strings
        # not in extracted binaries)
        raw_versions = self._extract_version_strings(context.firmware_path)
        for product, version in raw_versions.items():
            if product in CPE_MAP and not any(c.product == CPE_MAP[product][1] for c in components):
                vendor, prod = CPE_MAP[product]
                components.append(
                    SoftwareComponent(
                        vendor=vendor,
                        product=prod,
                        version=version,
                        cpe_string=f"cpe:2.3:a:{vendor}:{prod}:{version}",
                        source_file=Path(context.firmware_path.name),
                        source_method="string_extraction",
                    )
                )

        context.software_components = components

        hardened = sum(1 for b in binaries if self._is_hardened(b.hardening))
        unhardened = len(binaries) - hardened

        return BinaryIntelligenceResult(
            binaries=binaries,
            total_binaries=len(binaries),
            hardened_binaries=hardened,
            unhardened_binaries=unhardened,
        )

    def _analyze_binary(self, abs_path: Path, rel_path: Path) -> BinaryMetadata | None:
        """Analyze a single binary file."""
        try:
            file_type = self._get_file_type(abs_path)
        except (OSError, PermissionError):
            return None

        if "elf" not in file_type.lower():
            return None

        arch = self._detect_architecture(file_type)
        endianness = self._detect_endianness(file_type)
        link_type = self._detect_link_type(abs_path)
        hardening = self._check_hardening(abs_path)
        version_strings = self._extract_version_strings(abs_path)

        return BinaryMetadata(
            path=rel_path,
            architecture=arch,
            endianness=endianness,
            link_type=link_type,
            hardening=hardening,
            version_strings=version_strings,
        )

    def _analyze_raw_firmware(self, path: Path) -> BinaryMetadata | None:
        """Analyze the raw firmware file as a potential ELF."""
        try:
            file_type = self._get_file_type(path)
        except (OSError, PermissionError):
            return None

        if "elf" not in file_type.lower():
            return None

        return BinaryMetadata(
            path=Path(path.name),
            architecture=self._detect_architecture(file_type),
            endianness=self._detect_endianness(file_type),
            version_strings=self._extract_version_strings(path),
        )

    def _extract_version_strings(self, path: Path) -> dict[str, str]:
        """Extract version strings from a binary using the SDR patterns."""
        versions: dict[str, str] = {}
        try:
            data = path.read_bytes()
            text = data.decode("ascii", errors="ignore")
            for product, pattern in VERSION_PATTERNS.items():
                match = pattern.search(text)
                if match:
                    versions[product] = match.group(1)
        except (OSError, PermissionError, MemoryError):
            logger.debug("Cannot read %s for version extraction", path)
        return versions

    def _get_file_type(self, path: Path) -> str:
        """Get file type description."""
        try:
            import magic

            return magic.from_file(str(path))
        except (ImportError, Exception):
            return ""

    def _detect_architecture(self, file_type: str) -> str | None:
        """Detect CPU architecture from file type string."""
        ft_lower = file_type.lower()
        arch_map = {
            "mips": "MIPS",
            "arm": "ARM",
            "x86": "x86",
            "x86-64": "x86_64",
            "powerpc": "PowerPC",
            "riscv": "RISC-V",
            "aarch64": "AArch64",
        }
        for key, arch in arch_map.items():
            if key in ft_lower:
                return arch
        return None

    def _detect_endianness(self, file_type: str) -> str | None:
        """Detect endianness from file type string."""
        ft_lower = file_type.lower()
        if "msb" in ft_lower or "big" in ft_lower:
            return "big"
        if "lsb" in ft_lower or "little" in ft_lower:
            return "little"
        return None

    def _detect_link_type(self, path: Path) -> str | None:
        """Detect static vs dynamic linking."""
        try:
            data = path.read_bytes()
            if b"libc.so" in data or b"ld-linux" in data:
                return "dynamic"
            return "static"
        except (OSError, PermissionError):
            return None

    def _check_hardening(self, path: Path) -> BinaryHardening:
        """Check binary hardening flags (NX, canary, PIE, RELRO, FORTIFY)."""
        hardening = BinaryHardening()

        try:
            import subprocess

            # Try readelf for NX/PIE/RELRO
            result = subprocess.run(
                ["readelf", "-lW", str(path)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            output = result.stdout.lower()
            hardening.nx_enabled = (
                "gnu_stack" not in output or "e " not in output.split("gnu_stack")[0][-20:]
            )

            result = subprocess.run(
                ["readelf", "-h", str(path)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            hardening.pie_enabled = "dyn" in result.stdout.lower()

            # Check for stack canary
            result = subprocess.run(
                ["readelf", "-aW", str(path)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            hardening.stack_canary = "stack_chk_fail" in result.stdout
            hardening.relro = (
                "full"
                if "bind_now" in result.stdout.lower()
                else "partial"
                if "relro" in result.stdout.lower()
                else "none"
            )
            hardening.fortify_source = "__fortified" in result.stdout or "_chk@" in result.stdout

        except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
            logger.debug("readelf not available or failed for %s", path)

        return hardening

    def _is_hardened(self, h: BinaryHardening) -> bool:
        """Check if a binary has basic hardening enabled."""
        if h.nx_enabled is False:
            return False
        if h.stack_canary is False:
            return False
        return h.pie_enabled is not False
