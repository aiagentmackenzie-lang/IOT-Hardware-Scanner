"""Binary Intelligence — Phase 3b.

Extract metadata from ELF/PE/Mach-O binaries found in firmware.
Checks binary hardening and extracts version strings.

SDR §9.2 — Binary Intelligence

Hardening checks (OWASP FSTM Stage 5 / checksec pattern):
- NX (No Execute stack)
- Stack canary (__stack_chk_fail)
- PIE (Position-Independent Executable)
- RELRO (Relocation Read-Only)
- FORTIFY_SOURCE (__ fortified symbols)

Version strings feed into CVE Scanner (Phase 5).
"""

from __future__ import annotations

import logging
import re
import subprocess
from pathlib import Path

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.models import (
    BinaryHardening,
    BinaryIntelligenceResult,
    BinaryMetadata,
    FileCategory,
    ScanContext,
    SoftwareComponent,
)

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# SDR §9.2 Version String Extraction Patterns
# ──────────────────────────────────────────────

VERSION_PATTERNS: dict[str, re.Pattern[str]] = {
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

# CPE vendor/product mapping (SDR §9.2)
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

# Architecture detection from file type strings
ARCH_MAP: dict[str, str] = {
    "mips": "MIPS",
    "arm": "ARM",
    "x86-64": "x86_64",
    "x86_64": "x86_64",
    "x86": "x86",
    "powerpc": "PowerPC",
    "risc-v": "RISC-V",
    "riscv": "RISC-V",
    "aarch64": "AArch64",
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

        # Phase 2b inventory of binaries
        if context.filesystem_inventory:
            binary_findings = context.filesystem_inventory.categories.get(
                FileCategory.CRITICAL_BINARY, []
            )
            for finding in binary_findings:
                meta = self._analyze_binary(finding.absolute_path, finding.path)
                if meta:
                    binaries.append(meta)
                    for product, version in meta.version_strings.items():
                        if product in CPE_MAP:
                            vendor, prod = CPE_MAP[product]
                            components.append(
                                SoftwareComponent(
                                    vendor=vendor,
                                    product=prod,
                                    version=version,
                                    cpe_string=(f"cpe:2.3:a:{vendor}:{prod}:{version}"),
                                    source_file=finding.path,
                                    source_method="string_extraction",
                                )
                            )

        # Also scan raw firmware for version strings
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

        logger.info(
            "Binary intelligence: %d binaries, %d hardened, %d unhardened, %d software components",
            len(binaries),
            hardened,
            unhardened,
            len(components),
        )

        return BinaryIntelligenceResult(
            binaries=binaries,
            total_binaries=len(binaries),
            hardened_binaries=hardened,
            unhardened_binaries=unhardened,
        )

    def _analyze_binary(self, abs_path: Path, rel_path: Path) -> BinaryMetadata | None:
        """Analyze a single binary file for metadata and hardening."""
        try:
            file_type = self._get_file_type(abs_path)
        except (OSError, PermissionError):
            return None

        # Only analyze ELF binaries for hardening
        if "elf" not in file_type.lower() and "executable" not in file_type.lower():
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

    def _extract_version_strings(self, path: Path) -> dict[str, str]:
        """Extract version strings from a binary using SDR patterns."""
        versions: dict[str, str] = {}
        try:
            # Only read first 2MB for speed
            data = path.read_bytes()[: 2 * 1024 * 1024]
            text = data.decode("ascii", errors="ignore")
            for product, pattern in VERSION_PATTERNS.items():
                match = pattern.search(text)
                if match:
                    versions[product] = match.group(1)
        except (OSError, PermissionError):
            logger.debug("Cannot read %s for version extraction", path)
        return versions

    def _get_file_type(self, path: Path) -> str:
        """Get file type description using python-magic or extension."""
        try:
            import magic

            return magic.from_file(str(path))
        except (ImportError, Exception):
            # Fallback: check ELF magic bytes
            try:
                header = path.open("rb").read(16)
                if header[:4] == b"\x7fELF":
                    return "ELF executable"
                if header[:2] == b"MZ":
                    return "PE executable"
                if header[:4] == b"\xfe\xed\xfa\xce":
                    return "Mach-O executable"
            except (OSError, PermissionError):
                pass
            ext = path.suffix.lower()
            return ext if ext else "unknown"

    def _detect_architecture(self, file_type: str) -> str | None:
        """Detect CPU architecture from file type string."""
        ft_lower = file_type.lower()
        # Check longer keys first to avoid partial matches
        for key in sorted(ARCH_MAP.keys(), key=len, reverse=True):
            if key in ft_lower:
                return ARCH_MAP[key]
        return None

    def _detect_endianness(self, file_type: str) -> str | None:
        """Detect endianness from file type string."""
        ft_lower = file_type.lower()
        if "msb" in ft_lower or "big endian" in ft_lower:
            return "big"
        if "lsb" in ft_lower or "little endian" in ft_lower:
            return "little"
        return None

    def _detect_link_type(self, path: Path) -> str | None:
        """Detect static vs dynamic linking."""
        try:
            data = path.read_bytes()[: 2 * 1024 * 1024]
            if b"libc.so" in data or b"ld-linux" in data:
                return "dynamic"
            return "static"
        except (OSError, PermissionError):
            return None

    def _check_hardening(self, path: Path) -> BinaryHardening:
        """Check binary hardening flags (NX, canary, PIE, RELRO, FORTIFY).

        Uses readelf on Linux, otool on macOS. Falls back gracefully
        on unsupported platforms.
        """
        hardening = BinaryHardening()

        try:
            # Try readelf (Linux/ELF)
            result = subprocess.run(
                ["readelf", "-lW", str(path)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                output = result.stdout.lower()
                # NX: GNU_STACK segment without 'E' (execute) flag
                if "gnu_stack" in output:
                    stack_line = ""
                    for line in output.splitlines():
                        if "gnu_stack" in line:
                            stack_line = line
                            break
                    hardening.nx_enabled = "rwe" not in stack_line
                else:
                    hardening.nx_enabled = True  # No stack = NX default

                # RELRO and canary from symbol table
                result = subprocess.run(
                    ["readelf", "-aW", str(path)],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    full_output = result.stdout
                    full_lower = full_output.lower()

                    hardening.stack_canary = "stack_chk_fail" in full_lower
                    hardening.relro = (
                        "full"
                        if "bind_now" in full_lower
                        else "partial"
                        if "relro" in full_lower
                        else "none"
                    )
                    hardening.fortify_source = "__fortified" in full_lower or "_chk@" in full_lower

                # PIE from ELF header
                result = subprocess.run(
                    ["readelf", "-h", str(path)],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    header_lower = result.stdout.lower()
                    hardening.pie_enabled = "dyn" in header_lower or "shared" in header_lower

                return hardening

        except (FileNotFoundError, subprocess.TimeoutExpired):
            logger.debug("readelf not available, trying otool")

        try:
            # Try otool (macOS/Mach-O)
            result = subprocess.run(
                ["otool", "-hv", str(path)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                output = result.stdout.lower()
                hardening.pie_enabled = "pie" in output
                hardening.nx_enabled = True  # macOS defaults to NX

        except (FileNotFoundError, subprocess.TimeoutExpired):
            logger.debug("Neither readelf nor otool available for %s", path)

        return hardening

    def _is_hardened(self, h: BinaryHardening) -> bool:
        """Check if a binary has basic hardening enabled."""
        if h.nx_enabled is False:
            return False
        if h.stack_canary is False:
            return False
        return h.pie_enabled is not False
