"""Binary Intelligence — Phase 3b.

Metadata from ELF binaries found in firmware: identity, dependencies, hardening
evidence and version strings.

Two routes, deliberately separated by confidence
------------------------------------------------
**Structures (recorded).** An ELF file is identified by its header and parsed by
:mod:`iot_hardware_scanner.scanner.elf_parser`. Class, byte order, machine,
interpreter, dependencies, segments, build ID, stack permission, PIE, RELRO and
— where symbols exist — canary and FORTIFY all come from the file's own
structures. This is the route the report treats as evidence.

**Banners (candidate).** Version strings found in a file are a hint: a string
that says ``BusyBox v1.30.0`` in a README is not an installed package. Banner
records are kept, marked ``confidence="candidate"``, and the installed-package
database (slice 4B) outranks them.

All reads are bounded windows that keep their original offsets; there is no
``read()`` of an arbitrary-size file and no host tool in the path.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.intelligence.cpe_builder import PRODUCT_CPE_MAP, cpe_name, lookup
from iot_hardware_scanner.models import (
    BinaryHardening,
    BinaryIntelligenceResult,
    BinaryMetadata,
    ElfReport,
    FileCategory,
    ScanContext,
    SoftwareComponent,
)
from iot_hardware_scanner.scanner.bounded_reader import open_bounded
from iot_hardware_scanner.scanner.elf_parser import ElfParseError, looks_like_elf, parse_elf

logger = logging.getLogger(__name__)

#: One mapping for the whole scanner. Kept as a module attribute because the
#: banner route and the advisory route must never disagree about a product.
CPE_MAP = PRODUCT_CPE_MAP

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

# Architecture detection from file type strings (host ``file`` output only).
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

#: Banner scan window. Version strings live in the first windows of a binary, so
#: a bounded head is enough and keeps a large library out of memory.
BANNER_WINDOW = 2 * 1024 * 1024


class BinaryIntelligence:
    """Extract metadata and hardening evidence from firmware binaries."""

    def __init__(self, config: ScannerConfig) -> None:
        self.config = config

    # ──────────────────────────────────────────
    # Entry point
    # ──────────────────────────────────────────

    def analyze(self, context: ScanContext) -> BinaryIntelligenceResult:
        """Analyze every ELF file the inventory reached, plus a top-level input."""
        binaries: list[BinaryMetadata] = []
        reports: list[ElfReport] = []
        components: list[SoftwareComponent] = []
        rejected: list[dict[str, str]] = []

        inventory = context.filesystem_inventory
        eligible = 0
        if inventory is not None:
            for finding in inventory.findings:
                if finding.format != "elf":
                    continue
                eligible += 1
                record = self._parse(finding.absolute_path, str(finding.path), rejected)
                if record is None:
                    continue
                record.digest_sha256 = finding.hash_sha256
                record.artifact_id = getattr(finding, "artifact_id", None)
                reports.append(record)
                binaries.append(self._to_metadata(finding.absolute_path, finding.path, record))

        # A top-level ELF (``scan ./app``) is analysed the same way, not just
        # string-scanned: the file *is* the population.
        if inventory is None and context.input_kind.value == "file":
            source = (
                context.input_snapshot.snapshot_path
                if context.input_snapshot
                else (context.firmware_path)
            )
            if looks_like_elf(source):
                eligible += 1
                record = self._parse(source, context.firmware_path.name, rejected)
                if record is not None:
                    record.digest_sha256 = context.file_hash_sha256
                    reports.append(record)
                    binaries.append(
                        self._to_metadata(source, Path(context.firmware_path.name), record)
                    )

        components.extend(self._banner_components(context, binaries))

        context.elf_metadata = reports
        context.software_components = self._merge_components(
            existing=context.software_components, new=components
        )

        hardened = sum(1 for binary in binaries if self._is_hardened(binary.hardening))
        result = BinaryIntelligenceResult(
            binaries=binaries,
            total_binaries=len(binaries),
            hardened_binaries=hardened,
            unhardened_binaries=len(binaries) - hardened,
            rejected=rejected,
        )
        logger.info(
            "Binary intelligence: %d ELF file(s) of %d eligible, %d hardened, %d component(s), "
            "%d rejected",
            len(binaries),
            eligible,
            hardened,
            len(components),
            len(rejected),
        )
        return result

    # ──────────────────────────────────────────
    # ELF → metadata
    # ──────────────────────────────────────────

    def _parse(self, path: Path, locator: str, rejected: list[dict[str, str]]) -> ElfReport | None:
        try:
            return parse_elf(path, locator=locator)
        except (ElfParseError, OSError) as exc:
            rejected.append({"path": locator, "reason": str(exc)})
            logger.debug("Rejected %s: %s", locator, exc)
            return None

    def _to_metadata(self, path: Path, rel_path: Path, record: ElfReport) -> BinaryMetadata:
        return BinaryMetadata(
            path=rel_path,
            architecture=record.machine_name or None,
            endianness=record.byte_order or None,
            link_type=self._link_type_from(record),
            hardening=BinaryHardening(
                nx_enabled=None if record.stack_executable is None else not record.stack_executable,
                stack_canary=record.canary,
                pie_enabled=record.pie,
                relro=record.relro,
                fortify_source=record.fortify,
            ),
            version_strings=self._extract_version_strings(path),
            elf=record,
        )

    @staticmethod
    def _link_type_from(record: ElfReport) -> str:
        if record.interpreter or record.needed:
            return "dynamic"
        return "static"

    # ──────────────────────────────────────────
    # Banner fallback
    # ──────────────────────────────────────────

    def _banner_components(
        self, context: ScanContext, binaries: list[BinaryMetadata]
    ) -> list[SoftwareComponent]:
        """Version strings, at candidate confidence, from files that were read."""
        components: list[SoftwareComponent] = []
        sources: list[tuple[Path, str, str]] = [
            (binary.path, "elf_banner", "") for binary in binaries
        ]
        artifact = (
            str(context.input_snapshot.snapshot_path)
            if context.input_snapshot is not None
            else str(context.firmware_path)
            if context.input_kind.value == "file"
            else ""
        )
        if artifact:
            sources.append((Path(context.firmware_path.name), "artifact_banner", artifact))
        for rel_path, method, absolute in sources:
            versions = (
                self._extract_version_strings(Path(absolute))
                if absolute
                else self._extract_version_strings(self._locate(context, rel_path))
            )
            for product, version in versions.items():
                mapping = lookup(product)
                if mapping is None:
                    continue
                vendor, cpe_product = mapping
                components.append(
                    SoftwareComponent(
                        vendor=vendor,
                        product=cpe_product,
                        version=version,
                        cpe_string=cpe_name(vendor, cpe_product, version),
                        source_file=rel_path,
                        source_method=method,
                        confidence="candidate",
                        evidence=f"version string in {rel_path}",
                        occurrences=[str(rel_path)],
                    )
                )
        return components

    @staticmethod
    def _locate(context: ScanContext, rel_path: Path) -> Path:
        rootfs = context.extracted_rootfs
        if rootfs is not None:
            direct = rootfs / rel_path
            if direct.is_file():
                return direct
        if context.filesystem_inventory is not None:
            for finding in context.filesystem_inventory.findings:
                if finding.path == rel_path:
                    return finding.absolute_path
        return rel_path

    @staticmethod
    def _merge_components(
        existing: list[SoftwareComponent], new: list[SoftwareComponent]
    ) -> list[SoftwareComponent]:
        """Merge on (vendor, product, version), keeping every occurrence."""
        merged: dict[tuple[str, str, str], SoftwareComponent] = {}
        for component in [*existing, *new]:
            key = (component.vendor, component.product, component.version)
            if key in merged:
                current = merged[key]
                for occurrence in component.occurrences or [str(component.source_file)]:
                    if occurrence not in current.occurrences:
                        current.occurrences.append(occurrence)
                # A recorded source outranks a candidate one.
                if current.confidence == "candidate" and component.confidence != "candidate":
                    current.confidence = component.confidence
                    current.source_method = component.source_method
                continue
            component.occurrences = list(
                dict.fromkeys(component.occurrences or [str(component.source_file)])
            )
            merged[key] = component
        return [merged[key] for key in sorted(merged)]

    def _extract_version_strings(self, path: Path) -> dict[str, str]:
        """Extract version strings from a bounded head of a file."""
        versions: dict[str, str] = {}
        try:
            reader = open_bounded(Path(path))
            data = reader.read_head(min(BANNER_WINDOW, reader.size))
        except (OSError, ValueError):
            logger.debug("Cannot read %s for version extraction", path)
            return versions
        text = data.decode("ascii", errors="ignore")
        for product, pattern in VERSION_PATTERNS.items():
            match = pattern.search(text)
            if match:
                versions[product] = match.group(1)
        return versions

    # ──────────────────────────────────────────
    # Helpers retained for callers and tests
    # ──────────────────────────────────────────

    def _get_file_type(self, path: Path) -> str:
        """Header-based file type, with python-magic as a description only."""
        try:
            reader = open_bounded(Path(path))
            header = reader.read_head(8)
        except (OSError, ValueError):
            return "unknown"
        if header[:4] == b"\x7fELF":
            return "ELF executable"
        if header[:2] == b"MZ":
            return "PE executable"
        if header[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
            return "Mach-O executable"
        extension = Path(path).suffix.lower()
        return extension or "unknown"

    def _detect_architecture(self, file_type: str) -> str | None:
        """Detect CPU architecture from a file type string."""
        lowered = file_type.lower()
        for key in sorted(ARCH_MAP.keys(), key=len, reverse=True):
            if key in lowered:
                return ARCH_MAP[key]
        return None

    def _detect_endianness(self, file_type: str) -> str | None:
        """Detect endianness from a file type string."""
        lowered = file_type.lower()
        if "msb" in lowered or "big endian" in lowered:
            return "big"
        if "lsb" in lowered or "little endian" in lowered:
            return "little"
        return None

    def _detect_link_type(self, path: Path) -> str | None:
        """Static vs dynamic, from a bounded head (banner route only)."""
        try:
            reader = open_bounded(Path(path))
            data = reader.read_head(min(BANNER_WINDOW, reader.size))
        except (OSError, ValueError):
            return None
        if b"libc.so" in data or b"ld-linux" in data:
            return "dynamic"
        return "static"

    def _check_hardening(self, path: Path) -> BinaryHardening:
        """Hardening evidence for one file, from its own structures only.

        A file that is not ELF gets an all-``None`` result: nothing is known,
        which is different from "no hardening".
        """
        try:
            record = parse_elf(Path(path))
        except (ElfParseError, OSError):
            return BinaryHardening()
        return BinaryHardening(
            nx_enabled=None if record.stack_executable is None else not record.stack_executable,
            stack_canary=record.canary,
            pie_enabled=record.pie,
            relro=record.relro,
            fortify_source=record.fortify,
        )

    def _is_hardened(self, hardening: BinaryHardening) -> bool:
        """Whether the binary shows no *contrary* hardening evidence."""
        if hardening.nx_enabled is False:
            return False
        if hardening.stack_canary is False:
            return False
        return hardening.pie_enabled is not False


def elf_categories(inventory_categories: dict[FileCategory, list[object]]) -> int:
    """Count ELF files in an inventory, for callers that need the population."""
    return sum(
        1
        for finding in inventory_categories.get(FileCategory.CRITICAL_BINARY, [])
        if getattr(finding, "format", "") == "elf"
    )
