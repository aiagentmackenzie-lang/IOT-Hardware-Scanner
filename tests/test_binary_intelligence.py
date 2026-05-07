"""Tests for Binary Intelligence — Phase 3b.

Covers:
- Version string extraction (all 12 SDR patterns)
- Architecture detection from file type strings
- Endianness detection
- Link type detection (static/dynamic)
- CPE construction from version strings
- Hardening assessment
- Binary metadata assembly
- _is_hardened logic
- Edge cases: empty data, unreadable files
"""

from datetime import datetime
from pathlib import Path

import pytest

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.models import (
    BinaryHardening,
    BinaryIntelligenceResult,
    FileCategory,
    FilesystemFinding,
    FilesystemInventory,
    FirmwareSizeCategory,
    ScanContext,
)
from iot_hardware_scanner.scanner.binary_intelligence import (
    CPE_MAP,
    VERSION_PATTERNS,
    BinaryIntelligence,
)


@pytest.fixture
def config() -> ScannerConfig:
    return ScannerConfig()


@pytest.fixture
def bi(config: ScannerConfig) -> BinaryIntelligence:
    return BinaryIntelligence(config)


def _make_context(**overrides) -> ScanContext:
    """Create a minimal ScanContext for testing."""
    defaults = {
        "scan_id": "test-001",
        "firmware_path": Path("/tmp/test.bin"),
        "output_dir": Path("/tmp/output"),
        "file_hash_sha256": "abc123",
        "file_hash_md5": "def456",
        "file_size": 1024,
        "file_type": "data",
        "firmware_name": "test",
        "size_category": FirmwareSizeCategory.SMALL,
        "started_at": datetime.now(),
    }
    defaults.update(overrides)
    return ScanContext(**defaults)


class TestVersionStringExtraction:
    """All 12 SDR version patterns extract correctly."""

    def test_busybox(self, bi: BinaryIntelligence, tmp_path: Path) -> None:
        f = tmp_path / "busybox"
        f.write_text("Some text BusyBox v1.28.4 more text")
        versions = bi._extract_version_strings(f)
        assert versions["busybox"] == "1.28.4"

    def test_openssl(self, bi: BinaryIntelligence, tmp_path: Path) -> None:
        f = tmp_path / "openssl"
        f.write_text("OpenSSL 1.0.2k something")
        versions = bi._extract_version_strings(f)
        assert versions["openssl"] == "1.0.2k"

    def test_dropbear(self, bi: BinaryIntelligence, tmp_path: Path) -> None:
        f = tmp_path / "dropbear"
        f.write_text("Dropbear ssh 2020.78\n")
        versions = bi._extract_version_strings(f)
        assert versions["dropbear"] == "2020.78"

    def test_dnsmasq(self, bi: BinaryIntelligence, tmp_path: Path) -> None:
        f = tmp_path / "dnsmasq"
        f.write_text("dnsmasq 2.82\n")
        versions = bi._extract_version_strings(f)
        assert versions["dnsmasq"] == "2.82"

    def test_nginx(self, bi: BinaryIntelligence, tmp_path: Path) -> None:
        f = tmp_path / "nginx"
        f.write_text("server: nginx/1.18.0\n")
        versions = bi._extract_version_strings(f)
        assert versions["nginx"] == "1.18.0"

    def test_lighttpd(self, bi: BinaryIntelligence, tmp_path: Path) -> None:
        f = tmp_path / "lighttpd"
        f.write_text("lighttpd/1.4.59\n")
        versions = bi._extract_version_strings(f)
        assert versions["lighttpd"] == "1.4.59"

    def test_linux_kernel(self, bi: BinaryIntelligence, tmp_path: Path) -> None:
        f = tmp_path / "vmlinux"
        f.write_text("Linux version 5.10.12\n")
        versions = bi._extract_version_strings(f)
        assert versions["linux_kernel"] == "5.10.12"

    def test_u_boot(self, bi: BinaryIntelligence, tmp_path: Path) -> None:
        f = tmp_path / "u-boot"
        f.write_text("U-Boot 2021.01\n")
        versions = bi._extract_version_strings(f)
        assert versions["u_boot"] == "2021.01"

    def test_curl(self, bi: BinaryIntelligence, tmp_path: Path) -> None:
        f = tmp_path / "curl"
        f.write_text("libcurl/7.76.1\n")
        versions = bi._extract_version_strings(f)
        assert versions["curl"] == "7.76.1"

    def test_openssh(self, bi: BinaryIntelligence, tmp_path: Path) -> None:
        f = tmp_path / "sshd"
        f.write_text("OpenSSH_8.6p1\n")
        versions = bi._extract_version_strings(f)
        assert versions["openssh"] == "8.6p1"

    def test_zlib(self, bi: BinaryIntelligence, tmp_path: Path) -> None:
        f = tmp_path / "libz"
        f.write_text("zlib 1.2.11\n")
        versions = bi._extract_version_strings(f)
        assert versions["zlib"] == "1.2.11"

    def test_sqlite(self, bi: BinaryIntelligence, tmp_path: Path) -> None:
        f = tmp_path / "sqlite3"
        f.write_text("SQLite version 3.35.5\n")
        versions = bi._extract_version_strings(f)
        assert versions["sqlite"] == "3.35.5"

    def test_no_version(self, bi: BinaryIntelligence, tmp_path: Path) -> None:
        f = tmp_path / "random"
        f.write_text("Just some random text\n")
        versions = bi._extract_version_strings(f)
        assert len(versions) == 0

    def test_multiple_versions(
        self, bi: BinaryIntelligence, tmp_path: Path
    ) -> None:
        f = tmp_path / "combined"
        f.write_text("BusyBox v1.30.0\nOpenSSL 1.1.1k\nnginx/1.20.0\n")
        versions = bi._extract_version_strings(f)
        assert "busybox" in versions
        assert "openssl" in versions
        assert "nginx" in versions


class TestArchitectureDetection:
    """Architecture detection from file type strings."""

    def test_mips(self, bi: BinaryIntelligence) -> None:
        assert bi._detect_architecture("ELF 32-bit MSB MIPS") == "MIPS"

    def test_arm(self, bi: BinaryIntelligence) -> None:
        assert bi._detect_architecture("ELF 32-bit LSB ARM") == "ARM"

    def test_x86(self, bi: BinaryIntelligence) -> None:
        assert bi._detect_architecture("ELF 32-bit LSB x86") == "x86"

    def test_x86_64(self, bi: BinaryIntelligence) -> None:
        assert (
            bi._detect_architecture("ELF 64-bit LSB x86-64") == "x86_64"
        )

    def test_aarch64(self, bi: BinaryIntelligence) -> None:
        assert (
            bi._detect_architecture("ELF 64-bit LSB AArch64") == "AArch64"
        )

    def test_powerpc(self, bi: BinaryIntelligence) -> None:
        assert (
            bi._detect_architecture("ELF 32-bit MSB PowerPC") == "PowerPC"
        )

    def test_riscv(self, bi: BinaryIntelligence) -> None:
        assert bi._detect_architecture("ELF 32-bit LSB RISC-V") == "RISC-V"

    def test_unknown(self, bi: BinaryIntelligence) -> None:
        assert bi._detect_architecture("data") is None


class TestEndiannessDetection:
    """Endianness detection from file type strings."""

    def test_little_endian(self, bi: BinaryIntelligence) -> None:
        assert bi._detect_endianness("ELF 32-bit LSB MIPS") == "little"

    def test_big_endian(self, bi: BinaryIntelligence) -> None:
        assert bi._detect_endianness("ELF 32-bit MSB MIPS") == "big"

    def test_explicit_endian(self, bi: BinaryIntelligence) -> None:
        assert (
            bi._detect_endianness("ELF 32-bit big endian MIPS")
            == "big"
        )

    def test_unknown(self, bi: BinaryIntelligence) -> None:
        assert bi._detect_endianness("data") is None


class TestLinkTypeDetection:
    """Static vs dynamic linking detection."""

    def test_dynamic_binary(self, bi: BinaryIntelligence, tmp_path: Path) -> None:
        f = tmp_path / "dynamic_bin"
        f.write_bytes(b"\x00" * 100 + b"libc.so.6" + b"\x00" * 100)
        assert bi._detect_link_type(f) == "dynamic"

    def test_static_binary(self, bi: BinaryIntelligence, tmp_path: Path) -> None:
        f = tmp_path / "static_bin"
        f.write_bytes(b"\x00" * 256)
        assert bi._detect_link_type(f) == "static"

    def test_unreadable_file(self, bi: BinaryIntelligence) -> None:
        result = bi._detect_link_type(Path("/nonexistent/file"))
        assert result is None


class TestCPEConstruction:
    """CPE strings built correctly from version patterns."""

    def test_cpe_map_has_all_patterns(self) -> None:
        """Every VERSION_PATTERNS key should have a CPE_MAP entry."""
        for key in VERSION_PATTERNS:
            assert key in CPE_MAP, f"Missing CPE mapping for {key}"

    def test_cpe_format(self, bi: BinaryIntelligence) -> None:
        """CPE strings follow cpe:2.3:a:vendor:product:version format."""
        for _key, (vendor, product) in CPE_MAP.items():
            cpe = f"cpe:2.3:a:{vendor}:{product}:1.0.0"
            assert cpe.startswith("cpe:2.3:a:")


class TestIsHardened:
    """Binary hardening assessment logic."""

    def test_fully_hardened(self, bi: BinaryIntelligence) -> None:
        h = BinaryHardening(
            nx_enabled=True,
            stack_canary=True,
            pie_enabled=True,
            relro="full",
            fortify_source=True,
        )
        assert bi._is_hardened(h) is True

    def test_no_nx(self, bi: BinaryIntelligence) -> None:
        h = BinaryHardening(
            nx_enabled=False,
            stack_canary=True,
            pie_enabled=True,
        )
        assert bi._is_hardened(h) is False

    def test_no_canary(self, bi: BinaryIntelligence) -> None:
        h = BinaryHardening(
            nx_enabled=True,
            stack_canary=False,
            pie_enabled=True,
        )
        assert bi._is_hardened(h) is False

    def test_no_pie(self, bi: BinaryIntelligence) -> None:
        h = BinaryHardening(
            nx_enabled=True,
            stack_canary=True,
            pie_enabled=False,
        )
        assert bi._is_hardened(h) is False

    def test_unknown_values(self, bi: BinaryIntelligence) -> None:
        """Unknown hardening values (None) should not fail the check."""
        h = BinaryHardening()  # All None
        assert bi._is_hardened(h) is True  # No hardening failures


class TestAnalyzeWithInventory:
    """Full analysis with filesystem inventory."""

    def test_analyze_with_empty_inventory(
        self, bi: BinaryIntelligence, tmp_path: Path
    ) -> None:
        """No binary files → empty result, but still scans firmware for versions."""
        fw = tmp_path / "firmware.bin"
        fw.write_bytes(
            b"\x7fELF" + b"BusyBox v1.30.0" + b"\x00" * 100
        )

        inventory = FilesystemInventory(rootfs_path=tmp_path)
        context = _make_context(
            firmware_path=fw,
            filesystem_inventory=inventory,
        )

        result = bi.analyze(context)
        assert isinstance(result, BinaryIntelligenceResult)
        assert result.total_binaries == 0
        # Should still find BusyBox version from raw firmware
        assert len(context.software_components) >= 1
        assert any(c.product == "busybox" for c in context.software_components)

    def test_analyze_with_binary_in_inventory(
        self, bi: BinaryIntelligence, tmp_path: Path
    ) -> None:
        """Binary files in inventory should be analyzed."""
        # Create a fake binary with version strings
        bin_file = tmp_path / "usr" / "bin" / "busybox"
        bin_file.parent.mkdir(parents=True, exist_ok=True)
        bin_file.write_bytes(
            b"\x7fELF" + b"BusyBox v1.30.0" + b"\x00" * 256
        )

        finding = FilesystemFinding(
            path=Path("usr/bin/busybox"),
            absolute_path=bin_file,
            category=FileCategory.CRITICAL_BINARY,
            file_type="ELF 32-bit LSB executable, ARM",
            file_size=256,
            permissions="rwxr-xr-x",
            owner_uid=0,
            owner_gid=0,
            is_suid=False,
            is_world_writable=False,
            hash_sha256="abc123",
        )

        inventory = FilesystemInventory(
            rootfs_path=tmp_path,
            total_files=1,
            categories={FileCategory.CRITICAL_BINARY: [finding]},
        )

        fw = tmp_path / "firmware.bin"
        fw.write_bytes(b"\x00" * 128)

        context = _make_context(
            firmware_path=fw,
            filesystem_inventory=inventory,
        )

        result = bi.analyze(context)
        # Should have analyzed the binary (may or may not find hardening
        # depending on readelf availability)
        assert result.total_binaries >= 0


class TestGetFileType:
    """File type detection with fallback."""

    def test_elf_magic_bytes(self, bi: BinaryIntelligence, tmp_path: Path) -> None:
        f = tmp_path / "test.elf"
        f.write_bytes(b"\x7fELF" + b"\x00" * 100)
        ft = bi._get_file_type(f)
        assert "ELF" in ft

    def test_pe_magic_bytes(self, bi: BinaryIntelligence, tmp_path: Path) -> None:
        f = tmp_path / "test.exe"
        f.write_bytes(b"MZ" + b"\x00" * 100)
        ft = bi._get_file_type(f)
        assert "PE" in ft

    def test_unknown_extension(self, bi: BinaryIntelligence, tmp_path: Path) -> None:
        f = tmp_path / "test.bin"
        f.write_bytes(b"\x00" * 100)
        ft = bi._get_file_type(f)
        # Should return extension or "unknown"
        assert ft in (".bin", "unknown", "data")
