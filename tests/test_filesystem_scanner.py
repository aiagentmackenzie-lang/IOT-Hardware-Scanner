"""Tests for Filesystem Scanner — Phase 2b.

Covers:
- File categorization (all 11 categories)
- SUID binary detection
- World-writable file detection
- Symlink skipping (security)
- Boot process analysis (inittab, init.d)
- Service detection (telnetd, sshd, etc.)
- SHA-256 hashing (small files only)
- Permission formatting
- Empty/invalid rootfs handling
"""

import os
import tempfile
from pathlib import Path

import pytest

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.models import FileCategory
from iot_hardware_scanner.scanner.filesystem_scanner import FilesystemScanner


@pytest.fixture
def config() -> ScannerConfig:
    return ScannerConfig()


@pytest.fixture
def scanner(config: ScannerConfig) -> FilesystemScanner:
    return FilesystemScanner(config)


@pytest.fixture
def temp_rootfs() -> Path:
    """Create a realistic firmware rootfs structure."""
    with tempfile.TemporaryDirectory() as d:
        rootfs = Path(d)

        # /etc/passwd (CRITICAL_CREDENTIAL)
        etc = rootfs / "etc"
        etc.mkdir()
        (etc / "passwd").write_text("root:x:0:0:root:/root:/bin/sh\n")
        (etc / "shadow").write_text("root:$1$hash:19000:0:99999:7:::\n")
        (etc / "inittab").write_text(
            "::sysinit:/etc/init.d/rcS\n::respawn:/sbin/getty 115200 ttyS0\n"
        )

        # /etc/init.d/rcS (CRITICAL_SCRIPT)
        init_d = etc / "init.d"
        init_d.mkdir()
        (init_d / "rcS").write_text("#!/bin/sh\ntelnetd -l /bin/sh\n")
        (init_d / "rcS").chmod(0o755)

        # /etc/config.conf (CRITICAL_CONFIG)
        (etc / "config.conf").write_text("server=0.0.0.0\nport=80\n")

        # /bin/busybox with SUID (CRITICAL_BINARY + SUID)
        bin_dir = rootfs / "bin"
        bin_dir.mkdir()
        busybox = bin_dir / "busybox"
        busybox.write_bytes(os.urandom(256))
        busybox.chmod(0o4755)  # SUID

        # /bin/sshd (CRITICAL_SERVICE)
        sshd = bin_dir / "sshd"
        sshd.write_bytes(os.urandom(256))

        # /usr/bin/telnetd (CRITICAL_SERVICE)
        usr_bin = rootfs / "usr" / "bin"
        usr_bin.mkdir(parents=True)
        telnetd = usr_bin / "telnetd"
        telnetd.write_bytes(os.urandom(256))

        # World-writable file
        world_writable = etc / "world_writable.conf"
        world_writable.write_text("open=1\n")
        world_writable.chmod(0o666)

        # /www/cgi-bin/test.cgi (MEDIUM_WEB)
        www = rootfs / "www" / "cgi-bin"
        www.mkdir(parents=True)
        (www / "test.cgi").write_text("#!/bin/sh\necho test\n")

        # /var/log/syslog (MEDIUM_LOG)
        var_log = rootfs / "var" / "log"
        var_log.mkdir(parents=True)
        (var_log / "syslog").write_text("kernel: boot\n")

        # /etc/ssl/server.pem (HIGH_CRYPTO)
        ssl_dir = etc / "ssl"
        ssl_dir.mkdir()
        (ssl_dir / "server.pem").write_text("-----BEGIN CERTIFICATE-----\n")

        # /data/users.db (HIGH_DATABASE)
        data = rootfs / "data"
        data.mkdir()
        (data / "users.db").write_bytes(os.urandom(512))

        # .env file (HIGH_API_KEY)
        (rootfs / ".env").write_text("AWS_SECRET=abc123\n")

        yield rootfs


class TestFileCategorization:
    """Files are categorized into the correct security category."""

    def test_passwd_is_critical_credential(
        self, scanner: FilesystemScanner, temp_rootfs: Path
    ) -> None:
        inv = scanner.scan(temp_rootfs)
        creds = inv.categories.get(FileCategory.CRITICAL_CREDENTIAL, [])
        paths = [str(f.path) for f in creds]
        assert any("passwd" in p for p in paths)
        assert any("shadow" in p for p in paths)

    def test_config_is_critical_config(self, scanner: FilesystemScanner, temp_rootfs: Path) -> None:
        inv = scanner.scan(temp_rootfs)
        configs = inv.categories.get(FileCategory.CRITICAL_CONFIG, [])
        paths = [str(f.path) for f in configs]
        assert any("config.conf" in p for p in paths)

    def test_service_binary_detected(self, scanner: FilesystemScanner, temp_rootfs: Path) -> None:
        inv = scanner.scan(temp_rootfs)
        services = inv.categories.get(FileCategory.CRITICAL_SERVICE, [])
        names = [f.path.name for f in services]
        assert "sshd" in names or "telnetd" in names

    def test_init_script_detected(self, scanner: FilesystemScanner, temp_rootfs: Path) -> None:
        inv = scanner.scan(temp_rootfs)
        scripts = inv.categories.get(FileCategory.CRITICAL_SCRIPT, [])
        paths = [str(f.path) for f in scripts]
        assert any("init.d" in p or "rcS" in p for p in paths)

    def test_crypto_files_detected(self, scanner: FilesystemScanner, temp_rootfs: Path) -> None:
        inv = scanner.scan(temp_rootfs)
        crypto = inv.categories.get(FileCategory.HIGH_CRYPTO, [])
        paths = [str(f.path) for f in crypto]
        assert any("server.pem" in p for p in paths)

    def test_database_files_detected(self, scanner: FilesystemScanner, temp_rootfs: Path) -> None:
        inv = scanner.scan(temp_rootfs)
        dbs = inv.categories.get(FileCategory.HIGH_DATABASE, [])
        paths = [str(f.path) for f in dbs]
        assert any("users.db" in p for p in paths)

    def test_web_files_detected(self, scanner: FilesystemScanner, temp_rootfs: Path) -> None:
        inv = scanner.scan(temp_rootfs)
        web = inv.categories.get(FileCategory.MEDIUM_WEB, [])
        paths = [str(f.path) for f in web]
        assert any("test.cgi" in p for p in paths)

    def test_log_files_detected(self, scanner: FilesystemScanner, temp_rootfs: Path) -> None:
        inv = scanner.scan(temp_rootfs)
        logs = inv.categories.get(FileCategory.MEDIUM_LOG, [])
        paths = [str(f.path) for f in logs]
        assert any("syslog" in p for p in paths)

    def test_api_key_files_detected(self, scanner: FilesystemScanner, temp_rootfs: Path) -> None:
        inv = scanner.scan(temp_rootfs)
        api = inv.categories.get(FileCategory.HIGH_API_KEY, [])
        paths = [str(f.path) for f in api]
        assert any(".env" in p for p in paths)


class TestSecurityDetection:
    """SUID, world-writable, and other security flags."""

    def test_suid_binaries_detected(self, scanner: FilesystemScanner, temp_rootfs: Path) -> None:
        inv = scanner.scan(temp_rootfs)
        assert len(inv.suid_binaries) >= 1
        suid_names = [f.path.name for f in inv.suid_binaries]
        assert "busybox" in suid_names

    def test_world_writable_detected(self, scanner: FilesystemScanner, temp_rootfs: Path) -> None:
        inv = scanner.scan(temp_rootfs)
        assert len(inv.world_writable_files) >= 1
        names = [f.path.name for f in inv.world_writable_files]
        assert "world_writable.conf" in names

    def test_shadow_files_tracked(self, scanner: FilesystemScanner, temp_rootfs: Path) -> None:
        inv = scanner.scan(temp_rootfs)
        assert len(inv.shadow_files) >= 1

    def test_ssl_certs_tracked(self, scanner: FilesystemScanner, temp_rootfs: Path) -> None:
        inv = scanner.scan(temp_rootfs)
        assert len(inv.ssl_cert_files) >= 1

    def test_init_scripts_tracked(self, scanner: FilesystemScanner, temp_rootfs: Path) -> None:
        inv = scanner.scan(temp_rootfs)
        assert len(inv.init_scripts) >= 1

    def test_network_services_tracked(self, scanner: FilesystemScanner, temp_rootfs: Path) -> None:
        inv = scanner.scan(temp_rootfs)
        assert len(inv.network_services) >= 1


class TestBootProcessAnalysis:
    """Boot process analysis per SDR §8.2."""

    def test_inittab_parsing(self, scanner: FilesystemScanner, temp_rootfs: Path) -> None:
        inv = scanner.scan(temp_rootfs)
        result = scanner.analyze_boot_process(inv)

        assert len(result["inittab_entries"]) >= 1
        # Should find respawn entries
        inittab_str = " ".join(result["inittab_entries"])
        assert "respawn" in inittab_str or "sysinit" in inittab_str

    def test_service_detection_in_init_scripts(
        self, scanner: FilesystemScanner, temp_rootfs: Path
    ) -> None:
        inv = scanner.scan(temp_rootfs)
        result = scanner.analyze_boot_process(inv)

        # Should detect telnetd from init.d/rcS script
        assert len(result["services"]) >= 1
        assert "telnetd" in result["services"]

    def test_findings_generated(self, scanner: FilesystemScanner, temp_rootfs: Path) -> None:
        inv = scanner.scan(temp_rootfs)
        result = scanner.analyze_boot_process(inv)

        # Should have at least one finding about telnetd
        assert len(result["findings"]) >= 1
        findings_str = " ".join(result["findings"])
        assert "telnetd" in findings_str.lower()


class TestSymlinkSkipping:
    """Symlinks in rootfs are skipped for security."""

    def test_symlink_skipped(self, scanner: FilesystemScanner, temp_rootfs: Path) -> None:
        """Symlinks inside rootfs should NOT appear in findings."""
        link = temp_rootfs / "etc" / "passwd_link"
        link.symlink_to(temp_rootfs / "etc" / "passwd")

        inv = scanner.scan(temp_rootfs)
        # passwd_link should not be in findings
        all_paths = [str(f.path) for f in inv.findings]
        assert not any("passwd_link" in p for p in all_paths)


class TestEdgeCases:
    """Edge cases: empty dir, invalid path, hash limits."""

    def test_empty_rootfs(self, scanner: FilesystemScanner) -> None:
        with tempfile.TemporaryDirectory() as d:
            inv = scanner.scan(Path(d))
            assert inv.total_files == 0
            assert inv.total_directories == 0

    def test_invalid_rootfs(self, scanner: FilesystemScanner, tmp_path: Path) -> None:
        inv = scanner.scan(tmp_path / "nonexistent")
        assert inv.total_files == 0

    def test_total_files_count(self, scanner: FilesystemScanner, temp_rootfs: Path) -> None:
        inv = scanner.scan(temp_rootfs)
        assert inv.total_files > 0
        # Each file should appear exactly once
        paths = [str(f.path) for f in inv.findings]
        assert len(paths) == len(set(paths))

    def test_all_categories_initialized(
        self, scanner: FilesystemScanner, temp_rootfs: Path
    ) -> None:
        inv = scanner.scan(temp_rootfs)
        # All categories should be present (possibly empty)
        for cat in FileCategory:
            assert cat in inv.categories

    def test_permissions_format(self, scanner: FilesystemScanner, temp_rootfs: Path) -> None:
        inv = scanner.scan(temp_rootfs)
        # SUID busybox should have "rwsr-xr-x"
        busybox_findings = [f for f in inv.findings if f.path.name == "busybox"]
        if busybox_findings:
            assert "s" in busybox_findings[0].permissions

    def test_hash_for_small_files(self, scanner: FilesystemScanner, temp_rootfs: Path) -> None:
        inv = scanner.scan(temp_rootfs)
        # Small files should have SHA-256 hashes (64 hex chars)
        small_files = [f for f in inv.findings if f.file_size < 10 * 1024 * 1024]
        for f in small_files:
            # Hash may be empty for files we can't read, but should be
            # valid hex if present
            if f.hash_sha256:
                assert len(f.hash_sha256) == 64
                assert all(c in "0123456789abcdef" for c in f.hash_sha256)

    def test_get_files_by_category(self, scanner: FilesystemScanner, temp_rootfs: Path) -> None:
        inv = scanner.scan(temp_rootfs)
        creds = scanner.get_files_by_category(inv, FileCategory.CRITICAL_CREDENTIAL)
        assert len(creds) >= 1
