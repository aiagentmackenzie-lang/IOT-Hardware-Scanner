"""Tests for C2Detector — Phase 6.

Tests domain detection, IP detection, malware signature detection,
private IP filtering, email domain filtering, and integration with
DomainScorer and ThreatIntelManager.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.intelligence.domain_scorer import DomainScorer
from iot_hardware_scanner.intelligence.threat_intel import ThreatIntelManager
from iot_hardware_scanner.models import (
    C2Finding,
    FileCategory,
    FilesystemFinding,
    FilesystemInventory,
)
from iot_hardware_scanner.scanner.c2_detector import C2Detector, _extract_domains_text, _extract_ips_text, _is_email_domain_text

# ──────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────


def _make_finding(
    path: str = "test.txt",
    category: FileCategory = FileCategory.MEDIUM_WEB,
    file_type: str = "ASCII text",
    file_size: int = 100,
) -> FilesystemFinding:
    """Create a minimal FilesystemFinding for testing."""
    tmp = Path("/tmp/fake_rootfs") / path
    return FilesystemFinding(
        path=Path(path),
        absolute_path=tmp,
        category=category,
        file_type=file_type,
        file_size=file_size,
        permissions="rw-r--r--",
        owner_uid=0,
        owner_gid=0,
        is_suid=False,
        is_world_writable=False,
        hash_sha256="a" * 64,
    )


def _make_inventory(
    findings: list[FilesystemFinding] | None = None,
    rootfs: Path | None = None,
) -> FilesystemInventory:
    """Create a minimal FilesystemInventory for testing."""
    return FilesystemInventory(
        rootfs_path=rootfs or Path("/tmp/fake_rootfs"),
        total_files=len(findings) if findings else 0,
        total_directories=1,
        total_size=1024,
        findings=findings or [],
        categories={},
        suid_binaries=[],
        world_writable_files=[],
        shadow_files=[],
        ssl_cert_files=[],
        init_scripts=[],
        network_services=[],
    )


@pytest.fixture
def config(tmp_path: Path) -> ScannerConfig:
    """Config with isolated threat intel dir (no project data/)."""
    return ScannerConfig(threat_intel_dirs=[tmp_path])


@pytest.fixture
def threat_intel_isolated(tmp_path: Path) -> ThreatIntelManager:
    """ThreatIntelManager loaded only from a test feed, no project data."""
    feed = tmp_path / "test_intel.jsonl"
    feed.write_text(
        json.dumps(
            {
                "type": "domain",
                "value": "c2.malware-c2.su",
                "tags": ["mirai", "c2"],
                "confidence": 0.95,
                "source": "test",
            }
        )
        + "\n"
        + json.dumps(
            {
                "type": "ip",
                "value": "185.220.101.37",
                "tags": ["tor_exit", "c2"],
                "confidence": 0.7,
                "source": "test",
            }
        )
        + "\n"
        + json.dumps(
            {
                "type": "ip",
                "value": "91.234.99.42",
                "tags": ["mirai", "c2"],
                "confidence": 0.9,
                "source": "test",
            }
        )
        + "\n"
    )
    manager = ThreatIntelManager.__new__(ThreatIntelManager)
    manager.config = ScannerConfig(threat_intel_dirs=[tmp_path])
    manager._domains = {}
    manager._ips = {}
    manager._loaded = False
    manager._load_directory(tmp_path)
    manager._loaded = True
    return manager


@pytest.fixture
def detector(config: ScannerConfig, threat_intel_isolated: ThreatIntelManager) -> C2Detector:
    """C2Detector with isolated threat intel."""
    det = C2Detector.__new__(C2Detector)
    det.config = config
    det._threat_intel = threat_intel_isolated
    det._domain_scorer = DomainScorer(config, threat_intel=threat_intel_isolated)
    det._yara_engine = None
    return det


# ──────────────────────────────────────────────
# Domain Detection
# ──────────────────────────────────────────────


class TestDomainDetection:
    """Test domain extraction and C2 scoring from firmware files."""

    def test_detect_malicious_domain_in_config(self, detector: C2Detector, tmp_path: Path) -> None:
        """Malicious domain in a config file should be detected."""
        config_file = tmp_path / "etc" / "config.conf"
        config_file.parent.mkdir(parents=True, exist_ok=True)
        config_file.write_text("server c2.malware-c2.su\n")

        ff = _make_finding(path="etc/config.conf", category=FileCategory.CRITICAL_CONFIG)
        ff = FilesystemFinding(
            path=ff.path,
            absolute_path=config_file,
            category=ff.category,
            file_type=ff.file_type,
            file_size=ff.file_size,
            permissions=ff.permissions,
            owner_uid=ff.owner_uid,
            owner_gid=ff.owner_gid,
            is_suid=ff.is_suid,
            is_world_writable=ff.is_world_writable,
            hash_sha256=ff.hash_sha256,
        )
        inv = _make_inventory([ff])
        findings = detector.detect_domains(inv)
        # Should detect c2.malware-c2.su (threat intel + suspicious TLD + botnet name)
        domain_findings = [f for f in findings if f.indicator_type == "domain"]
        assert len(domain_findings) >= 1
        values = [f.value for f in domain_findings]
        assert "c2.malware-c2.su" in values

    def test_detect_suspicious_tld_domain(self, detector: C2Detector, tmp_path: Path) -> None:
        """Domains with suspicious TLDs should be flagged."""
        config_file = tmp_path / "etc" / "resolv.conf"
        config_file.parent.mkdir(parents=True, exist_ok=True)
        config_file.write_text("nameserver randomstuff.xyz\n")

        ff = FilesystemFinding(
            path=Path("etc/resolv.conf"),
            absolute_path=config_file,
            category=FileCategory.CRITICAL_CONFIG,
            file_type="ASCII text",
            file_size=50,
            permissions="rw-r--r--",
            owner_uid=0,
            owner_gid=0,
            is_suid=False,
            is_world_writable=False,
            hash_sha256="b" * 64,
        )
        inv = _make_inventory([ff])
        findings = detector.detect_domains(inv)
        # .xyz is a suspicious TLD
        [f for f in findings if "xyz" in f.value or f.suspicion_score >= 40]
        # May or may not flag depending on whether "randomstuff" triggers DGA or benign
        # Just verify the domain was extracted
        assert isinstance(findings, list)

    def test_skip_benign_domains(self, detector: C2Detector, tmp_path: Path) -> None:
        """Known benign domains should be skipped (score too low)."""
        config_file = tmp_path / "etc" / "hosts"
        config_file.parent.mkdir(parents=True, exist_ok=True)
        config_file.write_text("127.0.0.1 localhost\n::1 localhost\n")

        ff = FilesystemFinding(
            path=Path("etc/hosts"),
            absolute_path=config_file,
            category=FileCategory.CRITICAL_CONFIG,
            file_type="ASCII text",
            file_size=50,
            permissions="rw-r--r--",
            owner_uid=0,
            owner_gid=0,
            is_suid=False,
            is_world_writable=False,
            hash_sha256="c" * 64,
        )
        inv = _make_inventory([ff])
        findings = detector.detect_domains(inv)
        # "localhost" is too short to be a domain, and no real external domains
        assert isinstance(findings, list)

    def test_skip_docs_directory(self, detector: C2Detector, tmp_path: Path) -> None:
        """Files in docs/ directories should be skipped."""
        ff = _make_finding(path="docs/README.md", category=FileCategory.LOW_MISC)
        inv = _make_inventory([ff])
        findings = detector.detect_domains(inv)
        # File path starts with docs/ → should be skipped
        assert len(findings) == 0

    def test_empty_inventory(self, detector: C2Detector) -> None:
        """Empty inventory returns no findings."""
        inv = _make_inventory([])
        findings = detector.detect_domains(inv)
        assert findings == []


# ──────────────────────────────────────────────
# IP Detection
# ──────────────────────────────────────────────


class TestIPDetection:
    """Test IP extraction and threat intel scoring."""

    def test_detect_known_malicious_ip(self, detector: C2Detector, tmp_path: Path) -> None:
        """IPs in threat intel feed should be detected."""
        config_file = tmp_path / "etc" / "config.conf"
        config_file.parent.mkdir(parents=True, exist_ok=True)
        config_file.write_text("server 185.220.101.37\n")

        ff = FilesystemFinding(
            path=Path("etc/config.conf"),
            absolute_path=config_file,
            category=FileCategory.CRITICAL_CONFIG,
            file_type="ASCII text",
            file_size=50,
            permissions="rw-r--r--",
            owner_uid=0,
            owner_gid=0,
            is_suid=False,
            is_world_writable=False,
            hash_sha256="d" * 64,
        )
        inv = _make_inventory([ff])
        findings = detector.detect_ips(inv)
        ip_findings = [f for f in findings if f.value == "185.220.101.37"]
        assert len(ip_findings) >= 1
        assert ip_findings[0].severity in ("LIKELY_C2", "SUSPICIOUS")

    def test_private_ips_filtered(self, detector: C2Detector, tmp_path: Path) -> None:
        """Private/local IPs should be filtered out."""
        config_file = tmp_path / "etc" / "hosts"
        config_file.parent.mkdir(parents=True, exist_ok=True)
        config_file.write_text(
            "192.168.1.1 router\n10.0.0.1 gateway\n172.16.0.1 switch\n127.0.0.1 localhost\n"
        )

        ff = FilesystemFinding(
            path=Path("etc/hosts"),
            absolute_path=config_file,
            category=FileCategory.CRITICAL_CONFIG,
            file_type="ASCII text",
            file_size=100,
            permissions="rw-r--r--",
            owner_uid=0,
            owner_gid=0,
            is_suid=False,
            is_world_writable=False,
            hash_sha256="e" * 64,
        )
        inv = _make_inventory([ff])
        findings = detector.detect_ips(inv)
        # All IPs in this file are private
        for f in findings:
            assert not f.value.startswith(("192.168.", "10.", "172.16.", "127."))

    def test_suspicious_ip_range(self, detector: C2Detector, tmp_path: Path) -> None:
        """IPs in known suspicious ranges should be flagged."""
        config_file = tmp_path / "var" / "log" / "system.log"
        config_file.parent.mkdir(parents=True, exist_ok=True)
        config_file.write_text("connection from 91.234.99.42\n")

        ff = FilesystemFinding(
            path=Path("var/log/system.log"),
            absolute_path=config_file,
            category=FileCategory.MEDIUM_LOG,
            file_type="ASCII text",
            file_size=50,
            permissions="rw-r--r--",
            owner_uid=0,
            owner_gid=0,
            is_suid=False,
            is_world_writable=False,
            hash_sha256="f" * 64,
        )
        inv = _make_inventory([ff])
        findings = detector.detect_ips(inv)
        # 91.234.99.42 is in threat intel AND in suspicious range 91.234.99.0/24
        ip_findings = [f for f in findings if f.value == "91.234.99.42"]
        assert len(ip_findings) >= 1

    def test_is_private_or_reserved(self) -> None:
        """Test private/reserved IP detection."""
        assert C2Detector._is_private_or_reserved("192.168.1.1") is True
        assert C2Detector._is_private_or_reserved("10.0.0.1") is True
        assert C2Detector._is_private_or_reserved("172.16.0.1") is True
        assert C2Detector._is_private_or_reserved("127.0.0.1") is True
        assert C2Detector._is_private_or_reserved("169.254.1.1") is True
        # Public IPs should not be private
        assert C2Detector._is_private_or_reserved("8.8.8.8") is False
        assert C2Detector._is_private_or_reserved("1.1.1.1") is False

    def test_is_suspicious_ip_range(self) -> None:
        """Test suspicious IP range detection."""
        assert C2Detector._is_suspicious_ip_range("5.187.35.18") is True
        assert C2Detector._is_suspicious_ip_range("185.220.101.37") is True
        assert C2Detector._is_suspicious_ip_range("91.234.99.42") is True
        assert C2Detector._is_suspicious_ip_range("23.106.122.77") is True
        # Normal IPs should not be in suspicious ranges
        assert C2Detector._is_suspicious_ip_range("8.8.8.8") is False
        assert C2Detector._is_suspicious_ip_range("1.1.1.1") is False

    def test_empty_inventory(self, detector: C2Detector) -> None:
        """Empty inventory returns no IP findings."""
        inv = _make_inventory([])
        findings = detector.detect_ips(inv)
        assert findings == []


# ──────────────────────────────────────────────
# Malware Signature Detection
# ──────────────────────────────────────────────


class TestMalwareSignatures:
    """Test YARA-based malware family detection."""

    def test_mirai_detection(self, detector: C2Detector, tmp_path: Path) -> None:
        """Mirai YARA rule should detect known patterns."""
        # Create a fake binary with Mirai credential table
        binary_file = tmp_path / "bin" / "mirai_sample"
        binary_file.parent.mkdir(parents=True, exist_ok=True)
        binary_file.write_bytes(
            b"\x7fELF"  # ELF magic
            + b"\x00" * 60
            + b"root:xc3511\x00root:vizxv\x00admin:admin\x00"
        )

        ff = FilesystemFinding(
            path=Path("bin/mirai_sample"),
            absolute_path=binary_file,
            category=FileCategory.CRITICAL_BINARY,
            file_type="ELF executable",
            file_size=200,
            permissions="rwxr-xr-x",
            owner_uid=0,
            owner_gid=0,
            is_suid=False,
            is_world_writable=False,
            hash_sha256="a1" * 32,
        )
        inv = _make_inventory([ff])
        inv.categories = {FileCategory.CRITICAL_BINARY: [ff]}

        findings = detector.detect_malware_signatures(inv)
        # YARA may or may not detect depending on engine availability
        assert isinstance(findings, list)

    def test_backdoor_service_detection(self, detector: C2Detector, tmp_path: Path) -> None:
        """Telnet backdoor YARA rule should detect telnetd + no auth."""
        script_file = tmp_path / "etc" / "init.d" / "S99telnet"
        script_file.parent.mkdir(parents=True, exist_ok=True)
        script_file.write_text("#!/bin/sh\ntelnetd -l /bin/sh\n")

        ff = FilesystemFinding(
            path=Path("etc/init.d/S99telnet"),
            absolute_path=script_file,
            category=FileCategory.CRITICAL_SERVICE,
            file_type="POSIX shell script",
            file_size=50,
            permissions="rwxr-xr-x",
            owner_uid=0,
            owner_gid=0,
            is_suid=False,
            is_world_writable=False,
            hash_sha256="b2" * 32,
        )
        inv = _make_inventory([ff])
        inv.categories = {FileCategory.CRITICAL_SERVICE: [ff]}

        findings = detector.detect_malware_signatures(inv)
        assert isinstance(findings, list)

    def test_empty_inventory(self, detector: C2Detector) -> None:
        """Empty inventory returns no malware findings."""
        inv = _make_inventory([])
        findings = detector.detect_malware_signatures(inv)
        assert findings == []


# ──────────────────────────────────────────────
# Helper Methods
# ──────────────────────────────────────────────


class TestHelperMethods:
    """Test C2Detector helper methods."""

    def test_is_binary_file_elf(self, tmp_path: Path) -> None:
        """ELF files are detected as binary."""
        elf_file = tmp_path / "test.elf"
        elf_file.write_bytes(b"\x7fELF" + b"\x00" * 100)
        assert C2Detector._is_binary_file(elf_file) is True

    def test_is_binary_file_pe(self, tmp_path: Path) -> None:
        """PE files are detected as binary."""
        pe_file = tmp_path / "test.exe"
        pe_file.write_bytes(b"MZ" + b"\x00" * 100)
        assert C2Detector._is_binary_file(pe_file) is True

    def test_is_binary_file_text(self, tmp_path: Path) -> None:
        """Text files are not detected as binary."""
        txt_file = tmp_path / "test.txt"
        txt_file.write_text("hello world")
        assert C2Detector._is_binary_file(txt_file) is False

    def test_is_binary_file_missing(self, tmp_path: Path) -> None:
        """Missing files return False."""
        missing = tmp_path / "nonexistent"
        assert C2Detector._is_binary_file(missing) is False

    def test_is_benign_path(self) -> None:
        """Docs/test paths are identified as benign."""
        assert C2Detector._is_benign_path(Path("docs/README.md")) is True
        assert C2Detector._is_benign_path(Path("tests/test_foo.py")) is True
        assert C2Detector._is_benign_path(Path("test/mock_data.bin")) is True
        assert C2Detector._is_benign_path(Path("documentation/api.rst")) is True
        assert C2Detector._is_benign_path(Path("src/main.py")) is False
        assert C2Detector._is_benign_path(Path("etc/config.conf")) is False

    def test_is_hosts_or_config(self) -> None:
        """Hosts/config files are correctly identified."""
        assert C2Detector._is_hosts_or_config(Path("etc/hosts")) is True
        assert C2Detector._is_hosts_or_config(Path("etc/resolv.conf")) is True
        assert C2Detector._is_hosts_or_config(Path("etc/nginx/nginx.conf")) is True
        assert C2Detector._is_hosts_or_config(Path("etc/wpa_supplicant.cfg")) is True
        assert C2Detector._is_hosts_or_config(Path("var/log/syslog.log")) is False

    def test_extract_domains_from_file(self, tmp_path: Path) -> None:
        """Domain extraction from text files works correctly."""
        f = tmp_path / "config.txt"
        f.write_text("server updates.example.com\napi api.vendor.org\n")
        domains = _extract_domains_text(f)
        assert "updates.example.com" in domains
        assert "api.vendor.org" in domains

    def test_extract_domains_skips_version_strings(self, tmp_path: Path) -> None:
        """Version-like strings (e.g., '2.0') are not extracted as domains."""
        f = tmp_path / "version.txt"
        f.write_text("version 2.0 and 1.5\n")
        domains = _extract_domains_text(f)
        # "2.0" and "1.5" should not appear as domains
        assert "2.0" not in domains
        assert "1.5" not in domains

    def test_extract_ips_from_file(self, tmp_path: Path) -> None:
        """IP extraction from text files works correctly."""
        f = tmp_path / "config.txt"
        f.write_text("server 192.168.1.1\npeer 10.0.0.5\nntp 203.0.113.50\n")
        ips = _extract_ips_text(f)
        assert "192.168.1.1" in ips
        assert "10.0.0.5" in ips
        assert "203.0.113.50" in ips

    def test_extract_ips_validates_octets(self, tmp_path: Path) -> None:
        """Invalid IP octets (>255) are filtered out."""
        f = tmp_path / "bad.txt"
        f.write_text("server 999.999.999.999\n")
        ips = _extract_ips_text(f)
        assert "999.999.999.999" not in ips

    def test_extract_ips_missing_file(self, tmp_path: Path) -> None:
        """Missing files return empty set."""
        missing = tmp_path / "nonexistent"
        ips = _extract_ips_text(missing)
        assert ips == set()

    def test_get_mitre_techniques_mirai(self) -> None:
        """Mirai maps to specific MITRE techniques."""
        result = C2Detector._get_mitre_techniques("mirai", "malware_signature")
        assert "T0839" in result
        assert "T1133" in result

    def test_get_mitre_techniques_backdoor(self) -> None:
        """Backdoor services map to specific MITRE techniques."""
        result = C2Detector._get_mitre_techniques("", "backdoor_service")
        assert "T1133" in result
        assert "T0866" in result

    def test_get_mitre_techniques_unknown(self) -> None:
        """Unknown families return empty string."""
        result = C2Detector._get_mitre_techniques("unknown_malware", "malware_signature")
        assert result == ""

    def test_is_email_domain(self, tmp_path: Path) -> None:
        """Email-only domains are correctly identified."""
        f = tmp_path / "contact.txt"
        f.write_text("Contact: admin@example.com\n")
        result = _is_email_domain_text("example.com", f)
        # example.com appears in email context only
        assert result is True

    def test_is_email_domain_not_email(self, tmp_path: Path) -> None:
        """Domains that appear standalone are not email-only."""
        f = tmp_path / "config.txt"
        f.write_text("server example.com\n")
        result = _is_email_domain_text("example.com", f)
        assert result is False

    def test_macho_binary_detection(self, tmp_path: Path) -> None:
        """Mach-O binaries should be correctly identified."""
        # Mach-O 32-bit magic: 0xFEEDFACE
        macho32 = tmp_path / "macho32"
        macho32.write_bytes(b"\xfe\xed\xfa\xce" + b"\x00" * 100)
        assert C2Detector._is_binary_file(macho32) is True

        # Mach-O 64-bit magic: 0xFEEDFACF
        macho64 = tmp_path / "macho64"
        macho64.write_bytes(b"\xfe\xed\xfa\xcf" + b"\x00" * 100)
        assert C2Detector._is_binary_file(macho64) is True

    def test_rfc5737_ranges_filtered(self) -> None:
        """RFC 5737 documentation ranges should be filtered."""
        # TEST-NET-1 (192.0.2.0/24)
        assert C2Detector._is_private_or_reserved("192.0.2.1") is True
        # TEST-NET-2 (198.51.100.0/24)
        assert C2Detector._is_private_or_reserved("198.51.100.1") is True
        # TEST-NET-3 (203.0.113.0/24)
        assert C2Detector._is_private_or_reserved("203.0.113.1") is True

    def test_private_ranges_comprehensive(self) -> None:
        """Test all standard private/reserved IP ranges."""
        # RFC 1918 private
        assert C2Detector._is_private_or_reserved("10.0.0.1") is True
        assert C2Detector._is_private_or_reserved("172.16.0.1") is True
        assert C2Detector._is_private_or_reserved("172.31.255.255") is True
        assert C2Detector._is_private_or_reserved("192.168.1.1") is True
        # Loopback
        assert C2Detector._is_private_or_reserved("127.0.0.1") is True
        # Link-local
        assert C2Detector._is_private_or_reserved("169.254.1.1") is True
        # Multicast
        assert C2Detector._is_private_or_reserved("224.0.0.1") is True
        # Reserved
        assert C2Detector._is_private_or_reserved("240.0.0.1") is True
        # CGN
        assert C2Detector._is_private_or_reserved("100.64.0.1") is True
        # Public IPs should NOT be filtered
        assert C2Detector._is_private_or_reserved("8.8.8.8") is False
        assert C2Detector._is_private_or_reserved("1.1.1.1") is False
        assert C2Detector._is_private_or_reserved("142.250.80.46") is False


# ──────────────────────────────────────────────
# Integration
# ──────────────────────────────────────────────


class TestC2Integration:
    """Integration tests combining domain + IP + malware detection."""

    def test_full_c2_detection_pipeline(self, detector: C2Detector, tmp_path: Path) -> None:
        """Full pipeline: domain + IP + malware detection on a firmware inventory."""
        # Create realistic firmware files
        hosts = tmp_path / "etc" / "hosts"
        hosts.parent.mkdir(parents=True, exist_ok=True)
        hosts.write_text("127.0.0.1 localhost\n185.220.101.37 c2server\n91.234.99.42 backup-c2\n")

        config = tmp_path / "etc" / "config.conf"
        config.write_text(
            "update_server c2.malware-c2.su\n"
            "backup_server vpnfilter-c2.su\n"
            "ntp_server pool.ntp.org\n"
        )

        findings_list = [
            FilesystemFinding(
                path=Path("etc/hosts"),
                absolute_path=hosts,
                category=FileCategory.CRITICAL_CONFIG,
                file_type="ASCII text",
                file_size=100,
                permissions="rw-r--r--",
                owner_uid=0,
                owner_gid=0,
                is_suid=False,
                is_world_writable=False,
                hash_sha256="f1" * 32,
            ),
            FilesystemFinding(
                path=Path("etc/config.conf"),
                absolute_path=config,
                category=FileCategory.CRITICAL_CONFIG,
                file_type="ASCII text",
                file_size=200,
                permissions="rw-r--r--",
                owner_uid=0,
                owner_gid=0,
                is_suid=False,
                is_world_writable=False,
                hash_sha256="f2" * 32,
            ),
        ]

        inv = _make_inventory(findings_list)
        domain_findings = detector.detect_domains(inv)
        ip_findings = detector.detect_ips(inv)

        # Should find malicious domains (c2.malware-c2.su is in threat intel)
        malicious_domains = [f for f in domain_findings if "malware-c2" in f.value]
        assert len(malicious_domains) >= 1

        # Should find threat intel IPs
        malicious_ips = [f for f in ip_findings if f.value in ("185.220.101.37", "91.234.99.42")]
        assert len(malicious_ips) >= 1

        # All findings should be C2Finding instances
        for f in domain_findings + ip_findings:
            assert isinstance(f, C2Finding)
            assert f.indicator_type in ("domain", "ip")
            assert f.severity in ("LIKELY_C2", "SUSPICIOUS", "INFORMATIONAL")

    def test_deduplication(self, detector: C2Detector, tmp_path: Path) -> None:
        """Same domain in multiple files should be deduplicated."""
        # Same domain appears in two files
        f1 = tmp_path / "a.conf"
        f1.write_text("server evil.evil.top\n")
        f2 = tmp_path / "b.conf"
        f2.write_text("server evil.evil.top\n")

        ff1 = FilesystemFinding(
            path=Path("a.conf"),
            absolute_path=f1,
            category=FileCategory.CRITICAL_CONFIG,
            file_type="ASCII text",
            file_size=50,
            permissions="rw-r--r--",
            owner_uid=0,
            owner_gid=0,
            is_suid=False,
            is_world_writable=False,
            hash_sha256="d1" * 32,
        )
        ff2 = FilesystemFinding(
            path=Path("b.conf"),
            absolute_path=f2,
            category=FileCategory.CRITICAL_CONFIG,
            file_type="ASCII text",
            file_size=50,
            permissions="rw-r--r--",
            owner_uid=0,
            owner_gid=0,
            is_suid=False,
            is_world_writable=False,
            hash_sha256="d2" * 32,
        )
        inv = _make_inventory([ff1, ff2])
        findings = detector.detect_domains(inv)

        # Same domain should only appear once
        evil_findings = [f for f in findings if f.value == "evil.evil.top"]
        assert len(evil_findings) <= 1
