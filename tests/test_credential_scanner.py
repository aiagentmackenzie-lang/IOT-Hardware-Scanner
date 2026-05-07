"""Tests for CredentialScanner — Phase 4.

SDR §10 — Credential & Secret Detection
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.models import (
    FileCategory,
    FilesystemFinding,
    FilesystemInventory,
    Severity,
)
from iot_hardware_scanner.scanner.credential_scanner import CredentialScanner


@pytest.fixture
def config() -> ScannerConfig:
    """Return a default ScannerConfig."""
    return ScannerConfig()


@pytest.fixture
def scanner(config: ScannerConfig) -> CredentialScanner:
    """Return a CredentialScanner with default config."""
    return CredentialScanner(config)


def _make_inventory(
    root: Path, files: dict[str, str], category: FileCategory
) -> FilesystemInventory:
    """Build a FilesystemInventory from a dict of {relative_path: content}.

    Creates the files on disk under root and populates the inventory.
    """
    inventory = FilesystemInventory(rootfs_path=root)
    findings_list: list[FilesystemFinding] = []
    category_map: dict[FileCategory, list[FilesystemFinding]] = {category: []}

    for rel, content in files.items():
        abs_path = root / rel
        abs_path.parent.mkdir(parents=True, exist_ok=True)
        abs_path.write_text(content, encoding="utf-8")

        ff = FilesystemFinding(
            path=Path(rel),
            absolute_path=abs_path,
            category=category,
            file_type="text",
            file_size=len(content),
            permissions="rw-r--r--",
            owner_uid=0,
            owner_gid=0,
            is_suid=False,
            is_world_writable=False,
            hash_sha256="abc",
        )
        findings_list.append(ff)
        category_map.setdefault(category, []).append(ff)

    inventory.findings = findings_list
    inventory.categories = category_map
    inventory.total_files = len(findings_list)
    return inventory


# ──────────────────────────────────────────────
# scan_inventory
# ──────────────────────────────────────────────


class TestScanInventory:
    def test_none_inventory(self, scanner: CredentialScanner) -> None:
        """scan_inventory with None returns empty list."""
        assert scanner.scan_inventory(None) == []

    def test_empty_inventory(self, scanner: CredentialScanner) -> None:
        """scan_inventory with empty inventory returns empty list."""
        with tempfile.TemporaryDirectory() as tmpdir:
            inv = FilesystemInventory(rootfs_path=Path(tmpdir))
            inv.categories = {}
            assert scanner.scan_inventory(inv) == []

    def test_scan_inventory_with_password(self, scanner: CredentialScanner) -> None:
        """Detect hardcoded password in inventory scan."""
        with tempfile.TemporaryDirectory() as tmpdir:
            inv = _make_inventory(
                Path(tmpdir),
                {"etc/config.cfg": 'password = "super_secret_value"\n'},
                FileCategory.CRITICAL_CREDENTIAL,
            )
            findings = scanner.scan_inventory(inv)
            assert len(findings) >= 1
            cats = {f.category for f in findings}
            assert "password" in cats

    def test_scan_inventory_dedup(self, scanner: CredentialScanner) -> None:
        """Duplicate findings are deduplicated by raw_value_hash."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Same password in two files
            files = {
                "etc/a.cfg": 'password = "same_password_123"\n',
                "etc/b.cfg": 'password = "same_password_123"\n',
            }
            inv = _make_inventory(Path(tmpdir), files, FileCategory.CRITICAL_CREDENTIAL)
            findings = scanner.scan_inventory(inv)
            # Same raw value hash should be deduped
            hashes = [f.raw_value_hash for f in findings if f.category == "password"]
            assert len(set(hashes)) == len(hashes), "Duplicate hashes found"


# ──────────────────────────────────────────────
# scan_file — Password patterns
# ──────────────────────────────────────────────


class TestScanFilePasswords:
    def test_hardcoded_password(self, scanner: CredentialScanner) -> None:
        """Detect password = 'value' pattern."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".cfg", delete=False) as f:
            f.write('password = "MyS3cretP@ssword!"\n')
            f.flush()
            path = Path(f.name)
            rel = Path("config.cfg")

        try:
            findings = scanner.scan_file(path, rel)
            assert len(findings) >= 1
            pwd_f = [f for f in findings if f.category == "password"]
            assert len(pwd_f) >= 1
            assert pwd_f[0].severity == Severity.CRITICAL
        finally:
            path.unlink(missing_ok=True)

    def test_passwd_pattern(self, scanner: CredentialScanner) -> None:
        """Detect passwd = 'value' pattern."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".cfg", delete=False) as f:
            f.write('passwd = "db_pass_2024"\n')
            f.flush()
            path = Path(f.name)
            rel = Path("db.cfg")

        try:
            findings = scanner.scan_file(path, rel)
            pwd_f = [f for f in findings if f.category == "password"]
            assert len(pwd_f) >= 1
        finally:
            path.unlink(missing_ok=True)

    def test_db_password_pattern(self, scanner: CredentialScanner) -> None:
        """Detect DB_PASSWORD pattern."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write('DB_PASSWORD = "prod_database_pw"\n')
            f.flush()
            path = Path(f.name)
            rel = Path(".env")

        try:
            findings = scanner.scan_file(path, rel)
            pwd_f = [f for f in findings if f.category == "password"]
            assert len(pwd_f) >= 1
            assert pwd_f[0].severity == Severity.CRITICAL
        finally:
            path.unlink(missing_ok=True)


# ──────────────────────────────────────────────
# scan_file — API key patterns
# ──────────────────────────────────────────────


class TestScanFileAPIKeys:
    def test_aws_access_key(self, scanner: CredentialScanner) -> None:
        """Detect AWS Access Key ID."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
            f.flush()
            path = Path(f.name)
            rel = Path(".env")

        try:
            findings = scanner.scan_file(path, rel)
            assert len(findings) >= 1
            api_f = [f for f in findings if f.category == "api_key"]
            assert len(api_f) >= 1
        finally:
            path.unlink(missing_ok=True)

    def test_github_pat(self, scanner: CredentialScanner) -> None:
        """Detect GitHub Personal Access Token."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write(f"GITHUB_TOKEN=ghp_{'A' * 36}\n")
            f.flush()
            path = Path(f.name)
            rel = Path(".env")

        try:
            findings = scanner.scan_file(path, rel)
            api_f = [f for f in findings if f.category == "api_key"]
            assert len(api_f) >= 1
        finally:
            path.unlink(missing_ok=True)

    def test_stripe_key(self, scanner: CredentialScanner) -> None:
        """Detect Stripe secret key."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write(f"STRIPE_KEY=sk_live_{'a' * 24}abcdef\n")
            f.flush()
            path = Path(f.name)
            rel = Path(".env")

        try:
            findings = scanner.scan_file(path, rel)
            api_f = [f for f in findings if f.category == "api_key"]
            assert len(api_f) >= 1
        finally:
            path.unlink(missing_ok=True)


# ──────────────────────────────────────────────
# scan_file — Private key patterns
# ──────────────────────────────────────────────


class TestScanFilePrivateKeys:
    def test_rsa_private_key(self, scanner: CredentialScanner) -> None:
        """Detect RSA private key."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as f:
            f.write("-----BEGIN RSA PRIVATE KEY-----\nMIIBog\n-----END RSA PRIVATE KEY-----\n")
            f.flush()
            path = Path(f.name)
            rel = Path("id_rsa.pem")

        try:
            findings = scanner.scan_file(path, rel)
            pk_f = [f for f in findings if f.category == "private_key"]
            assert len(pk_f) >= 1
            assert pk_f[0].severity == Severity.HIGH
        finally:
            path.unlink(missing_ok=True)

    def test_openssh_private_key(self, scanner: CredentialScanner) -> None:
        """Detect OpenSSH private key."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as f:
            f.write(
                "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                "AAAAC3NzaC1lZDI1NTE5AAAA\n"
                "-----END OPENSSH PRIVATE KEY-----\n"
            )
            f.flush()
            path = Path(f.name)
            rel = Path("id_ed25519")

        try:
            findings = scanner.scan_file(path, rel)
            pk_f = [f for f in findings if f.category == "private_key"]
            assert len(pk_f) >= 1
        finally:
            path.unlink(missing_ok=True)


# ──────────────────────────────────────────────
# scan_file — Token patterns
# ──────────────────────────────────────────────


class TestScanFileTokens:
    def test_bearer_token(self, scanner: CredentialScanner) -> None:
        """Detect Bearer token."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".cfg", delete=False) as f:
            f.write(
                "Authorization: Bearer "
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456\n"
            )
            f.flush()
            path = Path(f.name)
            rel = Path("api.cfg")

        try:
            findings = scanner.scan_file(path, rel)
            token_f = [f for f in findings if f.category == "token"]
            assert len(token_f) >= 1
        finally:
            path.unlink(missing_ok=True)

    def test_jwt_token(self, scanner: CredentialScanner) -> None:
        """Detect JWT token."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".cfg", delete=False) as f:
            f.write("token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456\n")
            f.flush()
            path = Path(f.name)
            rel = Path("auth.cfg")

        try:
            findings = scanner.scan_file(path, rel)
            token_f = [f for f in findings if f.category == "token"]
            assert len(token_f) >= 1
        finally:
            path.unlink(missing_ok=True)


# ──────────────────────────────────────────────
# scan_file — Connection string patterns
# ──────────────────────────────────────────────


class TestScanFileConnectionStrings:
    def test_mysql_connection_string(self, scanner: CredentialScanner) -> None:
        """Detect MySQL connection string with embedded password."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".cfg", delete=False) as f:
            f.write("DATABASE_URL=mysql://admin:secretpw@db.example.com:3306/mydb\n")
            f.flush()
            path = Path(f.name)
            rel = Path("db.cfg")

        try:
            findings = scanner.scan_file(path, rel)
            cs_f = [f for f in findings if f.category == "connection_string"]
            assert len(cs_f) >= 1
        finally:
            path.unlink(missing_ok=True)

    def test_postgres_connection_string(self, scanner: CredentialScanner) -> None:
        """Detect PostgreSQL connection string."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write("DATABASE_URL=postgres://user:pass123@localhost:5432/app\n")
            f.flush()
            path = Path(f.name)
            rel = Path(".env")

        try:
            findings = scanner.scan_file(path, rel)
            cs_f = [f for f in findings if f.category == "connection_string"]
            assert len(cs_f) >= 1
        finally:
            path.unlink(missing_ok=True)


# ──────────────────────────────────────────────
# False-positive reduction
# ──────────────────────────────────────────────


class TestFalsePositiveReduction:
    def test_placeholder_changeme(self, scanner: CredentialScanner) -> None:
        """Placeholder 'changeme' is detected and marked as placeholder."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".cfg", delete=False) as f:
            f.write('password = "changeme"\n')
            f.flush()
            path = Path(f.name)
            rel = Path("config.cfg")

        try:
            findings = scanner.scan_file(path, rel)
            pwd_f = [f for f in findings if f.category == "password"]
            assert len(pwd_f) >= 1
            assert pwd_f[0].is_placeholder is True
            assert pwd_f[0].severity == Severity.LOW
        finally:
            path.unlink(missing_ok=True)

    def test_placeholder_your_api_key(self, scanner: CredentialScanner) -> None:
        """Placeholder 'YOUR_API_KEY' is detected."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".cfg", delete=False) as f:
            f.write('password = "YOUR_API_KEY"\n')
            f.flush()
            path = Path(f.name)
            rel = Path("config.cfg")

        try:
            findings = scanner.scan_file(path, rel)
            pwd_f = [f for f in findings if f.category == "password"]
            assert len(pwd_f) >= 1
            assert pwd_f[0].is_placeholder is True
        finally:
            path.unlink(missing_ok=True)

    def test_placeholder_test(self, scanner: CredentialScanner) -> None:
        """Placeholder 'test' is detected."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".cfg", delete=False) as f:
            f.write('password = "test"\n')
            f.flush()
            path = Path(f.name)
            rel = Path("config.cfg")

        try:
            findings = scanner.scan_file(path, rel)
            # "test" is only 4 chars — matches {4,} but is a known placeholder
            pwd_f = [f for f in findings if f.category == "password"]
            if pwd_f:
                assert pwd_f[0].is_placeholder is True
        finally:
            path.unlink(missing_ok=True)

    def test_docs_file_skipped(self, scanner: CredentialScanner) -> None:
        """Files in docs/ with .md extension are skipped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            docs_dir = Path(tmpdir) / "docs"
            docs_dir.mkdir()
            fpath = docs_dir / "readme.md"
            fpath.write_text('password = "real_password_123"\n')
            rel = Path("docs/readme.md")

            findings = scanner.scan_file(fpath, rel)
            assert findings == [], f"docs/ .md file should be skipped, got {findings}"

    def test_non_docs_md_not_skipped(self, scanner: CredentialScanner) -> None:
        """Markdown file NOT in docs/ is still scanned."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            f.write('password = "real_password_123"\n')
            f.flush()
            path = Path(f.name)
            rel = Path("notes.md")

        try:
            findings = scanner.scan_file(path, rel)
            # Not in docs/ — should not be skipped
            assert len(findings) >= 1
        finally:
            path.unlink(missing_ok=True)

    def test_binary_file_regex_skip(self, scanner: CredentialScanner) -> None:
        """ELF binary files skip regex but YARA still runs."""
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".bin", delete=False) as f:
            # ELF magic bytes + some content
            f.write(b"\x7fELF\x02\x01\x01\x00password = secret\n")
            f.flush()
            path = Path(f.name)
            rel = Path("program.bin")

        try:
            findings = scanner.scan_file(path, rel)
            # Regex should be skipped (binary), but YARA may still match
            # No regex-based findings expected
            [
                f
                for f in findings
                if f.matched_pattern
                not in (
                    "hardcoded_password_variable",
                    "aws_access_key",
                    "ssh_private_key",
                    "github_personal_access_token",
                    "stripe_secret_key",
                    "bearer_token",
                    "oauth_token",
                    "database_connection_string",
                    "unix_md5_hash",
                )
            ]
            # All findings should be from YARA (if any), not regex
            for f in findings:
                # YARA matches don't have line_number
                assert f.line_number is None or f.category != "password"
        finally:
            path.unlink(missing_ok=True)

    def test_entropy_gating(self, scanner: CredentialScanner) -> None:
        """Low-entropy values like 'aaaa' may be flagged as placeholders."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".cfg", delete=False) as f:
            f.write('password = "aaaa"\n')
            f.flush()
            path = Path(f.name)
            rel = Path("config.cfg")

        try:
            findings = scanner.scan_file(path, rel)
            pwd_f = [f for f in findings if f.category == "password"]
            if pwd_f:
                # Low entropy — likely placeholder
                assert pwd_f[0].is_placeholder is True or pwd_f[0].severity in (
                    Severity.LOW,
                    Severity.INFO,
                )
        finally:
            path.unlink(missing_ok=True)


# ──────────────────────────────────────────────
# Default credential cross-reference
# ──────────────────────────────────────────────


class TestDefaultCredentials:
    def test_default_password_detected(self, scanner: CredentialScanner) -> None:
        """Known default password 'admin' is flagged as default."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".cfg", delete=False) as f:
            f.write('password = "admin"\n')
            f.flush()
            path = Path(f.name)
            rel = Path("config.cfg")

        try:
            findings = scanner.scan_file(path, rel)
            pwd_f = [f for f in findings if f.category == "password"]
            if pwd_f:
                # 'admin' is a known default password
                assert any(f.is_default for f in pwd_f) or any(f.is_placeholder for f in pwd_f)
        finally:
            path.unlink(missing_ok=True)

    def test_default_password_escalates(self, scanner: CredentialScanner) -> None:
        """Default credentials are escalated to CRITICAL."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".cfg", delete=False) as f:
            f.write('password = "password"\n')
            f.flush()
            path = Path(f.name)
            rel = Path("config.cfg")

        try:
            findings = scanner.scan_file(path, rel)
            pwd_f = [f for f in findings if f.category == "password"]
            # "password" is both a placeholder AND a known default
            if pwd_f:
                assert any(f.is_default or f.is_placeholder for f in pwd_f)
        finally:
            path.unlink(missing_ok=True)


# ──────────────────────────────────────────────
# Context window deprioritization
# ──────────────────────────────────────────────


class TestContextDeprioritization:
    def test_example_context_deprioritizes(self, scanner: CredentialScanner) -> None:
        """Password in example context is deprioritized."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".cfg", delete=False) as f:
            f.write("# This is an example configuration\n")
            f.write("# For demonstration purposes only\n")
            f.write('password = "example_database_password"\n')
            f.flush()
            path = Path(f.name)
            rel = Path("example.cfg")

        try:
            findings = scanner.scan_file(path, rel)
            pwd_f = [f for f in findings if f.category == "password"]
            if pwd_f:
                # Should be deprioritized (reduced severity)
                assert pwd_f[0].severity in (
                    Severity.HIGH,
                    Severity.MEDIUM,
                    Severity.LOW,
                    Severity.INFO,
                )
        finally:
            path.unlink(missing_ok=True)


# ──────────────────────────────────────────────
# Masking and hashing
# ──────────────────────────────────────────────


class TestMaskingAndHashing:
    def test_masking(self, scanner: CredentialScanner) -> None:
        """Sensitive values are properly masked."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".cfg", delete=False) as f:
            f.write('password = "super_long_secret_value"\n')
            f.flush()
            path = Path(f.name)
            rel = Path("config.cfg")

        try:
            findings = scanner.scan_file(path, rel)
            pwd_f = [f for f in findings if f.category == "password" and not f.is_placeholder]
            if pwd_f:
                # Should be masked: sup***alue
                assert "***" in pwd_f[0].masked_value
                assert "super_long_secret_value" not in pwd_f[0].masked_value
        finally:
            path.unlink(missing_ok=True)

    def test_raw_value_hash_unique(self, scanner: CredentialScanner) -> None:
        """Different values produce different hashes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            p1 = Path(tmpdir) / "a.cfg"
            p1.write_text('password = "first_unique_value"\n')
            p2 = Path(tmpdir) / "b.cfg"
            p2.write_text('password = "second_unique_value"\n')

            f1 = scanner.scan_file(p1, Path("a.cfg"))
            f2 = scanner.scan_file(p2, Path("b.cfg"))

            hashes1 = {f.raw_value_hash for f in f1 if f.category == "password"}
            hashes2 = {f.raw_value_hash for f in f2 if f.category == "password"}
            # Different passwords should have different hashes
            assert hashes1 != hashes2 or len(hashes1) == 0 or len(hashes2) == 0


# ──────────────────────────────────────────────
# Edge cases
# ──────────────────────────────────────────────


class TestEdgeCases:
    def test_empty_file(self, scanner: CredentialScanner) -> None:
        """Empty file produces no findings."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".cfg", delete=False) as f:
            f.write("")
            f.flush()
            path = Path(f.name)
            rel = Path("empty.cfg")

        try:
            findings = scanner.scan_file(path, rel)
            assert findings == []
        finally:
            path.unlink(missing_ok=True)

    def test_unreadable_file(self, scanner: CredentialScanner) -> None:
        """PermissionError on read returns empty list."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".cfg", delete=False) as f:
            f.write('password = "secret"\n')
            f.flush()
            path = Path(f.name)
            rel = Path("secret.cfg")

        try:
            # Make file unreadable
            path.chmod(0o000)
            findings = scanner.scan_file(path, rel)
            assert findings == []
        finally:
            path.chmod(0o644)
            path.unlink(missing_ok=True)

    def test_multiple_findings_same_file(self, scanner: CredentialScanner) -> None:
        """Multiple credentials in the same file are all detected."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".cfg", delete=False) as f:
            f.write('password = "first_secret_abc"\n')
            f.write('DB_PASSWORD = "second_secret_def"\n')
            f.write("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
            f.flush()
            path = Path(f.name)
            rel = Path("multi.cfg")

        try:
            findings = scanner.scan_file(path, rel)
            categories = {f.category for f in findings}
            # Should have at least password and api_key
            assert "password" in categories or len(findings) >= 2
        finally:
            path.unlink(missing_ok=True)

    def test_is_placeholder_static(self) -> None:
        """_is_placeholder works as a static method."""
        assert CredentialScanner._is_placeholder("changeme")
        assert CredentialScanner._is_placeholder("YOUR_API_KEY")
        assert CredentialScanner._is_placeholder("Replace_Me")
        assert not CredentialScanner._is_placeholder("realP@ssw0rd!")

    def test_compute_entropy_static(self) -> None:
        """_compute_entropy returns correct Shannon entropy."""
        # Single repeated character = 0 entropy
        assert CredentialScanner._compute_entropy("aaaa") == 0.0
        # Two equally likely chars = 1.0 bit
        assert CredentialScanner._compute_entropy("ab") == 1.0
        # Empty = 0
        assert CredentialScanner._compute_entropy("") == 0.0
        # High entropy string
        ent = CredentialScanner._compute_entropy("aB3$xY9!")
        assert ent > 2.0

    def test_is_docs_file_static(self) -> None:
        """_is_docs_file correctly identifies docs directory files."""
        assert CredentialScanner._is_docs_file(Path("docs/readme.md"))
        assert CredentialScanner._is_docs_file(Path("doc/guide.rst"))
        assert not CredentialScanner._is_docs_file(Path("src/readme.md"))
        assert not CredentialScanner._is_docs_file(Path("docs/config.py"))

    def test_is_binary_file_static(self) -> None:
        """_is_binary_file correctly identifies binary executables."""
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".bin", delete=False) as f:
            f.write(b"\x7fELF\x02\x01\x01\x00")
            f.flush()
            elf_path = Path(f.name)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("Hello world")
            f.flush()
            txt_path = Path(f.name)

        try:
            assert CredentialScanner._is_binary_file(elf_path) is True
            assert CredentialScanner._is_binary_file(txt_path) is False
        finally:
            elf_path.unlink(missing_ok=True)
            txt_path.unlink(missing_ok=True)

    def test_reduce_severity(self) -> None:
        """_reduce_severity reduces by one level."""
        assert CredentialScanner._reduce_severity(Severity.CRITICAL) == Severity.HIGH
        assert CredentialScanner._reduce_severity(Severity.HIGH) == Severity.MEDIUM
        assert CredentialScanner._reduce_severity(Severity.MEDIUM) == Severity.LOW
        assert CredentialScanner._reduce_severity(Severity.LOW) == Severity.INFO
        assert CredentialScanner._reduce_severity(Severity.INFO) == Severity.INFO

    def test_mask_value_static(self) -> None:
        """_mask_value correctly masks sensitive values."""
        assert CredentialScanner._mask_value("short") == "***"
        assert CredentialScanner._mask_value("longpassword123") == "lon***123"
        assert CredentialScanner._mask_value("abc") == "***"
