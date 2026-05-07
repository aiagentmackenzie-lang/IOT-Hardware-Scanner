"""Tests for UnixCredentialParser — Phase 4.

SDR §10 — Unix Credential Parsing
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from iot_hardware_scanner.models import Severity
from iot_hardware_scanner.scanner.unix_cred_parser import (
    NON_LOGIN_SHELLS,
    UnixCredentialParser,
)


@pytest.fixture
def parser() -> UnixCredentialParser:
    """Return a UnixCredentialParser instance."""
    return UnixCredentialParser()


# ──────────────────────────────────────────────
# parse_passwd
# ──────────────────────────────────────────────


class TestParsePasswd:
    def test_valid_passwd(self, parser: UnixCredentialParser) -> None:
        """Parse a valid /etc/passwd file."""
        content = (
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(content)
            f.flush()
            path = Path(f.name)

        try:
            entries = parser.parse_passwd(path)
            assert len(entries) == 3
            assert entries[0].username == "root"
            assert entries[0].uid == 0
            assert entries[0].gid == 0
            assert entries[0].has_password_field is True
            assert entries[0].is_root_equivalent is True
            assert entries[0].has_login_shell is True
        finally:
            path.unlink(missing_ok=True)

    def test_uid_zero_detection(self, parser: UnixCredentialParser) -> None:
        """UID 0 entries are flagged as root-equivalent."""
        content = (
            "root:x:0:0:root:/root:/bin/bash\n"
            "toor:x:0:0:toor:/root:/bin/sh\n"
            "admin:x:1000:1000:admin:/home/admin:/bin/bash\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(content)
            f.flush()
            path = Path(f.name)

        try:
            entries = parser.parse_passwd(path)
            root_eq = [e for e in entries if e.is_root_equivalent]
            assert len(root_eq) == 2
            usernames = {e.username for e in root_eq}
            assert "root" in usernames
            assert "toor" in usernames
            assert "admin" not in usernames
        finally:
            path.unlink(missing_ok=True)

    def test_login_shell_detection(self, parser: UnixCredentialParser) -> None:
        """Login shells vs non-login shells are correctly identified."""
        content = (
            "user1:x:1000:1000::/home/user1:/bin/bash\n"
            "user2:x:1001:1001::/home/user2:/sbin/nologin\n"
            "user3:x:1002:1002::/home/user3:/bin/false\n"
            "user4:x:1003:1003::/home/user4:/bin/sh\n"
            "user5:x:1004:1004::/home/user5:/usr/sbin/nologin\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(content)
            f.flush()
            path = Path(f.name)

        try:
            entries = parser.parse_passwd(path)
            login_users = [e for e in entries if e.has_login_shell]
            nologin_users = [e for e in entries if not e.has_login_shell]
            assert len(login_users) == 2  # user1 (bash), user4 (sh)
            assert len(nologin_users) == 3  # user2, user3, user5
        finally:
            path.unlink(missing_ok=True)

    def test_empty_password_field(self, parser: UnixCredentialParser) -> None:
        """Empty password field (no 'x') is detected."""
        content = (
            "root:x:0:0:root:/root:/bin/bash\n"
            "nopw::1000:1000::/home/nopw:/bin/bash\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(content)
            f.flush()
            path = Path(f.name)

        try:
            entries = parser.parse_passwd(path)
            assert entries[0].has_password_field is True  # root has 'x'
            assert entries[1].has_password_field is False  # nopw has empty
        finally:
            path.unlink(missing_ok=True)

    def test_comments_and_blank_lines(self, parser: UnixCredentialParser) -> None:
        """Comments and blank lines are skipped."""
        content = (
            "# This is a comment\n"
            "\n"
            "root:x:0:0:root:/root:/bin/bash\n"
            "\n"
            "# Another comment\n"
            "admin:x:1000:1000:admin:/home/admin:/bin/sh\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(content)
            f.flush()
            path = Path(f.name)

        try:
            entries = parser.parse_passwd(path)
            assert len(entries) == 2
        finally:
            path.unlink(missing_ok=True)

    def test_malformed_lines(self, parser: UnixCredentialParser) -> None:
        """Lines with fewer than 7 fields are skipped."""
        content = (
            "root:x:0:0:root:/root:/bin/bash\n"
            "badline1:incomplete\n"
            "badline2:a:b:c\n"
            "admin:x:1000:1000:admin:/home/admin:/bin/sh\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(content)
            f.flush()
            path = Path(f.name)

        try:
            entries = parser.parse_passwd(path)
            assert len(entries) == 2
            usernames = {e.username for e in entries}
            assert "root" in usernames
            assert "admin" in usernames
        finally:
            path.unlink(missing_ok=True)

    def test_nonexistent_file(self, parser: UnixCredentialParser) -> None:
        """Non-existent file returns empty list."""
        entries = parser.parse_passwd(Path("/nonexistent/passwd"))
        assert entries == []

    def test_permission_error(self, parser: UnixCredentialParser) -> None:
        """PermissionError returns empty list."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("root:x:0:0:root:/root:/bin/bash\n")
            f.flush()
            path = Path(f.name)

        try:
            path.chmod(0o000)
            entries = parser.parse_passwd(path)
            assert entries == []
        finally:
            path.chmod(0o644)
            path.unlink(missing_ok=True)


# ──────────────────────────────────────────────
# parse_shadow
# ──────────────────────────────────────────────


class TestParseShadow:
    def test_md5_hash_high_severity(self, parser: UnixCredentialParser) -> None:
        """MD5 ($1$) hashes are flagged as HIGH severity."""
        content = "user1:$1$salt$hash123456789012345678901:19000:0:99999:7:::\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(content)
            f.flush()
            path = Path(f.name)

        try:
            entries = parser.parse_shadow(path)
            assert len(entries) == 1
            assert entries[0].hash_algorithm == "MD5"
            assert entries[0].severity == Severity.HIGH
            assert entries[0].is_locked is False
            assert entries[0].is_empty is False
        finally:
            path.unlink(missing_ok=True)

    def test_sha256_hash_medium_severity(self, parser: UnixCredentialParser) -> None:
        """SHA-256 ($5$) hashes are flagged as MEDIUM severity."""
        content = "user2:$5$salt$hash123456789012345678901234567890:19000:0:99999:7:::\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(content)
            f.flush()
            path = Path(f.name)

        try:
            entries = parser.parse_shadow(path)
            assert entries[0].hash_algorithm == "SHA-256"
            assert entries[0].severity == Severity.MEDIUM
        finally:
            path.unlink(missing_ok=True)

    def test_sha512_hash_low_severity(self, parser: UnixCredentialParser) -> None:
        """SHA-512 ($6$) hashes are flagged as LOW severity."""
        content = (
            "user3:$6$salt$hash12345678901234567890"
            "12345678901234567890123:19000:0:99999:7:::\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(content)
            f.flush()
            path = Path(f.name)

        try:
            entries = parser.parse_shadow(path)
            assert entries[0].hash_algorithm == "SHA-512"
            assert entries[0].severity == Severity.LOW
        finally:
            path.unlink(missing_ok=True)

    def test_bcrypt_hash_low_severity(self, parser: UnixCredentialParser) -> None:
        """bcrypt ($2y$) hashes are flagged as LOW severity."""
        content = "user4:$2y$10$abcdefghijklmnopqrstuvwxABCDEFGHIJ:19000:0:99999:7:::\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(content)
            f.flush()
            path = Path(f.name)

        try:
            entries = parser.parse_shadow(path)
            assert entries[0].hash_algorithm == "bcrypt"
            assert entries[0].severity == Severity.LOW
        finally:
            path.unlink(missing_ok=True)

    def test_bcrypt_2a_variant(self, parser: UnixCredentialParser) -> None:
        """bcrypt $2a$ variant is also detected."""
        content = "user5:$2a$10$abcdefghijklmnopqrstuvwxABCDEFGHIJ:19000:0:99999:7:::\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(content)
            f.flush()
            path = Path(f.name)

        try:
            entries = parser.parse_shadow(path)
            assert entries[0].hash_algorithm == "bcrypt"
        finally:
            path.unlink(missing_ok=True)

    def test_empty_hash_critical(self, parser: UnixCredentialParser) -> None:
        """Empty hash field = NO PASSWORD = CRITICAL severity."""
        content = "user6::19000:0:99999:7:::\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(content)
            f.flush()
            path = Path(f.name)

        try:
            entries = parser.parse_shadow(path)
            assert entries[0].is_empty is True
            assert entries[0].severity == Severity.CRITICAL
            assert entries[0].hash_value == ""
        finally:
            path.unlink(missing_ok=True)

    def test_locked_account_exclamation(self, parser: UnixCredentialParser) -> None:
        """Locked account (!) is INFO severity."""
        content = "user7:!$6$salt$hash123:19000:0:99999:7:::\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(content)
            f.flush()
            path = Path(f.name)

        try:
            entries = parser.parse_shadow(path)
            assert entries[0].is_locked is True
            assert entries[0].severity == Severity.INFO
        finally:
            path.unlink(missing_ok=True)

    def test_locked_account_star(self, parser: UnixCredentialParser) -> None:
        """Locked account (*) is INFO severity."""
        content = "user8:*:19000:0:99999:7:::\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(content)
            f.flush()
            path = Path(f.name)

        try:
            entries = parser.parse_shadow(path)
            assert entries[0].is_locked is True
            assert entries[0].severity == Severity.INFO
        finally:
            path.unlink(missing_ok=True)

    def test_comments_and_blank_lines(self, parser: UnixCredentialParser) -> None:
        """Comments and blank lines are skipped."""
        content = (
            "# Shadow file\n"
            "\n"
            "root:$6$salt$hash:19000:0:99999:7:::\n"
            "\n"
            "# Locked account\n"
            "daemon:*:19000:0:99999:7:::\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(content)
            f.flush()
            path = Path(f.name)

        try:
            entries = parser.parse_shadow(path)
            assert len(entries) == 2
        finally:
            path.unlink(missing_ok=True)

    def test_days_since_change(self, parser: UnixCredentialParser) -> None:
        """days_since_change is parsed from field 3."""
        content = "user:$6$salt$hash:19000:0:99999:7:::\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(content)
            f.flush()
            path = Path(f.name)

        try:
            entries = parser.parse_shadow(path)
            assert entries[0].days_since_change is not None
            assert entries[0].days_since_change > 0
        finally:
            path.unlink(missing_ok=True)

    def test_days_since_change_invalid(self, parser: UnixCredentialParser) -> None:
        """Invalid days_since_change is set to None."""
        content = "user:$6$salt$hash:invalid:0:99999:7:::\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(content)
            f.flush()
            path = Path(f.name)

        try:
            entries = parser.parse_shadow(path)
            assert entries[0].days_since_change is None
        finally:
            path.unlink(missing_ok=True)

    def test_hash_value_masking(self, parser: UnixCredentialParser) -> None:
        """Hash values are masked in the output."""
        content = "user:$6$salt$hash1234567890abcdef:19000:0:99999:7:::\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(content)
            f.flush()
            path = Path(f.name)

        try:
            entries = parser.parse_shadow(path)
            # Masked value should contain "***" not the raw hash
            assert "***" in entries[0].hash_value
            # Should contain algo prefix
            assert "$6$" in entries[0].hash_value or entries[0].hash_algorithm == "SHA-512"
        finally:
            path.unlink(missing_ok=True)

    def test_nonexistent_file(self, parser: UnixCredentialParser) -> None:
        """Non-existent file returns empty list."""
        entries = parser.parse_shadow(Path("/nonexistent/shadow"))
        assert entries == []

    def test_permission_error(self, parser: UnixCredentialParser) -> None:
        """PermissionError returns empty list."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("root:$6$salt$hash:19000:0:99999:7:::\n")
            f.flush()
            path = Path(f.name)

        try:
            path.chmod(0o000)
            entries = parser.parse_shadow(path)
            assert entries == []
        finally:
            path.chmod(0o644)
            path.unlink(missing_ok=True)

    def test_multiple_entries(self, parser: UnixCredentialParser) -> None:
        """Multiple shadow entries are all parsed."""
        content = (
            "root:$6$salt1$hash1:19000:0:99999:7:::\n"
            "admin:$1$salt2$hash23456789012345678901:19000:0:99999:7:::\n"
            "nobody:*:19000:0:99999:7:::\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(content)
            f.flush()
            path = Path(f.name)

        try:
            entries = parser.parse_shadow(path)
            assert len(entries) == 3
            assert entries[0].hash_algorithm == "SHA-512"
            assert entries[0].severity == Severity.LOW
            assert entries[1].hash_algorithm == "MD5"
            assert entries[1].severity == Severity.HIGH
            assert entries[2].is_locked is True
            assert entries[2].severity == Severity.INFO
        finally:
            path.unlink(missing_ok=True)


# ──────────────────────────────────────────────
# NON_LOGIN_SHELLS constant
# ──────────────────────────────────────────────


class TestConstants:
    def test_non_login_shells(self) -> None:
        """NON_LOGIN_SHELLS contains expected entries."""
        assert "/sbin/nologin" in NON_LOGIN_SHELLS
        assert "/bin/false" in NON_LOGIN_SHELLS
        assert "/bin/bash" not in NON_LOGIN_SHELLS
