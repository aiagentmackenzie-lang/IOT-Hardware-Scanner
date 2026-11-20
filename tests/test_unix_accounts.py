"""1F — account records are joined before anything is claimed about them.

A password field is one observation about one authentication method. These
tests pin the typology so a locked root account cannot be reported as a
critical plaintext password, and so two roots with the same paths stay
independent.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.scanner.credential_scanner import CredentialScanner
from iot_hardware_scanner.scanner.unix_cred_parser import (
    STATE_ABSENT,
    STATE_EMPTY,
    STATE_HASH_PRESENT,
    STATE_LOCKED,
    STATE_UNKNOWN,
    UnixCredentialParser,
)

PASSWD = "etc/passwd"


def write_pair(root: Path, passwd: str, shadow: str | None) -> tuple[Path, Path | None]:
    (root / "etc").mkdir(parents=True, exist_ok=True)
    passwd_path = root / PASSWD
    passwd_path.write_text(passwd)
    shadow_path = root / "etc" / "shadow"
    if shadow is None:
        return passwd_path, None
    shadow_path.write_text(shadow)
    return passwd_path, shadow_path


@pytest.fixture
def parser() -> UnixCredentialParser:
    return UnixCredentialParser()


class TestPasswordStateTyping:
    def test_locked_root(self, parser: UnixCredentialParser, tmp_path: Path) -> None:
        passwd, shadow = write_pair(
            tmp_path, "root:x:0:0:root:/root:/bin/ash\n", "root:!$6$s$h:19000::::::\n"
        )
        record = parser.join(passwd, shadow, root_id="r")[0]
        assert record.password_state == STATE_LOCKED
        assert record.is_root is True

    def test_star_locked(self, parser: UnixCredentialParser, tmp_path: Path) -> None:
        passwd, shadow = write_pair(
            tmp_path, "nobody:x:65534:65534::/:/sbin/nologin\n", "nobody:*:19000::::::\n"
        )
        assert parser.join(passwd, shadow, root_id="r")[0].password_state == STATE_LOCKED

    def test_empty_field(self, parser: UnixCredentialParser, tmp_path: Path) -> None:
        passwd, shadow = write_pair(tmp_path, "root:x:0:0::/root:/bin/sh\n", "root::19000::::::\n")
        record = parser.join(passwd, shadow, root_id="r")[0]
        assert record.password_state == STATE_EMPTY

    def test_hash_present_and_algorithm(self, parser: UnixCredentialParser, tmp_path: Path) -> None:
        passwd, shadow = write_pair(
            tmp_path, "root:x:0:0::/root:/bin/sh\n", "root:$1$salt$hash:19000::::::\n"
        )
        record = parser.join(passwd, shadow, root_id="r")[0]
        assert record.password_state == STATE_HASH_PRESENT
        assert record.hash_algorithm == "MD5"

    def test_delegated_field_without_shadow_record_is_unknown(
        self, parser: UnixCredentialParser, tmp_path: Path
    ) -> None:
        passwd, shadow = write_pair(tmp_path, "root:x:0:0::/root:/bin/sh\n", "other:!:::\n")
        record = parser.join(passwd, shadow, root_id="r")[0]
        assert record.password_state == STATE_UNKNOWN

    def test_delegated_field_without_shadow_file_is_absent(
        self, parser: UnixCredentialParser, tmp_path: Path
    ) -> None:
        passwd, shadow = write_pair(tmp_path, "root:x:0:0::/root:/bin/sh\n", None)
        record = parser.join(passwd, shadow, root_id="r")[0]
        assert record.password_state == STATE_ABSENT

    def test_legacy_hash_in_passwd_field(
        self, parser: UnixCredentialParser, tmp_path: Path
    ) -> None:
        passwd, shadow = write_pair(tmp_path, "root:$6$s$h:0:0::/root:/bin/sh\n", None)
        record = parser.join(passwd, shadow, root_id="r")[0]
        assert record.password_state == STATE_HASH_PRESENT


class TestLineProvenance:
    def test_line_numbers_are_recorded(self, parser: UnixCredentialParser, tmp_path: Path) -> None:
        passwd, shadow = write_pair(
            tmp_path,
            "daemon:x:1:1::/:/sbin/nologin\nroot:x:0:0::/root:/bin/sh\n",
            "daemon:!:::\nroot:!$6$s$h:19000::::::\n",
        )
        records = {r.username: r for r in parser.join(passwd, shadow, root_id="r")}
        assert records["root"].passwd_line == 2
        assert records["root"].shadow_line == 2

    def test_hashes_are_never_returned(self, parser: UnixCredentialParser, tmp_path: Path) -> None:
        secret = "$6$abcdefgh$super_secret_hash_value"
        _passwd, shadow = write_pair(tmp_path, "root:x:0:0::/root:/bin/sh\n", f"root:{secret}:::\n")
        entries = parser.parse_shadow(shadow)
        assert entries[0].hash_value != secret
        assert "super_secret" not in entries[0].hash_value


class TestFindingsFromAccounts:
    def _scanner(self) -> CredentialScanner:
        return CredentialScanner(ScannerConfig())

    def test_locked_root_produces_no_password_finding(self, tmp_path: Path) -> None:
        write_pair(tmp_path, "root:x:0:0:root:/root:/bin/ash\n", "root:!$6$s$h:19000::::::\n")
        findings = self._scanner().scan_unix_accounts(None, root=tmp_path)
        assert findings == []

    def test_empty_password_on_login_account_is_critical(self, tmp_path: Path) -> None:
        write_pair(tmp_path, "root:x:0:0:root:/root:/bin/ash\n", "root::19000::::::\n")
        findings = self._scanner().scan_unix_accounts(None, root=tmp_path)
        critical = [f for f in findings if f.severity.value == "CRITICAL"]
        assert len(critical) == 1
        assert critical[0].rule_id == "credential.unix.empty_password"
        assert critical[0].line_number == 1

    def test_empty_password_on_nologin_account_is_not_critical(self, tmp_path: Path) -> None:
        write_pair(
            tmp_path,
            "sync:x:5:5::/:/sbin/nologin\n",
            "sync::19000::::::\n",
        )
        findings = self._scanner().scan_unix_accounts(None, root=tmp_path)
        assert [f for f in findings if f.severity.value == "CRITICAL"] == []

    def test_extra_uid0_account_is_reviewed(self, tmp_path: Path) -> None:
        write_pair(
            tmp_path,
            "root:x:0:0:root:/root:/bin/ash\nadmin:x:0:0::/root:/bin/sh\n",
            "root:!$6$s$h:::\nadmin:!$6$s$h:::\n",
        )
        findings = self._scanner().scan_unix_accounts(None, root=tmp_path)
        assert [f.rule_id for f in findings] == ["credential.unix.uid0_account"]
        assert findings[0].severity.value == "MEDIUM"

    def test_root_itself_is_not_a_uid0_review_finding(self, tmp_path: Path) -> None:
        write_pair(tmp_path, "root:x:0:0:root:/root:/bin/ash\n", "root:!$6$s$h:::\n")
        assert self._scanner().scan_unix_accounts(None, root=tmp_path) == []

    def test_md5_hash_is_reported(self, tmp_path: Path) -> None:
        write_pair(tmp_path, "user:x:1000:1000::/home/u:/bin/sh\n", "user:$1$s$h:::\n")
        findings = self._scanner().scan_unix_accounts(None, root=tmp_path)
        assert [f.rule_id for f in findings] == ["credential.unix.md5_hash"]

    def test_two_roots_are_independent(self, tmp_path: Path) -> None:
        first = tmp_path / "slot_a"
        second = tmp_path / "slot_b"
        write_pair(first, "root:x:0:0::/root:/bin/sh\n", "root:!$6$s$h:::\n")
        write_pair(second, "root:x:0:0::/root:/bin/sh\n", "root::19000::::::\n")

        findings = self._scanner().scan_unix_accounts(None, root=tmp_path)
        assert [f.rule_id for f in findings] == ["credential.unix.empty_password"]
        # The finding is attributed to the slot that actually had the empty field.
        assert "slot_b" in str(findings[0].file_path)

    def test_pair_count_is_recorded(self, tmp_path: Path) -> None:
        write_pair(tmp_path, "root:x:0:0::/root:/bin/sh\n", "root:!$6$s$h:::\n")
        scanner = self._scanner()
        scanner.scan_unix_accounts(None, root=tmp_path)
        assert scanner.last_account_pairs == 1
