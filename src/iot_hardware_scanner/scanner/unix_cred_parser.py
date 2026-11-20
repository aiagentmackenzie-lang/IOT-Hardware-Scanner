"""Unix account parsing — /etc/passwd and /etc/shadow, joined.

SDR §10 — Unix Credential Parsing

The important property here is that an account is judged from **both** records
at once, addressed by the filesystem root it came from and its username. A
password lock in ``shadow`` describes one authentication method; it says
nothing about SSH keys, console login or a second account. Typing the evidence
first is what stops a conventional ``root:!...`` line being reported as a
critical plaintext password.
"""

from __future__ import annotations

import contextlib
import logging
import time
from dataclasses import dataclass
from pathlib import Path

from iot_hardware_scanner.models import PasswdEntry, Severity, ShadowEntry

logger = logging.getLogger(__name__)

NON_LOGIN_SHELLS = frozenset(
    {
        "/sbin/nologin",
        "/bin/false",
        "/usr/sbin/nologin",
        "/bin/nologin",
        "/usr/bin/nologin",
        "/usr/bin/false",
        "/bin/sync",
        "/sbin/shutdown",
        "/sbin/halt",
    }
)

# Password field states. These are observations about one record, not verdicts.
STATE_EMPTY = "empty"  # field present and blank: authentication is not required
STATE_LOCKED = "locked"  # "!" / "*" prefix: this method of login is disabled
STATE_HASH_PRESENT = "hash_present"  # a hash is stored; strength depends on algorithm
STATE_DELEGATED = "delegated"  # passwd says "x"; the hash lives in shadow
STATE_UNKNOWN = "unknown"  # shadow exists but has no record for this account
STATE_ABSENT = "absent"  # no shadow record and no shadow file


@dataclass
class AccountRecord:
    """One account, resolved across its passwd and shadow records."""

    root_id: str
    username: str
    uid: int
    gid: int
    shell: str
    is_login_shell: bool
    password_state: str
    hash_algorithm: str | None = None
    days_since_change: int | None = None
    passwd_source: str = "etc/passwd"
    passwd_line: int | None = None
    shadow_source: str | None = None
    shadow_line: int | None = None

    @property
    def is_root(self) -> bool:
        return self.uid == 0


def _classify_password_field(field: str) -> str:
    """Classify a raw password field without interpreting it further."""
    if field == "":
        return STATE_EMPTY
    if field.startswith("!") or field == "*" or field.startswith("*"):
        return STATE_LOCKED
    if field == "x":
        return STATE_DELEGATED
    if field.startswith("$"):
        return STATE_HASH_PRESENT
    return STATE_HASH_PRESENT


class UnixCredentialParser:
    """Parse /etc/passwd and /etc/shadow, with line provenance."""

    def parse_passwd(self, path: Path) -> list[PasswdEntry]:
        """Parse /etc/passwd format: ``username:x:uid:gid:gecos:home:shell``."""
        entries: list[PasswdEntry] = []

        try:
            content = path.read_text(errors="ignore")
        except (OSError, PermissionError):
            return entries

        for line_no, raw in enumerate(content.splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split(":")
            if len(parts) < 7:
                continue

            username, pw_field, uid_str, gid_str, _gecos, home, shell = parts[:7]
            try:
                uid = int(uid_str)
                gid = int(gid_str)
            except ValueError:
                continue

            entries.append(
                PasswdEntry(
                    username=username,
                    uid=uid,
                    gid=gid,
                    home=home,
                    shell=shell,
                    has_password_field=pw_field == "x",
                    is_root_equivalent=uid == 0,
                    has_login_shell=shell not in NON_LOGIN_SHELLS,
                    password_state=_classify_password_field(pw_field),
                    line_number=line_no,
                )
            )

        return entries

    def parse_shadow(self, path: Path) -> list[ShadowEntry]:
        """Parse /etc/shadow format."""
        entries: list[ShadowEntry] = []
        now_days = int(time.time() // 86400)

        try:
            content = path.read_text(errors="ignore")
        except (OSError, PermissionError):
            return entries

        for line_no, raw in enumerate(content.splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split(":")
            if len(parts) < 2:
                continue

            username = parts[0]
            hash_field = parts[1]

            days_since_change: int | None = None
            if len(parts) > 2 and parts[2]:
                with contextlib.suppress(ValueError):
                    days_since_change = now_days - int(parts[2])

            state = _classify_password_field(hash_field)
            hash_algorithm = _hash_algorithm(hash_field) if state == STATE_HASH_PRESENT else None
            severity = {
                STATE_EMPTY: Severity.CRITICAL,
                STATE_LOCKED: Severity.INFO,
                STATE_HASH_PRESENT: _hash_severity(hash_algorithm),
            }.get(state, Severity.INFO)

            entries.append(
                ShadowEntry(
                    username=username,
                    hash_algorithm=hash_algorithm,
                    hash_value=_mask_hash(hash_field, hash_algorithm),
                    is_empty=state == STATE_EMPTY,
                    is_locked=state == STATE_LOCKED,
                    days_since_change=days_since_change,
                    severity=severity,
                    line_number=line_no,
                    password_state=state,
                )
            )

        return entries

    def join(
        self,
        passwd_path: Path,
        shadow_path: Path | None,
        root_id: str = "",
        passwd_label: str = "etc/passwd",
        shadow_label: str | None = "etc/shadow",
    ) -> list[AccountRecord]:
        """Join passwd and shadow records by username, within one root.

        The join key is (root_id, username). Two roots that both contain
        ``etc/passwd`` therefore produce two independent record sets.
        """
        passwd_entries = self.parse_passwd(passwd_path)
        shadow_entries: dict[str, ShadowEntry] = {}
        if shadow_path is not None and shadow_path.exists():
            shadow_entries = {e.username: e for e in self.parse_shadow(shadow_path)}

        records: list[AccountRecord] = []
        for entry in passwd_entries:
            shadow = shadow_entries.get(entry.username)
            if shadow is not None:
                state = shadow.password_state
                algorithm = shadow.hash_algorithm
                days = shadow.days_since_change
                shadow_line = shadow.line_number
            elif shadow_path is not None and shadow_path.exists():
                # Shadow exists but has no line for this account. The passwd
                # field is then the only evidence, and "x" means the hash was
                # supposed to be delegated somewhere we cannot see.
                state = (
                    STATE_UNKNOWN
                    if entry.password_state == STATE_DELEGATED
                    else entry.password_state
                )
                algorithm = None
                days = None
                shadow_line = None
            else:
                state = (
                    STATE_ABSENT
                    if entry.password_state == STATE_DELEGATED
                    else entry.password_state
                )
                algorithm = None
                days = None
                shadow_line = None

            records.append(
                AccountRecord(
                    root_id=root_id,
                    username=entry.username,
                    uid=entry.uid,
                    gid=entry.gid,
                    shell=entry.shell,
                    is_login_shell=entry.has_login_shell,
                    password_state=state,
                    hash_algorithm=algorithm,
                    days_since_change=days,
                    passwd_source=passwd_label,
                    passwd_line=entry.line_number,
                    shadow_source=shadow_label if shadow is not None else None,
                    shadow_line=shadow_line,
                )
            )

        return records


def discover_account_databases(root: Path) -> list[tuple[Path, Path | None]]:
    """Locate ``etc/passwd`` (and ``etc/shadow``) under a staged root."""
    passwds: list[tuple[Path, Path | None]] = []
    for candidate in sorted(root.rglob("etc/passwd")):
        if candidate.is_symlink() or not candidate.is_file():
            continue
        shadow = candidate.with_name("shadow")
        passwds.append((candidate, shadow if shadow.exists() else None))
    return passwds


def _hash_algorithm(hash_field: str) -> str | None:
    """Map a crypt(3) prefix to a readable algorithm name."""
    mapping = {
        "1": "MD5",
        "2a": "bcrypt",
        "2b": "bcrypt",
        "2y": "bcrypt",
        "5": "SHA-256",
        "6": "SHA-512",
        "y": "yescrypt",
        "gy": "gost-yescrypt",
        "7": "scrypt",
    }
    if not hash_field.startswith("$"):
        return None
    body = hash_field[1:]
    two = body[:2]
    if two in mapping:
        return mapping[two]
    one = body[:1]
    return mapping.get(one)


def _hash_severity(algorithm: str | None) -> Severity:
    """Severity of a stored hash, by algorithm."""
    if algorithm == "MD5":
        return Severity.HIGH
    if algorithm in {"SHA-256"}:
        return Severity.MEDIUM
    if algorithm in {"SHA-512", "bcrypt", "yescrypt", "scrypt", "gost-yescrypt"}:
        return Severity.LOW
    return Severity.INFO


def _mask_hash(hash_field: str, algorithm: str | None) -> str:
    """Never emit the stored hash; show the algorithm prefix only."""
    if not hash_field:
        return ""
    if algorithm is None:
        return hash_field[:1] + "***"
    parts = hash_field.split("$")
    if len(parts) >= 3:
        return f"${parts[1]}${parts[2]}$***"
    return f"${parts[1]}***" if len(parts) == 2 else "***"
