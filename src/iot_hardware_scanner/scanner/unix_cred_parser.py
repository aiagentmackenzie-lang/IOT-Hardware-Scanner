"""Unix Credential Parser — Phase 4 specialized.

Specialized parser for /etc/passwd and /etc/shadow files.

SDR §10 — Unix Credential Parsing
"""

from __future__ import annotations

import logging
import time
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
    }
)


class UnixCredentialParser:
    """Parse /etc/passwd and /etc/shadow for security-relevant entries."""

    def parse_passwd(self, path: Path) -> list[PasswdEntry]:
        """Parse /etc/passwd format.

        Format: username:x:uid:gid:gecos:home:shell

        Flags:
        - UID 0 entries (root-equivalent users)
        - Login shells (not /sbin/nologin or /bin/false)
        - Empty password field (x missing = no password required)
        """
        entries: list[PasswdEntry] = []

        try:
            content = path.read_text(errors="ignore")
        except (OSError, PermissionError):
            return entries

        for line in content.splitlines():
            line = line.strip()
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

            has_password = pw_field == "x"
            is_root = uid == 0
            has_login = shell not in NON_LOGIN_SHELLS

            entries.append(
                PasswdEntry(
                    username=username,
                    uid=uid,
                    gid=gid,
                    home=home,
                    shell=shell,
                    has_password_field=has_password,
                    is_root_equivalent=is_root,
                    has_login_shell=has_login,
                )
            )

        return entries

    def parse_shadow(self, path: Path) -> list[ShadowEntry]:
        """Parse /etc/shadow format.

        Format: username:$algo$salt$hash:lastchange:min:max:warn:inactive:expire

        Detects:
        - Hash algorithm ($1=MD5, $5=SHA-256, $6=SHA-512, $2y$=bcrypt)
        - MD5 ($1$) = WEAK — flagged as HIGH severity
        - Empty hash field = NO PASSWORD — flagged as CRITICAL
        - Locked accounts (! or *) = OK — INFO severity
        """
        entries: list[ShadowEntry] = []
        now_days = int(time.time() // 86400)

        try:
            content = path.read_text(errors="ignore")
        except (OSError, PermissionError):
            return entries

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split(":")
            if len(parts) < 2:
                continue

            username = parts[0]
            hash_field = parts[1]

            # Parse days_since_change (field index 2)
            days_since_change: int | None = None
            if len(parts) > 2 and parts[2]:
                try:  # noqa: SIM105
                    days_since_change = now_days - int(parts[2])
                except ValueError:
                    pass

            # Determine state
            is_empty = hash_field == ""
            is_locked = (
                hash_field.startswith("!") or hash_field == "*" or hash_field.startswith("!*")
            )

            # Determine algorithm and severity
            hash_algorithm: str | None = None
            severity = Severity.INFO

            if not is_empty and not is_locked and hash_field.startswith("$"):
                algo_prefix = hash_field[1:3] if len(hash_field) > 2 else ""
                algo_map = {
                    "1$": ("MD5", Severity.HIGH),
                    "5$": ("SHA-256", Severity.MEDIUM),
                    "6$": ("SHA-512", Severity.LOW),
                    "2y": ("bcrypt", Severity.LOW),
                    "2a": ("bcrypt", Severity.LOW),
                    "2b": ("bcrypt", Severity.LOW),
                }
                for code, (algo, sev) in algo_map.items():
                    if algo_prefix.startswith(code.rstrip("$")):
                        hash_algorithm = algo
                        severity = sev
                        break

            if is_empty:
                severity = Severity.CRITICAL
            elif is_locked:
                severity = Severity.INFO

            # Build masked hash value: show algo prefix + "***"
            if is_empty:
                masked_hash = ""
            elif is_locked:
                masked_hash = hash_field[:1] + "***"
            elif hash_algorithm:
                # Show $algo$***  e.g. "$6$***" for SHA-512
                prefix_end = hash_field.find("$", 1)  # find second $
                if prefix_end > 0:
                    # Find third $ (end of salt)
                    salt_end = hash_field.find("$", prefix_end + 1)
                    if salt_end > 0:
                        masked_hash = hash_field[: salt_end + 1] + "***"
                    else:
                        masked_hash = hash_field[: prefix_end + 1] + "***"
                else:
                    masked_hash = "$" + algo_prefix + "***"
            else:
                masked_hash = "***"

            entries.append(
                ShadowEntry(
                    username=username,
                    hash_algorithm=hash_algorithm,
                    hash_value=masked_hash,
                    is_empty=is_empty,
                    is_locked=is_locked,
                    days_since_change=days_since_change,
                    severity=severity,
                )
            )

        return entries
