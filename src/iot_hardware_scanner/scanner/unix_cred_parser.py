"""Unix Credential Parser — Phase 4 specialized.

Specialized parser for /etc/passwd and /etc/shadow files.

SDR §10 — Unix Credential Parsing
"""

from __future__ import annotations

import logging
from pathlib import Path

from iot_hardware_scanner.models import PasswdEntry, Severity, ShadowEntry

logger = logging.getLogger(__name__)

LOGIN_SHELLS = {"/bin/sh", "/bin/bash", "/bin/ash", "/bin/dash", "/bin/zsh", "/usr/bin/sh"}
NON_LOGIN_SHELLS = {"/sbin/nologin", "/bin/false", "/usr/sbin/nologin", "/bin/nologin"}


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
        - Locked accounts (! or *) = OK
        """
        entries: list[ShadowEntry] = []

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
            hash_field = parts[1] if len(parts) > 1 else ""

            # Determine state
            is_empty = hash_field == ""
            is_locked = (
                hash_field.startswith("!") or hash_field == "*" or hash_field.startswith("!*")
            )

            # Determine algorithm
            hash_algorithm = None
            severity = Severity.INFO

            if not is_empty and not is_locked and hash_field.startswith("$"):
                algo_code = hash_field[1:3] if len(hash_field) > 2 else ""
                algo_map = {
                    "1$": ("MD5", Severity.HIGH),
                    "5$": ("SHA-256", Severity.MEDIUM),
                    "6$": ("SHA-512", Severity.LOW),
                    "2y": ("bcrypt", Severity.LOW),
                    "2a": ("bcrypt", Severity.LOW),
                    "2b": ("bcrypt", Severity.LOW),
                }
                for code, (algo, sev) in algo_map.items():
                    if algo_code.startswith(code.rstrip("$")):
                        hash_algorithm = algo
                        severity = sev
                        break

            if is_empty:
                severity = Severity.CRITICAL
            elif is_locked:
                severity = Severity.INFO

            entries.append(
                ShadowEntry(
                    username=username,
                    hash_algorithm=hash_algorithm,
                    hash_value="***" if not is_empty else "",
                    is_empty=is_empty,
                    is_locked=is_locked,
                    severity=severity,
                )
            )

        return entries
