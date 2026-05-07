"""Credential Scanner — Phase 4.

YARA + regex + entropy-gated detection of hardcoded credentials,
API keys, private keys, and secrets.

SDR §10 — Credential & Secret Detection

Stub implementation — full build in Phase 4 delivery.
"""

from __future__ import annotations

import logging
from pathlib import Path

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.models import (
    CredentialFinding,
    FilesystemInventory,
    Severity,
)

logger = logging.getLogger(__name__)


class CredentialScanner:
    """Detect hardcoded credentials and secrets in firmware files."""

    def __init__(self, config: ScannerConfig) -> None:
        self.config = config

    def scan_inventory(self, inventory: FilesystemInventory | None) -> list[CredentialFinding]:
        """Scan all CRITICAL/HIGH category files in the inventory."""
        if inventory is None:
            return []

        findings: list[CredentialFinding] = []

        # Scan CRITICAL_CREDENTIAL files
        from iot_hardware_scanner.models import FileCategory

        cred_files = inventory.categories.get(FileCategory.CRITICAL_CREDENTIAL, [])
        for finding in cred_files:
            file_findings = self.scan_file(
                finding.absolute_path, finding.path, FileCategory.CRITICAL_CREDENTIAL
            )
            findings.extend(file_findings)

        # Scan CRITICAL_CONFIG files for password patterns
        config_files = inventory.categories.get(FileCategory.CRITICAL_CONFIG, [])
        for finding in config_files:
            file_findings = self.scan_file(
                finding.absolute_path, finding.path, FileCategory.CRITICAL_CONFIG
            )
            findings.extend(file_findings)

        # Scan HIGH_CRYPTO files
        crypto_files = inventory.categories.get(FileCategory.HIGH_CRYPTO, [])
        for finding in crypto_files:
            file_findings = self.scan_file(
                finding.absolute_path, finding.path, FileCategory.HIGH_CRYPTO
            )
            findings.extend(file_findings)

        logger.info("Credential scan: %d findings", len(findings))
        return findings

    def scan_file(
        self,
        abs_path: Path,
        rel_path: Path,
        category: FileCategory,  # noqa: F821
    ) -> list[CredentialFinding]:
        """Scan a single file for credentials/secrets.

        Placeholder implementation using basic regex patterns.
        Full YARA engine integration in Phase 4 delivery.
        """
        import hashlib
        import re

        findings: list[CredentialFinding] = []

        try:
            content = abs_path.read_text(errors="ignore")
        except (OSError, PermissionError):
            return findings

        # Basic password pattern detection
        pwd_patterns = [
            (
                re.compile(r'password\s*=\s*["\']([^"\']{4,})["\']', re.IGNORECASE),
                "password",
                Severity.CRITICAL,
            ),
            (
                re.compile(r'passwd\s*=\s*["\']([^"\']{4,})["\']', re.IGNORECASE),
                "password",
                Severity.CRITICAL,
            ),
            (re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE), "api_key", Severity.HIGH),
            (re.compile(r"ghp_[A-Za-z0-9_]{36}"), "api_key", Severity.HIGH),
            (re.compile(r"sk_live_[0-9a-zA-Z]{24,}"), "api_key", Severity.HIGH),
            (re.compile(r"-----BEGIN[A-Z ]*PRIVATE KEY-----"), "private_key", Severity.HIGH),
        ]

        for line_num, line in enumerate(content.splitlines(), 1):
            for pattern, cred_type, severity in pwd_patterns:
                match = pattern.search(line)
                if match:
                    raw = match.group(1) if match.lastindex else match.group(0)
                    masked = raw[:3] + "***" + raw[-3:] if len(raw) > 6 else "***"
                    raw_hash = hashlib.sha256(raw.encode()).hexdigest()

                    findings.append(
                        CredentialFinding(
                            severity=severity,
                            category=cred_type,
                            file_path=rel_path,
                            line_number=line_num,
                            matched_pattern=pattern.pattern[:50],
                            masked_value=masked,
                            raw_value_hash=raw_hash,
                            context=line.strip()[:128],
                            is_default=False,
                            is_placeholder=self._is_placeholder(raw),
                        )
                    )

        return findings

    def _is_placeholder(self, value: str) -> bool:
        """Check if a value looks like a placeholder."""
        placeholders = {
            "changeme",
            "your_api_key",
            "replace_me",
            "xxx",
            "placeholder",
            "insert_here",
            "todo",
            "test",
            "example",
            "sample",
            "default",
            "password",
        }
        return value.lower().strip() in placeholders
