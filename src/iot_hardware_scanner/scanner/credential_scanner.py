"""Credential Scanner — Phase 4.

Layered detection of hardcoded credentials, API keys, private keys,
tokens, and secrets using YARA rules, regex patterns, entropy gating,
placeholder filtering, and default credential cross-referencing.

SDR §10 — Credential & Secret Detection
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import re
from pathlib import Path

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.models import (
    CredentialFinding,
    FileCategory,
    FilesystemInventory,
    PasswdEntry,
    Severity,
    ShadowEntry,
    YaraMatch,
)
from iot_hardware_scanner.scanner.unix_cred_parser import UnixCredentialParser
from iot_hardware_scanner.yara.yara_engine import YaraEngine

logger = logging.getLogger(__name__)

# ── Binary magic bytes ──
_ELF_MAGIC = b"\x7fELF"
_PE_MAGIC = b"MZ"
_MACHO_MAGIC = b"\xfe\xed\xfe\xce"
_MACHO_MAGIC_64 = b"\xfe\xed\xfe\xcf"

# ── Placeholder values (case-insensitive) ──
_PLACEHOLDERS = frozenset(
    {
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
        "secret",
        "your_secret",
        "api_key_here",
        "put_your_key_here",
        "<insert>",
        "<replace>",
        "redacted",
        "xxxxxx",
    }
)

# ── Documentation file extensions to skip in docs/ dirs ──
_DOC_EXTENSIONS = frozenset({".md", ".rst", ".txt"})

# ── Context-window deprioritization keywords ──
_DEPRIORITIZE_KEYWORDS = frozenset({"example", "sample", "template", "demo", "test"})

# ── Regex patterns by category ──
# Each entry: (compiled_regex, category, default_severity, has_capture_group)
_REGEX_PATTERNS: list[tuple[re.Pattern, str, Severity, bool]] = []

# Password patterns
for _pat, _cat, _sev in [
    (r'password\s*[=:]\s*["\x27]([^\x27"]{4,})["\x27]', "password", Severity.CRITICAL),
    (r'passwd\s*[=:]\s*["\x27]([^\x27"]{4,})["\x27]', "password", Severity.CRITICAL),
    (r'pwd\s*[=:]\s*["\x27]([^\x27"]{4,})["\x27]', "password", Severity.HIGH),
    (r'admin_password\s*[=:]\s*["\x27]([^\x27"]{4,})["\x27]', "password", Severity.CRITICAL),
    (r'DB_PASSWORD\s*[=:]\s*["\x27]([^\x27"]{4,})["\x27]', "password", Severity.CRITICAL),
    (r'SECRET_KEY\s*[=:]\s*["\x27]([^\x27"]{4,})["\x27]', "password", Severity.HIGH),
]:
    _REGEX_PATTERNS.append((re.compile(_pat, re.IGNORECASE), _cat, _sev, True))

# API key patterns (no capture group — full match is the key)
for _pat, _cat, _sev in [
    (r"AKIA[0-9A-Z]{16}", "api_key", Severity.HIGH),
    (r"ghp_[A-Za-z0-9_]{36}", "api_key", Severity.HIGH),
    (r"sk_live_[0-9a-zA-Z]{24,}", "api_key", Severity.HIGH),
    (r"xoxb-[0-9a-zA-Z-]{24,}", "api_key", Severity.HIGH),
    (r"xoxp-[0-9a-zA-Z-]{24,}", "api_key", Severity.HIGH),
    (r"AIza[0-9A-Za-z_-]{35}", "api_key", Severity.HIGH),
]:
    _REGEX_PATTERNS.append((re.compile(_pat), _cat, _sev, False))

# Private key patterns (no capture group)
for _pat, _cat, _sev in [
    (r"-----BEGIN RSA PRIVATE KEY-----", "private_key", Severity.HIGH),
    (r"-----BEGIN DSA PRIVATE KEY-----", "private_key", Severity.HIGH),
    (r"-----BEGIN EC PRIVATE KEY-----", "private_key", Severity.HIGH),
    (r"-----BEGIN OPENSSH PRIVATE KEY-----", "private_key", Severity.HIGH),
    (r"-----BEGIN ENCRYPTED PRIVATE KEY-----", "private_key", Severity.HIGH),
]:
    _REGEX_PATTERNS.append((re.compile(_pat), _cat, _sev, False))

# Token patterns
for _pat, _cat, _sev, _grp in [
    (r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", "token", Severity.MEDIUM, False),
    (
        r'token\s*[=:]\s*["\x27]([A-Za-z0-9\-._~+/]{20,})["\x27]',
        "token",
        Severity.MEDIUM,
        True,
    ),
    (r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+", "token", Severity.MEDIUM, False),
]:
    _REGEX_PATTERNS.append((re.compile(_pat, re.IGNORECASE), _cat, _sev, _grp))

# Connection string patterns (no capture group)
for _pat, _cat, _sev in [
    (r"mysql://[^\s\"']+(:[^\s\"']+)?@", "connection_string", Severity.HIGH),
    (r"postgres(?:ql)?://[^\s\"']+(:[^\s\"']+)?@", "connection_string", Severity.HIGH),
    (r"mongodb://[^\s\"']+(:[^\s\"']+)?@", "connection_string", Severity.HIGH),
    (r"redis://[^\s\"']+(:[^\s\"']+)?@", "connection_string", Severity.HIGH),
    (r"jdbc:[^\s\"']{10,}", "connection_string", Severity.HIGH),
]:
    _REGEX_PATTERNS.append((re.compile(_pat, re.IGNORECASE), _cat, _sev, False))


class CredentialScanner:
    """Detect hardcoded credentials and secrets in firmware files.

    Layered detection:
    1. YARA rules (high-confidence binary patterns)
    2. Regex patterns (structured text)
    3. Entropy gating (false-positive reduction)
    4. Placeholder filtering
    5. Default credential cross-reference
    6. Unix credential parsing (/etc/passwd, /etc/shadow)
    """

    def __init__(self, config: ScannerConfig) -> None:
        self.config = config
        self._yara_engine: YaraEngine | None = None
        self._default_creds: list[dict] = []
        self._default_creds_loaded = False

    def _init_yara(self) -> YaraEngine:
        """Lazy-init the YARA engine and load rules."""
        if self._yara_engine is None:
            self._yara_engine = YaraEngine(self.config)
            self._yara_engine.load_rules()
        return self._yara_engine

    def _load_default_credentials(self) -> list[dict]:
        """Load default credentials database."""
        if self._default_creds_loaded:
            return self._default_creds

        creds_path = (
            Path(__file__).parent.parent.parent.parent / "data" / "default_credentials.json"
        )
        try:
            if creds_path.exists():
                data = json.loads(creds_path.read_text(encoding="utf-8"))
                self._default_creds = data.get("credentials", [])
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Cannot load default credentials: %s", exc)
            self._default_creds = []

        self._default_creds_loaded = True
        return self._default_creds

    # ──────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────

    def scan_inventory(self, inventory: FilesystemInventory | None) -> list[CredentialFinding]:
        """Scan all CRITICAL/HIGH category files in the inventory."""
        if inventory is None:
            return []

        findings: list[CredentialFinding] = []
        seen_hashes: set[str] = set()

        # Categories to scan
        scan_categories = [
            FileCategory.CRITICAL_CREDENTIAL,
            FileCategory.CRITICAL_CONFIG,
            FileCategory.HIGH_API_KEY,
            FileCategory.HIGH_CRYPTO,
            FileCategory.HIGH_DATABASE,
        ]

        for category in scan_categories:
            files = inventory.categories.get(category, [])
            for ff in files:
                file_findings = self.scan_file(ff.absolute_path, ff.path, category)
                for f in file_findings:
                    # Deduplicate by raw_value_hash
                    if f.raw_value_hash and f.raw_value_hash in seen_hashes:
                        continue
                    if f.raw_value_hash:
                        seen_hashes.add(f.raw_value_hash)
                    findings.append(f)

        # Unix credential parsing
        unix_findings = self._unix_findings(inventory)
        for f in unix_findings:
            h = f.raw_value_hash
            if h and h in seen_hashes:
                continue
            if h:
                seen_hashes.add(h)
            findings.append(f)

        logger.info("Credential scan: %d findings", len(findings))
        return findings

    def scan_file(
        self,
        abs_path: Path,
        rel_path: Path,
        category: FileCategory | None = None,
    ) -> list[CredentialFinding]:
        """Scan a single file for credentials/secrets.

        Applies YARA + regex with false-positive reduction.
        """
        findings: list[CredentialFinding] = []

        # Skip docs/ files with documentation extensions
        if self._is_docs_file(abs_path):
            return findings

        # Determine if file is binary
        is_binary = self._is_binary_file(abs_path)

        # ── Layer 1: YARA scanning ──
        yara_engine = self._init_yara()
        if yara_engine.is_available:
            yara_matches = yara_engine.scan_file(abs_path)
            existing_hashes = {f.raw_value_hash for f in findings}
            for ym in yara_matches:
                finding = self._yara_match_to_finding(ym, rel_path)
                if finding and finding.raw_value_hash not in existing_hashes:
                    findings.append(finding)

        # ── Layer 2: Regex scanning (skip for binary files) ──
        if not is_binary:
            try:
                content = abs_path.read_text(errors="ignore")
            except (OSError, PermissionError):
                return findings

            lines = content.splitlines()
            for line_num, line in enumerate(lines, 1):
                for pattern, cred_category, severity, has_group in _REGEX_PATTERNS:
                    match = pattern.search(line)
                    if not match:
                        continue

                    raw = match.group(1) if has_group and match.lastindex else match.group(0)

                    # Layer 3+4: Placeholder check + default credential check
                    is_placeholder = has_group and self._is_placeholder(raw)
                    is_default = False
                    if has_group and cred_category == "password":
                        is_default = self._check_default_credentials(raw)

                    # Low entropy (below threshold) is likely placeholder
                    low_entropy = (
                        has_group
                        and self._compute_entropy(raw) < self.config.credential_entropy_threshold
                    )
                    if low_entropy and not is_placeholder:
                        is_placeholder = True

                    if is_placeholder:
                        # Placeholders still get recorded but at LOW severity
                        finding = self._make_finding(
                            severity=Severity.LOW,
                            category=cred_category,
                            file_path=rel_path,
                            line_number=line_num,
                            matched_pattern=pattern.pattern[:80],
                            raw_value=raw,
                            context=line.strip()[:128],
                            is_default=is_default,
                            is_placeholder=True,
                        )
                        findings.append(finding)
                        continue

                    # Layer 4b: Context window deprioritization
                    effective_severity = severity
                    if (
                        has_group
                        and line_num > 1
                        and self._context_deprioritize(lines, line_num - 1)
                    ):
                        effective_severity = self._reduce_severity(severity)

                    if is_default:
                        effective_severity = Severity.CRITICAL

                    finding = self._make_finding(
                        severity=effective_severity,
                        category=cred_category,
                        file_path=rel_path,
                        line_number=line_num,
                        matched_pattern=pattern.pattern[:80],
                        raw_value=raw,
                        context=line.strip()[:128],
                        is_default=is_default,
                        is_placeholder=False,
                    )
                    findings.append(finding)

        return findings

    # ──────────────────────────────────────────
    # Unix Credential Integration
    # ──────────────────────────────────────────

    def _unix_findings(self, inventory: FilesystemInventory) -> list[CredentialFinding]:
        """Parse /etc/passwd and /etc/shadow from inventory."""
        findings: list[CredentialFinding] = []
        parser = UnixCredentialParser()

        # Find passwd/shadow files in CRITICAL_CREDENTIAL category
        cred_files = inventory.categories.get(FileCategory.CRITICAL_CREDENTIAL, [])
        shadow_files = getattr(inventory, "shadow_files", [])

        passwd_path: Path | None = None
        shadow_path: Path | None = None

        for ff in cred_files:
            if ff.path.name == "passwd" and "etc" in str(ff.path):
                passwd_path = ff.absolute_path
            elif ff.path.name == "shadow" and "etc" in str(ff.path):
                shadow_path = ff.absolute_path

        # Also check the shadow_files index
        if not shadow_path:
            for ff in shadow_files:
                if ff.path.name == "shadow":
                    shadow_path = ff.absolute_path
                    break

        if passwd_path and passwd_path.exists():
            entries = parser.parse_passwd(passwd_path)
            for entry in entries:
                finding = self._passwd_entry_to_finding(entry, passwd_path)
                if finding:
                    findings.append(finding)

        if shadow_path and shadow_path.exists():
            entries = parser.parse_shadow(shadow_path)
            for entry in entries:
                finding = self._shadow_entry_to_finding(entry, shadow_path)
                if finding:
                    findings.append(finding)

        return findings

    # ──────────────────────────────────────────
    # YARA match conversion
    # ──────────────────────────────────────────

    def _yara_match_to_finding(self, ym: YaraMatch, rel_path: Path) -> CredentialFinding | None:
        """Convert a YaraMatch to a CredentialFinding."""
        meta = ym.meta
        category = meta.get("category", "password")
        severity_str = meta.get("severity", "HIGH").upper()
        severity = Severity(severity_str) if severity_str in Severity.__members__ else Severity.HIGH
        description = meta.get("description", ym.rule_name)

        # Extract matched data from strings
        raw_value = ""
        offset = None
        if ym.strings:
            offset, _identifier, sdata = ym.strings[0]
            raw_value = sdata.decode(errors="ignore")

        masked = self._mask_value(raw_value) if raw_value else description[:64]
        if raw_value:
            raw_hash = hashlib.sha256(raw_value.encode()).hexdigest()
        else:
            raw_hash = hashlib.sha256(description.encode()).hexdigest()

        return CredentialFinding(
            severity=severity,
            category=category,
            file_path=rel_path,
            line_number=None,
            offset=offset,
            matched_pattern=ym.rule_name,
            masked_value=masked,
            raw_value_hash=raw_hash,
            context=description[:128],
            is_default=False,
            is_placeholder=False,
        )

    # ──────────────────────────────────────────
    # Unix entry conversion
    # ──────────────────────────────────────────

    def _passwd_entry_to_finding(
        self, entry: PasswdEntry, abs_path: Path
    ) -> CredentialFinding | None:
        """Convert a PasswdEntry to a CredentialFinding if security-relevant."""
        # Only flag entries that are security-relevant
        if not entry.is_root_equivalent and not entry.has_login_shell and entry.has_password_field:
            return None

        if entry.is_root_equivalent:
            severity = Severity.CRITICAL
            desc = f"Root-equivalent user: {entry.username} (UID={entry.uid})"
        elif entry.has_login_shell:
            severity = Severity.MEDIUM
            desc = f"Login shell user: {entry.username} (shell={entry.shell})"
        elif not entry.has_password_field:
            severity = Severity.HIGH
            desc = f"User without password field: {entry.username}"
        else:
            return None

        rel_path = Path("etc") / "passwd"
        raw_hash = hashlib.sha256(desc.encode()).hexdigest()

        return CredentialFinding(
            severity=severity,
            category="password",
            file_path=rel_path,
            line_number=None,
            matched_pattern="unix_passwd_parse",
            masked_value=f"{entry.username}:***",
            raw_value_hash=raw_hash,
            context=desc[:128],
            is_default=False,
            is_placeholder=False,
        )

    def _shadow_entry_to_finding(
        self, entry: ShadowEntry, abs_path: Path
    ) -> CredentialFinding | None:
        """Convert a ShadowEntry to a CredentialFinding if security-relevant."""
        if entry.is_locked or entry.severity == Severity.INFO:
            return None

        rel_path = Path("etc") / "shadow"
        algo_label = entry.hash_algorithm or "unknown"
        desc = f"{entry.username}: {algo_label} hash"

        if entry.is_empty:
            desc = f"{entry.username}: NO PASSWORD SET"
        elif entry.hash_algorithm == "MD5":
            desc = f"{entry.username}: weak MD5 hash"

        raw_hash = hashlib.sha256(desc.encode()).hexdigest()

        masked_value = f"${algo_label.lower()}$***" if algo_label != "unknown" else "***"

        return CredentialFinding(
            severity=entry.severity,
            category="password",
            file_path=rel_path,
            line_number=None,
            matched_pattern="unix_shadow_parse",
            masked_value=f"{entry.username}:{masked_value}",
            raw_value_hash=raw_hash,
            context=desc[:128],
            is_default=False,
            is_placeholder=False,
        )

    # ──────────────────────────────────────────
    # Helper: Create CredentialFinding
    # ──────────────────────────────────────────

    def _make_finding(
        self,
        severity: Severity,
        category: str,
        file_path: Path,
        line_number: int | None,
        matched_pattern: str,
        raw_value: str,
        context: str,
        is_default: bool = False,
        is_placeholder: bool = False,
    ) -> CredentialFinding:
        """Build a CredentialFinding with masking and hashing."""
        masked = self._mask_value(raw_value)
        raw_hash = hashlib.sha256(raw_value.encode()).hexdigest()

        return CredentialFinding(
            severity=severity,
            category=category,
            file_path=file_path,
            line_number=line_number,
            matched_pattern=matched_pattern,
            masked_value=masked,
            raw_value_hash=raw_hash,
            context=context,
            is_default=is_default,
            is_placeholder=is_placeholder,
        )

    # ──────────────────────────────────────────
    # Helper: False-positive reduction
    # ──────────────────────────────────────────

    @staticmethod
    def _mask_value(value: str) -> str:
        """Mask sensitive parts of a discovered value."""
        if len(value) <= 6:
            return "***"
        return value[:3] + "***" + value[-3:]

    @staticmethod
    def _compute_entropy(value: str) -> float:
        """Compute Shannon entropy in bits/character."""
        if not value:
            return 0.0

        freq: dict[str, int] = {}
        for ch in value:
            freq[ch] = freq.get(ch, 0) + 1

        length = len(value)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)

        return entropy

    @staticmethod
    def _is_placeholder(value: str) -> bool:
        """Check if a value looks like a placeholder."""
        normalized = value.lower().strip()
        if normalized in _PLACEHOLDERS:
            return True
        return any(p in normalized for p in ("<insert>", "<replace>"))

    @staticmethod
    def _is_docs_file(path: Path) -> bool:
        """Check if file is a documentation file in a docs/ directory."""
        parts = path.parts
        in_docs = any(part.lower() in ("docs", "doc") for part in parts)
        return bool(in_docs and path.suffix.lower() in _DOC_EXTENSIONS)

    @staticmethod
    def _is_binary_file(path: Path) -> bool:
        """Check if a file is a binary executable (ELF/PE/Mach-O)."""
        try:
            with path.open("rb") as f:
                header = f.read(4)
        except (OSError, PermissionError):
            return False

        if header[:4] in (_ELF_MAGIC, _MACHO_MAGIC, _MACHO_MAGIC_64):
            return True
        return header[:2] == _PE_MAGIC

    @staticmethod
    def _context_deprioritize(lines: list[str], match_idx: int) -> bool:
        """Check if the 3 lines before the match contain deprioritization keywords.

        Args:
            lines: All file lines (0-indexed).
            match_idx: 0-indexed line of the match.

        Returns:
            True if context suggests this is an example/sample/template.
        """
        start = max(0, match_idx - 3)
        context_lines = " ".join(lines[start:match_idx]).lower()
        return any(kw in context_lines for kw in _DEPRIORITIZE_KEYWORDS)

    @staticmethod
    def _reduce_severity(severity: Severity) -> Severity:
        """Reduce severity by one level."""
        reduction = {
            Severity.CRITICAL: Severity.HIGH,
            Severity.HIGH: Severity.MEDIUM,
            Severity.MEDIUM: Severity.LOW,
            Severity.LOW: Severity.INFO,
            Severity.INFO: Severity.INFO,
        }
        return reduction.get(severity, severity)

    def _check_default_credentials(self, password: str) -> bool:
        """Check if a password matches a known default credential."""
        defaults = self._load_default_credentials()
        pw_lower = password.lower()
        return any(entry.get("password", "").lower() == pw_lower for entry in defaults)
