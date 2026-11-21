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
    Severity,
    YaraMatch,
)
from iot_hardware_scanner.scanner.bounded_reader import open_bounded
from iot_hardware_scanner.scanner.unix_cred_parser import (
    STATE_EMPTY,
    AccountRecord,
    UnixCredentialParser,
    discover_account_databases,
)
from iot_hardware_scanner.yara.yara_engine import YaraEngine

logger = logging.getLogger(__name__)

# ── Binary magic bytes ──
_ELF_MAGIC = b"\x7fELF"
_PE_MAGIC = b"MZ"
_MACHO_MAGIC = b"\xfe\xed\xfa\xce"
_MACHO_MAGIC_64 = b"\xfe\xed\xfa\xcf"

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


def _rel_label(path: Path | None, root_id: str) -> str:
    """Locate a record inside the root it came from.

    The root name qualifies the path so two roots that both contain
    ``etc/shadow`` produce two distinguishable locations, and a second
    extraction of the same image cannot silently overwrite the first one's
    evidence.
    """
    if path is None:
        return f"{Path(root_id).name or '<root>'}/etc/shadow"
    try:
        relative = path.relative_to(root_id)
    except ValueError:
        return str(path)
    return f"{Path(root_id).name or '<root>'}/{relative}"


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
        #: Number of passwd/shadow pairs parsed by the last unix account scan.
        self.last_account_pairs: int = 0

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

        from iot_hardware_scanner import resources

        try:
            data = json.loads(resources.read_text("default_credentials.json"))
            self._default_creds = data.get("credentials", [])
        except (OSError, json.JSONDecodeError, RuntimeError) as exc:
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

        # Unix credential parsing (account records are joined, not guessed)
        unix_findings = self.scan_unix_accounts(inventory)
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
            max_size = self.config.max_scan_file_size_mb * 1024 * 1024
            if abs_path.stat().st_size > max_size:
                logger.debug(
                    "Skipping large file for credential scan: %s (%s)",
                    abs_path,
                    self._fmt_size(abs_path.stat().st_size),
                )
                return findings
            try:
                # Bounded: a line longer than 64 KiB is yielded as empty text,
                # and the pass stops at the configured byte budget. Offsets stay
                # exact, so a finding can be quoted back to a physical range.
                text_lines = list(
                    open_bounded(abs_path).iter_lines(budget=max_size, encoding="utf-8")
                )
            except (OSError, ValueError):
                return findings

            lines = [line.text for line in text_lines]
            for line_obj in text_lines:
                line_num = line_obj.number
                line = line_obj.text
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
                        context=self._redact(line, raw),
                        is_default=is_default,
                        is_placeholder=False,
                    )
                    findings.append(finding)

        return findings

    # ──────────────────────────────────────────
    # Unix Credential Integration
    # ──────────────────────────────────────────

    def scan_unix_accounts(
        self,
        inventory: FilesystemInventory | None,
        root: Path | None = None,
    ) -> list[CredentialFinding]:
        """Join passwd/shadow per root and username, then type the evidence.

        Every root that contains ``etc/passwd`` is handled independently: two
        roots with the same path produce two sets of account records.

        Returns:
            Findings for accounts whose *observed* state warrants one. A locked
            password is not one of those states.
        """
        parser = UnixCredentialParser()
        findings: list[CredentialFinding] = []
        pairs = 0

        roots: list[tuple[str, Path, Path | None]] = []
        if inventory is not None:
            seen: set[Path] = set()
            for ff in inventory.findings:
                # Locators are root-qualified (``slot_b/etc/passwd``), so the
                # match is on the trailing components, never on the whole path.
                parts = ff.path.parts
                if len(parts) < 2 or parts[-2:] != ("etc", "passwd"):
                    continue
                root_dir = ff.absolute_path.parent.parent
                if root_dir in seen:
                    continue
                seen.add(root_dir)
                shadow = root_dir / "etc" / "shadow"
                roots.append((str(root_dir), ff.absolute_path, shadow if shadow.exists() else None))
        elif root is not None and root.is_dir():
            for passwd, shadow_opt in discover_account_databases(root):
                roots.append((str(passwd.parent.parent), passwd, shadow_opt))

        for root_id, passwd_path, shadow_path in roots:
            records = parser.join(
                passwd_path,
                shadow_path,
                root_id=root_id,
                passwd_label=_rel_label(passwd_path, root_id),
                shadow_label=_rel_label(shadow_path, root_id) if shadow_path else None,
            )
            if records:
                pairs += 1
            for record in records:
                findings.extend(self._account_to_findings(record))

        self.last_account_pairs = pairs
        return findings

    def _account_to_findings(self, record: AccountRecord) -> list[CredentialFinding]:
        """Convert one joined account record into zero or more findings.

        Rules, in descending confidence:

        ``credential.unix.empty_password``
            A blank password field on an account that can log in. Critical.
        ``credential.unix.uid0_account``
            An additional UID 0 account, reviewed separately from root's own
            password state.
        ``credential.unix.md5_hash``
            A stored MD5 password hash.
        """
        findings: list[CredentialFinding] = []
        locations = f"{record.passwd_source}:{record.passwd_line}"
        if record.shadow_source and record.shadow_line:
            locations += f" and {record.shadow_source}:{record.shadow_line}"

        if record.password_state == STATE_EMPTY and record.is_login_shell:
            description = (
                f"{record.username} (UID {record.uid}) has an empty password field "
                f"and a login shell ({record.shell})"
            )
            findings.append(
                self._make_finding(
                    severity=Severity.CRITICAL,
                    category="password",
                    file_path=Path(record.shadow_source or record.passwd_source),
                    line_number=record.shadow_line or record.passwd_line,
                    matched_pattern="credential.unix.empty_password",
                    raw_value=description,
                    context=f"{description} — {locations}",
                ).with_rule_id("credential.unix.empty_password")
            )

        # Root's own privilege is expected. A *second* UID 0 account is not.
        if record.is_root and record.username != "root":
            description = (
                f"Additional UID 0 account: {record.username} "
                f"(shell {record.shell}, password state {record.password_state})"
            )
            findings.append(
                self._make_finding(
                    severity=Severity.MEDIUM,
                    category="account",
                    file_path=Path(record.passwd_source),
                    line_number=record.passwd_line,
                    matched_pattern="credential.unix.uid0_account",
                    raw_value=description,
                    context=f"{description} — {locations}",
                ).with_rule_id("credential.unix.uid0_account")
            )

        if record.hash_algorithm == "MD5":
            description = f"{record.username} stores an MD5 password hash"
            findings.append(
                self._make_finding(
                    severity=Severity.HIGH,
                    category="password",
                    file_path=Path(record.shadow_source or record.passwd_source),
                    line_number=record.shadow_line or record.passwd_line,
                    matched_pattern="credential.unix.md5_hash",
                    raw_value=description,
                    context=f"{description} — {locations}",
                ).with_rule_id("credential.unix.md5_hash")
            )

        return findings

    def scan_artifact(self, artifact: Path, input_kind: object = None) -> list[CredentialFinding]:
        """Scan a whole artifact as one unit when no inventory exists.

        For a single image the artifact is the file. For a staged tree every
        regular file is scanned. Either way the scanned unit is recorded, so a
        zero result means "this population was inspected", not "nothing ran".
        """
        findings: list[CredentialFinding] = []
        if artifact.is_dir():
            for entry in sorted(artifact.rglob("*")):
                if entry.is_symlink() or not entry.is_file():
                    continue
                rel = entry.relative_to(artifact)
                findings.extend(self.scan_file(entry, rel, self._category_for(rel, entry)))
        else:
            findings.extend(self.scan_file(artifact, Path(artifact.name), None))
        return findings

    @staticmethod
    def _category_for(rel: Path, entry: Path) -> FileCategory | None:
        """Best-effort category for a staged-tree file (mirrors the scanner)."""
        name = rel.name.lower()
        if name in {"passwd", "shadow", "gshadow"}:
            return FileCategory.CRITICAL_CREDENTIAL
        if name in {"inittab", "rc.local"} or rel.suffix.lower() in {".conf", ".cfg", ".ini"}:
            return FileCategory.CRITICAL_CONFIG
        if rel.suffix.lower() in {".pem", ".crt", ".p12", ".pfx", ".cer", ".key"}:
            return FileCategory.HIGH_CRYPTO
        if rel.suffix.lower() in {".db", ".sqlite", ".sql"}:
            return FileCategory.HIGH_DATABASE
        return None

    # ──────────────────────────────────────────
    # YARA match conversion
    # ──────────────────────────────────────────

    #: YARA categories this scanner owns. Service, malware and crypto matches
    #: belong to their own detectors and must not be relabelled as credentials.
    _CREDENTIAL_YARA_CATEGORIES = frozenset(
        {"credential", "password", "api_key", "private_key", "token", "connection_string"}
    )

    def _yara_match_to_finding(self, ym: YaraMatch, rel_path: Path) -> CredentialFinding | None:
        """Convert a credential YARA match; ignore rules owned elsewhere."""
        meta = ym.meta
        category = meta.get("category", "password")
        if category not in self._CREDENTIAL_YARA_CATEGORIES:
            logger.debug(
                "Ignoring %s match from %s: category %s belongs to another detector",
                ym.rule_name,
                rel_path,
                category,
            )
            return None
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
            rule_id=f"credential.yara.{ym.rule_name}",
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
            rule_id=f"credential.regex.{category}",
        )

    # ──────────────────────────────────────────
    # Helper: False-positive reduction
    # ──────────────────────────────────────────

    @staticmethod
    def _mask_value(value: str) -> str:
        """Mask sensitive parts of a discovered value.

        Returns a fixed-length redaction string to prevent
        information leakage via prefix, suffix, or length.
        """
        return "*" * 8

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
    def _redact(line: str, raw_value: str) -> str:
        """Return the source line with the matched secret replaced.

        The context is useful for locating a finding and must never carry the
        value itself into a report, a log or a CI artefact.
        """
        masked = "*" * 8
        if raw_value:
            line = line.replace(raw_value, masked)
        return line.strip()[:128]

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
    def _fmt_size(n: int) -> str:
        """Format byte count as human-readable size."""
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1024:
                return f"{n:.1f} {unit}"
            n //= 1024
        return f"{n:.1f} TB"

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
