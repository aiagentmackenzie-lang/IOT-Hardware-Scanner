"""YARA rule engine — one compile per run, typed matches.

SDR §10 — YARA Rule Engine

The rule set is compiled **once per run** and shared by every detector, so the
report carries one ruleset digest and the cost of compiling is paid once. This
module owns three decisions that used to be spread across detectors:

* **Source of rules.** The packaged rule directory, plus any directory the
  operator names explicitly (``--yara-rules`` or ``yara_rules_dirs``). Nothing
  is loaded from the working directory or the user's home directory, so a scan
  cannot change verdict because of a file that happens to sit next to it.
* **Destination of a match.** A rule file's own ``category`` meta decides
  whether a match is a *credential*, a *configured service*, a *cryptographic
  algorithm* or an *indicator*. Detectors select by destination and never
  relabel a match that belongs to another detector.
* **Coverage.** A rule file that cannot be read or compiled is recorded, with
  its reason, in :class:`RuleSetInfo.errors`; the orchestrator turns that into
  stage coverage rather than a log line nobody reads.
"""

from __future__ import annotations

import hashlib
import logging
import re
from pathlib import Path
from typing import Any

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.models import RuleFileRecord, RuleSetInfo, YaraMatch
from iot_hardware_scanner.scanner.analysis_cache import AnalysisCache, sha256_file

logger = logging.getLogger(__name__)

# Rules ship inside the package. Ambient rule directories (the working
# directory or the user's home) are deliberately NOT loaded: a scan must not
# change verdict because of a file that happens to sit next to it. Additional
# rules are opt-in through configuration or the CLI.
_BUILTIN_RULES_DIR = Path(__file__).parent / "rules"

#: Category -> destination. A rule that names none of these is an indicator.
_CREDENTIAL_CATEGORIES = frozenset(
    {"credential", "password", "api_key", "private_key", "token", "connection_string"}
)
_SERVICE_CATEGORIES = frozenset({"backdoor_service"})
_CRYPTO_CATEGORIES = frozenset({"weak_crypto"})
_INDICATOR_CATEGORIES = frozenset({"malware_signature", "c2_indicator"})

_INCLUDE_STATEMENT = re.compile(r"^\s*include\s+")
_RULE_DECLARATION = re.compile(r"^\s*(?:private\s+|global\s+)*rule\s+[A-Za-z_]")


def _scalar(value: Any) -> Any:
    """A JSON-safe scalar for a cached match's meta block."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def destination_for(category: str) -> str:
    """The typed destination a rule category earns."""
    label = (category or "").strip().lower()
    if label in _CREDENTIAL_CATEGORIES:
        return "credential"
    if label in _SERVICE_CATEGORIES:
        return "service"
    if label in _CRYPTO_CATEGORIES:
        return "crypto"
    if label in _INDICATOR_CATEGORIES:
        return "indicator"
    # An unlabelled rule is an indicator claim and nothing more; it never
    # becomes a credential or a control verdict.
    return "indicator"


def _digest_of(files: list[tuple[str, str, bytes]]) -> str:
    """Digest over the compiled rule sources, independent of path and order.

    ``(namespace, name, content)`` triples are sorted by namespace, and the
    absolute path a rule happened to live at is never part of the digest, so
    the same rules produce the same digest from a wheel, a checkout or a
    relocated copy.
    """
    payload = "\n".join(
        f"{namespace}|{name}|{hashlib.sha256(content).hexdigest()}"
        for namespace, name, content in sorted(files)
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class YaraEngine:
    """Load, compile once, and execute YARA rules against files and data."""

    def __init__(
        self,
        config: ScannerConfig,
        rule_dirs: list[Path] | None = None,
        *,
        cache: AnalysisCache | None = None,
    ) -> None:
        self.config = config
        self._extra_dirs = list(rule_dirs or [])
        self._rules: Any = None
        self._rule_count: int = 0
        self._yara_available: bool = False
        self._info = RuleSetInfo()
        self._checked = False
        #: Optional content-addressed cache of per-file match sets (slice 5C).
        #: Entries are keyed by content digest + rule-set digest + engine
        #: version and never contain a path.
        self._cache = cache
        # Import and version-probe once, so `is_available` and the wheel's
        # dependency check answer without compiling anything.
        self._check_yara()
        self._checked = True

    # ──────────────────────────────────────────
    # Availability
    # ──────────────────────────────────────────

    def _check_yara(self) -> None:
        """Check whether yara-python is importable, and record its version."""
        try:
            import yara
        except ImportError:
            self._yara_available = False
            logger.warning("yara-python not installed. YARA scanning disabled.")
            return
        self._yara_available = True
        self._info.engine_version = getattr(yara, "__version__", None)

    # ──────────────────────────────────────────
    # Compilation — exactly once
    # ──────────────────────────────────────────

    def load_rules(self, rule_dirs: list[Path] | None = None) -> int:
        """Compile the packaged rules and any explicitly configured additions.

        Idempotent: a second call returns the count from the first compile and
        recompiles nothing, so a run with several detectors still pays for one
        compile and still records one digest.
        """
        if not self._checked:
            self._check_yara()
            self._checked = True
        if self._rules is not None:
            return self._rule_count
        if not self._yara_available:
            return 0

        import yara

        dirs: list[Path] = [_BUILTIN_RULES_DIR]
        dirs.extend(self.config.yara_rules_dirs)
        if rule_dirs:
            dirs.extend(rule_dirs)
        dirs.extend(self._extra_dirs)

        sources: list[tuple[str, str, bytes]] = []
        filepaths: dict[str, str] = {}
        seen_names: set[str] = set()
        explicit = False

        for directory in dirs:
            if not directory.exists() or not directory.is_dir():
                if directory != _BUILTIN_RULES_DIR:
                    self._info.errors.append(
                        {"file": str(directory), "reason": "rule directory does not exist"}
                    )
                continue
            if directory != _BUILTIN_RULES_DIR:
                explicit = True
            for yar_file in sorted(directory.rglob("*.yar")):
                try:
                    content = yar_file.read_bytes()
                except OSError as exc:
                    self._info.errors.append(
                        {"file": str(yar_file), "reason": f"unreadable: {exc}"}
                    )
                    continue

                text = content.decode("utf-8", errors="ignore")

                # An include index is not a rule file: its members are compiled
                # on their own, by path, so there is nothing to add here.
                if any(_INCLUDE_STATEMENT.match(line) for line in text.splitlines()):
                    logger.debug("Skipping include-based meta-rule: %s", yar_file)
                    continue

                try:
                    yara.compile(source=text)
                except yara.Error as exc:
                    self._info.errors.append(
                        {"file": yar_file.name, "reason": f"compilation error: {exc}"}
                    )
                    logger.warning(
                        "YARA compilation error in %s: %s — skipping", yar_file.name, exc
                    )
                    continue

                namespace = yar_file.stem
                if namespace in seen_names:
                    namespace = f"{yar_file.parent.name}_{namespace}"
                seen_names.add(namespace)
                filepaths[namespace] = str(yar_file)
                sources.append((namespace, yar_file.name, content))

        if not filepaths:
            logger.info("YARA engine: no rule files found")
            self._info.digest = _digest_of([])
            self._info.source = "package+explicit" if explicit else "package"
            self._rules = None
            self._rule_count = 0
            return 0

        try:
            self._rules = yara.compile(filepaths=filepaths)
        except yara.Error as exc:
            # One bad file must not remove every good rule from the run, and it
            # must not be silent either: compile the rest and record the gap.
            logger.warning("YARA compilation error for the full set: %s", exc)
            self._info.errors.append({"file": "<ruleset>", "reason": f"compilation error: {exc}"})
            self._rules = None
            self._rule_count = 0

        if self._rules is not None:
            self._rule_count = len(filepaths)
            self._info.files = [
                RuleFileRecord(
                    namespace=namespace,
                    name=name,
                    sha256=hashlib.sha256(content).hexdigest(),
                    rule_count=sum(
                        1
                        for line in content.decode("utf-8", errors="ignore").splitlines()
                        if _RULE_DECLARATION.match(line)
                    ),
                    destinations=sorted(
                        {
                            destination_for(category)
                            for category in _categories_in(content.decode("utf-8", errors="ignore"))
                        }
                    ),
                )
                for namespace, name, content in sources
            ]
            logger.info("YARA engine: %d rule files compiled", self._rule_count)

        self._info.digest = _digest_of(sources)
        self._info.source = "package+explicit" if explicit else "package"
        return self._rule_count

    @property
    def info(self) -> RuleSetInfo:
        """The compiled rule set's identity and its coverage gaps."""
        return self._info

    @property
    def digest(self) -> str:
        """Digest of the compiled rule sources (stable across paths and order)."""
        return self._info.digest

    @property
    def diagnostics(self) -> list[dict[str, str]]:
        """Rule files that could not be read or compiled, with the reason."""
        return list(self._info.errors)

    # ──────────────────────────────────────────
    # Scanning
    # ──────────────────────────────────────────

    def scan_file(self, file_path: Path) -> list[YaraMatch]:
        """Scan a file against the compiled rules, through the cache if enabled."""
        if self._rules is None or not file_path.exists():
            return []
        if self._cache is None:
            return self._scan(self._rules, file_path=file_path)

        digest = sha256_file(file_path)
        if digest is None:  # unreadable: let YARA report the failure itself
            return self._scan(self._rules, file_path=file_path)
        cached = self._cache.get("yara-file", digest, self._cache_dependencies())
        if isinstance(cached, list):
            return [self._match_from_entry(item, file_path) for item in cached]

        matches = self._scan(self._rules, file_path=file_path)
        self._cache.put(
            "yara-file",
            digest,
            self._cache_dependencies(),
            [self._match_to_entry(match) for match in matches],
        )
        return matches

    def scan_data(self, data: bytes, module_name: str = "") -> list[YaraMatch]:
        """Scan raw bytes against the compiled rules."""
        if self._rules is None or not data:
            return []
        if self._cache is None:
            return self._scan(self._rules, data=data, module_name=module_name)

        digest = hashlib.sha256(data).hexdigest()
        cached = self._cache.get("yara-data", digest, self._cache_dependencies())
        if isinstance(cached, list):
            return [self._match_from_entry(item, None) for item in cached]
        matches = self._scan(self._rules, data=data, module_name=module_name)
        self._cache.put(
            "yara-data",
            digest,
            self._cache_dependencies(),
            [self._match_to_entry(match) for match in matches],
        )
        return matches

    def _cache_dependencies(self) -> dict[str, Any]:
        """Everything a match set depends on besides the content itself."""
        return {
            "ruleset_digest": self._info.digest,
            "engine_version": self._info.engine_version or "unknown",
        }

    @staticmethod
    def _match_to_entry(match: YaraMatch) -> dict[str, Any]:
        """A path-free serialisable form. Locations are rebound on read."""
        return {
            "rule_name": match.rule_name,
            "namespace": match.namespace,
            "meta": {str(k): _scalar(v) for k, v in match.meta.items()},
            "strings": [
                [offset, identifier, blob.hex()] for offset, identifier, blob in match.strings
            ],
            "destination": match.destination,
            "category": match.category,
            "severity": match.severity,
            "rule_file": match.rule_file,
        }

    def _match_from_entry(self, entry: Any, file_path: Path | None) -> YaraMatch:
        if not isinstance(entry, dict):
            return YaraMatch(
                rule_name="invalid-cache-entry",
                namespace="",
                meta={},
                strings=[],
                file_path=file_path,
            )
        strings: list[tuple[int, str, bytes]] = []
        for item in entry.get("strings", []):
            try:
                offset, identifier, blob = item
                strings.append((int(offset), str(identifier), bytes.fromhex(str(blob))))
            except (TypeError, ValueError):
                continue
        meta = entry.get("meta", {})
        return YaraMatch(
            rule_name=str(entry.get("rule_name", "unknown")),
            namespace=str(entry.get("namespace", "")),
            meta=dict(meta) if isinstance(meta, dict) else {},
            strings=strings,
            file_path=file_path,
            destination=str(entry.get("destination", "indicator")),
            category=str(entry.get("category", "")),
            severity=str(entry.get("severity", "INFO")).upper(),
            rule_file=str(entry.get("rule_file", "")),
            ruleset_digest=self._info.digest,
        )

    def _scan(
        self,
        rules: Any,
        file_path: Path | None = None,
        data: bytes | None = None,
        module_name: str = "",
    ) -> list[YaraMatch]:
        """Execute one YARA scan and convert results to typed matches."""
        import yara

        matches: list[YaraMatch] = []
        try:
            if data is not None:
                results = rules.match(data=data)
            elif file_path is not None:
                results = rules.match(filepath=str(file_path))
            else:
                return matches
        except yara.Error as exc:
            logger.warning("YARA scan error: %s", exc)
            return matches

        rule_files = {record.namespace: record.name for record in self._info.files}
        for match in results:
            namespace = getattr(match, "namespace", "") or module_name or "default"
            matches.append(
                self._to_yara_match(
                    match,
                    namespace=namespace,
                    file_path=file_path,
                    rule_file=rule_files.get(namespace, ""),
                )
            )
        return matches

    def _to_yara_match(
        self,
        match: object,
        namespace: str,
        file_path: Path | None,
        rule_file: str,
    ) -> YaraMatch:
        """Convert a ``yara.Match`` into a typed :class:`YaraMatch`."""
        meta = dict(getattr(match, "meta", {}) or {})
        category = str(meta.get("category", ""))
        strings: list[tuple[int, str, bytes]] = []
        for string_match in getattr(match, "strings", []):
            identifier = getattr(string_match, "identifier", "")
            for instance in getattr(string_match, "instances", []):
                strings.append(
                    (
                        getattr(instance, "offset", 0),
                        identifier,
                        getattr(instance, "matched_data", b""),
                    )
                )

        return YaraMatch(
            rule_name=getattr(match, "rule", "unknown"),
            namespace=namespace,
            meta=meta,
            strings=strings,
            file_path=file_path,
            destination=destination_for(category),
            category=category,
            severity=str(meta.get("severity", "INFO")).upper(),
            rule_file=rule_file,
            ruleset_digest=self._info.digest,
        )

    # ──────────────────────────────────────────
    # Introspection
    # ──────────────────────────────────────────

    @property
    def destinations(self) -> list[str]:
        """Every destination the compiled set can route a match to."""
        return sorted({item for record in self._info.files for item in record.destinations})

    @property
    def rule_count(self) -> int:
        """Number of compiled rule files."""
        return self._rule_count

    @property
    def is_available(self) -> bool:
        """Whether yara-python is available and rules are loaded."""
        return self._yara_available and self._rules is not None


def _categories_in(text: str) -> list[str]:
    """Every category a rule file declares in its meta blocks."""
    return re.findall(r"^\s*category\s*=\s*\"([^\"]+)\"", text, re.MULTILINE)
