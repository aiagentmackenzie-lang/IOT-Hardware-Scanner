"""YARA Rule Engine — loader, compiler, and scanner.

SDR §10 — YARA Rule Engine

Loads rules from built-in, user, and project directories.
Compiles them for fast matching. Scans files and raw data.
"""

from __future__ import annotations

import logging
from pathlib import Path

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.models import YaraMatch

logger = logging.getLogger(__name__)

# Directories to search for YARA rules (in order of priority)
_BUILTIN_RULES_DIR = Path(__file__).parent / "rules"
_USER_RULES_DIR = Path.home() / ".iot_hardware_scanner" / "yara_rules"
_PROJECT_RULES_DIR = Path.cwd() / "yara_rules"


class YaraEngine:
    """Load, compile, and execute YARA rules against files and data."""

    def __init__(self, config: ScannerConfig) -> None:
        self.config = config
        self._rules: object | None = None
        self._rule_count: int = 0
        self._yara_available: bool = False
        self._check_yara()

    def _check_yara(self) -> None:
        """Check if yara-python is available."""
        try:
            import yara  # noqa: F401

            self._yara_available = True
        except ImportError:
            self._yara_available = False
            logger.warning("yara-python not installed. YARA scanning disabled.")

    def load_rules(self, rule_dirs: list[Path] | None = None) -> int:
        """Load and compile YARA rules from built-in and user directories.

        Returns number of rules loaded (0 if yara-python unavailable).
        """
        if not self._yara_available:
            return 0

        import yara

        # Gather all rule directories
        dirs: list[Path] = [
            _BUILTIN_RULES_DIR,
            _USER_RULES_DIR,
            _PROJECT_RULES_DIR,
        ]
        # Add config-specified dirs
        dirs.extend(self.config.yara_rules_dirs)
        # Add caller-specified dirs
        if rule_dirs:
            dirs.extend(rule_dirs)

        # Collect all .yar files, keyed by filepath
        # Use filepath-based compilation with namespaces
        filepaths_dict: dict[str, str] = {}  # namespace -> filepath
        seen_names: set[str] = set()

        for d in dirs:
            if d.exists() and d.is_dir():
                for yar_file in sorted(d.rglob("*.yar")):
                    # Skip the meta-rule file that uses include directives
                    try:
                        first_line = yar_file.read_text(
                            encoding="utf-8", errors="ignore"
                        ).splitlines()[0] if yar_file.exists() else ""
                    except OSError:
                        first_line = ""
                    if first_line.strip().startswith("//") and "include" in first_line:
                        logger.debug("Skipping include-based meta-rule: %s", yar_file)
                        continue
                    # Also skip if any line starts with 'include '
                    try:
                        content = yar_file.read_text(encoding="utf-8", errors="ignore")
                    except OSError:
                        continue
                    if any(
                        line.strip().startswith("include ")
                        for line in content.splitlines()
                    ):
                        logger.debug(
                            "Skipping include-based meta-rule: %s", yar_file
                        )
                        continue

                    # Check for compilation errors before adding
                    try:
                        yara.compile(source=content)
                    except yara.Error as exc:
                        logger.warning(
                            "YARA compilation error in %s: %s — skipping",
                            yar_file.name,
                            exc,
                        )
                        continue

                    # Use filename stem as namespace, deduplicate
                    namespace = yar_file.stem
                    if namespace in seen_names:
                        # Append parent dir name for uniqueness
                        namespace = f"{yar_file.parent.name}_{namespace}"
                    seen_names.add(namespace)
                    filepaths_dict[namespace] = str(yar_file)

        if not filepaths_dict:
            logger.info("YARA engine: no rule files found")
            self._rules = None
            self._rule_count = 0
            return 0

        # Compile all rules together
        try:
            self._rules = yara.compile(filepaths=filepaths_dict)
            self._rule_count = len(filepaths_dict)
        except yara.Error as exc:
            logger.warning("YARA compilation error: %s", exc)
            self._rules = None
            self._rule_count = 0
            return 0

        logger.info("YARA engine: %d rule files compiled", self._rule_count)
        return self._rule_count

    def scan_file(self, file_path: Path) -> list[YaraMatch]:
        """Scan a file against loaded YARA rules.

        Returns list of YaraMatch objects (empty if no rules loaded or file
        doesn't exist).
        """
        if self._rules is None or not file_path.exists():
            return []

        return self._scan(self._rules, file_path=file_path)

    def scan_data(self, data: bytes, module_name: str = "") -> list[YaraMatch]:
        """Scan raw bytes against loaded YARA rules.

        Args:
            data: Bytes to scan.
            module_name: Optional namespace label for the data source.

        Returns:
            List of YaraMatch objects.
        """
        if self._rules is None or not data:
            return []

        return self._scan(self._rules, data=data, module_name=module_name)

    def _scan(
        self,
        rules: object,
        file_path: Path | None = None,
        data: bytes | None = None,
        module_name: str = "",
    ) -> list[YaraMatch]:
        """Execute YARA scan and convert results to YaraMatch objects."""
        import yara

        matches: list[YaraMatch] = []

        try:
            if data is not None:
                results = rules.match(data=data)  # type: ignore[union-attr]
            elif file_path is not None:
                results = rules.match(filepath=str(file_path))  # type: ignore[union-attr]
            else:
                return matches

            for m in results:
                matches.append(
                    self._to_yara_match(m, module_name or "default", file_path)
                )

        except yara.Error as exc:
            logger.warning("YARA scan error: %s", exc)

        return matches

    @staticmethod
    def _to_yara_match(match: object, namespace: str, file_path: Path | None) -> YaraMatch:
        """Convert a yara.Match object to our YaraMatch dataclass."""
        rule_name = getattr(match, "rule", "unknown")
        meta = getattr(match, "meta", {})
        strings = []

        for s in getattr(match, "strings", []):
            # yara-python 4.x: StringMatch objects with .identifier, .instances
            identifier = getattr(s, "identifier", "")
            for inst in getattr(s, "instances", []):
                offset = getattr(inst, "offset", 0)
                sdata = getattr(inst, "matched_data", b"")
                strings.append((offset, identifier, sdata))

        return YaraMatch(
            rule_name=rule_name,
            namespace=namespace,
            meta=meta,
            strings=strings,
            file_path=file_path,
        )

    @property
    def rule_count(self) -> int:
        """Number of compiled rule files."""
        return self._rule_count

    @property
    def is_available(self) -> bool:
        """Whether yara-python is available and rules are loaded."""
        return self._yara_available and self._rules is not None
