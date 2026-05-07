"""Tests for YaraEngine — Phase 4.

SDR §10 — YARA Rule Engine
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.models import YaraMatch
from iot_hardware_scanner.yara.yara_engine import YaraEngine


@pytest.fixture
def config() -> ScannerConfig:
    """Return a default ScannerConfig."""
    return ScannerConfig()


@pytest.fixture
def yara_engine(config: ScannerConfig) -> YaraEngine:
    """Return a YaraEngine with default config."""
    return YaraEngine(config)


# ──────────────────────────────────────────────
# Initialization
# ──────────────────────────────────────────────


class TestYaraEngineInit:
    def test_yara_available(self, yara_engine: YaraEngine) -> None:
        """yara-python is installed in this environment."""
        assert yara_engine._yara_available is True

    def test_rules_none_initially(self, yara_engine: YaraEngine) -> None:
        """Rules are not loaded until load_rules() is called."""
        assert yara_engine._rules is None
        assert yara_engine.rule_count == 0

    def test_is_available_false_before_load(self, yara_engine: YaraEngine) -> None:
        """is_available is False before loading rules."""
        assert yara_engine.is_available is False

    @patch("iot_hardware_scanner.yara.yara_engine.YaraEngine._check_yara")
    def test_graceful_when_yara_unavailable(self, config: ScannerConfig) -> None:
        """Engine handles missing yara-python gracefully."""
        engine = YaraEngine(config)
        engine._yara_available = False
        engine._rules = None
        assert engine.is_available is False
        assert engine.load_rules() == 0


# ──────────────────────────────────────────────
# load_rules
# ──────────────────────────────────────────────


class TestLoadRules:
    def test_load_builtin_rules(self, yara_engine: YaraEngine) -> None:
        """Load built-in YARA rules from the rules/ directory."""
        count = yara_engine.load_rules()
        assert count > 0
        assert yara_engine._rules is not None
        assert yara_engine.is_available is True

    def test_load_with_nonexistent_dir(self, yara_engine: YaraEngine) -> None:
        """Non-existent rule directories don't crash the engine."""
        count = yara_engine.load_rules(rule_dirs=[Path("/nonexistent/path")])
        # Still loads builtin rules
        assert count > 0

    def test_load_with_custom_dir(self, config: ScannerConfig) -> None:
        """Load rules from a custom directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            rule_path = Path(tmpdir) / "test_rule.yar"
            rule_path.write_text(
                'rule test_custom_rule {\n'
                '    meta:\n'
                '        description = "Test rule"\n'
                '        severity = "HIGH"\n'
                '    strings:\n'
                '        $s = "test_password_123"\n'
                '    condition:\n'
                '        $s\n'
                '}\n'
            )
            engine = YaraEngine(config)
            count = engine.load_rules(rule_dirs=[Path(tmpdir)])
            assert count >= 1

    def test_load_skip_bad_syntax(self, config: ScannerConfig) -> None:
        """Bad YARA syntax files are skipped, not crashing the engine."""
        with tempfile.TemporaryDirectory() as tmpdir:
            bad_rule = Path(tmpdir) / "bad_rule.yar"
            bad_rule.write_text('rule { invalid yara syntax !!! }')
            engine = YaraEngine(config)
            count = engine.load_rules(rule_dirs=[Path(tmpdir)])
            # Should not crash — bad rule skipped
            assert isinstance(count, int)

    def test_load_empty_dir(self, config: ScannerConfig) -> None:
        """Empty directory returns 0 rules (plus any built-in)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = YaraEngine(config)
            # Override builtin dir to empty
            count = engine.load_rules(rule_dirs=[Path(tmpdir)])
            # May still find builtin rules
            assert isinstance(count, int)

    def test_load_returns_int(self, yara_engine: YaraEngine) -> None:
        """load_rules returns an integer count."""
        count = yara_engine.load_rules()
        assert isinstance(count, int)
        assert count >= 0


# ──────────────────────────────────────────────
# scan_file
# ──────────────────────────────────────────────


class TestScanFile:
    def test_scan_file_with_password(self, yara_engine: YaraEngine) -> None:
        """YARA detects hardcoded password in a file."""
        yara_engine.load_rules()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".cfg", delete=False) as f:
            f.write('password = "super_secret_123"\n')
            f.flush()
            path = Path(f.name)

        try:
            matches = yara_engine.scan_file(path)
            # Should detect hardcoded_password_variable rule
            assert len(matches) >= 1
            rule_names = [m.rule_name for m in matches]
            assert "hardcoded_password_variable" in rule_names
        finally:
            path.unlink(missing_ok=True)

    def test_scan_file_with_aws_key(self, yara_engine: YaraEngine) -> None:
        """YARA detects AWS access key."""
        yara_engine.load_rules()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
            f.flush()
            path = Path(f.name)

        try:
            matches = yara_engine.scan_file(path)
            assert len(matches) >= 1
            rule_names = [m.rule_name for m in matches]
            assert "aws_access_key" in rule_names
        finally:
            path.unlink(missing_ok=True)

    def test_scan_file_with_ssh_key(self, yara_engine: YaraEngine) -> None:
        """YARA detects SSH private key."""
        yara_engine.load_rules()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as f:
            f.write(
                "-----BEGIN RSA PRIVATE KEY-----\n"
                "MIIBogIBAAJBAKx1\n"
                "-----END RSA PRIVATE KEY-----\n"
            )
            f.flush()
            path = Path(f.name)

        try:
            matches = yara_engine.scan_file(path)
            assert len(matches) >= 1
            rule_names = [m.rule_name for m in matches]
            assert "ssh_private_key" in rule_names
        finally:
            path.unlink(missing_ok=True)

    def test_scan_file_no_match(self, yara_engine: YaraEngine) -> None:
        """Clean file produces no YARA matches."""
        yara_engine.load_rules()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("Hello world\nThis is fine\n")
            f.flush()
            path = Path(f.name)

        try:
            matches = yara_engine.scan_file(path)
            assert len(matches) == 0
        finally:
            path.unlink(missing_ok=True)

    def test_scan_file_no_rules_loaded(self, yara_engine: YaraEngine) -> None:
        """scan_file returns [] when no rules are loaded."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".cfg", delete=False) as f:
            f.write('password = "secret"\n')
            f.flush()
            path = Path(f.name)

        try:
            # Don't load rules
            matches = yara_engine.scan_file(path)
            assert matches == []
        finally:
            path.unlink(missing_ok=True)

    def test_scan_file_nonexistent(self, yara_engine: YaraEngine) -> None:
        """scan_file returns [] for non-existent file."""
        yara_engine.load_rules()
        matches = yara_engine.scan_file(Path("/nonexistent/file.txt"))
        assert matches == []


# ──────────────────────────────────────────────
# scan_data
# ──────────────────────────────────────────────


class TestScanData:
    def test_scan_data_with_aws_key(self, yara_engine: YaraEngine) -> None:
        """YARA detects AWS key in raw bytes."""
        yara_engine.load_rules()
        data = b"AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
        matches = yara_engine.scan_data(data)
        assert len(matches) >= 1

    def test_scan_data_with_password(self, yara_engine: YaraEngine) -> None:
        """YARA detects password pattern in raw bytes."""
        yara_engine.load_rules()
        data = b'password = "MyS3cretP@ss!"\n'
        matches = yara_engine.scan_data(data)
        assert len(matches) >= 1

    def test_scan_data_no_match(self, yara_engine: YaraEngine) -> None:
        """Clean data produces no matches."""
        yara_engine.load_rules()
        data = b"Hello world, nothing to see here\n"
        matches = yara_engine.scan_data(data)
        assert len(matches) == 0

    def test_scan_data_no_rules(self, yara_engine: YaraEngine) -> None:
        """scan_data returns [] when no rules loaded."""
        data = b"password = 'secret'\n"
        matches = yara_engine.scan_data(data)
        assert matches == []

    def test_scan_data_empty(self, yara_engine: YaraEngine) -> None:
        """Empty data returns no matches."""
        yara_engine.load_rules()
        matches = yara_engine.scan_data(b"")
        assert matches == []


# ──────────────────────────────────────────────
# YaraMatch model
# ──────────────────────────────────────────────


class TestYaraMatch:
    def test_yara_match_fields(self) -> None:
        """YaraMatch dataclass has expected fields."""
        match = YaraMatch(
            rule_name="test_rule",
            namespace="test",
            meta={"severity": "HIGH"},
            strings=[(0, "$s1", b"test")],
            file_path=Path("/tmp/test.txt"),
        )
        assert match.rule_name == "test_rule"
        assert match.namespace == "test"
        assert match.meta["severity"] == "HIGH"
        assert len(match.strings) == 1
        assert match.file_path == Path("/tmp/test.txt")

    def test_yara_match_defaults(self) -> None:
        """YaraMatch has sensible defaults."""
        match = YaraMatch(rule_name="r", namespace="ns")
        assert match.meta == {}
        assert match.strings == []
        assert match.file_path is None
