"""Tests for ScannerConfig — Phase 1.

Covers:
- Default configuration values
- Validation constraints
- Config from file (YAML/TOML)
- Threshold validation
"""

import os
import tempfile
from pathlib import Path

import pytest

from iot_hardware_scanner.config import ScannerConfig


class TestConfigDefaults:
    """Test default configuration values."""

    def test_defaults(self) -> None:
        config = ScannerConfig()
        assert config.max_file_size_mb == 2048
        assert config.extraction_timeout_seconds == 300
        assert config.extraction_depth == 3
        assert config.disk_space_multiplier == 3.0
        assert config.entropy_block_size is None
        assert config.credential_entropy_threshold == 1.5
        assert config.nvd_api_key is None
        assert config.nvd_cache_days == 7
        assert config.offline_mode is False
        assert config.c2_suspicion_threshold == 40.0
        assert config.c2_likely_threshold == 60.0
        assert "json" in config.report_formats
        assert "markdown" in config.report_formats
        assert config.verbose is False


class TestConfigValidation:
    """Test configuration validation."""

    def test_invalid_report_format(self) -> None:
        with pytest.raises(ValueError, match="Invalid report format"):
            ScannerConfig(report_formats=["xml"])

    def test_inverted_thresholds(self) -> None:
        """suspicion_threshold must be <= likely_threshold."""
        with pytest.raises(ValueError, match="suspicion_threshold"):
            ScannerConfig(c2_suspicion_threshold=70.0, c2_likely_threshold=40.0)

    def test_max_size_range(self) -> None:
        with pytest.raises(ValueError):
            ScannerConfig(max_file_size_mb=0)
        with pytest.raises(ValueError):
            ScannerConfig(max_file_size_mb=99999)

    def test_extraction_timeout_range(self) -> None:
        with pytest.raises(ValueError):
            ScannerConfig(extraction_timeout_seconds=5)
        with pytest.raises(ValueError):
            ScannerConfig(extraction_timeout_seconds=9999)


class TestConfigFromYaml:
    """Test loading config from YAML file."""

    def test_load_yaml(self) -> None:
        yaml_content = """
max_file_size_mb: 1024
verbose: true
offline_mode: true
report_formats:
  - json
  - markdown
"""
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            try:
                import yaml  # noqa: F401

                config = ScannerConfig.from_file(Path(f.name))
                assert config.max_file_size_mb == 1024
                assert config.verbose is True
                assert config.offline_mode is True
                assert config.report_formats == ["json", "markdown"]
            except ImportError:
                pytest.skip("PyYAML not installed")
            finally:
                os.unlink(f.name)


class TestConfigFromToml:
    """Test loading config from TOML file."""

    def test_load_toml(self) -> None:
        toml_content = """
max_file_size_mb = 512
verbose = true
offline_mode = true
report_formats = ["json"]
"""
        with tempfile.NamedTemporaryFile(suffix=".toml", mode="w", delete=False) as f:
            f.write(toml_content)
            f.flush()
            config = ScannerConfig.from_file(Path(f.name))

        assert config.max_file_size_mb == 512
        assert config.verbose is True
        assert config.report_formats == ["json"]


class TestConfigUnsupportedFormat:
    """Test config file format validation."""

    def test_unsupported_format(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            f.write("{}")
            f.flush()
            with pytest.raises(ValueError, match="Unsupported config format"):
                ScannerConfig.from_file(Path(f.name))
