"""Scanner configuration via Pydantic.

Supports YAML/TOML config files, environment variables, and CLI overrides.
All values have sensible defaults — zero-config operation works out of the box.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import Field, field_validator, model_validator
from pydantic.dataclasses import dataclass


@dataclass
class ScannerConfig:
    """Root configuration for the entire scanner pipeline."""

    # ── Firmware Ingest ──
    max_file_size_mb: int = Field(
        default=2048,
        description="Maximum firmware file size in MB (default: 2 GB)",
        ge=1,
        le=10240,
    )

    # ── Extraction ──
    extraction_timeout_seconds: int = Field(
        default=300,
        description="Timeout for firmware extraction in seconds",
        ge=30,
        le=3600,
    )
    extraction_depth: int = Field(
        default=3,
        description="Maximum recursive extraction depth (Matryoshka)",
        ge=1,
        le=10,
    )
    disk_space_multiplier: float = Field(
        default=3.0,
        description="Required free disk space as multiplier of firmware size",
        ge=1.0,
        le=10.0,
    )

    # ── Entropy ──
    entropy_block_size: int | None = Field(
        default=None,
        description="Block size for entropy calculation. None = auto-compute.",
    )
    entropy_detail_threshold_mb: int = Field(
        default=100,
        description="Files below this size get detailed (128B block) entropy scan",
        ge=1,
    )

    # ── Credential Scanner ──
    yara_rules_dirs: list[Path] = Field(
        default_factory=list,
        description="Additional YARA rule directories (built-in rules always loaded)",
    )
    credential_entropy_threshold: float = Field(
        default=1.5,
        description="Min entropy (bits/char) for a value to not be a placeholder",
        ge=0.0,
        le=8.0,
    )

    # ── CVE Scanner ──
    nvd_api_key: str | None = Field(
        default=None,
        description="NVD API key for faster rate limits (optional)",
    )
    nvd_cache_days: int = Field(
        default=7,
        description="NVD cache TTL in days",
        ge=1,
        le=30,
    )
    offline_mode: bool = Field(
        default=False,
        description="Disable all network requests (NVD, threat intel)",
    )

    # ── C2 Detector ──
    threat_intel_dirs: list[Path] = Field(
        default_factory=list,
        description="Threat intelligence feed directories",
    )
    c2_suspicion_threshold: float = Field(
        default=40.0,
        description="Score threshold to flag a domain as SUSPICIOUS",
        ge=0.0,
        le=100.0,
    )
    c2_likely_threshold: float = Field(
        default=60.0,
        description="Score threshold to flag a domain as LIKELY_C2",
        ge=0.0,
        le=100.0,
    )

    # ── Output ──
    output_dir: Path | None = Field(
        default=None,
        description="Base output directory. None = auto-generate per scan.",
    )
    report_formats: list[str] = Field(
        default_factory=lambda: ["json", "markdown"],
        description="Report output formats: json, markdown, html, terminal",
    )

    # ── General ──
    verbose: bool = Field(
        default=False,
        description="Enable verbose logging",
    )
    log_file: Path | None = Field(
        default=None,
        description="Log file path. None = stderr only.",
    )

    @field_validator("report_formats")
    @classmethod
    def validate_report_formats(cls, v: list[str]) -> list[str]:
        allowed = {"json", "markdown", "html", "terminal"}
        invalid = set(v) - allowed
        if invalid:
            raise ValueError(f"Invalid report format(s): {invalid}. Allowed: {allowed}")
        return v

    @model_validator(mode="after")
    def validate_thresholds(self) -> ScannerConfig:
        if self.c2_suspicion_threshold > self.c2_likely_threshold:
            raise ValueError(
                f"c2_suspicion_threshold ({self.c2_suspicion_threshold}) must be "
                f"<= c2_likely_threshold ({self.c2_likely_threshold})"
            )
        return self

    @classmethod
    def from_file(cls, path: Path) -> ScannerConfig:
        """Load configuration from a YAML or TOML file."""
        text = path.read_text(encoding="utf-8")
        if path.suffix in (".yaml", ".yml"):
            import yaml

            data = yaml.safe_load(text)
        elif path.suffix == ".toml":
            import tomllib

            data = tomllib.loads(text)
        else:
            raise ValueError(f"Unsupported config format: {path.suffix}. Use .yaml or .toml")
        return cls(**(data or {}))
