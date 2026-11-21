"""Scanner configuration via Pydantic.

Supports YAML/TOML config files, environment variables, and CLI overrides.
All values have sensible defaults — zero-config operation works out of the box.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from pydantic import Field, field_validator, model_validator
from pydantic.dataclasses import dataclass

#: Environment variable prefix for every setting.
ENV_PREFIX = "IOT_HARDWARE_SCANNER_"


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
        description=(
            "Wall-clock deadline for the extraction worker in seconds. A short "
            "deadline is a legitimate choice; when it expires the worker is killed "
            "and the analysis is reported incomplete."
        ),
        ge=5,
        le=3600,
    )
    extraction_depth: int = Field(
        default=3,
        description="Maximum recursive extraction depth (Matryoshka)",
        ge=1,
        le=10,
    )
    extraction_worker: str = Field(
        default="auto",
        description=(
            "Image extraction worker: auto (podman, then docker), podman, docker, "
            "host-process (unsandboxed, Linux only) or none"
        ),
    )
    extraction_require_isolation: bool = Field(
        default=True,
        description=(
            "Refuse a host-process extraction helper. A qualified result needs the "
            "read-only, no-network, size-limited worker sandbox."
        ),
    )
    worker_image: str = Field(
        default="ihs-squashfs-worker:4.5.1",
        description="Pinned worker image carrying upstream unsquashfs",
    )
    worker_memory_mb: int = Field(
        default=1024,
        description="Memory limit for the extraction worker in MB",
        ge=128,
        le=16384,
    )
    max_decoded_bytes_mb: int = Field(
        default=1024,
        description=(
            "Budget for bytes decoded from the gzip wrapper. Separate from the wrapper "
            "size and from the filesystem extent."
        ),
        ge=1,
        le=16384,
    )
    max_extracted_bytes_mb: int = Field(
        default=1024,
        description="Budget for bytes materialised from an extracted filesystem",
        ge=1,
        le=16384,
    )
    max_extracted_entries: int = Field(
        default=200000,
        description="Budget for entries in an extracted filesystem",
        ge=1,
    )
    keep_scratch: bool = Field(
        default=False,
        description="Keep the extraction scratch directory after a failed run",
    )
    snapshot_budget_mb: int = Field(
        default=4096,
        description=(
            "Storage budget for the private immutable copy of a file input; every "
            "later read is bound to this snapshot"
        ),
        ge=1,
        le=65536,
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
    max_entropy_scan_size_mb: int = Field(
        default=256,
        description=(
            "Max firmware file size in MB for full entropy analysis. "
            "Larger files get sampled/streamed."
        ),
        ge=1,
        le=4096,
    )
    max_scan_file_size_mb: int = Field(
        default=50,
        description=(
            "Max size in MB for full-text file scanning (credentials, C2). "
            "Larger files are skipped."
        ),
        ge=1,
        le=1024,
    )
    bounded_window_kb: int = Field(
        default=1024,
        description=(
            "Window size for bounded passes over a binary artifact; every window keeps "
            "its original offset"
        ),
        ge=4,
        le=65536,
    )
    nvd_max_retries: int = Field(
        default=3,
        description="Max retries for NVD API on 429/503 errors.",
        ge=0,
        le=10,
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
        default=True,
        description=(
            "Disable all network requests (NVD, threat intel). Default true: a "
            "scan never reaches the network unless the operator asks it to."
        ),
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

    # ── Precedence: explicit CLI > environment > config file > defaults ──

    @classmethod
    def field_names(cls) -> set[str]:
        """Every configurable field name."""
        return set(cls.__dataclass_fields__)

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> dict[str, Any]:
        """Read ``IOT_HARDWARE_SCANNER_<FIELD>`` variables into a dict.

        Values are coerced using the field's declared default type, so
        ``..._OFFLINE_MODE=false`` becomes ``False`` and
        ``..._MAX_FILE_SIZE_MB=64`` becomes ``64``.
        """
        environ = os.environ if environ is None else environ
        values: dict[str, Any] = {}
        known = cls.field_names()
        for key, raw in environ.items():
            if not key.startswith(ENV_PREFIX):
                continue
            name = key[len(ENV_PREFIX) :].lower()
            if name not in known:
                continue
            values[name] = _coerce(name, raw)
        return values

    @classmethod
    def resolve(
        cls,
        config_file: Path | None = None,
        environ: Mapping[str, str] | None = None,
        cli_overrides: Mapping[str, Any] | None = None,
    ) -> ScanConfigAlias:
        """Build a config from all four layers, in precedence order."""
        values: dict[str, Any] = {}
        values.update(cls.from_env(environ))
        values.update(cls._file_values(config_file, environ))
        values.update({k: v for k, v in (cli_overrides or {}).items() if v is not None})
        return cls(**values)

    @classmethod
    def _file_values(
        cls, config_file: Path | None, environ: Mapping[str, str] | None
    ) -> dict[str, Any]:
        """Values from the config file, located by argument or environment."""
        environ = os.environ if environ is None else environ
        path = config_file
        if path is None:
            from_env_path = environ.get(f"{ENV_PREFIX}CONFIG")
            path = Path(from_env_path) if from_env_path else None
        if path is None:
            return {}
        if not path.exists():
            raise ValueError(f"config file not found: {path}")
        loaded = cls.from_file(path)
        return {name: getattr(loaded, name) for name in cls.field_names()}

    @classmethod
    def from_file(cls, path: Path) -> ScannerConfig:
        """Load configuration from a YAML or TOML file."""
        text = path.read_text(encoding="utf-8")
        if path.suffix in (".yaml", ".yml"):
            try:
                import yaml
            except ModuleNotFoundError as exc:  # pragma: no cover - optional extra
                raise ValueError(
                    "YAML config files need the yaml_support extra: "
                    "pip install 'iot-hardware-scanner[yaml_support]' "
                    "(or use a .toml file)"
                ) from exc

            data = yaml.safe_load(text)
        elif path.suffix == ".toml":
            try:
                import tomllib
            except ModuleNotFoundError:  # Python 3.10 — stdlib tomllib is 3.11+
                import tomli as tomllib

            data = tomllib.loads(text)
        else:
            raise ValueError(f"Unsupported config format: {path.suffix}. Use .yaml or .toml")
        if not isinstance(data, dict):
            raise ValueError(f"config file must contain a mapping: {path}")
        unknown = sorted(set(data) - cls.field_names())
        if unknown:
            raise ValueError(
                f"unknown setting(s) in {path}: {', '.join(unknown)}. "
                f"Valid settings: {', '.join(sorted(cls.field_names()))}"
            )
        return cls(**data)


#: Self-reference alias that keeps ``from __future__ import annotations`` happy.
ScanConfigAlias = ScannerConfig


def _coerce(field_name: str, raw: str) -> Any:
    """Coerce a string environment value using the field's default type."""
    default = ScannerConfig.__dataclass_fields__[field_name].default
    if isinstance(default, bool):
        return raw.strip().lower() in {"1", "true", "yes", "on"}
    if isinstance(default, int) and not isinstance(default, bool):
        return int(raw)
    if isinstance(default, float):
        return float(raw)
    if isinstance(default, Path):
        return Path(raw)
    if field_name.endswith("_dirs") or isinstance(default, list):
        return [Path(part) if "dirs" in field_name else part for part in raw.split(",") if part]
    if field_name == "log_file":
        return Path(raw)
    if field_name == "nvd_api_key":
        return raw
    return raw
