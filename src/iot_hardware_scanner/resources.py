"""Bundled resources: rules, mappings, feeds and catalogs.

Every file the scanner needs at run time ships **inside the installed
package**, so a wheel installed outside a source checkout behaves exactly like
an editable install. Loading anything from the current working directory or the
user's home directory is deliberately not supported by the qualified paths.

The scanner also records what it loaded: which file, its digest, and whether it
is an example rather than a current feed. A bundled sample must never be
presented as a current advisory catalog.
"""

from __future__ import annotations

import hashlib
from importlib import resources
from pathlib import Path

PACKAGE = "iot_hardware_scanner"

#: Bundled files that are examples, not current operational data.
SAMPLE_FILES: dict[str, str] = {
    "threat_intel_sample.jsonl": "example threat-intelligence feed",
    "kev_catalog.json": "bundled CISA KEV sample, not the current catalog",
}

#: Role of each bundled data file, used when recording provenance.
DATA_ROLES: dict[str, str] = {
    "benign_domains.txt": "domain allow-list used to damp indicator scores",
    "suspicious_tlds.txt": "TLD list used to raise indicator scores",
    "component_cpe_map.json": "product-to-CPE mapping",
    "default_credentials.json": "known default credential table",
    "kev_catalog.json": "known-exploited-vulnerability identifiers",
    "threat_intel_sample.jsonl": "threat-intelligence indicators",
}


class ResourceUnavailableError(RuntimeError):
    """A bundled resource the profile requires is missing from the install."""


def data_dir() -> Path:
    """Directory holding the bundled data files."""
    root = resources.files(PACKAGE).joinpath("data")
    path = Path(str(root))
    if not path.is_dir():  # pragma: no cover - zipped install
        raise ResourceUnavailableError(f"bundled data is not readable as a directory: {path}")
    return path


def data_file(name: str) -> Path:
    """Path to one bundled data file."""
    path = data_dir() / name
    if not path.is_file():
        raise ResourceUnavailableError(f"bundled data file missing: {name}")
    return path


def read_text(name: str) -> str:
    """Read a bundled UTF-8 text file."""
    return data_file(name).read_text(encoding="utf-8")


def data_files() -> list[Path]:
    """Every bundled data file, sorted by name."""
    return sorted(p for p in data_dir().iterdir() if p.is_file())


def is_sample(name: str) -> bool:
    """Whether a bundled file is an example rather than current data."""
    return name in SAMPLE_FILES


def describe_loaded(names: list[str] | None = None) -> list[dict[str, object]]:
    """Describe bundled files actually loaded by this run.

    Returns one entry per file with its role, digest and sample status, so a
    report can say exactly which data backed its conclusions.
    """
    described: list[dict[str, object]] = []
    for path in data_files():
        if names is not None and path.name not in names:
            continue
        try:
            payload = path.read_bytes()
        except OSError as exc:  # pragma: no cover - unreadable install
            described.append({"name": path.name, "error": str(exc)})
            continue
        described.append(
            {
                "name": path.name,
                "role": DATA_ROLES.get(path.name, "unknown"),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "bytes": len(payload),
                "sample": is_sample(path.name),
                "sample_note": SAMPLE_FILES.get(path.name),
            }
        )
    return described


def yara_rules_dir() -> Path:
    """Directory holding the bundled YARA rules."""
    path = Path(str(resources.files(PACKAGE).joinpath("yara").joinpath("rules")))
    if not path.is_dir():  # pragma: no cover - packaging failure
        raise ResourceUnavailableError(f"bundled YARA rules missing: {path}")
    return path
