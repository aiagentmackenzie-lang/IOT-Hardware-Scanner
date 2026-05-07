"""Threat Intelligence Feed Manager.

SDR §12 + Appendix D — Threat Intelligence Feed Specification

Loads JSON Lines threat intel feeds from configured directories.
Supports domain and IP lookups with in-memory caching.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from iot_hardware_scanner.config import ScannerConfig

logger = logging.getLogger(__name__)

# Default data directory (project root / data)
_DATA_DIR = Path(__file__).parent.parent.parent.parent / "data"


class ThreatIntelManager:
    """Manage and query threat intelligence feeds.

    Loads JSON Lines feeds from configured directories.
    Each line: {"type": "domain"|"ip"|"ip_range", "value": ..., "tags": [...], ...}
    """

    def __init__(self, config: ScannerConfig) -> None:
        self.config = config
        self._domains: dict[str, dict] = {}
        self._ips: dict[str, dict] = {}
        self._loaded = False

    def load_feeds(self) -> int:
        """Load all configured threat intelligence feeds.

        Returns total number of indicators loaded.
        """
        dirs: list[Path] = list(self.config.threat_intel_dirs)
        # Always include project data directory
        if _DATA_DIR not in dirs:
            dirs.append(_DATA_DIR)

        total = 0
        for d in dirs:
            count = self._load_directory(d)
            total += count

        self._loaded = True
        logger.info(
            "Threat intel loaded: %d domains, %d IPs from %d dirs",
            len(self._domains),
            len(self._ips),
            len(dirs),
        )
        return total

    def _load_directory(self, directory: Path) -> int:
        """Load all .jsonl files from a directory."""
        if not directory.exists() or not directory.is_dir():
            logger.debug("Threat intel dir missing or not a directory: %s", directory)
            return 0

        count = 0
        for jsonl_file in sorted(directory.glob("*.jsonl")):
            file_count = self._load_jsonl(jsonl_file)
            count += file_count
            if file_count > 0:
                logger.debug("Loaded %d indicators from %s", file_count, jsonl_file.name)

        return count

    def _load_jsonl(self, path: Path) -> int:
        """Load a single JSON Lines file."""
        count = 0
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, PermissionError) as exc:
            logger.warning("Cannot read threat intel file %s: %s", path.name, exc)
            return 0

        for line_num, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                logger.debug("Malformed entry in %s line %d: %s", path.name, line_num, exc)
                continue

            indicator_type = entry.get("type", "")
            value = entry.get("value", "")
            if not indicator_type or not value:
                continue

            if indicator_type == "domain":
                self._domains[value.lower()] = entry
                count += 1
            elif indicator_type == "ip":
                self._ips[value] = entry
                count += 1
            elif indicator_type == "ip_range":
                # Store range as-is; lookup checks CIDR membership
                self._ips[value] = entry
                count += 1
            # Silently skip unknown types

        return count

    def check_domain(self, domain: str) -> dict | None:
        """Check if a domain appears in any threat intel feed."""
        if not self._loaded:
            self.load_feeds()
        return self._domains.get(domain.lower())

    def check_ip(self, ip: str) -> dict | None:
        """Check if an IP appears in any threat intel feed.

        Checks exact match first, then CIDR range membership.
        """
        if not self._loaded:
            self.load_feeds()

        # Exact match
        if ip in self._ips:
            return self._ips[ip]

        # CIDR range check
        import ipaddress

        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return None

        for key, entry in self._ips.items():
            if "/" in key:  # CIDR range
                try:
                    network = ipaddress.ip_network(key, strict=False)
                    if ip_obj in network:
                        return entry
                except ValueError:
                    continue

        return None

    @property
    def domain_count(self) -> int:
        """Number of domain indicators loaded."""
        return len(self._domains)

    @property
    def ip_count(self) -> int:
        """Number of IP indicators loaded."""
        return len(self._ips)
