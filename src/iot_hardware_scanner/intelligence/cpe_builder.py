"""CPE String Builder.

SDR §11.1 — CPE Constructor

Constructs NVD-compatible CPE 2.3 strings from detected
software components.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Product → CPE vendor/product mapping (from SDR §9.2)
PRODUCT_CPE_MAP: dict[str, tuple[str, str]] = {
    "busybox": ("busybox", "busybox"),
    "openssl": ("openssl", "openssl"),
    "dropbear": ("matt_johnston", "dropbear_ssh"),
    "dnsmasq": ("thekelleys", "dnsmasq"),
    "nginx": ("f5", "nginx"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "linux_kernel": ("linux", "linux_kernel"),
    "u_boot": ("denx", "u-boot"),
    "curl": ("haxx", "curl"),
    "openssh": ("openbsd", "openssh"),
    "zlib": ("zlib", "zlib"),
    "sqlite": ("sqlite", "sqlite"),
}

# Load additional mappings from data/component_cpe_map.json
_DATA_MAP_LOADED = False


def _load_data_map() -> dict[str, tuple[str, str]]:
    """Load CPE mappings from data file, merging with built-in."""
    global _DATA_MAP_LOADED
    if _DATA_MAP_LOADED:
        return PRODUCT_CPE_MAP

    data_path = Path(__file__).parent.parent.parent.parent / "data" / "component_cpe_map.json"
    try:
        if data_path.exists():
            raw = json.loads(data_path.read_text(encoding="utf-8"))
            for product, mapping in raw.items():
                vendor = mapping.get("vendor", product)
                cpe_product = mapping.get("product", product)
                PRODUCT_CPE_MAP.setdefault(product, (vendor, cpe_product))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Cannot load CPE map: %s", exc)

    _DATA_MAP_LOADED = True
    return PRODUCT_CPE_MAP


class CPEBuilder:
    """Construct CPE 2.3 strings from product names and versions."""

    def build(self, product: str, version: str) -> str | None:
        """Build a CPE 2.3 string.

        Format: cpe:2.3:a:<vendor>:<product>:<version>
        """
        mappings = _load_data_map()
        if product not in mappings:
            logger.warning("No CPE mapping for product: %s", product)
            return None

        vendor, prod = mappings[product]
        return f"cpe:2.3:a:{vendor}:{prod}:{version}"

    def build_from_component(self, vendor: str, product: str, version: str) -> str:
        """Build CPE string with explicit vendor and product names."""
        return f"cpe:2.3:a:{vendor}:{product}:{version}"

    def build_from_map(self, product: str, version: str, vendor: str, cpe_product: str) -> str:
        """Build CPE string with explicit vendor and product names."""
        return f"cpe:2.3:a:{vendor}:{cpe_product}:{version}"

    def lookup_product(self, product: str) -> tuple[str, str] | None:
        """Look up CPE vendor/product for a known product name."""
        mappings = _load_data_map()
        return mappings.get(product)
