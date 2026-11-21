"""CPE naming — the single product mapping for the whole scanner (slice 4B).

Before this module was consolidated there were two maps: one in
``scanner/binary_intelligence.py`` for banner-derived versions and one here for
advisory lookups. They drifted, so the same component could be named two ways
depending on which detector saw it first. There is now one mapping, loaded from
the bundled ``data/component_cpe_map.json``, and one serialiser.

The serialised form is a CPE 2.3 formatted string with all thirteen attributes,
per NIST IR 7695::

    cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*

A short ``cpe:2.3:a:v:p:ver`` string is not a CPE 2.3 name — it has the wrong
number of components — and downstream tooling that parses it will silently
misread the version as an update. Components are escaped with a backslash when
they contain a character the formatted-string grammar reserves.

Reference: https://csrc.nist.gov/pubs/ir/7695/final
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from iot_hardware_scanner import resources

logger = logging.getLogger(__name__)

#: Built-in fallbacks. The bundled data file is authoritative and may extend
#: this map; it never has to repeat it.
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

#: Characters the CPE formatted-string grammar reserves. Anything outside
#: ``[A-Za-z0-9._-]`` is escaped with a backslash.
_RESERVED = re.compile(r"([^A-Za-z0-9._-])")

_DATA_MAP_LOADED = False


def escape_component(value: str) -> str:
    """Escape one CPE formatted-string component.

    ``*`` is the grammar's ANY wildcard and is passed through unescaped; an
    empty value becomes ANY rather than an empty component, which would make the
    name invalid.
    """
    if not value:
        return "*"
    if value == "*":
        return "*"
    return _RESERVED.sub(r"\\\1", value)


def cpe_name(
    vendor: str,
    product: str,
    version: str,
    *,
    part: str = "a",
    target_sw: str = "*",
) -> str:
    """Build a complete CPE 2.3 formatted string (13 attributes)."""
    return ":".join(
        [
            "cpe",
            "2.3",
            escape_component(part),
            escape_component(vendor),
            escape_component(product),
            escape_component(version),
            "*",  # update
            "*",  # edition
            "*",  # language
            "*",  # sw_edition
            escape_component(target_sw),
            "*",  # target_hw
            "*",  # other
        ]
    )


def _load_data_map() -> dict[str, tuple[str, str]]:
    """Merge the bundled mapping into the built-in one, once."""
    global _DATA_MAP_LOADED
    if _DATA_MAP_LOADED:
        return PRODUCT_CPE_MAP
    try:
        data_path: Path = resources.data_file("component_cpe_map.json")
        if data_path.exists():
            raw = json.loads(data_path.read_text(encoding="utf-8"))
            for product, mapping in raw.items():
                vendor = mapping.get("vendor", product)
                cpe_product = mapping.get("product", product)
                PRODUCT_CPE_MAP.setdefault(product, (vendor, cpe_product))
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        logger.warning("Cannot load CPE map: %s", exc)
    _DATA_MAP_LOADED = True
    return PRODUCT_CPE_MAP


def lookup(product: str) -> tuple[str, str] | None:
    """Vendor and CPE product for a known product name, or ``None``."""
    return _load_data_map().get(product)


class CPEBuilder:
    """Construct CPE 2.3 names from product names and versions."""

    def build(self, product: str, version: str) -> str | None:
        """Build a CPE 2.3 name for a mapped product, or ``None`` if unmapped."""
        mapping = lookup(product)
        if mapping is None:
            logger.warning("No CPE mapping for product: %s", product)
            return None
        vendor, prod = mapping
        return cpe_name(vendor, prod, version)

    def build_from_component(self, vendor: str, product: str, version: str) -> str:
        """Build a CPE 2.3 name with explicit vendor and product names."""
        return cpe_name(vendor, product, version)

    def build_from_map(self, product: str, version: str, vendor: str, cpe_product: str) -> str:
        """Build a CPE 2.3 name from an explicit mapping row."""
        return cpe_name(vendor, cpe_product, version)

    def lookup_product(self, product: str) -> tuple[str, str] | None:
        """Look up the CPE vendor/product for a known product name."""
        return lookup(product)
