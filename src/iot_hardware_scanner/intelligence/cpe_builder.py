"""CPE naming — the single product mapping for the whole scanner (slice 4B/4B+).

Before this module was consolidated there were two maps: one in
``scanner/binary_intelligence.py`` for banner-derived versions and one here for
advisory lookups. They drifted, so the same component could be named two ways
depending on which detector saw it first. There is now one mapping, loaded from
the bundled ``data/component_cpe_map.json``, and one serialiser.

Resolution has three bases, and every component records which one produced its
name so a reader can weigh it:

``nist-mapped``
    The product has an authoritative vendor/product pair in the mapping. Rows
    are added only when NIST's own CPE dictionary names the product that way;
    the mapping never guesses a vendor.
``opkg-package-name``
    The package has no authoritative NIST entry. The name is built from the
    opkg package name with vendor ``openwrt`` and the *package's own* name as
    the product, so it is a traceable identity for the inventory it came from
    and not a claim that NIST knows the product. A CPE name is still a complete
    CPE 2.3 formatted string — 13 attributes — because a truncated
    ``cpe:2.3:a:v:p:ver`` is not CPE 2.3 and downstream parsers misread it.
``banner``
    The name came from a version string found in a file, not from the package
    database. It is a candidate, and it only exists when the mapping knows the
    product.

Versions are never normalised: ``1.36.1-r2`` stays ``1.36.1-r2``, because the
revision is a distinct fact and dropping it turns a comparison into a guess.

Reference: https://csrc.nist.gov/pubs/ir/7695/final
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path

from iot_hardware_scanner import resources

logger = logging.getLogger(__name__)

#: Basis labels, recorded per component and counted in the report.
BASIS_NIST_MAPPED = "nist-mapped"
BASIS_OPKG_PACKAGE_NAME = "opkg-package-name"
BASIS_BANNER = "banner"
BASES = (BASIS_NIST_MAPPED, BASIS_OPKG_PACKAGE_NAME, BASIS_BANNER)

#: Vendor used when a package has no authoritative NIST entry. It is the
#: distribution that built the package, not an invented upstream vendor.
OPKG_FALLBACK_VENDOR = "openwrt"

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


@dataclass(frozen=True)
class CpeResolution:
    """A resolved identity: vendor, product, complete CPE name and its basis."""

    vendor: str
    product: str
    cpe_string: str
    basis: str


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


def resolve_product(
    product: str,
    version: str,
    *,
    fallback_to_package_name: bool = False,
) -> CpeResolution | None:
    """Resolve one product name to a complete CPE 2.3 name and its basis.

    ``fallback_to_package_name`` is used for installed-package records only:
    every installed record must have a traceable component, so a package with no
    authoritative mapping is named with vendor ``openwrt`` and the package's own
    name. Banner-derived names never take that fallback — a version string in a
    file is not evidence that the distribution built the product.
    """
    mapping = lookup(product)
    if mapping is not None:
        vendor, cpe_product = mapping
        return CpeResolution(
            vendor=vendor,
            product=cpe_product,
            cpe_string=cpe_name(vendor, cpe_product, version),
            basis=BASIS_NIST_MAPPED,
        )
    if not fallback_to_package_name:
        return None
    return CpeResolution(
        vendor=OPKG_FALLBACK_VENDOR,
        product=product,
        cpe_string=cpe_name(OPKG_FALLBACK_VENDOR, product, version),
        basis=BASIS_OPKG_PACKAGE_NAME,
    )


class CPEBuilder:
    """Construct CPE 2.3 names from product names and versions."""

    def build(self, product: str, version: str) -> str | None:
        """Build a CPE 2.3 name for a mapped product, or ``None`` if unmapped."""
        resolved = resolve_product(product, version)
        if resolved is None:
            logger.warning("No CPE mapping for product: %s", product)
            return None
        return resolved.cpe_string

    def build_from_component(self, vendor: str, product: str, version: str) -> str:
        """Build a CPE 2.3 name with explicit vendor and product names."""
        return cpe_name(vendor, product, version)

    def build_from_map(self, product: str, version: str, vendor: str, cpe_product: str) -> str:
        """Build a CPE 2.3 name from an explicit mapping row."""
        return cpe_name(vendor, cpe_product, version)

    def lookup_product(self, product: str) -> tuple[str, str] | None:
        """Look up the CPE vendor/product for a known product name."""
        return lookup(product)
