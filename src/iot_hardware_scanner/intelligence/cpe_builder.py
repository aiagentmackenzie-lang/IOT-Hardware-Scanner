"""CPE String Builder.

SDR §11.1 — CPE Constructor

Constructs NVD-compatible CPE 2.3 strings from detected
software components.
"""

from __future__ import annotations

import logging

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


class CPEBuilder:
    """Construct CPE 2.3 strings from product names and versions."""

    def build(self, product: str, version: str) -> str | None:
        """Build a CPE 2.3 string.

        Format: cpe:2.3:a:<vendor>:<product>:<version>
        """
        if product not in PRODUCT_CPE_MAP:
            logger.warning("No CPE mapping for product: %s", product)
            return None

        vendor, prod = PRODUCT_CPE_MAP[product]
        return f"cpe:2.3:a:{vendor}:{prod}:{version}"

    def build_from_map(self, product: str, version: str, vendor: str, cpe_product: str) -> str:
        """Build CPE string with explicit vendor and product names."""
        return f"cpe:2.3:a:{vendor}:{cpe_product}:{version}"
