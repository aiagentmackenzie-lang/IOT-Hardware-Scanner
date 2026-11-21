"""Bounded parsers for flattened device trees and U-Boot FIT images (slice 3D).

An FIT or a DTB is a *boot manifest*, not a Linux root filesystem. This module
reads what such an artifact **declares** and keeps four facts separate, because
conflating them is how a scanner ends up claiming secure boot:

1. **Digest integrity** — does a referenced payload hash to the value the FIT
   declares? (``match`` / ``mismatch`` / ``undeclared`` / ``out-of-bounds``)
2. **Signature presence** — is a signature node there at all?
3. **Signature verification** — does it verify against a key the *operator*
   supplied? ``None`` unless such a key was parsed and used.
4. **Boot enforcement** — always ``"unknown"``. A static parser cannot answer
   whether the board refuses unverified content.

Bounds
------
Every read is a bounded read. The FDT header's ``totalsize`` is validated
against the bytes that actually exist, every structural and string offset is
checked in-bounds, node depth, node count and property count are capped, and a
referenced FIT payload is hashed in fixed windows — never one ``read()`` of a
declared range.

The signature convention
------------------------
The signature node names the nodes it covers in ``hashed-nodes``. Each named
node is serialised deterministically — BEGIN_NODE, its properties in FDT order
with the property name inline, its children, END_NODE — with the signature
node's own ``value`` property excluded, and the SHA-256 of the concatenation is
what the RSA key signs. This is the model U-Boot uses (a signature cannot cover
its own value); the exact byte form is documented here because a verifier and a
signer must agree on it.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from iot_hardware_scanner.models import (
    BootArtifact,
    BootConfiguration,
    BootPayload,
    BootSignature,
)
from iot_hardware_scanner.scanner.bounded_reader import BoundedReader

FDT_MAGIC = 0xD00DFEED
FDT_MAGIC_BYTES = struct.pack(">I", FDT_MAGIC)
FDT_BEGIN_NODE = 0x1
FDT_END_NODE = 0x2
FDT_PROP = 0x3
FDT_NOP = 0x4
FDT_END = 0x9

#: A boot artifact larger than this is not parsed structurally.
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
#: Structural caps. Exceeding one is a malformed artifact, not a partial read.
MAX_NODES = 4096
MAX_PROPERTIES = 16384
MAX_DEPTH = 32
MAX_NAME_BYTES = 256
MAX_PROPERTY_BYTES = 1024 * 1024
MAX_STRING_TABLE_BYTES = 4 * 1024 * 1024
MAX_STRUCTURE_BYTES = 8 * 1024 * 1024
MAX_MEMORY_RESERVATIONS = 128
#: Cap on a trust-anchor file.
MAX_TRUST_ANCHOR_BYTES = 1024 * 1024
#: Hashing a payload streams in windows of this size.
PAYLOAD_WINDOW = 1024 * 1024


class FitDtbError(Exception):
    """Raised when a device tree or FIT is malformed or truncated."""


# ──────────────────────────────────────────────
# A parsed device tree
# ──────────────────────────────────────────────


@dataclass
class FdtProperty:
    """One property, with the byte offset of its value in the structure block."""

    name: str
    value: bytes
    offset: int = 0


@dataclass
class FdtNode:
    """One node of a flattened device tree."""

    name: str
    path: str
    properties: list[FdtProperty] = field(default_factory=list)
    children: list[FdtNode] = field(default_factory=list)

    def prop(self, name: str) -> bytes | None:
        """The raw value of a property, or ``None`` when it is absent."""
        for item in self.properties:
            if item.name == name:
                return item.value
        return None

    def text(self, name: str) -> str | None:
        """A NUL-terminated string property, decoded, or ``None``."""
        raw = self.prop(name)
        if raw is None:
            return None
        return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")

    def strings(self, name: str) -> list[str]:
        """A string-list property (NUL-separated), or an empty list."""
        raw = self.prop(name)
        if raw is None:
            return []
        return [part.decode("utf-8", errors="replace") for part in raw.split(b"\x00") if part]

    def child(self, name: str) -> FdtNode | None:
        return next((c for c in self.children if c.name == name), None)

    def find(self, path: str) -> FdtNode | None:
        """Resolve an absolute node path, or ``None``."""
        if path in ("", "/"):
            return self
        current: FdtNode | None = self
        for part in path.strip("/").split("/"):
            if current is None:
                return None
            current = current.child(part)
        return current

    def walk(self) -> list[FdtNode]:
        """This node and its descendants, depth first."""
        nodes = [self]
        for child in self.children:
            nodes.extend(child.walk())
        return nodes


@dataclass
class ParsedFdt:
    """A validated flattened device tree."""

    offset: int
    totalsize: int
    version: int
    last_comp_version: int
    boot_cpuid_phys: int
    root: FdtNode
    memory_reservations: list[tuple[int, int]] = field(default_factory=list)


def looks_like_fdt(head: bytes) -> bool:
    """Whether the first bytes are an FDT header magic (big-endian)."""
    return len(head) >= 4 and head[:4] == FDT_MAGIC_BYTES


def parse_fdt(
    reader: BoundedReader,
    *,
    offset: int = 0,
    length: int | None = None,
) -> ParsedFdt:
    """Parse one flattened device tree inside ``reader`` without trusting it."""
    available = reader.size - offset
    if length is not None:
        available = min(available, length)
    if available < 40:
        raise FitDtbError(f"only {max(available, 0)} byte(s) available for an FDT header (need 40)")
    head = reader.read_at(offset, 40)
    (
        magic,
        totalsize,
        off_dt_struct,
        off_dt_strings,
        off_mem_rsvmap,
        version,
        last_comp_version,
        boot_cpuid_phys,
        size_dt_strings,
        size_dt_struct,
    ) = struct.unpack(">10I", head)

    if magic != FDT_MAGIC:
        raise FitDtbError(f"bad FDT magic 0x{magic:08x} at offset {offset}")
    if totalsize < 40:
        raise FitDtbError(f"declared totalsize {totalsize} is smaller than the header")
    if totalsize > available:
        raise FitDtbError(f"truncated FDT: declares {totalsize} byte(s), {available} exist")
    if totalsize > MAX_ARTIFACT_BYTES:
        raise FitDtbError(
            f"declared totalsize {totalsize} exceeds the {MAX_ARTIFACT_BYTES}-byte cap"
        )
    if size_dt_struct > MAX_STRUCTURE_BYTES:
        raise FitDtbError(
            f"declared structure size {size_dt_struct} exceeds the {MAX_STRUCTURE_BYTES}-byte cap"
        )
    if size_dt_strings > MAX_STRING_TABLE_BYTES:
        raise FitDtbError(
            f"declared string-table size {size_dt_strings} exceeds the "
            f"{MAX_STRING_TABLE_BYTES}-byte cap"
        )
    if off_dt_struct + size_dt_struct > totalsize:
        raise FitDtbError("structure block lies outside the declared totalsize")
    if off_dt_strings + size_dt_strings > totalsize:
        raise FitDtbError("string table lies outside the declared totalsize")
    if off_mem_rsvmap >= totalsize:
        raise FitDtbError("memory-reservation block starts outside the artifact")

    strings = reader.read_at(offset + off_dt_strings, size_dt_strings)
    structure = reader.read_at(offset + off_dt_struct, size_dt_struct)

    root, consumed = _parse_structure(structure, strings)
    if consumed > size_dt_struct:
        raise FitDtbError("structure parser overran its declared block")

    reservations = _parse_memory_reservations(reader, offset + off_mem_rsvmap, offset + totalsize)
    return ParsedFdt(
        offset=offset,
        totalsize=totalsize,
        version=version,
        last_comp_version=last_comp_version,
        boot_cpuid_phys=boot_cpuid_phys,
        root=root,
        memory_reservations=reservations,
    )


def _align4(value: int) -> int:
    return (value + 3) & ~3


def _parse_structure(structure: bytes, strings: bytes) -> tuple[FdtNode, int]:
    """Parse the structure block into nodes, enforcing depth and count caps."""
    cursor = 0
    stack: list[FdtNode] = []
    nodes = 0
    total_properties = 0
    root: FdtNode | None = None

    def take(count: int) -> bytes:
        nonlocal cursor
        if count < 0 or cursor + count > len(structure):
            raise FitDtbError("structure block ended mid-token")
        value = structure[cursor : cursor + count]
        cursor += count
        return value

    while True:
        if cursor + 4 > len(structure):
            raise FitDtbError("structure block ended before FDT_END")
        (token,) = struct.unpack(">I", take(4))
        if token == FDT_NOP:
            continue
        if token == FDT_END:
            if stack:
                raise FitDtbError("FDT_END before every FDT_END_NODE")
            if root is None:
                raise FitDtbError("structure block contains no nodes")
            return root, cursor
        if token == FDT_BEGIN_NODE:
            nodes += 1
            if nodes > MAX_NODES:
                raise FitDtbError(f"more than {MAX_NODES} nodes")
            if len(stack) + 1 > MAX_DEPTH:
                raise FitDtbError(f"node nesting deeper than {MAX_DEPTH}")
            name, cursor = _read_cstring(structure, cursor, MAX_NAME_BYTES)
            cursor = _align4(cursor)
            if root is None:
                if stack:
                    raise FitDtbError("root node began inside another node")
                path = "/"
                node = FdtNode(name=name or "/", path=path)
            else:
                parent = stack[-1]
                name = name or ""
                path = (parent.path.rstrip("/") + "/" + name) if parent.path != "/" else "/" + name
                node = FdtNode(name=name, path=path)
                parent.children.append(node)
            stack.append(node)
            if root is None:
                root = node
            continue
        if token == FDT_END_NODE:
            if not stack:
                raise FitDtbError("FDT_END_NODE without a matching FDT_BEGIN_NODE")
            stack.pop()
            continue
        if token == FDT_PROP:
            total_properties += 1
            if total_properties > MAX_PROPERTIES:
                raise FitDtbError(f"more than {MAX_PROPERTIES} properties")
            if not stack:
                raise FitDtbError("property outside every node")
            if cursor + 8 > len(structure):
                raise FitDtbError("property header truncated")
            length, name_offset = struct.unpack(">II", take(8))
            if length > MAX_PROPERTY_BYTES:
                raise FitDtbError(
                    f"property of {length} byte(s) exceeds the {MAX_PROPERTY_BYTES}-byte cap"
                )
            if name_offset >= len(strings):
                raise FitDtbError("property name offset outside the string table")
            end = strings.find(b"\x00", name_offset)
            if end < 0:
                raise FitDtbError("property name is not NUL-terminated")
            try:
                name = strings[name_offset:end].decode("utf-8")
            except UnicodeDecodeError as exc:
                raise FitDtbError(f"property name is not UTF-8: {exc}") from exc
            value_offset = cursor
            value = take(length)
            cursor = _align4(cursor)
            stack[-1].properties.append(FdtProperty(name=name, value=value, offset=value_offset))
            continue
        raise FitDtbError(f"unknown structure token 0x{token:08x}")


def _read_cstring(data: bytes, cursor: int, limit: int) -> tuple[str, int]:
    end = data.find(b"\x00", cursor, cursor + limit + 1)
    if end < 0:
        raise FitDtbError(f"node name longer than {limit} bytes or unterminated")
    try:
        name = data[cursor:end].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FitDtbError(f"node name is not UTF-8: {exc}") from exc
    return name, end + 1


def _parse_memory_reservations(
    reader: BoundedReader, start: int, limit: int
) -> list[tuple[int, int]]:
    """Read the reservation map, bounded by count and by the declared end."""
    reservations: list[tuple[int, int]] = []
    cursor = start
    while len(reservations) < MAX_MEMORY_RESERVATIONS:
        if cursor + 16 > limit:
            raise FitDtbError("memory-reservation map ended before its terminator")
        raw = reader.read_at(cursor, 16)
        address, size = struct.unpack(">QQ", raw)
        cursor += 16
        if address == 0 and size == 0:
            return reservations
        reservations.append((address, size))
    raise FitDtbError(f"more than {MAX_MEMORY_RESERVATIONS} memory reservations")


# ──────────────────────────────────────────────
# Board description extraction
# ──────────────────────────────────────────────


def _cells(node: FdtNode) -> tuple[int, int]:
    """Address/size cell counts declared by a node (device-tree defaults)."""
    address = node.prop("#address-cells")
    size = node.prop("#size-cells")
    addr_cells = struct.unpack(">I", address)[0] if address and len(address) == 4 else 2
    size_cells = struct.unpack(">I", size)[0] if size and len(size) == 4 else 1
    return addr_cells, size_cells


def _reg_entries(node: FdtNode, addr_cells: int, size_cells: int) -> list[dict[str, Any]]:
    """Decode a ``reg`` property into ``{base, size}`` entries, bounded."""
    raw = node.prop("reg")
    if not raw:
        return []
    width = 4
    entry_bytes = (addr_cells + size_cells) * width
    if entry_bytes <= 0 or len(raw) % entry_bytes:
        return []
    entries: list[dict[str, Any]] = []
    for index in range(0, len(raw), entry_bytes):
        chunk = raw[index : index + entry_bytes]
        address_bytes = chunk[: addr_cells * width]
        size_bytes = chunk[addr_cells * width :]
        base = int.from_bytes(address_bytes, "big")
        size = int.from_bytes(size_bytes, "big")
        entries.append(
            {
                "base": base,
                "size": size,
                "reg": [base, size],
                "hex": f"0x{base:x}",
                "size_hex": f"0x{size:x}",
            }
        )
    return entries


def _memory_regions(root: FdtNode) -> list[dict[str, Any]]:
    regions: list[dict[str, Any]] = []
    root_cells = _cells(root)
    for node in root.walk():
        is_memory = node.name.startswith("memory")
        if node.text("device_type") == "memory":
            is_memory = True
        if not is_memory:
            continue
        for entry in _reg_entries(node, *root_cells):
            regions.append({"name": node.path, **entry})
    return regions


def _reserved_memory(root: FdtNode) -> list[dict[str, Any]]:
    container = root.find("/reserved-memory")
    if container is None:
        return []
    regions: list[dict[str, Any]] = []
    addr_cells, size_cells = _cells(container)
    for child in container.children:
        for entry in _reg_entries(child, addr_cells, size_cells):
            regions.append({"name": child.path, **entry})
    return regions


def _partitions(root: FdtNode) -> list[dict[str, Any]]:
    partitions: list[dict[str, Any]] = []
    for node in root.walk():
        compatible = " ".join(node.strings("compatible"))
        if node.name != "partitions" and "fixed-partitions" not in compatible:
            continue
        addr_cells, size_cells = _cells(node)
        for child in node.children:
            label = child.text("label")
            entries = _reg_entries(child, addr_cells, size_cells)
            if label is None and not entries:
                continue
            fallback: dict[str, Any] = {
                "base": None,
                "size": None,
                "reg": [],
                "hex": None,
                "size_hex": None,
            }
            for entry in entries or [fallback]:
                partitions.append(
                    {
                        "label": label,
                        "offset": entry["base"],
                        "size": entry["size"],
                        "node": child.path,
                    }
                )
    return partitions


def board_description(parsed: ParsedFdt) -> dict[str, Any]:
    """The board facts a device tree declares, attributed to its own root."""
    root = parsed.root
    return {
        "fdt_version": parsed.version,
        "compatible": root.strings("compatible"),
        "model": root.text("model"),
        "memory": _memory_regions(root),
        "reserved_memory": _reserved_memory(root),
        "partitions": _partitions(root),
    }


# ──────────────────────────────────────────────
# FIT analysis
# ──────────────────────────────────────────────


@dataclass
class TrustAnchor:
    """An operator-supplied RSA public key, recorded by digest and source."""

    n: int
    e: int
    sha256: str
    source: str

    @property
    def bits(self) -> int:
        return self.n.bit_length()


class TrustAnchorError(Exception):
    """Raised when a supplied trust anchor cannot be parsed."""


_PEM = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----\s*(.*?)\s*-----END \1-----", re.DOTALL)


def load_trust_anchor(path: Path, *, source: str | None = None) -> TrustAnchor:
    """Parse a PEM RSA public key from an operator-supplied file (bounded)."""
    size = path.stat().st_size
    if size > MAX_TRUST_ANCHOR_BYTES:
        raise TrustAnchorError(
            f"{path.name} is {size} bytes, over the {MAX_TRUST_ANCHOR_BYTES}-byte budget"
        )
    with path.open("rb") as handle:
        data = handle.read(MAX_TRUST_ANCHOR_BYTES + 1)
    if len(data) > MAX_TRUST_ANCHOR_BYTES:
        raise TrustAnchorError(f"{path.name} exceeds the trust-anchor budget")
    match = _PEM.search(data)
    if match is None:
        raise TrustAnchorError(
            "no PEM block found; supply a 'PUBLIC KEY' or 'RSA PUBLIC KEY' file "
            "(certificates are not accepted as trust anchors)"
        )
    label = match.group(1).decode("ascii", errors="replace")
    if label not in ("PUBLIC KEY", "RSA PUBLIC KEY"):
        raise TrustAnchorError(
            f"unsupported PEM block {label!r}; supply a public key, not a certificate"
        )
    try:
        der = base64.b64decode(re.sub(rb"\s+", b"", match.group(2)), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise TrustAnchorError(f"invalid base64 in {path.name}: {exc}") from exc
    n, e = _rsa_from_der(der, spki=(label == "PUBLIC KEY"))
    digest = hashlib.sha256(data).hexdigest()
    return TrustAnchor(n=n, e=e, sha256=digest, source=source or str(path))


def _tlv(data: bytes, pos: int) -> tuple[int, bytes, int]:
    if pos + 2 > len(data):
        raise TrustAnchorError("truncated DER element")
    tag = data[pos]
    length_byte = data[pos + 1]
    pos += 2
    if length_byte & 0x80:
        count = length_byte & 0x7F
        if count == 0 or count > 4 or pos + count > len(data):
            raise TrustAnchorError("invalid DER length")
        length = int.from_bytes(data[pos : pos + count], "big")
        pos += count
    else:
        length = length_byte
    if pos + length > len(data):
        raise TrustAnchorError("DER element runs past the input")
    return tag, data[pos : pos + length], pos + length


def _rsa_from_der(der: bytes, *, spki: bool) -> tuple[int, int]:
    tag, body, _ = _tlv(der, 0)
    if tag != 0x30:
        raise TrustAnchorError("expected a DER SEQUENCE")
    if spki:
        tag, _algorithm, pos = _tlv(body, 0)
        if tag != 0x30:
            raise TrustAnchorError("expected an AlgorithmIdentifier")
        tag, bit_string, _ = _tlv(body, pos)
        if tag != 0x03 or not bit_string:
            raise TrustAnchorError("expected a BIT STRING public key")
        if bit_string[0] != 0:
            raise TrustAnchorError("public key BIT STRING has unused bits")
        der = bit_string[1:]
        tag, body, _ = _tlv(der, 0)
        if tag != 0x30:
            raise TrustAnchorError("expected an RSAPublicKey SEQUENCE")
    tag, n_bytes, pos = _tlv(body, 0)
    if tag != 0x02:
        raise TrustAnchorError("expected an INTEGER modulus")
    tag, e_bytes, _ = _tlv(body, pos)
    if tag != 0x02:
        raise TrustAnchorError("expected an INTEGER exponent")
    n = int.from_bytes(n_bytes, "big")
    e = int.from_bytes(e_bytes, "big")
    if n <= 0 or e <= 0:
        raise TrustAnchorError("RSA key has a non-positive component")
    return n, e


_DIGEST_INFO = {
    "sha1": bytes.fromhex("3021300906052b0e03021a05000414"),
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}


def _rsa_pkcs1_verify(anchor: TrustAnchor, signature: bytes, digest: bytes, algo: str) -> bool:
    """PKCS#1 v1.5 verification with a pure-Python modular exponentiation."""
    prefix = _DIGEST_INFO.get(algo)
    if prefix is None:
        return False
    modulus_bytes = (anchor.n.bit_length() + 7) // 8
    if len(signature) != modulus_bytes:
        return False
    expected_info = prefix + digest
    padding = modulus_bytes - len(expected_info) - 3
    if padding < 8:
        return False
    expected = b"\x00\x01" + b"\xff" * padding + b"\x00" + expected_info
    value = pow(int.from_bytes(signature, "big"), anchor.e, anchor.n)
    return value.to_bytes(modulus_bytes, "big") == expected


def _canonical_node(node: FdtNode, *, skip_signature_values: bool = True) -> bytes:
    """A deterministic serialisation of a node subtree for signature coverage."""
    out = bytearray()
    out += struct.pack(">I", FDT_BEGIN_NODE) + node.name.encode("utf-8") + b"\x00"
    out += b"\x00" * ((4 - len(out) % 4) % 4)
    for prop in node.properties:
        if skip_signature_values and prop.name == "value" and _is_signature_node(node):
            continue
        out += struct.pack(">III", FDT_PROP, len(prop.value), 0)
        out += prop.name.encode("utf-8") + b"\x00"
        out += b"\x00" * ((4 - len(out) % 4) % 4)
        out += prop.value
        out += b"\x00" * ((4 - len(out) % 4) % 4)
    for child in node.children:
        out += _canonical_node(child)
    out += struct.pack(">I", FDT_END_NODE)
    return bytes(out)


def _is_signature_node(node: FdtNode) -> bool:
    return node.name.startswith("signature")


def _signature_from_node(
    node: FdtNode,
    *,
    root: FdtNode,
    anchors: list[TrustAnchor],
    default_path: str,
) -> BootSignature:
    """Read one signature node; verify only against operator-supplied keys."""
    algo = node.text("algo")
    value = node.prop("value") or b""
    hashed_nodes = node.strings("hashed-nodes") or [default_path]
    signature = BootSignature(
        present=True,
        algo=algo,
        signed_nodes=hashed_nodes,
    )
    if not value:
        signature.reason = "signature node has no value"
        return signature
    if not algo:
        signature.reason = "signature node declares no algorithm"
        return signature
    if not anchors:
        signature.reason = (
            "no operator-supplied trust anchor; presence is recorded, authenticity is unverified"
        )
        return signature

    parts = [item.strip().lower() for item in algo.split(",")]
    digest_name = parts[0] if parts else ""
    if digest_name not in _DIGEST_INFO or not (len(parts) > 1 and parts[1].startswith("rsa")):
        signature.reason = f"unsupported signature algorithm {algo!r}"
        return signature
    covered = bytearray()
    for path in hashed_nodes:
        target = root.find(path)
        if target is None:
            signature.reason = f"hashed node {path!r} is not present in the artifact"
            return signature
        covered += _canonical_node(target)
    digest = hashlib.new(digest_name, bytes(covered)).digest()

    for anchor in anchors:
        if _rsa_pkcs1_verify(anchor, value, digest, digest_name):
            signature.verified = True
            signature.key_source = "operator-supplied"
            signature.key_sha256 = anchor.sha256
            signature.reason = (
                f"verified over {', '.join(hashed_nodes)} with the supplied "
                f"{anchor.bits}-bit RSA key"
            )
            return signature
    signature.verified = False
    signature.key_source = "operator-supplied"
    signature.key_sha256 = anchors[0].sha256
    signature.reason = "no supplied key verifies this signature"
    return signature


def _declared_digest(node: FdtNode) -> tuple[str | None, str | None]:
    """The first supported hash child: ``(algo, hex value)``."""
    for child in node.children:
        if not child.name.startswith("hash"):
            continue
        algo = child.text("algo")
        value = child.prop("value")
        if algo and value:
            return algo.lower(), value.hex()
    return None, None


def _payload_range(node: FdtNode, artifact_size: int) -> tuple[int | None, int | None, str | None]:
    """Resolve a payload's absolute range inside the artifact, validated."""
    size_raw = node.prop("data-size")
    position_raw = node.prop("data-position")
    offset_raw = node.prop("data-offset")
    if size_raw is None or (position_raw is None and offset_raw is None):
        return None, None, "payload declares no data-size/data-position"
    if len(size_raw) != 4:
        return None, None, "data-size is not a 32-bit value"
    size = struct.unpack(">I", size_raw)[0]
    if position_raw is not None:
        if len(position_raw) != 4:
            return None, None, "data-position is not a 32-bit value"
        offset = struct.unpack(">I", position_raw)[0]
    else:
        if offset_raw is None or len(offset_raw) != 4:
            return None, None, "data-offset is not a 32-bit value"
        # U-Boot records data-offset from the end of the FIT.
        offset = artifact_size - struct.unpack(">I", offset_raw)[0]
    if offset < 0 or size <= 0 or offset + size > artifact_size:
        return offset, size, "payload range lies outside the artifact"
    return offset, size, None


def _hash_range(reader: BoundedReader, offset: int, length: int, algo: str) -> str | None:
    try:
        digest = hashlib.new(algo)
    except ValueError:
        return None
    consumed = 0
    for window in reader.iter_windows(PAYLOAD_WINDOW, budget=length, start=offset):
        digest.update(window.data)
        consumed += window.length
    if consumed != length:
        return None
    return digest.hexdigest()


def analyse_boot(
    reader: BoundedReader,
    *,
    locator: str,
    digest: str,
    artifact_id: str,
    anchors: list[TrustAnchor] | None = None,
) -> tuple[BootArtifact, list[str]]:
    """Parse one boot artifact into report facts, with omissions named."""
    anchors = anchors or []
    parsed = parse_fdt(reader)
    root = parsed.root
    omissions: list[str] = []
    board = board_description(parsed)
    images = root.child("images")
    is_fit = images is not None

    artifact = BootArtifact(
        locator=locator,
        artifact_id=artifact_id,
        kind="fit" if is_fit else "dtb",
        size=reader.size,
        digest=digest,
        fdt_version=parsed.version,
        compatible=board["compatible"],
        model=board["model"],
        memory=board["memory"],
        reserved_memory=board["reserved_memory"],
        partitions=board["partitions"],
    )

    if parsed.memory_reservations:
        for address, size in parsed.memory_reservations:
            artifact.reserved_memory.append(
                {
                    "name": "<memory-reservation-map>",
                    "base": address,
                    "size": size,
                    "reg": [address, size],
                    "hex": f"0x{address:x}",
                    "size_hex": f"0x{size:x}",
                }
            )

    if not is_fit:
        artifact.notes.append(
            "No /images node: this is a device tree, not an FIT. Board facts come "
            "from the artifact's own root."
        )
        artifact.notes.append(
            "A device tree declares compatible boards and memory; it does not declare "
            "a kernel payload or a signature."
        )
        return artifact, omissions

    configurations = root.child("configurations")
    if configurations is None:
        artifact.notes.append(
            "No /configurations node: this FIT declares no configuration, so no "
            "selected configuration is recorded. The default is unknown, not guessed."
        )
        artifact.default_config = None
    else:
        default = configurations.text("default")
        artifact.default_config = default
        if default and configurations.child(default) is None:
            omissions.append(f"declared default configuration {default!r} is absent")

        for node in configurations.children:
            config = BootConfiguration(
                name=node.name,
                default=(node.name == default),
                kernel=node.text("kernel"),
                fdt=node.text("fdt"),
                ramdisk=node.text("ramdisk"),
                loadables=node.strings("loadables"),
            )
            signature_node = next((c for c in node.children if _is_signature_node(c)), None)
            if signature_node is not None:
                config.signature = _signature_from_node(
                    signature_node,
                    root=root,
                    anchors=anchors,
                    default_path=node.path,
                )
            artifact.configurations.append(config)

    # Referenced payloads are the union of every configuration's references, so
    # a payload is never dropped because it belongs to a non-default config.
    referenced: dict[str, str] = {}
    for config in artifact.configurations:
        for name, kind in (
            (config.kernel, "kernel"),
            (config.fdt, "fdt"),
            (config.ramdisk, "ramdisk"),
        ):
            if name:
                referenced.setdefault(name, kind)
        for name in config.loadables:
            referenced.setdefault(name, "loadable")

    board_cache: dict[str, dict[str, Any] | None] = {}
    for name, kind in referenced.items():
        payload_node = images.child(name) if images is not None else None
        if payload_node is None:
            omissions.append(f"configuration references payload {name!r}, which is absent")
            continue
        algo, declared = _declared_digest(payload_node)
        offset, length, problem = _payload_range(payload_node, reader.size)
        payload = BootPayload(
            node=payload_node.path,
            kind=kind,
            offset=offset,
            length=length,
            digest_declared=declared,
            integrity="undeclared",
        )
        if problem:
            payload.integrity = "out-of-bounds"
            omissions.append(f"{payload_node.path}: {problem}")
        if declared is None:
            payload.integrity = "undeclared"
        elif offset is not None and length is not None and problem is None:
            observed = _hash_range(reader, offset, length, algo or "sha256")
            payload.digest_observed = observed
            if observed is None:
                payload.integrity = "out-of-bounds"
                omissions.append(f"{payload_node.path}: payload could not be read completely")
            elif observed.lower() == declared.lower():
                payload.integrity = "match"
            else:
                payload.integrity = "mismatch"
                # A mismatch is an observation with evidence, not incomplete
                # analysis: the bytes were read completely. It is reported as a
                # review finding and does not make the stage partial.
                artifact.notes.append(
                    f"{payload_node.path}: declared {algo} {declared[:16]}… but observed "
                    f"{observed[:16]}…"
                )

        signature_node = next((c for c in payload_node.children if _is_signature_node(c)), None)
        if signature_node is not None:
            payload.signature = _signature_from_node(
                signature_node, root=root, anchors=anchors, default_path=payload_node.path
            )

        # A referenced FDT is a board description in its own right.
        if (
            kind == "fdt"
            and offset is not None
            and length is not None
            and problem is None
            and length <= MAX_ARTIFACT_BYTES
        ):
            key = f"{offset}:{length}"
            if key not in board_cache:
                try:
                    inner = parse_fdt(reader, offset=offset, length=length)
                    board_cache[key] = board_description(inner)
                except FitDtbError as exc:
                    board_cache[key] = None
                    omissions.append(f"{payload_node.path}: referenced FDT not parsed: {exc}")
            payload.board = board_cache[key]
        artifact.referenced_payloads.append(payload)

    if not artifact.configurations:
        artifact.notes.append(
            "No configuration could be selected, so no kernel/device-tree pairing was "
            "asserted. Physical boot enforcement remains unknown."
        )
    return artifact, omissions


def selected_configuration(artifact: BootArtifact) -> BootConfiguration | None:
    """The configuration the artifact names as default, if it names one."""
    if artifact.default_config is None:
        return None
    for config in artifact.configurations:
        if config.name == artifact.default_config:
            return config
    return None
