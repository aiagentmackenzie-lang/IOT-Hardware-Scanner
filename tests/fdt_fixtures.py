"""Byte-by-byte device-tree and FIT fixtures for slice 3D.

No cross-toolchain and no network: every structure here is written by hand, the
same way ``tests/elf_fixtures.py`` writes ELF files. The single RSA key is a
**test key**, generated once and embedded; it protects nothing.

The signing convention is the one the parser documents: the signature node's
``hashed-nodes`` names the covered node(s); each is serialised deterministically
with the signature node's ``value`` property excluded, and the SHA-256 of that
concatenation is RSA/PKCS#1-v1.5 signed.
"""

from __future__ import annotations

import base64
import hashlib
import struct
from dataclasses import dataclass, field

FDT_MAGIC = 0xD00DFEED
ALIGN = 4

#: Deterministic 2048-bit test key (n, d). The public exponent is 65537.
TEST_N = int(
    "bddbf5697da48cbb55d0e34fe7e45731a3f298ccc564813099cd05f09ae2fffd"
    "5445b3092108b82ce9122a0e61f3093611a0ecfdf0c8934ebc37616e004d97"
    "dae915ae89d8a2e1f80957803cf0dd954b6d87350a24bcc12d27aedf0e5c25"
    "57a4b8368c41a341b19d009f8d2631a89dd993819c950f86b84c1dab6641ad"
    "a00cce4193c98b2ae99b1d1d376fb55028331a7371773f7554054ef409dc6f"
    "82be1b23211a7bad9aa13fc42f625a26ac303931227e6fa259e2422d3bbdb5"
    "de2829d2c2ff2f647e5757faeb551554b461570eaa5d869cb65028862b839a"
    "61c9606851f511515892716826c11c1ce348d570fd6722643b949fd5116a2e"
    "a3ae73dddf2b75",
    16,
)
TEST_D = int(
    "240f647fca48d81ff6af2b95702e5aef473bdb10bd8716d083cdc08c8fe680"
    "877d9b95632cfe8a78a135fd7de8d5afd0b0ad7785cdd752bf38196eac656b"
    "5765d13278899ef764e2e6e753287ff91e138af48cbae5fa61d8713a920c18"
    "ad5105aca553a35dde2add6e925f4d3b4e52d8d1dee2be1f0a4ff3c908d66d"
    "b00bff92535098d337f42fab0d47c81f76a57549dc4ed3d134675195119a44"
    "4928f56f050a2a42ca1373aa6817af9077ac5f844c9a39b635ba7e827c3b05"
    "d9cff340a9d126c7f0cac25ff6512f9b504617eff60fcf6b25d745f318dea4"
    "32097659410313e3d1e1729fb375b1fddf22a2a771028b723ea75d6d096b22"
    "3696e2aaf252087b",
    16,
)
TEST_E = 65537

_DIGEST_INFO_SHA256 = bytes.fromhex("3031300d060960864801650304020105000420")


@dataclass
class Node:
    """One node in a device-tree fixture."""

    name: str
    props: list[tuple[str, bytes]] = field(default_factory=list)
    children: list[Node] = field(default_factory=list)

    def add(self, name: str, value: bytes) -> Node:
        self.props.append((name, value))
        return self

    def add_str(self, name: str, value: str) -> Node:
        return self.add(name, value.encode() + b"\x00")

    def add_u32(self, name: str, value: int) -> Node:
        return self.add(name, struct.pack(">I", value))

    def add_strings(self, name: str, values: list[str]) -> Node:
        return self.add(name, b"".join(v.encode() + b"\x00" for v in values))

    def child(self, node: Node) -> Node:
        self.children.append(node)
        return self

    def set(self, name: str, value: bytes) -> Node:
        for index, (existing, _old) in enumerate(self.props):
            if existing == name:
                self.props[index] = (name, value)
                return self
        return self.add(name, value)


def _pad(out: bytearray) -> None:
    out += b"\x00" * ((ALIGN - len(out) % ALIGN) % ALIGN)


def _collect_names(node: Node, names: list[str]) -> None:
    for name, _value in node.props:
        if name not in names:
            names.append(name)
    for child in node.children:
        _collect_names(child, names)


def _emit_structure(node: Node, offsets: dict[str, int]) -> bytes:
    out = bytearray(struct.pack(">I", 0x1))
    out += node.name.encode() + b"\x00"
    _pad(out)
    for name, value in node.props:
        out += struct.pack(">III", 0x3, len(value), offsets[name])
        out += value
        _pad(out)
    for child in node.children:
        out += _emit_structure(child, offsets)
    out += struct.pack(">I", 0x2)
    return bytes(out)


def canonical_node(node: Node) -> bytes:
    """The signature-covered bytes, with a signature's own value excluded."""
    out = bytearray(struct.pack(">I", 0x1))
    out += node.name.encode() + b"\x00"
    _pad(out)
    for name, value in node.props:
        if name == "value" and node.name.startswith("signature"):
            continue
        out += struct.pack(">III", 0x3, len(value), 0)
        out += name.encode() + b"\x00"
        _pad(out)
        out += value
        _pad(out)
    for child in node.children:
        out += canonical_node(child)
    out += struct.pack(">I", 0x2)
    return bytes(out)


def build_fdt(
    root: Node,
    *,
    reservations: list[tuple[int, int]] | None = None,
    tail: bytes = b"",
) -> bytes:
    """Serialise a complete FDT (optionally with appended data)."""
    names: list[str] = []
    _collect_names(root, names)
    offsets = {}
    strings = bytearray()
    for name in names:
        offsets[name] = len(strings)
        strings += name.encode() + b"\x00"
    structure = _emit_structure(root, offsets) + struct.pack(">I", 0x9)

    reservation_bytes = b"".join(
        struct.pack(">QQ", address, size) for address, size in (reservations or [])
    ) + struct.pack(">QQ", 0, 0)
    off_rsvmap = 40
    off_struct = off_rsvmap + len(reservation_bytes)
    while off_struct % ALIGN:
        reservation_bytes += b"\x00"
        off_struct += 1
    off_strings = off_struct + len(structure)
    totalsize = off_strings + len(strings) + len(tail)
    header = struct.pack(
        ">10I",
        FDT_MAGIC,
        totalsize,
        off_struct,
        off_strings,
        off_rsvmap,
        17,
        16,
        0,
        len(strings),
        len(structure),
    )
    return header + reservation_bytes + structure + bytes(strings) + tail


def board_dtb(
    *,
    compatible: tuple[str, ...] = ("test,board", "test,soc"),
    model: str = "IHS Test Board",
    partition_label: str = "firmware",
) -> bytes:
    """A device tree that declares a board, memory and one fixed partition."""
    root = Node("")
    root.add_strings("compatible", list(compatible))
    root.add_str("model", model)
    root.add_u32("#address-cells", 2)
    root.add_u32("#size-cells", 1)

    memory = Node("memory@40000000")
    memory.add_str("device_type", "memory")
    memory.add("reg", struct.pack(">III", 0, 0x40000000, 0x10000000))
    root.child(memory)

    reserved = Node("reserved-memory")
    reserved.add_u32("#address-cells", 2)
    reserved.add_u32("#size-cells", 1)
    carveout = Node("framebuffer@48000000")
    carveout.add("reg", struct.pack(">III", 0, 0x48000000, 0x00800000))
    reserved.child(carveout)
    root.child(reserved)

    flash = Node("flash@0")
    flash.add_str("compatible", "jedec,spi-nor")
    flash.add_u32("#address-cells", 1)
    flash.add_u32("#size-cells", 1)
    partitions = Node("partitions")
    partitions.add_str("compatible", "fixed-partitions")
    partitions.add_u32("#address-cells", 1)
    partitions.add_u32("#size-cells", 1)
    part = Node("partition@0")
    part.add_str("label", partition_label)
    part.add("reg", struct.pack(">II", 0, 0x00400000))
    partitions.child(part)
    flash.child(partitions)
    root.child(flash)
    return build_fdt(root)


def _rsa_sign(payload: bytes) -> bytes:
    digest = hashlib.sha256(payload).digest()
    info = _DIGEST_INFO_SHA256 + digest
    modulus_bytes = (TEST_N.bit_length() + 7) // 8
    padding = modulus_bytes - len(info) - 3
    encoded = b"\x00\x01" + b"\xff" * padding + b"\x00" + info
    value = pow(int.from_bytes(encoded, "big"), TEST_D, TEST_N)
    return value.to_bytes(modulus_bytes, "big")


def _der_integer(value: int) -> bytes:
    raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return b"\x02" + _der_length(len(raw)) + raw


def _der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _der_sequence(*parts: bytes) -> bytes:
    body = b"".join(parts)
    return b"\x30" + _der_length(len(body)) + body


def public_key_pem(n: int = TEST_N, e: int = TEST_E) -> bytes:
    """A PEM SPKI public key for the test key (operator trust anchor)."""
    rsa_key = _der_sequence(_der_integer(n), _der_integer(e))
    algorithm = _der_sequence(b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01", b"\x05\x00")
    spki = _der_sequence(algorithm, b"\x03" + _der_length(len(rsa_key) + 1) + b"\x00" + rsa_key)
    body = base64.encodebytes(spki).replace(b"\n", b"")
    return (
        b"-----BEGIN PUBLIC KEY-----\n"
        + b"\n".join(body[i : i + 64] for i in range(0, len(body), 64))
        + b"\n-----END PUBLIC KEY-----\n"
    )


@dataclass
class FitFixture:
    """A complete FIT plus the facts the test expects."""

    data: bytes
    kernel: bytes
    dtb: bytes
    config_name: str
    default_config: str | None
    signed_config: str | None
    payload_integrity: str


def _hash_node(algo: str, value: bytes) -> Node:
    node = Node("hash@1")
    node.add_str("algo", algo)
    node.add("value", hashlib.new(algo, value).digest())
    return node


def _image_node(
    name: str,
    data: bytes,
    *,
    position: int,
    hash_algo: str = "sha256",
    declare_hash: bool = True,
    data_offset: int | None = None,
) -> Node:
    node = Node(name)
    node.add_str("description", name)
    node.add_str("type", "kernel" if "kernel" in name else "flat_dt")
    if data_offset is None:
        node.add_u32("data-position", position)
    else:
        node.add_u32("data-offset", data_offset)
    node.add_u32("data-size", len(data))
    if declare_hash:
        node.child(_hash_node(hash_algo, data))
    return node


def build_fit(
    *,
    declare_wrong_hash: bool = False,
    out_of_bounds: bool = False,
    sign_config: str | None = None,
    default_config: str | None = "config-1",
    extra_configurations: list[str] | None = None,
    truncated: int | None = None,
    declare_hashes: bool = True,
    use_data_offset: bool = False,
    reference_payloads: bool = True,
) -> FitFixture:
    """Build kernel + FDT payloads and an FIT that selects them."""
    kernel = b"KERNEL-PAYLOAD-" + hashlib.sha256(b"kernel").hexdigest().encode()
    dtb = board_dtb()

    config_names = ["config-1", *(extra_configurations or [])]
    configurations = Node("configurations")
    if default_config is not None:
        configurations.add_str("default", default_config)

    config_nodes: dict[str, Node] = {}
    for name in config_names:
        config = Node(name)
        config.add_str("description", f"configuration {name}")
        if reference_payloads:
            config.add_str("kernel", "kernel-1")
            config.add_str("fdt", "fdt-1")
        config_nodes[name] = config
        configurations.child(config)

    def assemble(
        tail: bytes,
        positions: dict[str, int],
        *,
        total: int = 0,
        data_offset: bool = False,
    ) -> bytes:
        images_node = Node("images")
        kernel_node = _image_node(
            "kernel-1",
            kernel,
            position=positions["kernel"],
            declare_hash=declare_hashes,
            data_offset=(total - positions["kernel"]) if data_offset else None,
        )
        if not reference_payloads:
            kernel_node = Node("kernel-1")
            kernel_node.add_str("description", "kernel-1")
        fdt_node = _image_node(
            "fdt-1",
            dtb,
            position=positions["fdt"],
            declare_hash=declare_hashes,
            data_offset=(total - positions["fdt"]) if data_offset else None,
        )
        # A deliberately wrong declared digest keeps the same length.
        if declare_wrong_hash:
            for child in fdt_node.children:
                if child.name.startswith("hash"):
                    child.set("value", b"\x00" * 32)
        if reference_payloads:
            images_node.children = []
            images_node.child(kernel_node)
            images_node.child(fdt_node)
        root = Node("")
        root.add_str("description", "IHS test FIT")
        root.add("timestamp", struct.pack(">I", 1700000000))
        root.child(images_node)
        root.child(configurations)
        return build_fdt(root, tail=tail)

    # A signature node exists once. Its value is excluded from the covered
    # bytes, then set before the layout is measured, so the measured size is
    # the real one.
    signed_values: dict[str, bytes] = {}
    if sign_config is not None:
        config = config_nodes[sign_config]
        signature_node = Node("signature@1")
        signature_node.add_str("algo", "sha256,rsa2048")
        signature_node.add_str("key-name-hint", "test-key")
        signature_node.add_strings("hashed-nodes", [f"/configurations/{sign_config}"])
        signature_node.add("value", b"")
        config.child(signature_node)
        signed_values[sign_config] = _rsa_sign(canonical_node(config))
        signature_node.set("value", signed_values[sign_config])

    # Pass 1: measure the structure with placeholder positions.
    base = len(assemble(b"", {"kernel": 0, "fdt": 0}))
    positions = {"kernel": base, "fdt": base + len(kernel)}

    if out_of_bounds:
        positions["fdt"] = base + len(kernel) + len(dtb) + 4096

    data = assemble(
        kernel + dtb,
        positions,
        total=base + len(kernel) + len(dtb),
        data_offset=use_data_offset,
    )
    if truncated is not None:
        data = data[:truncated]
    return FitFixture(
        data=data,
        kernel=kernel,
        dtb=dtb,
        config_name="config-1",
        default_config=default_config,
        signed_config=sign_config,
        payload_integrity="mismatch" if declare_wrong_hash else "match",
    )
