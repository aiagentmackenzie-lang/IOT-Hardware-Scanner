"""Deterministic ELF fixtures, built byte by byte.

The suite must be able to assert ELF facts on machines that have no compiler and
no cross-toolchain, so the fixtures are assembled here rather than taken from
the host. Two shapes are needed for the release gate:

``pie_dynamic``
    A 64-bit little-endian AArch64 PIE executable: PT_INTERP, two DT_NEEDED
    entries, PT_GNU_RELRO with BIND_NOW, a non-executable stack, a build ID and
    a ``.dynsym`` naming ``__stack_chk_fail`` and ``__printf_chk``.

``exec_static``
    A 32-bit big-endian MIPS non-PIE executable with no interpreter, no dynamic
    section and no symbol table — the shape OpenWrt's BusyBox actually has, and
    the one that must not be credited with hardening evidence it cannot show.

Both are structurally valid: program headers point inside the file, the section
header table is consistent, and pyelftools and readelf agree on them.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ElfSpec:
    """What to build."""

    elf_class: int = 64  # 64 or 32
    little_endian: bool = True
    machine: int = 183  # AArch64
    elf_type: int = 3  # ET_DYN (PIE)
    interpreter: str | None = "/lib/ld-musl-aarch64.so.1"
    soname: str | None = None
    needed: list[str] = field(default_factory=lambda: ["libc.so", "libgcc_s.so.1"])
    bind_now: bool = True
    stack_executable: bool = False
    symbols: list[str] = field(default_factory=lambda: ["__stack_chk_fail", "__printf_chk"])
    build_id: bytes | None = b"\xde\xad\xbe\xef\x01\x02\x03\x04"
    dynamic: bool = True
    gnu_relro: bool = True


def build_elf(spec: ElfSpec) -> bytes:
    """Assemble a structurally valid ELF file for ``spec``."""
    endian = "<" if spec.little_endian else ">"
    is64 = spec.elf_class == 64
    ehsize = 64 if is64 else 52
    phentsize = 56 if is64 else 32

    dynamic_items: list[tuple[int, int]] = []
    dynstr = b"\x00"
    name_offsets: dict[str, int] = {}
    for name in spec.needed:
        name_offsets[name] = len(dynstr)
        dynstr += name.encode() + b"\x00"
    symtab = b""
    if spec.symbols:
        # One null symbol, then one per name, all in the dynamic string table.
        symtab = b"\x00" * (24 if is64 else 16)
        for name in spec.symbols:
            name_offsets[name] = len(dynstr)
            dynstr += name.encode() + b"\x00"
            if is64:
                symtab += struct.pack(endian + "IBBHQQ", name_offsets[name], 0x12, 0, 1, 0, 0)
            else:
                symtab += struct.pack(endian + "IIIBBH", name_offsets[name], 0, 0, 0x12, 0, 1)

    if spec.soname:
        name_offsets[spec.soname] = len(dynstr)
        dynstr += spec.soname.encode() + b"\x00"

    interp = (spec.interpreter.encode() + b"\x00") if spec.interpreter else b""
    note = b""
    if spec.build_id is not None:
        name = b"GNU\x00"
        desc = spec.build_id
        note = struct.pack(endian + "III", len(name), len(desc), 3) + name
        note += b"\x00" * (-len(note) % 4) + desc
        note += b"\x00" * (-len(desc) % 4)

    # Layout: header | phdrs | interp | note | dynstr | dynsym | dynamic | shdrs
    # PT_PHDR, [PT_INTERP], PT_LOAD, [PT_DYNAMIC], [PT_NOTE], PT_GNU_STACK, [PT_GNU_RELRO]
    phnum = (
        3
        + (1 if spec.interpreter else 0)
        + (1 if spec.build_id is not None else 0)
        + (1 if spec.dynamic else 0)
        + (1 if spec.gnu_relro else 0)
    )
    offset = ehsize + phentsize * phnum

    interp_off = offset if interp else 0
    offset += len(interp)
    note_off = offset if note else 0
    offset += len(note)
    dynstr_off = offset
    offset += len(dynstr)
    dynsym_off = offset
    offset += len(symtab)

    for name in spec.needed:
        dynamic_items.append((1, name_offsets[name]))  # DT_NEEDED
    if spec.symbols:
        dynamic_items.append((6, dynsym_off))  # DT_SYMTAB
        dynamic_items.append((5, dynstr_off))  # DT_STRTAB
    if spec.soname:
        dynamic_items.append((14, name_offsets[spec.soname]))  # DT_SONAME
    flags = 0x8 if spec.bind_now else 0  # DF_BIND_NOW
    dynamic_items.append((30, flags))  # DT_FLAGS
    flags_1 = 0x1 if spec.bind_now else 0
    if spec.elf_type == 3 and spec.interpreter:
        flags_1 |= 0x08000000  # DF_1_PIE: only an executable carries this
    if flags_1:
        dynamic_items.append((0x6FFFFFFB, flags_1))  # DT_FLAGS_1
    dynamic_items.append((0, 0))

    dyn_ent = 16 if is64 else 8
    dynamic_off = offset
    dynamic = b"".join(
        struct.pack(endian + ("qQ" if is64 else "iI"), tag, value) for tag, value in dynamic_items
    )
    offset += len(dynamic)

    shstrtab = b"\x00"
    sh_name_offsets: dict[str, int] = {}
    for name in (".interp", ".note.gnu.build-id", ".dynstr", ".dynsym", ".dynamic", ".shstrtab"):
        sh_name_offsets[name] = len(shstrtab)
        shstrtab += name.encode() + b"\x00"
    shstrtab_off = offset
    offset += len(shstrtab)
    shoff = offset
    # null, .dynstr, .dynamic, .shstrtab, plus the optional ones below
    shnum = 4 + (1 if interp else 0) + (1 if note else 0) + (1 if symtab else 0)
    shentsize = 64 if is64 else 40
    offset += shentsize * shnum

    # ── program headers ──
    phdrs = b""

    def phdr(ptype: int, flags: int, off: int, size: int, vaddr: int = 0x1000) -> bytes:
        if is64:
            return struct.pack(
                endian + "IIQQQQQQ", ptype, flags, off, vaddr + off, vaddr + off, size, size, 0x1000
            )
        return struct.pack(
            endian + "IIIIIIII", ptype, off, vaddr + off, vaddr + off, size, size, flags, 0x1000
        )

    phdrs += phdr(6, 0x5, 0, offset)  # PT_PHDR
    if spec.interpreter:
        phdrs += phdr(3, 0x4, interp_off, len(interp))  # PT_INTERP
    phdrs += phdr(1, 0x5, 0, offset)  # PT_LOAD
    if spec.dynamic:
        phdrs += phdr(2, 0x6, dynamic_off, len(dynamic))  # PT_DYNAMIC
    if note:
        phdrs += phdr(4, 0x4, note_off, len(note))  # PT_NOTE
    phdrs += phdr(0x6474E551, 0x7 if spec.stack_executable else 0x6, 0, 0)  # GNU_STACK
    if spec.gnu_relro:
        phdrs += phdr(0x6474E552, 0x4, 0, 0)  # GNU_RELRO

    # ── section headers ──
    def shdr(
        name_off: int,
        sh_type: int,
        flags: int,
        off: int,
        size: int,
        align: int = 1,
        link: int = 0,
        entsize: int = 0,
    ) -> bytes:
        if is64:
            return struct.pack(
                endian + "IIQQQQIIQQ",
                name_off,
                sh_type,
                flags,
                0,
                off,
                size,
                link,
                0,  # sh_info
                align,
                entsize,
            )
        return struct.pack(
            endian + "IIIIIIIIII",
            name_off,
            sh_type,
            flags,
            0,
            off,
            size,
            link,
            0,  # sh_info
            align,
            entsize,
        )

    # Assemble the section list first so sh_link can name a real index.
    sym_entsize = 24 if is64 else 16
    sections: list[tuple[str, int, int, int, int, int, int, int]] = [("", 0, 0, 0, 0, 0, 0, 0)]
    if interp:
        sections.append((".interp", 1, 0x2, interp_off, len(interp), 1, 0, 0))
    if note:
        sections.append((".note.gnu.build-id", 7, 0x2, note_off, len(note), 4, 0, 0))
    dynstr_index = len(sections)
    sections.append((".dynstr", 3, 0x2, dynstr_off, len(dynstr), 1, 0, 0))
    if symtab:
        sections.append((".dynsym", 11, 0x2, dynsym_off, len(symtab), 8, dynstr_index, sym_entsize))
    sections.append((".dynamic", 6, 0x3, dynamic_off, len(dynamic), 8, dynstr_index, dyn_ent))
    sections.append((".shstrtab", 3, 0, shstrtab_off, len(shstrtab), 1, 0, 0))
    assert len(sections) == shnum, (len(sections), shnum)
    shstrndx = next(index for index, section in enumerate(sections) if section[0] == ".shstrtab")
    shdrs = b"".join(
        shdr(sh_name_offsets.get(name, 0), sh_type, flags, off, size, align, link, entsize)
        for name, sh_type, flags, off, size, align, link, entsize in sections
    )

    ident = bytearray(16)
    ident[0:4] = b"\x7fELF"
    ident[4] = 2 if is64 else 1
    ident[5] = 1 if spec.little_endian else 2
    ident[6] = 1
    ident[7] = 0

    if is64:
        header = bytes(ident) + struct.pack(
            endian + "HHIQQQIHHHHHH",
            spec.elf_type,
            spec.machine,
            1,
            0x1000,  # entry
            ehsize,  # phoff
            shoff,
            0,
            ehsize,
            phentsize,
            phnum,
            shentsize,
            shnum,
            shstrndx,
        )
    else:
        header = bytes(ident) + struct.pack(
            endian + "HHIIIIIHHHHHH",
            spec.elf_type,
            spec.machine,
            1,
            0x1000,
            ehsize,
            shoff,
            0,
            ehsize,
            phentsize,
            phnum,
            shentsize,
            shnum,
            shstrndx,
        )

    body = header + phdrs + interp + note + dynstr + symtab + dynamic + shstrtab + shdrs
    assert len(body) == offset, (len(body), offset)
    return body


def write_fixture(path: Path, spec: ElfSpec) -> Path:
    """Write one fixture and return its path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(build_elf(spec))
    return path


PIE_AARCH64 = ElfSpec()


MIPS_BIG_ENDIAN = ElfSpec(
    elf_class=32,
    little_endian=False,
    machine=8,
    elf_type=2,
    interpreter=None,
    needed=[],
    bind_now=False,
    stack_executable=True,
    symbols=[],
    build_id=None,
    dynamic=False,
    gnu_relro=False,
)
