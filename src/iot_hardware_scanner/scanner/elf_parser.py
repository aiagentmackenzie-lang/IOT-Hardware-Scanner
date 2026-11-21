"""Direct ELF metadata from the target's own structures (slice 3B).

Why not ``file``, ``readelf`` or a filename
------------------------------------------
Those all agree most of the time and disagree exactly when it matters: a
relocatable object, a truncated download, a statically linked BusyBox, or a
binary renamed to ``config.js`` to dodge a suffix-based check. This module
identifies ELF from its **header** and then reads the structures that support
each claim:

* class, byte order, machine and ABI — from ``e_ident`` and ``e_machine``;
* interpreter and dependencies — from ``PT_INTERP`` and ``DT_NEEDED``;
* segments — from the program header table;
* build ID — from the ``.note.gnu.build-id`` note;
* stack permission, PIE, RELRO — from program headers and dynamic flags;
* canary and FORTIFY — only from symbol names that are actually present.

Anything the structures cannot support is ``unknown``, not ``False``. A
stripped binary has no symbol table, so "no canary" is not an observation: it
is missing evidence, and the hardening control reports it as such.

Reading discipline
------------------
pyelftools walks a file object, so this module hands it a *bounded* one: reads
and seeks are clipped to the size that was validated at ingest. A section that
declares 4 GiB cannot make the parser allocate 4 GiB.
"""

from __future__ import annotations

import logging
import struct
from pathlib import Path
from types import TracebackType
from typing import IO, Any

from iot_hardware_scanner.models import ElfReport

logger = logging.getLogger(__name__)

#: ELF ``e_machine`` values this scanner names. Others are reported numerically.
MACHINE_NAMES: dict[int, str] = {
    2: "SPARC",
    3: "Intel 80386",
    8: "MIPS",
    20: "PowerPC",
    21: "PowerPC64",
    22: "IBM S/390",
    40: "ARM",
    42: "SuperH",
    43: "SPARC v9",
    50: "Intel IA-64",
    62: "AMD x86-64",
    183: "AArch64",
    188: "Tilera TILEPro",
    243: "RISC-V",
}

#: ``e_type`` values this scanner names.
_ELF_TYPES = {2: "EXEC", 3: "DYN", 1: "REL", 4: "CORE"}

#: ``EI_OSABI`` values.
OS_ABI = {0: "SYSV", 1: "HP-UX", 2: "NetBSD", 3: "Linux", 6: "Solaris", 9: "FreeBSD"}


#: Symbol names that evidence a stack protector. A stripped binary has none.
_CANARY_SYMBOL = "__stack_chk_fail"
#: Symbol-name suffix glibc's FORTIFY wrappers use.
_FORTIFY_SUFFIX = "_chk"


class ElfParseError(Exception):
    """Raised when a file is not ELF, or its structures cannot be read."""


class _BoundedFile:
    """A seekable read-only view whose reads can never exceed the real bytes."""

    def __init__(self, handle: IO[bytes], size: int) -> None:
        self._handle = handle
        self._size = size
        self.name = getattr(handle, "name", "<elf>")

    def read(self, size: int = -1) -> bytes:
        """Read at most ``size`` bytes, clipped to the validated length."""
        position = self._handle.tell()
        available = max(0, self._size - position)
        if size is None or size < 0:
            size = available
        return self._handle.read(min(size, available))

    def seek(self, offset: int, whence: int = 0) -> int:
        """Seek within the validated length."""
        if whence == 0:
            offset = max(0, min(offset, self._size))
        return self._handle.seek(offset, whence)

    def tell(self) -> int:
        """Current position."""
        return self._handle.tell()

    def seekable(self) -> bool:
        """pyelftools requires a seekable stream."""
        return True

    def readable(self) -> bool:
        """This view is read-only."""
        return True

    def close(self) -> None:
        """Close the underlying handle."""
        self._handle.close()

    def __enter__(self) -> _BoundedFile:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


def _parser_version() -> str | None:
    try:
        from importlib.metadata import version

        return version("pyelftools")
    except Exception:  # pragma: no cover - metadata always present when installed
        return None


def looks_like_elf(path: Path) -> bool:
    """Whether the file's first four bytes are the ELF magic."""
    try:
        with Path(path).open("rb") as handle:
            return handle.read(4) == b"\x7fELF"
    except OSError:
        return False


def parse_elf(path: Path, *, locator: str | None = None, digest: str = "") -> ElfReport:
    """Read one ELF file from its own header and program headers.

    Raises:
        ElfParseError: the file is not ELF, is truncated, or its headers are
            not consistent enough to read.
    """
    from elftools.common.exceptions import ELFError
    from elftools.common.exceptions import ELFParseError as PyElfParseError
    from elftools.elf.elffile import ELFFile

    path = Path(path)
    size = path.stat().st_size
    with path.open("rb") as raw:
        stream = _BoundedFile(raw, size)
        head = stream.read(20)
        if len(head) < 20 or head[:4] != b"\x7fELF":
            raise ElfParseError(f"{path.name}: no ELF header")
        facts = _header_facts(head)
        stream.seek(0)
        try:
            elf = ELFFile(stream)  # type: ignore[arg-type]
            # pyelftools reads section and segment tables lazily, so an offset
            # declared past the end of the file only surfaces while describing
            # it. Every structural failure is one refusal here: the file cannot
            # be parsed, and nothing about it may be reported as observed.
            return _describe(
                elf, facts=facts, size=size, locator=locator or path.name, digest=digest
            )
        except (
            ELFError,
            PyElfParseError,
            ValueError,
            struct.error,
            IndexError,
            KeyError,
        ) as exc:
            raise ElfParseError(f"{path.name}: {exc}") from exc


def _header_facts(head: bytes) -> dict[str, Any]:
    """The identifying fields, decoded from the header bytes themselves.

    pyelftools exposes ``e_machine`` as a name string in recent releases, and
    this scanner reports the numeric value the plan records, so the two bytes are
    read here rather than inferred from a library's enum table.
    """
    ei_class = head[4]
    ei_data = head[5]
    if ei_class not in (1, 2) or ei_data not in (1, 2):
        raise ElfParseError(f"invalid ELF identification bytes: class={ei_class} data={ei_data}")
    endian = "<" if ei_data == 1 else ">"
    e_type, e_machine = struct.unpack(f"{endian}HH", head[16:20])
    return {
        "elf_class": "ELF64" if ei_class == 2 else "ELF32",
        "byte_order": "little" if ei_data == 1 else "big",
        "machine": e_machine,
        "machine_name": MACHINE_NAMES.get(e_machine, f"machine-{e_machine}"),
        "type": _ELF_TYPES.get(e_type, f"type-{e_type}"),
        "os_abi": OS_ABI.get(head[7], f"abi-{head[7]}"),
    }


def _describe(
    elf: Any, *, facts: dict[str, Any], size: int, locator: str, digest: str
) -> ElfReport:
    """Fill an :class:`ElfReport` from a parsed ELF object."""
    report = ElfReport(
        locator=locator,
        digest_sha256=digest,
        size=size,
        elf_class=str(facts["elf_class"]),
        byte_order=str(facts["byte_order"]),
        machine=int(facts["machine"]),
        machine_name=str(facts["machine_name"]),
        elf_type=str(facts["type"]),
        os_abi=str(facts["os_abi"]),
        parser_version=_parser_version(),
    )

    segments = _segments(elf)
    report.segments = segments
    by_type: dict[str, dict[str, Any]] = {}
    for segment in segments:
        by_type.setdefault(str(segment["type"]), segment)

    interp = by_type.get("PT_INTERP")
    if interp is not None:
        report.interpreter = _interpreter(elf, interp)

    dynamic = _dynamic(elf)
    report.needed = list(dynamic["needed"])
    report.soname = dynamic["soname"]
    report.build_id = _build_id(elf)

    report.stack_executable = _stack_executable(by_type.get("PT_GNU_STACK"))
    report.pie = _pie(report.elf_type, by_type, dynamic, report.soname)
    report.relro = _relro(by_type.get("PT_GNU_RELRO"), dynamic)

    symbols = _symbol_names(elf)
    if symbols is None:
        report.unknown.append(
            "no symbol table is present (the file may be section-stripped), so canary "
            "and FORTIFY evidence is unavailable"
        )
        report.canary = None
        report.fortify = None
    else:
        report.canary = _CANARY_SYMBOL in symbols
        report.fortify = any(name.endswith(_FORTIFY_SUFFIX) for name in symbols)
        if not report.canary:
            report.unknown.append(
                "the symbol table is present and does not reference the stack protector"
            )

    if report.interpreter is None and report.elf_type == "EXEC":
        report.unknown.append("no PT_INTERP: statically linked or an entry point without a loader")
    if report.build_id is None:
        report.unknown.append("no .note.gnu.build-id note")
    return report


def _segments(elf: Any) -> list[dict[str, Any]]:
    segments: list[dict[str, Any]] = []
    for index, segment in enumerate(elf.iter_segments()):
        # A hostile image cannot make this list unbounded: program headers are
        # bounded by the header table, which pyelftools validates against the
        # file, but cap the recorded detail anyway.
        if index >= 64:
            break
        flags = int(segment["p_flags"])
        segments.append(
            {
                "type": str(segment["p_type"]),
                "offset": int(segment["p_offset"]),
                "vaddr": int(segment["p_vaddr"]),
                "filesz": int(segment["p_filesz"]),
                "flags": _flag_string(flags),
                "executable": bool(flags & 0x1),
                "writable": bool(flags & 0x2),
                "readable": bool(flags & 0x4),
            }
        )
    return segments


def _flag_string(flags: int) -> str:
    return "".join(letter for bit, letter in ((0x4, "R"), (0x2, "W"), (0x1, "E")) if flags & bit)


def _interpreter(elf: Any, segment: dict[str, Any]) -> str | None:
    try:
        for candidate in elf.iter_segments():
            if str(candidate["p_type"]) == "PT_INTERP":
                data = bytes(candidate.data())
                return data.split(b"\x00", 1)[0].decode("utf-8", "replace")
    except Exception as exc:  # pragma: no cover - malformed segment data
        logger.debug("Cannot read PT_INTERP: %s", exc)
    return None


def _dynamic(elf: Any) -> dict[str, Any]:
    """Dynamic tags, from the ``.dynamic`` section or the ``PT_DYNAMIC`` segment.

    A fully section-stripped binary — OpenWrt's BusyBox is one — has no section
    headers at all, so dependencies and flags must come from the segment. Reading
    only the section would silently report "no dependencies" for every such file,
    which is an absence of evidence presented as a finding.
    """
    result: dict[str, Any] = {"needed": [], "soname": None, "bind_now": False, "flags_1": 0}
    try:
        source = elf.get_section_by_name(".dynamic")
        if source is None:
            for segment in elf.iter_segments():
                if str(segment["p_type"]) == "PT_DYNAMIC":
                    source = segment
                    break
        if source is None:
            return result
        for tag in source.iter_tags():
            if tag.entry.d_tag == "DT_NEEDED":
                result["needed"].append(str(tag.needed))
            elif tag.entry.d_tag == "DT_SONAME":
                result["soname"] = str(tag.soname)
            elif tag.entry.d_tag in ("DT_BIND_NOW", "DT_FLAGS") and (
                tag.entry.d_tag == "DT_BIND_NOW" or int(tag.entry.d_val) & 0x8
            ):
                # DF_BIND_NOW in DT_FLAGS, or the standalone DT_BIND_NOW tag.
                result["bind_now"] = True
            elif tag.entry.d_tag == "DT_FLAGS_1":
                value = int(tag.entry.d_val)
                result["flags_1"] = value
                if value & 0x1:  # DF_1_NOW
                    result["bind_now"] = True
    except Exception as exc:  # pragma: no cover - malformed dynamic section
        logger.debug("Cannot read .dynamic: %s", exc)
    return result


def _build_id(elf: Any) -> str | None:
    """The GNU build ID, from note sections or ``PT_NOTE`` segments."""
    try:
        for section in elf.iter_sections():
            if section["sh_type"] == "SHT_NOTE":
                for note in section.iter_notes():
                    if note["n_type"] == "NT_GNU_BUILD_ID":
                        return str(note["n_desc"])
    except Exception as exc:  # pragma: no cover - malformed notes
        logger.debug("Cannot read build ID from sections: %s", exc)
    try:
        for segment in elf.iter_segments():
            if str(segment["p_type"]) != "PT_NOTE":
                continue
            for note in segment.iter_notes():
                if note["n_type"] == "NT_GNU_BUILD_ID":
                    return str(note["n_desc"])
    except Exception as exc:  # pragma: no cover - malformed notes
        logger.debug("Cannot read build ID from segments: %s", exc)
    return None


def _stack_executable(segment: dict[str, Any] | None) -> bool | None:
    if segment is None:
        return None
    return bool(segment["executable"])


def _pie(
    elf_type: str, by_type: dict[str, dict[str, Any]], dynamic: dict[str, Any], soname: str | None
) -> bool | None:
    if elf_type == "EXEC":
        return False
    if elf_type == "REL":
        return None
    if elf_type != "DYN":
        return None
    if int(dynamic.get("flags_1", 0)) & 0x08000000:  # DF_1_PIE
        return True
    if soname and "PT_INTERP" not in by_type:
        # A shared library, not an executable: ET_DYN says "load anywhere",
        # not "runnable image".
        return None
    if "PT_INTERP" in by_type:
        return True
    return None


def _relro(segment: dict[str, Any] | None, dynamic: dict[str, Any]) -> str:
    if segment is None:
        return "none"
    return "full" if dynamic.get("bind_now") else "partial"


def _symbol_names(elf: Any) -> set[str] | None:
    """Every dynamic/symbol-table name, or ``None`` when the file is stripped."""
    names: set[str] = set()
    found_table = False
    for section_name in (".dynsym", ".symtab"):
        try:
            section = elf.get_section_by_name(section_name)
        except Exception:  # pragma: no cover - malformed section headers
            continue
        if section is None:
            continue
        found_table = True
        try:
            for symbol in section.iter_symbols():
                if symbol.name:
                    names.add(symbol.name)
        except Exception:  # pragma: no cover - malformed symbol table
            continue
    return names if found_table else None
