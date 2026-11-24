"""P3 — how a type label was established, and what the host could actually use.

The plan's rule is to record what ran, not what was available in principle. A
"file type" string without its source is not evidence: ``ELF executable`` read
from libmagic and the same words read from a ``.elf`` suffix are different
claims, and a scan on a host without libmagic must say so instead of quietly
identifying less.

Schema 7 records two new facts:

* ``artifact.file_type_source`` — ``libmagic``, ``magic-bytes``, ``extension``
  or ``directory``;
* ``tool.capabilities`` — libmagic availability **with its reason**, the parser
  package versions, and which container runtimes are on ``PATH`` (presence
  only; reachability and the image used live in ``extraction``).
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.models import FirmwareSizeCategory, ScanContext
from iot_hardware_scanner.scanner import report_document
from iot_hardware_scanner.scanner.firmware_ingest import (
    FILE_TYPE_SOURCE_DIRECTORY,
    FILE_TYPE_SOURCE_EXTENSION,
    FILE_TYPE_SOURCE_LIBMAGIC,
    FILE_TYPE_SOURCE_MAGIC_BYTES,
    FirmwareIngest,
)
from iot_hardware_scanner.scanner.report_document import (
    SCHEMA_VERSION,
    build_document,
    render,
)


def _context(**overrides: Any) -> ScanContext:
    values: dict[str, Any] = {
        "scan_id": "capability-scan",
        "firmware_path": Path("firmware.img"),
        "output_dir": Path("reports/scan"),
        "file_hash_sha256": "a" * 64,
        "file_hash_md5": "b" * 32,
        "file_size": 4096,
        "file_type": "data",
        "file_type_source": FILE_TYPE_SOURCE_EXTENSION,
        "firmware_name": "firmware",
        "size_category": FirmwareSizeCategory.SMALL,
        "started_at": datetime(2026, 11, 24, tzinfo=timezone.utc),
    }
    values.update(overrides)
    return ScanContext(**values)


class _FakeMagic:
    """A libmagic binding that answers, so the happy path needs no library."""

    @staticmethod
    def from_file(path: str, mime: bool = False) -> str:
        return "application/octet-stream" if mime else "ELF 32-bit LSB executable, ARM"

    @staticmethod
    def from_buffer(buffer: bytes, mime: bool = False) -> str:
        return "application/octet-stream" if mime else "data"

    @staticmethod
    def version() -> str:
        return "540"


class _BrokenMagic:
    """Importable, but the shared library does not answer."""

    @staticmethod
    def from_buffer(buffer: bytes, mime: bool = False) -> str:
        raise RuntimeError("libmagic could not be initialised")


# ──────────────────────────────────────────────
# Ingest records the source
# ──────────────────────────────────────────────


def test_a_fdt_with_no_extension_is_identified_from_its_own_magic(tmp_path: Path) -> None:
    firmware = tmp_path / "board.img"
    firmware.write_bytes(b"\xd0\x0d\xfe\xed" + b"\x00" * 512)

    file_type, source = FirmwareIngest(ScannerConfig())._identify_file_type(firmware)

    assert "Flattened device tree" in file_type
    assert source == FILE_TYPE_SOURCE_MAGIC_BYTES


def test_libmagic_is_recorded_when_it_answers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    firmware = tmp_path / "firmware.bin"
    firmware.write_bytes(b"\x00" * 64)
    monkeypatch.setitem(sys.modules, "magic", _FakeMagic)

    file_type, source = FirmwareIngest(ScannerConfig())._identify_file_type(firmware)

    assert "ELF 32-bit" in file_type
    assert source == FILE_TYPE_SOURCE_LIBMAGIC


def test_a_missing_library_falls_back_and_names_the_real_cause(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # Content that is *not* a record stream: this exercises the extension
    # fallback. A valid Intel HEX line would be recognised from its own magic
    # bytes before libmagic is consulted at all (slice 3C).
    firmware = tmp_path / "board.hex"
    firmware.write_bytes(b"\x00" * 16)
    # `None` in sys.modules is how the interpreter models "this import raises":
    # the binding is present and the library is not, which is the real fault.
    monkeypatch.setitem(sys.modules, "magic", None)

    with caplog.at_level("WARNING"):
        file_type, source = FirmwareIngest(ScannerConfig())._identify_file_type(firmware)

    assert "Intel HEX" in file_type
    assert source == FILE_TYPE_SOURCE_EXTENSION
    assert "No libmagic binding" in caplog.text
    assert "magic" in caplog.text


def test_a_binding_that_cannot_answer_falls_back_to_the_extension(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    firmware = tmp_path / "board.uf2"
    firmware.write_bytes(b"\x00" * 16)
    monkeypatch.setitem(sys.modules, "magic", _BrokenMagic)

    file_type, source = FirmwareIngest(ScannerConfig())._identify_file_type(firmware)

    assert "UF2" in file_type
    assert source == FILE_TYPE_SOURCE_EXTENSION


def test_a_staged_tree_records_that_its_type_is_a_directory(
    tmp_path: Path, output_config: ScannerConfig
) -> None:
    tree = tmp_path / "rootfs"
    (tree / "etc").mkdir(parents=True)
    (tree / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/sh\n")

    context = FirmwareIngest(output_config).ingest_tree(tree)

    assert context.file_type_source == FILE_TYPE_SOURCE_DIRECTORY


# ──────────────────────────────────────────────
# The document carries both facts
# ──────────────────────────────────────────────


def test_the_document_records_the_type_source_next_to_the_type() -> None:
    document = build_document(
        _context(
            file_type="ELF 32-bit LSB executable, ARM",
            file_type_source=FILE_TYPE_SOURCE_LIBMAGIC,
        ),
        "2.7.0",
    )

    assert document["schema_version"] == SCHEMA_VERSION
    assert document["artifact"]["file_type_source"] == FILE_TYPE_SOURCE_LIBMAGIC
    assert "identified by libmagic" in render(document, "markdown")
    assert "identified by libmagic" in render(document, "terminal")


def test_capabilities_record_package_versions_and_the_runtime_on_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(report_document.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setitem(sys.modules, "magic", _FakeMagic)

    document = build_document(_context(), "2.7.0")
    capabilities = document["tool"]["capabilities"]

    assert document["tool"]["name"] == "iot-hardware-scanner"
    assert capabilities["libmagic"] == {"available": True, "version": "540", "detail": None}
    assert capabilities["pyelftools"]["available"] is True
    assert capabilities["yara-python"]["available"] is True
    assert capabilities["container_runtime_on_path"] == ["podman", "docker"]
    assert "Host capabilities" in render(document, "markdown")


def test_an_unavailable_capability_names_the_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(report_document.shutil, "which", lambda name: None)
    monkeypatch.setitem(sys.modules, "magic", _BrokenMagic)

    document = build_document(_context(), "2.7.0")
    capabilities = document["tool"]["capabilities"]

    assert capabilities["libmagic"]["available"] is False
    assert "libmagic" in capabilities["libmagic"]["detail"]
    assert capabilities["container_runtime_on_path"] == []
    markdown = render(document, "markdown")
    assert "libmagic **unavailable**" in markdown
    assert "container runtime on PATH: none" in markdown


def test_an_unrecorded_capability_renders_as_silence_not_as_empty() -> None:
    document = {
        "schema_version": 7,
        "tool": {"name": "iot-hardware-scanner", "version": "2.4.0", "capabilities": None},
        "artifact": {"name": "board", "file_type": "ELF", "file_type_source": None},
        "assessment": {
            "completion": "COMPLETE",
            "profile": "firmware-boot",
            "profile_version": "5.0",
        },
        "stages": [],
        "controls": [],
        "findings": [],
    }

    markdown = render(document, "markdown")

    assert "Host capabilities" not in markdown
    assert "identified by" not in markdown
    assert "identified by" not in render(document, "terminal")
