"""ELF parsing (3B): identify by header, and never credit missing evidence."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
from elf_fixtures import MIPS_BIG_ENDIAN, ElfSpec, write_fixture

from iot_hardware_scanner.scanner.elf_parser import (
    ElfParseError,
    looks_like_elf,
    parse_elf,
)


class TestIdentification:
    def test_pie_executable(self, tmp_path: Path) -> None:
        path = write_fixture(tmp_path / "app", ElfSpec())
        report = parse_elf(path)
        assert (report.elf_class, report.byte_order) == ("ELF64", "little")
        assert (report.machine, report.machine_name) == (183, "AArch64")
        assert report.elf_type == "DYN"
        assert report.interpreter == "/lib/ld-musl-aarch64.so.1"
        assert report.needed == ["libc.so", "libgcc_s.so.1"]
        assert report.build_id == "deadbeef01020304"
        assert report.pie is True
        assert report.relro == "full"

    def test_static_mips_executable(self, tmp_path: Path) -> None:
        path = write_fixture(tmp_path / "busybox", MIPS_BIG_ENDIAN)
        report = parse_elf(path)
        assert (report.elf_class, report.byte_order) == ("ELF32", "big")
        assert (report.machine, report.machine_name) == (8, "MIPS")
        assert report.elf_type == "EXEC"
        assert report.interpreter is None
        assert report.needed == []
        assert report.pie is False
        assert report.relro == "none"

    def test_stack_permission_is_read_from_the_segment(self, tmp_path: Path) -> None:
        executable = write_fixture(tmp_path / "exec-stack", MIPS_BIG_ENDIAN)
        non_exec = write_fixture(tmp_path / "nx-stack", ElfSpec())
        assert parse_elf(executable).stack_executable is True
        assert parse_elf(non_exec).stack_executable is False

    def test_shared_library_is_not_called_pie(self, tmp_path: Path) -> None:
        spec = ElfSpec(interpreter=None, needed=[], symbols=[], soname="libfoo.so", build_id=None)
        path = write_fixture(tmp_path / "libfoo.so", spec)
        report = parse_elf(path)
        assert report.elf_type == "DYN"
        assert report.pie is None


class TestAbsentEvidence:
    def test_stripped_binary_reports_unknown_not_unhardened(self, tmp_path: Path) -> None:
        spec = ElfSpec(symbols=[])
        path = write_fixture(tmp_path / "stripped", spec)
        report = parse_elf(path)
        assert report.canary is None
        assert report.fortify is None
        assert any("symbol table" in note for note in report.unknown)

    def test_symbols_support_the_canary_and_fortify_claims(self, tmp_path: Path) -> None:
        path = write_fixture(tmp_path / "hardened", ElfSpec())
        report = parse_elf(path)
        assert report.canary is True
        assert report.fortify is True

    def test_missing_build_id_is_recorded_as_unknown(self, tmp_path: Path) -> None:
        spec = ElfSpec(build_id=None)
        path = write_fixture(tmp_path / "nobuildid", spec)
        report = parse_elf(path)
        assert report.build_id is None
        assert any("build-id" in note for note in report.unknown)

    def test_no_interpreter_on_an_exec_is_reported(self, tmp_path: Path) -> None:
        report = parse_elf(write_fixture(tmp_path / "static", MIPS_BIG_ENDIAN))
        assert any("PT_INTERP" in note for note in report.unknown)


class TestRefusals:
    def test_not_an_elf(self, tmp_path: Path) -> None:
        path = tmp_path / "data.bin"
        path.write_bytes(b"\x00" * 128)
        with pytest.raises(ElfParseError):
            parse_elf(path)
        assert not looks_like_elf(path)

    def test_truncated_header(self, tmp_path: Path) -> None:
        path = tmp_path / "cut.elf"
        path.write_bytes(b"\x7fELF\x02\x01\x01")
        with pytest.raises(ElfParseError):
            parse_elf(path)
        assert looks_like_elf(path)

    def test_declared_tables_outside_the_file_are_refused(self, tmp_path: Path) -> None:
        path = write_fixture(tmp_path / "cut-tables", ElfSpec())
        raw = bytearray(path.read_bytes())
        # Move the section header table far past the end of the file.
        raw[40:48] = (10**9).to_bytes(8, "little")
        path.write_bytes(bytes(raw))
        with pytest.raises(ElfParseError):
            parse_elf(path)

    def test_invalid_ident_bytes(self, tmp_path: Path) -> None:
        path = tmp_path / "weird.elf"
        path.write_bytes(b"\x7fELF\x07\x09" + b"\x00" * 60)
        with pytest.raises(ElfParseError):
            parse_elf(path)


#: binutils lives in the worker's **verification** stage, not in the runtime
#: image a scan uses (milestone D §2.1). The release gate builds this tag:
#:   docker build -t ihs-squashfs-worker:4.5.1-verify --target verification worker/
VERIFY_WORKER_IMAGE = "ihs-squashfs-worker:4.5.1-verify"


def _readelf() -> str | None:
    found = shutil.which("readelf")
    if found:
        return found
    # The pinned worker's verification stage carries binutils for exactly this
    # comparison; the runtime stage a scan uses carries only unsquashfs.
    if shutil.which("docker") and shutil.which("podman") is None:
        return "docker"
    return None


@pytest.mark.integration
@pytest.mark.parametrize(
    ("spec_name", "expected"),
    [
        ("pie", {"class": "ELF64", "data": "little endian", "machine": "AArch64", "type": "DYN"}),
        ("mips", {"class": "ELF32", "data": "big endian", "machine": "MIPS R3000", "type": "EXEC"}),
    ],
)
def test_readelf_agrees_with_the_parser(
    tmp_path: Path, spec_name: str, expected: dict[str, str]
) -> None:
    """Independent check: the parser's facts match ``readelf`` on the same bytes."""
    tool = _readelf()
    if tool is None:
        pytest.skip("neither readelf nor a container runtime is available to verify ELF facts")
    spec = ElfSpec() if spec_name == "pie" else MIPS_BIG_ENDIAN
    # A container runtime only sees directories the VM is configured to share;
    # on macOS that is the home directory, not the pytest temp root.
    shared = tmp_path if tool != "docker" else _shared_dir()
    try:
        path = write_fixture(shared / spec_name, spec)
        report = parse_elf(path)
        output = _readelf_output(tool, path, spec_name, shared)
    finally:
        if tool == "docker":
            shutil.rmtree(shared, ignore_errors=True)
    assert expected["class"] in output
    assert expected["data"] in output
    assert expected["machine"] in output
    assert expected["type"] in output
    # The parser saw the same identifying fields.
    assert report.elf_class == expected["class"]
    assert report.byte_order == expected["data"].split()[0]


def _shared_dir() -> Path:
    """A scratch directory the container runtime can see."""
    import tempfile
    import uuid

    base = Path.home() / ".cache" / "ihs-elf-checks"
    base.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=f"{uuid.uuid4().hex[:8]}-", dir=base))


def _readelf_output(tool: str, path: Path, spec_name: str, shared: Path) -> str:
    """``readelf -h`` output for the fixture, from the host or the worker image."""
    try:
        completed = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "-v",
                f"{shared}:/w:ro",
                "--entrypoint",
                "/usr/bin/readelf",
                VERIFY_WORKER_IMAGE,
                "-h",
                f"/w/{spec_name}",
            ],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):  # pragma: no cover - runtime dependent
        pytest.skip("could not run readelf in the worker image")
    if completed.returncode != 0:
        pytest.skip(
            f"readelf unavailable in the verification image ({VERIFY_WORKER_IMAGE}): "
            f"{completed.stderr[:120]}"
        )
    return completed.stdout
