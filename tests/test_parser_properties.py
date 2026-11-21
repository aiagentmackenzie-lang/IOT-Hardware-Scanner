"""Property tests for the parsers that consume untrusted bytes (slice 2E).

Fixture-based tests prove the cases someone thought of. These prove the
invariant across arbitrary input: **only the parser's own error type escapes**,
so a hostile artifact cannot reach the operator as a traceback, and a returned
fact never points outside the artifact.

Hypothesis is configured deterministically (``derandomize``) so a CI failure is
reproducible from the seed printed in the report.
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest
from hostile_fixtures import tar_with_member
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from iot_hardware_scanner.scanner.bounded_reader import open_bounded
from iot_hardware_scanner.scanner.extraction_worker import (
    EXTRACTION_CORRUPT,
    ExtractedTree,
    ExtractionError,
    SquashfsWorker,
    _safe_member_name,
)
from iot_hardware_scanner.scanner.fit_dtb import FitDtbError, analyse_boot
from iot_hardware_scanner.scanner.image_map import ImageMapBuilder, ImageMapError
from iot_hardware_scanner.scanner.opkg_inventory import parse_opkg_status
from iot_hardware_scanner.scanner.report_document import load_document

PROPERTY = settings(
    max_examples=150,
    deadline=None,
    derandomize=True,
    suppress_health_check=[
        HealthCheck.too_slow,
        # ``tmp_path`` is deliberately reused: each example rewrites the same
        # file, and the reader re-opens it per pass.
        HealthCheck.function_scoped_fixture,
    ],
)

JSON_SCALARS = (
    st.none()
    | st.booleans()
    | st.integers(min_value=-(2**63), max_value=2**63)
    | st.floats(allow_nan=False, allow_infinity=False)
    | st.text(max_size=24)
)
JSON_VALUES = st.recursive(
    JSON_SCALARS,
    lambda children: (
        st.lists(children, max_size=3) | st.dictionaries(st.text(max_size=12), children, max_size=3)
    ),
    max_leaves=12,
)


def _reader(tmp_path: Path, payload: bytes):
    path = tmp_path / "artifact.bin"
    path.write_bytes(payload)
    return open_bounded(path)


@pytest.mark.parametrize("kind", ["squashfs", "gzip"])
@PROPERTY
@given(payload=st.binary(max_size=4096))
def test_container_headers_raise_only_their_own_error(
    tmp_path: Path, kind: str, payload: bytes
) -> None:
    """A container header is either decoded or ``ImageMapError``; nothing else."""
    reader = _reader(tmp_path, payload)
    builder = ImageMapBuilder()
    try:
        if kind == "squashfs":
            builder.parse_squashfs(reader)
        else:
            builder.parse_gzip_header(reader)
    except ImageMapError:
        return  # the documented rejection
    except Exception as exc:  # pragma: no cover - the property failing
        raise AssertionError(
            f"{kind} leaked {type(exc).__name__}: {exc} for {payload[:32]!r}"
        ) from exc


@PROPERTY
@given(payload=st.binary(max_size=8192))
def test_boot_parsing_raises_only_fit_dtb_error(tmp_path: Path, payload: bytes) -> None:
    """An FDT/FIT parser never leaks a struct, index or attribute error."""
    reader = _reader(tmp_path, payload)
    try:
        analyse_boot(reader, locator="fuzz.bin", digest="0" * 64, artifact_id="a0")
    except FitDtbError:
        return
    except Exception as exc:  # pragma: no cover - the property failing
        raise AssertionError(
            f"boot parser leaked {type(exc).__name__}: {exc} for {payload[:32]!r}"
        ) from exc


@PROPERTY
@given(payload=st.binary(max_size=16384))
def test_opkg_parser_is_total(payload: bytes) -> None:
    """Any byte string is a package database with zero or more stanzas."""
    inventory = parse_opkg_status(payload)
    assert inventory.byte_length == len(payload)
    for record in inventory.records:
        assert 0 <= record.evidence_start <= record.evidence_end <= len(payload)


@PROPERTY
@given(payload=st.binary(max_size=2048))
def test_bounded_reader_windows_stay_inside_the_artifact(tmp_path: Path, payload: bytes) -> None:
    """Every window is inside the file and offsets advance monotonically."""
    reader = _reader(tmp_path, payload)
    scan = reader.iter_windows(128)
    previous_end = 0
    for window in scan:
        assert 0 <= window.offset <= window.end <= len(payload)
        assert window.offset >= previous_end
        previous_end = window.end


@PROPERTY
@given(document=st.dictionaries(st.text(max_size=16), JSON_VALUES, max_size=12))
def test_document_loader_rejects_or_returns(document: dict[str, object]) -> None:
    """A saved document is validated before a renderer can index into it."""
    try:
        loaded = load_document(document)
    except ValueError:
        return
    except Exception as exc:  # pragma: no cover - the property failing
        raise AssertionError(f"loader leaked {type(exc).__name__}: {exc}") from exc
    assert isinstance(loaded, dict)


@given(name=st.text(max_size=128))
def test_member_name_check_is_total(name: str) -> None:
    """The worker's return path validates every name without raising."""
    verdict = _safe_member_name(name)
    assert isinstance(verdict, bool)
    if verdict:
        assert not name.startswith(("/", "~", "\\"))
        assert ".." not in name.split("/")


def test_the_tar_collector_rejects_an_escaping_member(tmp_path: Path) -> None:
    """A member that leaves the tree is a corrupt worker response, not a write."""
    from iot_hardware_scanner.config import ScannerConfig

    worker = SquashfsWorker(ScannerConfig())
    stream = io.BytesIO(tar_with_member("../escape"))
    with pytest.raises(ExtractionError) as raised:
        worker._collect_tar(stream, tmp_path / "root", ExtractedTree(), budget=1024 * 1024)
    assert raised.value.state == EXTRACTION_CORRUPT
    assert not (tmp_path / "escape").exists()


def test_the_tar_collector_rejects_an_absolute_member(tmp_path: Path) -> None:
    """An absolute member name is rejected before anything is created."""
    from iot_hardware_scanner.config import ScannerConfig

    worker = SquashfsWorker(ScannerConfig())
    stream = io.BytesIO(tar_with_member("/etc/passwd"))
    with pytest.raises(ExtractionError) as raised:
        worker._collect_tar(stream, tmp_path / "root", ExtractedTree(), budget=1024 * 1024)
    assert raised.value.state == EXTRACTION_CORRUPT
