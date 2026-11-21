"""Slice 3D — bounded FDT/FIT parsing, with an independent tool check.

The fixtures are written byte by byte by :mod:`tests.fdt_fixtures`. The
independent check runs the *verification* worker image, which carries
``device-tree-compiler 1.6.1`` and ``u-boot-tools 2023.01`` — tools that share
no code with the scanner. The runtime image a scan uses still has only
``unsquashfs``.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from fdt_fixtures import (
    Node,
    board_dtb,
    build_fdt,
    build_fit,
    public_key_pem,
)

from iot_hardware_scanner.scanner.bounded_reader import open_bounded
from iot_hardware_scanner.scanner.fit_dtb import (
    FitDtbError,
    TrustAnchorError,
    analyse_boot,
    load_trust_anchor,
    parse_fdt,
    selected_configuration,
)

VERIFY_WORKER_IMAGE = os.environ.get("IHS_WORKER_IMAGE", "ihs-squashfs-worker:4.5.1") + "-verify"


def _parse(path: Path, *, anchors=None):
    return analyse_boot(
        open_bounded(path),
        locator=path.name,
        digest="0" * 64,
        artifact_id="a0",
        anchors=anchors,
    )


# ──────────────────────────────────────────────
# Device-tree parsing
# ──────────────────────────────────────────────


class TestFdtParser:
    def test_board_facts_match_the_bytes_that_declare_them(self, tmp_path: Path) -> None:
        path = tmp_path / "board.dtb"
        path.write_bytes(board_dtb())

        parsed = parse_fdt(open_bounded(path))

        assert parsed.version == 17
        assert parsed.root.strings("compatible") == ["test,board", "test,soc"]
        assert parsed.root.text("model") == "IHS Test Board"
        artifact, omissions = _parse(path)
        assert omissions == []
        assert artifact.kind == "dtb"
        assert artifact.default_config is None
        assert artifact.memory[0]["base"] == 0x40000000
        assert artifact.memory[0]["size"] == 0x10000000
        assert artifact.reserved_memory[0]["base"] == 0x48000000
        assert artifact.partitions == [
            {
                "label": "firmware",
                "offset": 0,
                "size": 0x00400000,
                "node": "/flash@0/partitions/partition@0",
            }
        ]

    def test_a_dtb_is_not_a_fit(self, tmp_path: Path) -> None:
        path = tmp_path / "board.dtb"
        path.write_bytes(board_dtb())

        artifact, _ = _parse(path)

        assert artifact.kind == "dtb"
        assert artifact.referenced_payloads == []
        assert artifact.configurations == []
        assert any("not an FIT" in note for note in artifact.notes)

    def test_deep_nesting_is_rejected_not_recursed(self, tmp_path: Path) -> None:
        root = Node("")
        current = root
        for index in range(40):
            child = Node(f"level{index}")
            current.child(child)
            current = child
        path = tmp_path / "deep.dtb"
        path.write_bytes(build_fdt(root))

        with pytest.raises(FitDtbError, match="nesting deeper"):
            parse_fdt(open_bounded(path))

    def test_a_truncated_declared_size_is_rejected(self, tmp_path: Path) -> None:
        data = board_dtb()
        path = tmp_path / "truncated.dtb"
        path.write_bytes(data[: len(data) // 2])

        with pytest.raises(FitDtbError, match="truncated"):
            parse_fdt(open_bounded(path))

    def test_bad_magic_is_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.dtb"
        path.write_bytes(b"\x00" * 64)

        with pytest.raises(FitDtbError, match="magic"):
            parse_fdt(open_bounded(path))

    def test_a_property_name_offset_outside_the_table_is_rejected(self, tmp_path: Path) -> None:
        data = bytearray(board_dtb())
        # The first property's name offset sits 12 bytes into the structure.
        structure_offset = int.from_bytes(data[8:12], "big")
        name_offset_position = structure_offset + 12 + 4
        data[name_offset_position : name_offset_position + 4] = (0xFFFFFF).to_bytes(4, "big")
        path = tmp_path / "bad-name.dtb"
        path.write_bytes(bytes(data))

        with pytest.raises(FitDtbError, match="string table"):
            parse_fdt(open_bounded(path))


# ──────────────────────────────────────────────
# FIT integrity, signature and configuration facts
# ──────────────────────────────────────────────


class TestFitAnalysis:
    def test_a_pair_resolves_the_kernel_and_the_device_tree(self, tmp_path: Path) -> None:
        fixture = build_fit()
        path = tmp_path / "fit.itb"
        path.write_bytes(fixture.data)

        artifact, omissions = _parse(path)

        assert omissions == []
        assert artifact.kind == "fit"
        assert artifact.default_config == "config-1"
        config = selected_configuration(artifact)
        assert config is not None
        assert (config.kernel, config.fdt) == ("kernel-1", "fdt-1")
        payloads = {payload.kind: payload for payload in artifact.referenced_payloads}
        assert payloads["kernel"].node == "/images/kernel-1"
        assert payloads["fdt"].node == "/images/fdt-1"
        assert payloads["kernel"].integrity == "match"
        assert payloads["fdt"].integrity == "match"
        assert payloads["kernel"].digest_observed is not None
        assert payloads["fdt"].board is not None
        assert payloads["fdt"].board["compatible"] == ["test,board", "test,soc"]
        assert payloads["fdt"].board["partitions"][0]["label"] == "firmware"

    def test_a_mismatched_payload_fails_integrity(self, tmp_path: Path) -> None:
        fixture = build_fit(declare_wrong_hash=True)
        path = tmp_path / "bad-hash.itb"
        path.write_bytes(fixture.data)

        artifact, omissions = _parse(path)

        payload = next(p for p in artifact.referenced_payloads if p.kind == "fdt")
        assert payload.integrity == "mismatch"
        assert payload.digest_declared == "00" * 32
        assert payload.digest_observed != payload.digest_declared
        assert omissions == []
        assert any("declared sha256" in item for item in artifact.notes)

    def test_an_out_of_bounds_payload_range_is_recorded(self, tmp_path: Path) -> None:
        fixture = build_fit(out_of_bounds=True)
        path = tmp_path / "oob.itb"
        path.write_bytes(fixture.data)

        artifact, omissions = _parse(path)

        payload = next(p for p in artifact.referenced_payloads if p.kind == "fdt")
        assert payload.integrity == "out-of-bounds"
        assert payload.digest_observed is None
        assert any("outside the artifact" in item for item in omissions)

    def test_a_truncated_fit_is_a_named_error(self, tmp_path: Path) -> None:
        fixture = build_fit(truncated=200)
        path = tmp_path / "truncated.itb"
        path.write_bytes(fixture.data)

        with pytest.raises(FitDtbError):
            parse_fdt(open_bounded(path))

    def test_no_configurations_means_no_selected_configuration(self, tmp_path: Path) -> None:
        root = Node("")
        images = Node("images")
        images.child(Node("kernel-1").add_str("type", "kernel"))
        root.child(images)
        path = tmp_path / "no-config.itb"
        path.write_bytes(build_fdt(root))

        artifact, _ = _parse(path)

        assert artifact.kind == "fit"
        assert artifact.configurations == []
        assert artifact.default_config is None
        assert selected_configuration(artifact) is None
        assert any(
            "no selected configuration" in note.lower() or "No configuration" in note
            for note in artifact.notes
        )

    def test_an_absent_key_leaves_authenticity_unverified(self, tmp_path: Path) -> None:
        fixture = build_fit(sign_config="config-1")
        path = tmp_path / "signed.itb"
        path.write_bytes(fixture.data)

        artifact, _ = _parse(path)

        signature = artifact.configurations[0].signature
        assert signature.present is True
        assert signature.verified is None
        assert signature.key_source == "none"

    def test_a_supplied_key_verifies_only_the_selected_configuration(self, tmp_path: Path) -> None:
        fixture = build_fit(sign_config="config-1")
        path = tmp_path / "signed.itb"
        path.write_bytes(fixture.data)
        key = tmp_path / "test-key.pem"
        key.write_bytes(public_key_pem())
        anchor = load_trust_anchor(key)

        artifact, _ = _parse(path, anchors=[anchor])

        signature = artifact.configurations[0].signature
        assert signature.present is True
        assert signature.verified is True
        assert signature.key_source == "operator-supplied"
        assert signature.key_sha256 == anchor.sha256

    def test_a_signature_over_another_configuration_is_not_promoted(self, tmp_path: Path) -> None:
        fixture = build_fit(sign_config="config-2", extra_configurations=["config-2"])
        path = tmp_path / "other-config.itb"
        path.write_bytes(fixture.data)
        key = tmp_path / "test-key.pem"
        key.write_bytes(public_key_pem())
        anchor = load_trust_anchor(key)

        artifact, _ = _parse(path, anchors=[anchor])

        selected = selected_configuration(artifact)
        assert selected is not None and selected.name == "config-1"
        assert selected.signature.present is False
        assert selected.signature.verified is None
        signed = next(c for c in artifact.configurations if c.name == "config-2")
        assert signed.signature.verified is True

    def test_a_certificate_is_not_accepted_as_a_trust_anchor(self, tmp_path: Path) -> None:
        key = tmp_path / "cert.pem"
        key.write_bytes(b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")

        with pytest.raises(TrustAnchorError, match=r"public key, not a certificate|base64"):
            load_trust_anchor(key)


# ──────────────────────────────────────────────
# Independent check: DTC and mkimage, in the verification image
# ──────────────────────────────────────────────


def _container_tool() -> str | None:
    if shutil.which("docker"):
        return "docker"
    if shutil.which("podman"):
        return "podman"
    return None


def _shared_dir() -> Path:
    """A directory the colima VM can mount: only $HOME is visible on macOS."""
    path = Path.home() / ".cache" / "ihs-fit-oracle"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _run_tool(tool: str, directory: Path, argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            tool,
            "run",
            "--rm",
            "-v",
            f"{directory}:/w",
            "--entrypoint",
            argv[0],
            VERIFY_WORKER_IMAGE,
            *argv[1:],
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_dtc_and_mkimage_agree_with_the_parsed_facts(tmp_path: Path) -> None:
    tool = _container_tool()
    if tool is None:
        pytest.skip("no container runtime for the DTC/u-boot-tools cross-check")
    probe = subprocess.run(
        [tool, "image", "inspect", VERIFY_WORKER_IMAGE],
        capture_output=True,
        text=True,
    )
    if probe.returncode != 0:
        pytest.skip(f"verification image {VERIFY_WORKER_IMAGE} is not present")

    shared = _shared_dir()
    (shared / "board.dtb").write_bytes(board_dtb())
    fixture = build_fit()
    (shared / "fit.itb").write_bytes(fixture.data)
    artifact, _ = _parse(shared / "fit.itb")

    model = _run_tool(tool, shared, ["/usr/bin/fdtget", "/w/board.dtb", "/", "model"])
    assert model.returncode == 0, model.stderr
    assert model.stdout.strip() == "IHS Test Board"

    memory = _run_tool(tool, shared, ["/usr/bin/fdtget", "/w/board.dtb", "/memory@40000000", "reg"])
    assert memory.stdout.split() == ["0", "1073741824", "268435456"]

    label = _run_tool(
        tool,
        shared,
        [
            "/usr/bin/fdtget",
            "/w/board.dtb",
            "/flash@0/partitions/partition@0",
            "label",
        ],
    )
    assert label.stdout.strip() == "firmware"

    listing = _run_tool(tool, shared, ["/usr/bin/mkimage", "-l", "/w/fit.itb"])
    assert listing.returncode == 0, listing.stderr
    assert "Default Configuration: 'config-1'" in listing.stdout
    assert "Kernel:       kernel-1" in listing.stdout
    assert "fdt-1" in listing.stdout
    fdt_payload = next(payload for payload in artifact.referenced_payloads if payload.kind == "fdt")
    assert fdt_payload.digest_observed is not None
    # mkimage prints the hash value it read from the same hash node.
    assert hashlib.sha256(fixture.dtb).hexdigest() == fdt_payload.digest_declared, (
        "fixture hash and the parsed declaration must be the same bytes"
    )
    dumped = _run_tool(tool, shared, ["/usr/bin/fdtdump", "/w/board.dtb"])
    assert 'compatible = "test,board", "test,soc";' in dumped.stdout


def test_boot_parsing_issues_no_request(tmp_path: Path, monkeypatch) -> None:
    """A parse is local: any socket creation is a failure, not a slow path."""
    import socket

    def refuse(*_args, **_kwargs):
        raise AssertionError("boot parsing attempted a network operation")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)

    path = tmp_path / "fit.itb"
    path.write_bytes(build_fit().data)
    artifact, _ = _parse(path)
    assert artifact.kind == "fit"
