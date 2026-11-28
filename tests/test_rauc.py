"""RAUC bundle manifests (slice 3E).

The manifest is the only part of a bundle that says what the payloads *mean*, and
it is text: these rows need no worker, no bundle image and no container runtime.
What they pin is the refusal discipline — a slot is only associated with bytes that
hash to what the manifest declares, ``UNCHECKED`` is never ``VERIFIED``, and the
running slot is never inferred.
"""

from __future__ import annotations

import pytest

from iot_hardware_scanner.scanner.rauc import (
    MISMATCH,
    MISSING,
    UNCHECKED,
    VERIFIED,
    RaucError,
    apply_payload_facts,
    is_rauc_manifest_name,
    parse_manifest,
    signature_from_extent,
)

SHA_ROOTFS = "a" * 64
SHA_RECOVERY = "b" * 64

MANIFEST = f"""\
[update]
compatible=my-board-v1
version=2026.11.0
description=Mighty release
build=20261128010102-1

[bundle]
format=verity

[handler]
filename=custom_handler.sh
sha256={"c" * 64}
size=321

[image.rootfs]
filename=rootfs.ext4
sha256={SHA_ROOTFS}
size=1048576

[image.recovery]
filename=recovery.squashfs
sha256={SHA_RECOVERY}
size=4096
hooks=post-install
"""


def test_a_manifest_is_read_as_the_bundle_it_declares() -> None:
    bundle = parse_manifest(MANIFEST)

    assert bundle.compatible == "my-board-v1"
    assert bundle.version == "2026.11.0"
    assert bundle.description == "Mighty release"
    assert bundle.build == "20261128010102-1"
    assert bundle.bundle_format == "verity"
    assert [image.slot for image in bundle.images] == ["rootfs", "recovery"]
    assert [image.slot_class for image in bundle.images] == ["rootfs", "recovery"]
    assert bundle.images[0].declared_sha256 == SHA_ROOTFS
    assert bundle.images[0].declared_size == 1_048_576
    assert bundle.images[1].hooks == ["post-install"]
    assert bundle.handler == {
        "filename": "custom_handler.sh",
        "sha256": "c" * 64,
        "size": 321,
    }


def test_the_running_slot_is_never_inferred() -> None:
    """A static artifact cannot name the slot a device booted from."""
    bundle = parse_manifest(MANIFEST)
    assert bundle.running_slot == "unknown"
    assert bundle.as_dict()["running_slot"] == "unknown"


def test_optional_update_fields_may_be_absent() -> None:
    bundle = parse_manifest("[update]\ncompatible=board\n[image.rootfs]\nfilename=rootfs.img\n")
    assert bundle.version is None
    assert bundle.description is None
    assert bundle.build is None
    assert bundle.bundle_format is None
    assert bundle.handler is None


def test_a_manifest_with_no_update_section_is_refused() -> None:
    with pytest.raises(RaucError, match=r"no \[update\] section"):
        parse_manifest("[image.rootfs]\nfilename=rootfs.img\n")


def test_a_manifest_with_no_compatible_string_is_refused() -> None:
    with pytest.raises(RaucError, match="compatible board string"):
        parse_manifest("[update]\nversion=1\n[image.rootfs]\nfilename=rootfs.img\n")


def test_an_image_section_with_no_filename_is_refused() -> None:
    with pytest.raises(RaucError, match="names no filename"):
        parse_manifest("[update]\ncompatible=board\n[image.rootfs]\nsha256=" + SHA_ROOTFS + "\n")


def test_a_manifest_with_no_image_is_refused() -> None:
    with pytest.raises(RaucError, match="no image section"):
        parse_manifest("[update]\ncompatible=board\n")


def test_a_malformed_digest_is_refused_rather_than_compared() -> None:
    """A short digest compares against nothing; it must not become a silent mismatch."""
    with pytest.raises(RaucError, match="malformed sha256"):
        parse_manifest("[update]\ncompatible=board\n[image.rootfs]\nfilename=x\nsha256=abc123\n")


def test_a_malformed_size_is_refused() -> None:
    with pytest.raises(RaucError, match="not an integer"):
        parse_manifest("[update]\ncompatible=board\n[image.rootfs]\nfilename=x\nsize=big\n")


def test_a_hexadecimal_size_is_accepted() -> None:
    bundle = parse_manifest("[update]\ncompatible=board\n[image.rootfs]\nfilename=x\nsize=0x1000\n")
    assert bundle.images[0].declared_size == 4096


def test_manifest_keys_are_case_sensitive() -> None:
    """``Filename`` is not ``filename``: a manifest is not fuzzy-matched."""
    with pytest.raises(RaucError, match="names no filename"):
        parse_manifest("[update]\ncompatible=board\n[image.rootfs]\nFilename=x\n")


def test_a_section_may_name_a_specific_slot() -> None:
    bundle = parse_manifest("[update]\ncompatible=board\n[image.rootfs.0]\nfilename=rootfs-0.img\n")
    assert bundle.images[0].slot == "rootfs.0"
    assert bundle.images[0].slot_class == "rootfs"
    assert bundle.images[0].slot_name == "0"


def test_a_duplicate_image_section_is_refused_not_merged() -> None:
    """``strict=False`` would keep only the last payload: a lost slot, not a layout."""
    with pytest.raises(RaucError, match="not a readable INI document"):
        parse_manifest(
            "[update]\ncompatible=board\n[image.rootfs]\nfilename=a\n[image.rootfs]\nfilename=b\n"
        )


def test_two_payloads_of_one_class_with_slot_names_are_both_kept() -> None:
    bundle = parse_manifest(
        "[update]\ncompatible=board\n[image.rootfs.0]\nfilename=a\n[image.rootfs.1]\nfilename=b\n"
    )
    assert [image.slot_name for image in bundle.images] == ["0", "1"]
    assert bundle.diagnostics == []


# ──────────────────────────────────────────────
# Payload facts: the bytes decide, not the manifest
# ──────────────────────────────────────────────


def _bundle() -> object:
    return parse_manifest(MANIFEST)


def test_matching_size_and_digest_is_the_only_verified_state() -> None:
    bundle = _bundle()
    apply_payload_facts(
        bundle,
        sizes={"rootfs.ext4": 1_048_576, "recovery.squashfs": 4096},
        digests={"rootfs.ext4": SHA_ROOTFS, "recovery.squashfs": SHA_RECOVERY},
    )
    assert [image.state for image in bundle.images] == [VERIFIED, VERIFIED]
    assert all(image.association_valid for image in bundle.images)


def test_a_different_digest_invalidates_the_slot() -> None:
    bundle = _bundle()
    apply_payload_facts(
        bundle,
        sizes={"rootfs.ext4": 1_048_576, "recovery.squashfs": 4096},
        digests={"rootfs.ext4": "d" * 64, "recovery.squashfs": SHA_RECOVERY},
    )
    rootfs = bundle.images[0]
    assert rootfs.state == MISMATCH
    assert rootfs.association_valid is False
    assert "do not hash to the digest" in (rootfs.detail or "")
    # The other slot is untouched: one bad payload does not poison the bundle.
    assert bundle.images[1].state == VERIFIED
    assert bundle.invalidated == [rootfs]


def test_a_size_disagreement_invalidates_the_slot_even_when_the_digest_matches() -> None:
    bundle = _bundle()
    apply_payload_facts(
        bundle,
        sizes={"rootfs.ext4": 1_048_575, "recovery.squashfs": 4096},
        digests={"rootfs.ext4": SHA_ROOTFS, "recovery.squashfs": SHA_RECOVERY},
    )
    assert bundle.images[0].state == MISMATCH
    assert "declares 1048576 byte(s)" in (bundle.images[0].detail or "")


def test_a_payload_the_bundle_does_not_carry_is_missing() -> None:
    bundle = _bundle()
    apply_payload_facts(bundle, sizes={}, digests={})
    assert [image.state for image in bundle.images] == [MISSING, MISSING]
    assert bundle.verified_images == []


def test_no_declared_digest_is_unchecked_never_verified() -> None:
    """Older ``format=plain`` bundles may omit ``sha256``; that is not a pass."""
    bundle = parse_manifest("[update]\ncompatible=board\n[image.rootfs]\nfilename=x\n")
    apply_payload_facts(bundle, sizes={"x": 10}, digests={"x": "e" * 64})
    assert bundle.images[0].state == UNCHECKED
    assert bundle.images[0].association_valid is False
    assert "declares no sha256" in (bundle.images[0].detail or "")


def test_a_declared_digest_with_no_actual_one_is_unchecked() -> None:
    bundle = _bundle()
    apply_payload_facts(bundle, sizes={"rootfs.ext4": 1_048_576}, digests={})
    assert bundle.images[0].state == UNCHECKED
    assert "was not hashed" in (bundle.images[0].detail or "")


def test_a_slot_class_lookup_names_the_payload() -> None:
    bundle = _bundle()
    apply_payload_facts(
        bundle,
        sizes={"rootfs.ext4": 1_048_576, "recovery.squashfs": 4096},
        digests={"rootfs.ext4": SHA_ROOTFS, "recovery.squashfs": SHA_RECOVERY},
    )
    recovery = bundle.by_slot_class("recovery")
    assert recovery is not None
    assert recovery.filename == "recovery.squashfs"
    assert bundle.by_slot_class("appfs") is None


# ──────────────────────────────────────────────
# The appended signature
# ──────────────────────────────────────────────


def test_trailing_bytes_are_a_present_signature() -> None:
    signature = signature_from_extent(file_size=5000, squashfs_extent=3000)
    assert signature.present is True
    assert signature.bytes == 2000


def test_a_bundle_that_ends_with_its_filesystem_has_no_signature() -> None:
    signature = signature_from_extent(file_size=3000, squashfs_extent=3000)
    assert signature.present is False
    assert signature.bytes == 0
    assert signature.verified is None


def test_a_signature_is_present_but_never_claimed_verified() -> None:
    """``False`` would read as "checked and invalid"; the honest value is ``None``."""
    signature = signature_from_extent(file_size=5000, squashfs_extent=3000)
    assert signature.verified is None
    assert "trust store" in (signature.reason or "")
    assert signature.as_dict()["present"] is True


def test_a_nonsense_extent_is_not_a_signature() -> None:
    assert signature_from_extent(file_size=10, squashfs_extent=0).present is False
    assert signature_from_extent(file_size=10, squashfs_extent=99).present is False


def test_the_manifest_name_is_matched_by_base_name() -> None:
    assert is_rauc_manifest_name("manifest.raucm")
    assert is_rauc_manifest_name("root/manifest.raucm")
    assert not is_rauc_manifest_name("manifest.raucm.bak")
    assert not is_rauc_manifest_name("MANIFEST.RAUCM")
