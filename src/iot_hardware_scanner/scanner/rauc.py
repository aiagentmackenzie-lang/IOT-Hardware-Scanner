"""RAUC update bundles (slice 3E): an update is a *proposed* device state.

A RAUC bundle is a SquashFS image whose root holds a ``manifest.raucm`` and the
payload images the manifest names. Installed, it replaces one slot of a
redundant A/B system. Nothing here can know which slot is *running* — that is a
fact about the device, not about the artifact — so it is always reported as
``unknown`` and never inferred from the slot order.

What this module decides, and what it refuses to decide:

* **The manifest is a declaration.** Its ``compatible`` string says which board
  the release is for; it is recorded, not matched against a device nobody asked.
* **A payload is what its bytes are.** Every image's declared SHA-256 and size
  are checked against the file the bundle actually carries. A mismatch
  **invalidates that slot's association**: the bytes in the bundle are not the
  bytes the manifest describes, so nothing about them may be attributed to the
  slot. ``UNCHECKED`` (no digest declared) is not ``VERIFIED``.
* **A signature is presence first, verification second.** RAUC appends a detached
  CMS signature after the SquashFS extent, which this scanner already measures
  as ``extent_bytes``. Presence is a byte count and is always reportable; whether
  it verifies against a trust store is a separate field, and in this release it
  is ``None`` with the reason stated rather than guessed.
* **An installed hook is an artifact.** A custom handler named by the manifest is
  a script inside the bundle; it is scanned like any other file, never executed.

The parser is text-only and takes the manifest exactly as RAUC writes it
(``configparser``-compatible INI, ``[update]``, ``[bundle]``, ``[image.<slot>]``,
``[handler]``). Everything that needs the bundle's *files* is done by the caller,
which has the extracted tree; this module never opens a path.
"""

from __future__ import annotations

import configparser
from dataclasses import dataclass, field
from typing import Any

#: The manifest file every RAUC bundle carries at its root.
RAUC_MANIFEST_NAME = "manifest.raucm"

#: Image states. ``VERIFIED`` is the only one that may carry a slot association.
VERIFIED = "VERIFIED"
MISMATCH = "MISMATCH"
MISSING = "MISSING"
UNCHECKED = "UNCHECKED"

#: Slots a bundle may target. An unknown class is reported by its own name.
KNOWN_SLOT_CLASSES = ("rootfs", "recovery", "appfs", "boot", "data")

RAUC_DECODER_NAME = "ihs-rauc"
RAUC_DECODER_VERSION = "1"


class RaucError(Exception):
    """A manifest that cannot be read as a manifest."""


@dataclass
class RaucImage:
    """One ``[image.<slot>]`` section, and what the bytes did about it."""

    slot: str
    slot_class: str
    slot_name: str | None
    filename: str
    declared_sha256: str | None = None
    declared_size: int | None = None
    hooks: list[str] = field(default_factory=list)
    state: str = UNCHECKED
    actual_sha256: str | None = None
    actual_size: int | None = None
    #: The root filesystem this payload produced, when it was decoded.
    root_id: str | None = None
    detail: str | None = None

    @property
    def association_valid(self) -> bool:
        """Whether anything may be attributed to this slot."""
        return self.state == VERIFIED

    def as_dict(self) -> dict[str, Any]:
        return {
            "slot": self.slot,
            "slot_class": self.slot_class,
            "slot_name": self.slot_name,
            "filename": self.filename,
            "declared_sha256": self.declared_sha256,
            "declared_size": self.declared_size,
            "actual_sha256": self.actual_sha256,
            "actual_size": self.actual_size,
            "state": self.state,
            "hooks": list(self.hooks),
            "root_id": self.root_id,
            "detail": self.detail,
        }


@dataclass
class RaucSignature:
    """The detached CMS block appended to the bundle, as far as bytes go.

    ``present`` and ``bytes`` come from the file's size against the SquashFS
    extent. ``verified`` stays ``None`` in this release: a trust decision needs a
    supplied certificate *and* a CMS verifier, and reporting ``False`` for an
    unchecked signature would read as "checked and invalid".
    """

    present: bool = False
    bytes: int = 0
    verified: bool | None = None
    reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "present": self.present,
            "bytes": self.bytes,
            "verified": self.verified,
            "reason": self.reason,
        }


@dataclass
class RaucBundle:
    """A bundle as its manifest declares it, plus the facts the bytes supplied."""

    compatible: str = ""
    version: str | None = None
    description: str | None = None
    build: str | None = None
    bundle_format: str | None = None
    images: list[RaucImage] = field(default_factory=list)
    handler: dict[str, Any] | None = None
    #: The detached CMS block after the SquashFS extent, as far as bytes go.
    signature: RaucSignature = field(default_factory=RaucSignature)
    diagnostics: list[str] = field(default_factory=list)
    #: Always ``unknown``: a static artifact cannot name the slot a device booted.
    running_slot: str = "unknown"
    decoder: str = RAUC_DECODER_NAME
    decoder_version: str = RAUC_DECODER_VERSION

    @property
    def verified_images(self) -> list[RaucImage]:
        return [image for image in self.images if image.association_valid]

    @property
    def invalidated(self) -> list[RaucImage]:
        return [image for image in self.images if image.state in (MISMATCH, MISSING)]

    def by_slot_class(self, slot_class: str) -> RaucImage | None:
        return next((image for image in self.images if image.slot_class == slot_class), None)

    def as_dict(self) -> dict[str, Any]:
        return {
            "compatible": self.compatible,
            "version": self.version,
            "description": self.description,
            "build": self.build,
            "bundle_format": self.bundle_format,
            "running_slot": self.running_slot,
            "decoder": self.decoder,
            "decoder_version": self.decoder_version,
            "images": [image.as_dict() for image in self.images],
            "handler": self.handler,
            "signature": self.signature.as_dict(),
            "diagnostics": list(self.diagnostics),
        }


def is_rauc_manifest_name(name: str) -> bool:
    """Whether a path's base name is the manifest RAUC writes."""
    return name.rsplit("/", 1)[-1] == RAUC_MANIFEST_NAME


def parse_manifest(text: str) -> RaucBundle:
    """Parse ``manifest.raucm`` into the bundle it declares.

    A manifest that does not parse, or that declares no ``[update] compatible``
    string, is not a bundle description: the caller is told, and the slot
    association is never attempted. An image section without a ``filename`` is
    equally refused — a slot with no payload is not a slot.
    """
    # ``strict=True``: a duplicate ``[image.x]`` section would silently keep only
    # the last payload, which is a lost slot, not a layout.
    parser = configparser.ConfigParser(strict=True, interpolation=None)
    parser.optionxform = str  # type: ignore[assignment]  # keys are case-sensitive
    try:
        parser.read_string(text)
    except configparser.Error as exc:
        raise RaucError(f"the manifest is not a readable INI document: {exc}") from exc

    if not parser.has_section("update"):
        raise RaucError("the manifest has no [update] section")
    compatible = parser.get("update", "compatible", fallback="").strip()
    if not compatible:
        raise RaucError("the manifest declares no compatible board string")

    bundle = RaucBundle(
        compatible=compatible,
        version=parser.get("update", "version", fallback=None),
        description=parser.get("update", "description", fallback=None),
        build=parser.get("update", "build", fallback=None),
        bundle_format=parser.get("bundle", "format", fallback=None),
    )

    for section in parser.sections():
        if not section.startswith("image."):
            continue
        slot = section.split(".", 1)[1]
        if not slot:
            raise RaucError("an [image.] section names no slot")
        slot_class, _, slot_name = slot.partition(".")
        filename = parser.get(section, "filename", fallback="").strip()
        if not filename:
            raise RaucError(f"the image section {slot!r} names no filename")
        sha256 = _optional(parser, section, "sha256")
        if sha256 is not None:
            sha256 = sha256.lower()
            if len(sha256) != 64 or any(char not in "0123456789abcdef" for char in sha256):
                raise RaucError(f"the image section {slot!r} declares a malformed sha256")
        size = _optional_int(parser, section, "size")
        hooks = [
            hook.strip()
            for hook in (parser.get(section, "hooks", fallback="") or "").split()
            if hook.strip()
        ]
        bundle.images.append(
            RaucImage(
                slot=slot,
                slot_class=slot_class,
                slot_name=slot_name or None,
                filename=filename,
                declared_sha256=sha256,
                declared_size=size,
                hooks=hooks,
            )
        )

    if not bundle.images:
        raise RaucError("the manifest declares no image section")

    if parser.has_section("handler"):
        bundle.handler = {
            "filename": parser.get("handler", "filename", fallback=None),
            "sha256": _optional(parser, "handler", "sha256"),
            "size": _optional_int(parser, "handler", "size"),
        }

    return bundle


def _optional(parser: configparser.ConfigParser, section: str, key: str) -> str | None:
    value = parser.get(section, key, fallback=None)
    if value is None:
        return None
    value = value.strip()
    return value or None


def _optional_int(parser: configparser.ConfigParser, section: str, key: str) -> int | None:
    value = _optional(parser, section, key)
    if value is None:
        return None
    if value.startswith("0x"):
        return int(value, 16)
    try:
        return int(value)
    except ValueError as exc:
        raise RaucError(f"the {key} field of {section!r} is not an integer: {value!r}") from exc


def apply_payload_facts(
    bundle: RaucBundle,
    *,
    sizes: dict[str, int],
    digests: dict[str, str],
) -> None:
    """Settle each image's state from the bytes the bundle actually carries.

    ``sizes`` and ``digests`` are keyed by the manifest's ``filename`` as the
    caller found it in the extracted tree. A file the manifest names but the
    bundle does not carry is ``MISSING``; a file whose size or digest disagrees is
    ``MISMATCH``; a section that declares no digest is ``UNCHECKED`` — never
    ``VERIFIED``, because nothing was checked.
    """
    for image in bundle.images:
        actual_size = sizes.get(image.filename)
        actual_digest = digests.get(image.filename)
        image.actual_size = actual_size
        image.actual_sha256 = actual_digest
        if actual_size is None:
            image.state = MISSING
            image.detail = "the bundle does not carry a file with this name"
            continue
        if image.declared_size is not None and actual_size != image.declared_size:
            image.state = MISMATCH
            image.detail = (
                f"the manifest declares {image.declared_size} byte(s), the bundle carries "
                f"{actual_size}"
            )
            continue
        if image.declared_sha256 is None:
            image.state = UNCHECKED
            image.detail = "the manifest declares no sha256 for this payload"
            continue
        if actual_digest is None:
            image.state = UNCHECKED
            image.detail = "this payload was not hashed by this scan"
            continue
        if actual_digest != image.declared_sha256:
            image.state = MISMATCH
            image.detail = (
                "the payload's bytes do not hash to the digest the manifest declares; "
                "nothing in it may be attributed to this slot"
            )
            continue
        image.state = VERIFIED


def signature_from_extent(*, file_size: int, squashfs_extent: int) -> RaucSignature:
    """Describe the detached signature RAUC appends after the filesystem.

    RAUC's bundle is a SquashFS image with a CMS signature appended: the
    superblock's ``bytes_used`` is where the filesystem ends, and everything after
    it is the signature block. Presence is arithmetic; verification needs a trust
    store and a CMS implementation, so ``verified`` is ``None`` here and the reason
    says so — ``False`` would read as "checked and invalid".
    """
    trailing = file_size - squashfs_extent
    if squashfs_extent <= 0 or trailing <= 0:
        return RaucSignature(present=False, bytes=0, verified=None, reason=None)
    return RaucSignature(
        present=True,
        bytes=trailing,
        verified=None,
        reason=(
            "a detached signature is present; verifying it needs a trust store and a CMS "
            "verifier, and this release supplies neither for RAUC bundles"
        ),
    )
