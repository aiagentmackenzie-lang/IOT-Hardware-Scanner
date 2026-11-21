"""CycloneDX 1.6 export for a saved scan document (slice 5A).

The export reads a scan document — never a live scan, never the firmware — and
writes a CycloneDX 1.6 JSON BOM whose components are the inventory records that
document already carries. Two rules make it worth having:

* **Every emitted component maps back.** Each one carries the firmware digest it
  belongs to and the inventory record that evidenced it, and its ``bom-ref`` is
  a deterministic function of its own identity, so a consumer can trace any
  entry back to the scan and to the byte range in the image's package database.
* **It validates offline.** The versioned CycloneDX 1.6 schema is vendored in
  this package together with the two schemas it references, so validation needs
  no network and no guess about which schema version applied.

An emitted component without a traceable identity would be worse than no
export, so a component with no version, no product or no evidence is refused
rather than written with a placeholder.

Reference: https://cyclonedx.org/docs/1.6/json/
"""

from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path
from typing import Any

from iot_hardware_scanner import resources

#: The CycloneDX version this export emits. It is a constant because a report,
#: a test and the CI gate all name it.
CYCLONEDX_SPEC_VERSION = "1.6"
SCHEMA_BASE_URI = "http://cyclonedx.org/schema/bom-1.6.schema.json"

#: The vendored schema files, by the names the schema references them with.
VENDORED_SCHEMAS = ("bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json")

#: Namespace for deterministic bom-refs and serial numbers.
_BOM_REF_PREFIX = "urn:ihs:component:"
_FIRMWARE_REF_PREFIX = "urn:ihs:firmware:"
_SERIAL_NAMESPACE = uuid.UUID("8f0d6e1c-9f6b-4d4a-9a3e-2b1c5d7e9f01")


class SbomExportError(ValueError):
    """The document cannot be exported as a traceable BOM."""


def component_bom_ref(vendor: str, product: str, version: str) -> str:
    """Deterministic ``bom-ref`` for one component identity."""
    identity = "\x00".join([vendor, product, version])
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    return f"{_BOM_REF_PREFIX}{digest}"


def firmware_bom_ref(sha256: str) -> str:
    """Deterministic ``bom-ref`` for the artifact the BOM describes."""
    return f"{_FIRMWARE_REF_PREFIX}{sha256}"


def _component_entry(component: dict[str, Any], firmware_sha256: str) -> dict[str, Any]:
    vendor = str(component.get("vendor") or "")
    product = str(component.get("product") or "")
    version = str(component.get("version") or "")
    if not product or not version:
        raise SbomExportError(
            f"a component without a product and version has no traceable identity: {component!r}"
        )
    evidence = str(component.get("evidence") or "")
    occurrences = [str(item) for item in (component.get("occurrences") or [])]
    if not evidence and not occurrences:
        raise SbomExportError(
            f"component {vendor}:{product}:{version} has no evidence and no occurrence"
        )

    properties = [
        {"name": "ihs:firmware-sha256", "value": firmware_sha256},
        {"name": "ihs:source-method", "value": str(component.get("source_method") or "")},
        {"name": "ihs:confidence", "value": str(component.get("confidence") or "")},
        {"name": "ihs:cpe-basis", "value": str(component.get("cpe_basis") or "unrecorded")},
        {
            "name": "ihs:database-sha256",
            "value": str(component.get("digest_sha256") or ""),
        },
    ]
    if evidence:
        properties.append({"name": "ihs:evidence", "value": evidence})
    for occurrence in occurrences:
        properties.append({"name": "ihs:occurrence", "value": occurrence})
    architecture = component.get("architecture")
    if architecture:
        properties.append({"name": "ihs:architecture", "value": str(architecture)})

    entry: dict[str, Any] = {
        "type": "library",
        "bom-ref": component_bom_ref(vendor, product, version),
        "group": vendor or "unknown",
        "name": product,
        "version": version,
        "scope": "required",
        "properties": properties,
    }
    cpe = str(component.get("cpe") or "")
    if cpe.startswith("cpe:2.3:"):
        entry["cpe"] = cpe
    return entry


def export_sbom(document: dict[str, Any], *, tool_version: str) -> dict[str, Any]:
    """Build a CycloneDX 1.6 BOM from one scan document.

    The document must be a scan report (``artifact`` with a SHA-256); a
    comparison document is deliberately refused, because a comparison is not an
    inventory of one artifact.
    """
    artifact = document.get("artifact") or {}
    firmware_sha256 = str(artifact.get("sha256") or "")
    if not firmware_sha256:
        raise SbomExportError("the document records no artifact digest to bind components to")
    if document.get("schema_version") is None:
        raise SbomExportError("the document is not a versioned scan report")

    components = []
    for component in document.get("components") or []:
        components.append(_component_entry(component, firmware_sha256))
    if not components:
        raise SbomExportError("the document carries no components to export")

    firmware_ref = firmware_bom_ref(firmware_sha256)
    timestamp = (
        document.get("report_generated") or document.get("scan_date") or "1970-01-01T00:00:00+00:00"
    )
    serial = uuid.uuid5(_SERIAL_NAMESPACE, f"{firmware_sha256}:{document.get('scan_id')}")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "iot-hardware-scanner",
                        "version": tool_version,
                    }
                ]
            },
            "component": {
                "type": "firmware",
                "bom-ref": firmware_ref,
                "name": str(artifact.get("name") or "artifact"),
                "version": str(artifact.get("sha256") or "")[:12],
                "hashes": [{"alg": "SHA-256", "content": firmware_sha256}],
                "properties": [
                    {"name": "ihs:artifact-kind", "value": str(artifact.get("kind") or "")},
                    {"name": "ihs:artifact-size", "value": str(artifact.get("size") or "")},
                    {
                        "name": "ihs:scan-schema-version",
                        "value": str(document.get("schema_version")),
                    },
                    {"name": "ihs:scan-id", "value": str(document.get("scan_id") or "")},
                ],
            },
        },
        "components": components,
        "dependencies": [
            {
                "ref": firmware_ref,
                "dependsOn": [entry["bom-ref"] for entry in components],
            }
        ],
    }


def schema_directory() -> Path:
    """The vendored CycloneDX 1.6 schema directory, inside the package."""
    path = resources.data_dir() / "cyclonedx-1.6"
    missing = [name for name in VENDORED_SCHEMAS if not (path / name).is_file()]
    if missing:  # pragma: no cover - packaging failure
        raise SbomExportError(f"vendored CycloneDX schema missing: {', '.join(missing)}")
    return path


def validate_sbom(payload: dict[str, Any]) -> None:
    """Validate a BOM offline against the vendored CycloneDX 1.6 schema.

    Raises :class:`SbomExportError` with the validator's messages when the BOM
    does not conform. Validation needs the ``jsonschema`` package from the
    ``sbom`` extra; without it, this raises rather than silently skipping the
    check.
    """
    try:
        from jsonschema import Draft7Validator
        from referencing import Registry, Resource
    except ModuleNotFoundError as exc:  # pragma: no cover - extra not installed
        raise SbomExportError(
            "validating an export needs the sbom extra: pip install 'iot-hardware-scanner[sbom]'"
        ) from exc

    directory = schema_directory()
    registry = Registry()
    for name in VENDORED_SCHEMAS:
        contents = json.loads((directory / name).read_text(encoding="utf-8"))
        registry = registry.with_resource(
            f"http://cyclonedx.org/schema/{name}", Resource.from_contents(contents)
        )
    schema = json.loads((directory / "bom-1.6.schema.json").read_text(encoding="utf-8"))
    validator = Draft7Validator(schema, registry=registry)
    errors = sorted(validator.iter_errors(payload), key=lambda error: list(error.path))
    if errors:
        first = errors[0]
        location = "/".join(str(part) for part in first.path)
        raise SbomExportError(
            f"the exported BOM does not validate against CycloneDX "
            f"{CYCLONEDX_SPEC_VERSION}: {first.message} (at {location or '/'})"
        )


def render_sbom(payload: dict[str, Any]) -> str:
    """Serialise a BOM deterministically."""
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"
