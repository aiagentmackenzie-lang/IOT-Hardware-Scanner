"""CycloneDX 1.6 export (5A): offline validation and traceable identity.

The export is only useful if two things hold, so both are asserted here:

* the emitted BOM **validates offline** against the versioned schema vendored in
  the package (no network, no "latest" schema), and
* **every** component maps back to the firmware digest of the scan and to the
  inventory record that evidenced it — a component without a traceable identity
  is refused instead of written with a placeholder.

The rows run against the shipped code, and the same export is exercised through
the installed CLI in ``test_installed_cli.py`` and
``test_installed_image_cli.py``.
"""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from test_comparison import FIRMWARE_A, scan_document

from iot_hardware_scanner import __version__
from iot_hardware_scanner.cli import main
from iot_hardware_scanner.scanner.sbom_export import (
    CYCLONEDX_SPEC_VERSION,
    SbomExportError,
    component_bom_ref,
    export_sbom,
    render_sbom,
    validate_sbom,
)


def _component(**overrides: Any) -> dict[str, Any]:
    component = {
        "vendor": "busybox",
        "product": "busybox",
        "version": "1.36.1-r2",
        "cpe": "cpe:2.3:a:busybox:busybox:1.36.1-r2:*:*:*:*:*:*:*",
        "cpe_basis": "nist-mapped",
        "source_file": "rootfs/usr/lib/opkg/status",
        "source_method": "opkg_status",
        "confidence": "recorded",
        "evidence": "rootfs/usr/lib/opkg/status:8-72 (line 2)",
        "digest_sha256": "9" * 64,
        "architecture": "aarch64_generic",
        "occurrences": ["rootfs/usr/lib/opkg/status:8-72"],
    }
    component.update(overrides)
    return component


@pytest.fixture
def document() -> dict[str, Any]:
    return scan_document(
        components=[
            _component(),
            _component(
                vendor="openwrt",
                product="uhttpd",
                version="2024.01.01-r1",
                cpe="cpe:2.3:a:openwrt:uhttpd:2024.01.01-r1:*:*:*:*:*:*:*",
                cpe_basis="opkg-package-name",
                evidence="rootfs/usr/lib/opkg/status:80-140 (line 9)",
                occurrences=["rootfs/usr/lib/opkg/status:80-140"],
            ),
        ]
    )


class TestExport:
    def test_the_export_validates_against_the_vendored_16_schema(
        self, document: dict[str, Any]
    ) -> None:
        payload = export_sbom(document, tool_version=__version__)
        assert payload["bomFormat"] == "CycloneDX"
        assert payload["specVersion"] == CYCLONEDX_SPEC_VERSION == "1.6"
        validate_sbom(payload)  # raises on any schema violation

    def test_every_component_maps_back_to_the_firmware_and_its_record(
        self, document: dict[str, Any]
    ) -> None:
        payload = export_sbom(document, tool_version=__version__)
        firmware = payload["metadata"]["component"]
        assert firmware["bom-ref"] == f"urn:ihs:firmware:{FIRMWARE_A}"
        assert firmware["hashes"] == [{"alg": "SHA-256", "content": FIRMWARE_A}]

        source = {
            component_bom_ref(entry["vendor"], entry["product"], entry["version"]): entry
            for entry in document["components"]
        }
        for component in payload["components"]:
            properties = {item["name"]: item["value"] for item in component["properties"]}
            assert properties["ihs:firmware-sha256"] == FIRMWARE_A
            original = source[component["bom-ref"]]
            assert properties["ihs:evidence"] == original["evidence"]
            assert properties["ihs:cpe-basis"] == original["cpe_basis"]
            assert properties["ihs:database-sha256"] == original["digest_sha256"]
            assert component["bom-ref"] == component_bom_ref(
                original["vendor"], original["product"], original["version"]
            )

    def test_the_dependency_graph_names_every_component_once(
        self, document: dict[str, Any]
    ) -> None:
        payload = export_sbom(document, tool_version=__version__)
        dependencies = payload["dependencies"]
        assert len(dependencies) == 1
        assert dependencies[0]["ref"] == payload["metadata"]["component"]["bom-ref"]
        assert dependencies[0]["dependsOn"] == [
            component["bom-ref"] for component in payload["components"]
        ]

    def test_the_same_document_exports_the_same_bytes(self, document: dict[str, Any]) -> None:
        first = render_sbom(export_sbom(document, tool_version=__version__))
        second = render_sbom(export_sbom(deepcopy(document), tool_version=__version__))
        assert first == second

    def test_a_component_without_identity_is_refused(self, document: dict[str, Any]) -> None:
        document["components"][0]["version"] = ""
        with pytest.raises(SbomExportError) as excinfo:
            export_sbom(document, tool_version=__version__)
        assert "traceable identity" in str(excinfo.value)

    def test_a_component_without_evidence_is_refused(self, document: dict[str, Any]) -> None:
        document["components"][0]["evidence"] = ""
        document["components"][0]["occurrences"] = []
        with pytest.raises(SbomExportError):
            export_sbom(document, tool_version=__version__)

    def test_a_document_without_components_is_refused(self) -> None:
        with pytest.raises(SbomExportError):
            export_sbom(scan_document(components=[]), tool_version=__version__)

    def test_a_document_without_an_artifact_digest_is_refused(self) -> None:
        document = scan_document()
        document["artifact"]["sha256"] = ""
        with pytest.raises(SbomExportError) as excinfo:
            export_sbom(document, tool_version=__version__)
        assert "artifact digest" in str(excinfo.value)

    def test_the_schema_files_ship_inside_the_package(self) -> None:
        from iot_hardware_scanner.scanner.sbom_export import schema_directory

        directory = schema_directory()
        for name in ("bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json"):
            assert (directory / name).is_file(), name


class TestSbomCommand:
    def _write(self, path: Path, document: dict[str, Any]) -> Path:
        path.write_text(json.dumps(document))
        return path

    def test_the_command_writes_a_validated_bom(
        self, tmp_path: Path, document: dict[str, Any]
    ) -> None:
        scan = self._write(tmp_path / "scan.json", document)
        destination = tmp_path / "bom.cdx.json"
        result = CliRunner().invoke(
            main, ["sbom", str(scan), "--out", str(destination), "--validate"]
        )
        assert result.exit_code == 0, result.output
        assert "Validated offline" in result.output
        payload = json.loads(destination.read_text())
        assert payload["specVersion"] == "1.6"
        validate_sbom(payload)

    def test_the_command_refuses_a_document_that_is_not_a_scan(self, tmp_path: Path) -> None:
        scan = self._write(
            tmp_path / "other.json",
            {"schema_version": 5, "artifact": {"name": "x"}, "assessment": {}},
        )
        result = CliRunner().invoke(main, ["sbom", str(scan)])
        assert result.exit_code == 3
        assert "artifact digest" in result.output

    def test_an_unwritable_destination_is_six_not_success(
        self, tmp_path: Path, document: dict[str, Any]
    ) -> None:
        scan = self._write(tmp_path / "scan.json", document)
        blocker = tmp_path / "blocker"
        blocker.write_text("not a directory")
        result = CliRunner().invoke(main, ["sbom", str(scan), "--out", str(blocker / "bom.json")])
        assert result.exit_code == 6
        assert "BOM not written" in result.output
