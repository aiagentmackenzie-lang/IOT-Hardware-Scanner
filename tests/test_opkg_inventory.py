"""opkg status parsing (4B): verbatim versions, held state and evidence ranges."""

from __future__ import annotations

from pathlib import Path

import pytest

from iot_hardware_scanner.scanner.opkg_inventory import (
    PackageIndex,
    parse_opkg_status,
    read_opkg_status,
)

STATUS = b"""Package: base-files
Version: 1589~0123456789
Depends: libc, libubox20220515
Status: install user installed
Architecture: aarch64_generic
Installed-Time: 1730000000

Package: busybox
Version: 1.36.1-r2
Depends: libc
Status: install user installed
Architecture: aarch64_generic
Source: feeds/base/busybox
Installed-Time: 1730000001

Package: libc
Version: 1.2.5-r4
Status: install hold installed
Architecture: aarch64_generic

Package: rpcd
Version: 2024.09.10
Status: deinstall user not-installed
Architecture: aarch64_generic
"""


class TestParsing:
    def test_every_stanza_is_recorded_with_its_full_version(self) -> None:
        inventory = parse_opkg_status(STATUS)
        assert [record.name for record in inventory.records] == [
            "base-files",
            "busybox",
            "libc",
            "rpcd",
        ]
        busybox = inventory.records[1]
        # The complete version string, including the package revision.
        assert busybox.version == "1.36.1-r2"
        assert busybox.architecture == "aarch64_generic"
        assert busybox.source == "feeds/base/busybox"
        assert busybox.depends == "libc"

    def test_installed_and_held_are_separate_facts(self) -> None:
        inventory = parse_opkg_status(STATUS)
        assert inventory.installed_count == 3
        assert inventory.held_count == 1
        held = next(record for record in inventory.records if record.held)
        assert held.name == "libc"
        assert held.installed

    def test_not_installed_records_are_kept_but_not_counted(self) -> None:
        inventory = parse_opkg_status(STATUS)
        rpcd = next(record for record in inventory.records if record.name == "rpcd")
        assert not rpcd.installed
        assert rpcd.status == "deinstall user not-installed"

    def test_evidence_range_locates_the_stanza(self) -> None:
        inventory = parse_opkg_status(STATUS)
        busybox = inventory.records[1]
        stanza = STATUS[busybox.evidence_start : busybox.evidence_end]
        assert stanza.startswith(b"Package: busybox\n")
        assert b"Version: 1.36.1-r2" in stanza
        assert not stanza.endswith(b"\n\n")
        assert busybox.evidence_line == 8

    def test_database_digest_is_recorded(self) -> None:
        import hashlib

        inventory = parse_opkg_status(STATUS)
        assert inventory.database_sha256 == hashlib.sha256(STATUS).hexdigest()
        assert inventory.byte_length == len(STATUS)

    def test_stanza_without_a_package_name_is_counted_not_guessed(self) -> None:
        inventory = parse_opkg_status(STATUS + b"\nVersion: 1.0\nArchitecture: all\n")
        assert inventory.unparsed_stanzas == 1

    def test_continuation_lines_do_not_create_fields(self) -> None:
        data = (
            b"Package: odd\nVersion: 2.0-r1\nDescription: a long description\n"
            b" continued on another line\nStatus: install user installed\n"
        )
        inventory = parse_opkg_status(data)
        assert inventory.records[0].version == "2.0-r1"
        assert inventory.records[0].status == "install user installed"

    def test_empty_database_yields_no_records(self) -> None:
        inventory = parse_opkg_status(b"")
        assert inventory.records == []
        assert inventory.installed_count == 0


class TestBoundedRead:
    def test_file_is_read_through_the_bounded_reader(self, tmp_path: Path) -> None:
        path = tmp_path / "status"
        path.write_bytes(STATUS)
        inventory = read_opkg_status(path, locator="rootfs/usr/lib/opkg/status")
        assert inventory.locator == "rootfs/usr/lib/opkg/status"
        assert inventory.installed_count == 3

    def test_oversized_database_is_refused_rather_than_truncated(self, tmp_path: Path) -> None:
        path = tmp_path / "status"
        path.write_bytes(STATUS * 100)
        with pytest.raises(ValueError) as excinfo:
            read_opkg_status(path, budget=len(STATUS))
        assert "budget" in str(excinfo.value)


class TestLookup:
    def test_by_name_skips_records_that_are_not_installed(self) -> None:
        index = PackageIndex(parse_opkg_status(STATUS))
        assert index.by_name("busybox") is not None
        assert index.by_name("rpcd") is None
        assert index.by_name("absent") is None

    def test_names_are_sorted_and_unique(self) -> None:
        index = PackageIndex(parse_opkg_status(STATUS))
        assert index.names() == ["base-files", "busybox", "libc"]


class TestComponentsFromRecords:
    """Every installed record becomes a component, with a recorded basis (D §2.2).

    The failure this replaces: only records whose name happened to be in the CPE
    mapping produced a component, so the reference image reported 3 of its 196
    installed packages.
    """

    def test_every_installed_record_becomes_a_component(self) -> None:
        from pathlib import Path

        from iot_hardware_scanner.orchestrator import _package_components

        inventory = parse_opkg_status(STATUS, locator="rootfs/usr/lib/opkg/status")
        components = _package_components(inventory, type("F", (), {"path": Path("x")})())

        assert [component.product for component in components] == [
            "base-files",
            "busybox",
            "libc",
        ]
        assert {component.confidence for component in components} == {"recorded"}

    def test_an_unmapped_package_is_named_from_its_own_package_name(self) -> None:
        from iot_hardware_scanner.orchestrator import _package_components

        inventory = parse_opkg_status(STATUS, locator="rootfs/usr/lib/opkg/status")
        components = _package_components(inventory, type("F", (), {"path": "x"})())
        base_files = components[0]

        assert base_files.vendor == "openwrt"
        assert base_files.product == "base-files"
        assert base_files.cpe_basis == "opkg-package-name"
        # A complete CPE 2.3 name: thirteen attributes, not a short form.
        assert base_files.cpe_string.count(":") == 12
        assert base_files.cpe_string.startswith("cpe:2.3:a:openwrt:base-files:")

    def test_a_mapped_package_keeps_its_authoritative_vendor(self) -> None:
        from iot_hardware_scanner.orchestrator import _package_components

        inventory = parse_opkg_status(STATUS, locator="rootfs/usr/lib/opkg/status")
        components = _package_components(inventory, type("F", (), {"path": "x"})())
        busybox = components[1]
        assert busybox.vendor == "busybox"
        assert busybox.cpe_basis == "nist-mapped"

    def test_the_version_is_verbatim_and_the_evidence_range_is_the_stanza(self) -> None:
        from iot_hardware_scanner.orchestrator import _package_components

        inventory = parse_opkg_status(STATUS, locator="rootfs/usr/lib/opkg/status")
        components = _package_components(inventory, type("F", (), {"path": "x"})())
        busybox = components[1]
        record = inventory.records[1]

        assert busybox.version == "1.36.1-r2"
        assert busybox.digest_sha256 == inventory.database_sha256
        assert busybox.evidence == (
            f"rootfs/usr/lib/opkg/status:{record.evidence_start}-{record.evidence_end} "
            f"(line {record.evidence_line})"
        )
        assert busybox.occurrences == [
            f"rootfs/usr/lib/opkg/status:{record.evidence_start}-{record.evidence_end}"
        ]

    def test_a_record_that_is_not_installed_produces_no_component(self) -> None:
        from iot_hardware_scanner.orchestrator import _package_components

        inventory = parse_opkg_status(STATUS, locator="rootfs/usr/lib/opkg/status")
        components = _package_components(inventory, type("F", (), {"path": "x"})())
        assert "rpcd" not in {component.product for component in components}
