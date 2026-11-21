"""Release comparison and declaration reconciliation, at the document level.

These cases build the serialized scan documents directly, so they exercise the
comparison contract on every machine without a container. The rows that need
real image bytes — the two-release fixture built with ``mksquashfs`` and the
published OpenWrt pair — live in ``test_installed_image_cli.py`` and run through
the installed CLI.

What is asserted here is what the plan asks the comparison to *refuse* to do as
much as what it does: a detector that did not settle is indeterminate, never a
resolution; a declaration that claims another image resolves nothing; and a
component that moved is the same component.
"""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from iot_hardware_scanner.scanner.comparison import (
    COMPARISON_SCHEMA,
    EXIT_COMPARISON_CLEAN,
    EXIT_COMPARISON_DETERMINATE,
    EXIT_COMPARISON_INDETERMINATE,
    ComparisonError,
    compare_documents,
    decide_comparison_exit,
    load_scan,
    read_json_document,
    render_comparison,
)
from iot_hardware_scanner.scanner.report_document import SCHEMA_VERSION

FIRMWARE_A = "a" * 64
FIRMWARE_B = "b" * 64
STAGE_IDS = (
    "ingest",
    "rule_compilation",
    "extraction",
    "root_discovery",
    "enumeration",
    "entropy",
    "binary_inventory",
    "elf_metadata",
    "opkg_inventory",
    "credential_scan",
    "unix_accounts",
    "service_analysis",
    "advisory",
    "c2_indicators",
    "risk_controls",
)


def scan_document(
    *,
    firmware: str = FIRMWARE_A,
    name: str = "release-a.img",
    scan_id: str = "scan-a",
    packages: list[tuple[str, str]] | None = None,
    findings: list[dict[str, Any]] | None = None,
    elf: list[tuple[str, str]] | None = None,
    components: list[dict[str, Any]] | None = None,
    ruleset_digest: str = "1" * 64,
    scanner_version: str = "2.3.0",
    profile: str = "firmware-static",
    profile_version: str = "4.0",
    stage_overrides: dict[str, str] | None = None,
    advisory_digest: str | None = None,
    opkg_digest: str = "9" * 64,
) -> dict[str, Any]:
    """A minimal but complete schema-5 scan document."""
    packages = packages if packages is not None else [("busybox", "1.36.1-r2")]
    findings = findings or []
    elf = elf or []
    stage_overrides = stage_overrides or {}
    stages = [
        {
            "stage": stage_id,
            "status": stage_overrides.get(stage_id, "COMPLETE"),
            "required": stage_id != "advisory",
            "reason": "",
            "inspected": 1,
            "eligible": 1,
            "omissions": [],
            "dependency": None,
        }
        for stage_id in STAGE_IDS
    ]
    default_components = [
        {
            "vendor": "busybox",
            "product": "busybox",
            "version": "1.36.1-r2",
            "cpe": "cpe:2.3:a:busybox:busybox:1.36.1-r2:*:*:*:*:*:*:*",
            "cpe_basis": "nist-mapped",
            "source_file": "rootfs/usr/lib/opkg/status",
            "source_method": "opkg_status",
            "confidence": "recorded",
            "evidence": "rootfs/usr/lib/opkg/status:8-72 (line 2)",
            "digest_sha256": opkg_digest,
            "architecture": "aarch64_generic",
            "occurrences": ["rootfs/usr/lib/opkg/status:8-72"],
        }
    ]
    components = components if components is not None else default_components
    return {
        "schema_version": 5,
        "tool": {"name": "iot-hardware-scanner", "version": scanner_version},
        "scan_id": scan_id,
        "scan_date": "2026-11-01T00:00:00+00:00",
        "report_generated": "2026-11-01T00:01:00+00:00",
        "artifact": {
            "kind": "file",
            "name": name,
            "path": f"/work/{name}",
            "size": 4096,
            "sha256": firmware,
            "md5": "c" * 32,
            "file_type": "gzip",
            "size_category": "SMALL",
            "manifest_entries": None,
        },
        "assessment": {
            "profile": profile,
            "profile_version": profile_version,
            "completion": "COMPLETE",
            "check_counts": {},
            "incomplete_reasons": [],
            "missing_required_dependencies": [],
            "limitations": [],
        },
        "stages": stages,
        "controls": [],
        "findings": findings,
        "inventory": None,
        "entropy": None,
        "image_map": None,
        "extraction": {"worker_image": "sha256:" + "e" * 64, "backend_version": "4.5.1"},
        "input_binding": None,
        "elf": {
            "eligible": len(elf),
            "parsed": len(elf),
            "records": [
                {
                    "locator": locator,
                    "artifact_id": "artifact-1",
                    "digest_sha256": digest,
                    "size": 1024,
                    "class": "ELF64",
                    "byte_order": "little",
                    "machine": 183,
                    "machine_name": "AArch64",
                    "type": "DYN",
                    "os_abi": "SYSV",
                    "interpreter": "/lib/ld-musl-aarch64.so.1",
                    "needed": ["libc.so"],
                    "soname": None,
                    "segments": [],
                    "build_id": digest[:16],
                    "hardening": {},
                    "unknown": [],
                    "parser": "pyelftools",
                    "parser_version": "0.32",
                }
                for locator, digest in elf
            ],
            "rejected": [],
        },
        "opkg": {
            "locator": "rootfs/usr/lib/opkg/status",
            "database_sha256": opkg_digest,
            "byte_length": 400,
            "installed": len(packages),
            "held": 0,
            "unparsed_stanzas": 0,
            "truncated": False,
            "parser_version": "1",
            "records": [
                {
                    "name": package,
                    "version": version,
                    "architecture": "aarch64_generic",
                    "status": "install user installed",
                    "installed": True,
                    "held": False,
                    "source": "",
                    "depends": "",
                    "evidence": {
                        "start": 8 * (index + 1),
                        "end": 8 * (index + 2),
                        "line": index + 2,
                    },
                }
                for index, (package, version) in enumerate(packages)
            ],
        },
        "tree": None,
        "ruleset": {
            "digest": ruleset_digest,
            "engine": "yara",
            "engine_version": "4.5.4",
            "source": "bundled",
            "rule_files": [],
            "compile_errors": [],
        },
        "advisory": (
            {
                "state": "ASSESSED",
                "complete": True,
                "matched": 1,
                "snapshot": {"digest_sha256": advisory_digest, "provider": "nvd"},
            }
            if advisory_digest
            else None
        ),
        "components": components,
        "component_bases": {
            "counts": {"nist-mapped": len(components), "opkg-package-name": 0, "banner": 0},
            "total": len(components),
        },
        "data_sources": [],
        "risk_score": None,
    }


def finding(
    rule_id: str,
    *,
    destination: str,
    severity: str = "HIGH",
    locations: list[str] | None = None,
    title: str = "",
) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "severity": severity,
        "title": title or rule_id,
        "description": "",
        "category": destination,
        "locations": locations or ["rootfs/etc/shadow:1"],
        "evidence": [],
        "destination": destination,
        "namespaces": [],
        "ruleset_digest": "",
        "critical_qualified": False,
    }


def compare(base: dict[str, Any], target: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    return compare_documents(base, target, tool_version="2.3.0", **kwargs)


# ──────────────────────────────────────────────
# Packages
# ──────────────────────────────────────────────


class TestPackages:
    def test_a_version_change_is_one_changed_package(self) -> None:
        base = scan_document(packages=[("busybox", "1.36.1-r2"), ("libc", "1.2.5-r4")])
        target = scan_document(
            firmware=FIRMWARE_B, packages=[("busybox", "1.36.1-r3"), ("libc", "1.2.5-r4")]
        )
        document = compare(base, target)

        packages = document["packages"]
        assert [entry["name"] for entry in packages["changed"]] == ["busybox"]
        assert packages["changed"][0]["base_versions"] == ["1.36.1-r2"]
        assert packages["changed"][0]["target_versions"] == ["1.36.1-r3"]
        assert packages["counts"] == {
            "persistent": 1,
            "changed": 1,
            "new": 0,
            "removed": 0,
            "relocated": 0,
        }
        # Every record is accounted for on both sides.
        assert packages["base_records"] == 2
        assert packages["target_records"] == 2

    def test_records_are_compared_not_mapped_components(self) -> None:
        """A package with no NIST mapping is still compared."""
        base = scan_document(packages=[("libustream-mbedtls20201210", "2024.01.01-r1")])
        target = scan_document(
            firmware=FIRMWARE_B,
            packages=[("libustream-mbedtls20201210", "2024.01.01-r2")],
            components=[],
        )
        document = compare(base, target)
        assert document["packages"]["counts"]["changed"] == 1
        assert document["packages"]["changed"][0]["name"] == "libustream-mbedtls20201210"

    def test_every_occurrence_is_kept_when_one_root_differs(self) -> None:
        base = scan_document(packages=[("busybox", "1.36.1-r2")])
        base["opkg"]["records"].append(
            {
                **base["opkg"]["records"][0],
                "version": "1.36.1-r1",
                "evidence": {"start": 100, "end": 140, "line": 20},
            }
        )
        target = scan_document(firmware=FIRMWARE_B, packages=[("busybox", "1.36.1-r2")])
        document = compare(base, target)
        entry = document["packages"]["changed"][0]
        assert entry["base_versions"] == ["1.36.1-r1", "1.36.1-r2"]
        assert len(entry["base"]) == 2
        assert {record["evidence"]["line"] for record in entry["base"]} == {2, 20}

    def test_a_removed_package_is_removed_not_unmapped(self) -> None:
        base = scan_document(packages=[("busybox", "1.36.1-r2"), ("rpcd", "2024.09.10")])
        target = scan_document(firmware=FIRMWARE_B, packages=[("busybox", "1.36.1-r2")])
        document = compare(base, target)
        assert [entry["name"] for entry in document["packages"]["removed"]] == ["rpcd"]
        assert document["packages"]["counts"]["removed"] == 1


# ──────────────────────────────────────────────
# Components and layout
# ──────────────────────────────────────────────


class TestRelocation:
    def test_a_moved_identical_file_is_relocated_layout_not_new_and_removed(self) -> None:
        digest = "d" * 64
        base = scan_document(elf=[("rootfs/usr/lib/tool", digest)])
        target = scan_document(firmware=FIRMWARE_B, elf=[("rootfs/usr/bin/tool", digest)])
        document = compare(base, target)
        layout = document["layout"]
        assert layout["counts"]["relocated"] == 1
        assert layout["counts"]["new"] == 0
        assert layout["counts"]["removed"] == 0
        assert layout["relocated"][0]["base_locations"] == ["rootfs/usr/lib/tool"]
        assert layout["relocated"][0]["target_locations"] == ["rootfs/usr/bin/tool"]

    def test_the_same_path_with_new_bytes_is_a_rebuild(self) -> None:
        base = scan_document(elf=[("rootfs/usr/bin/tool", "1" * 64)])
        target = scan_document(firmware=FIRMWARE_B, elf=[("rootfs/usr/bin/tool", "2" * 64)])
        layout = compare(base, target)["layout"]
        assert layout["counts"]["rebuilt_at_same_path"] == 1
        assert layout["counts"]["relocated"] == 0

    def test_a_moved_component_is_recognised_by_identity(self) -> None:
        component = {
            "vendor": "openwrt",
            "product": "uhttpd",
            "version": "2024.01.01-r1",
            "cpe": "cpe:2.3:a:openwrt:uhttpd:2024.01.01-r1:*:*:*:*:*:*:*",
            "cpe_basis": "opkg-package-name",
            "source_file": "rootfs/usr/lib/opkg/status",
            "source_method": "opkg_status",
            "confidence": "recorded",
            "evidence": "rootfs/usr/lib/opkg/status:8-72",
            "digest_sha256": "9" * 64,
            "architecture": "aarch64_generic",
            "occurrences": ["rootfs-a/usr/lib/opkg/status:8-72"],
        }
        moved = deepcopy(component)
        moved["occurrences"] = ["rootfs-b/usr/lib/opkg/status:8-72"]
        base = scan_document(components=[component])
        target = scan_document(firmware=FIRMWARE_B, components=[moved])
        components = compare(base, target)["components"]
        assert components["counts"]["relocated"] == 1
        assert components["counts"]["new"] == 0
        assert components["counts"]["removed"] == 0
        assert components["relocated"][0]["identity"] == "openwrt:uhttpd"

    def test_the_component_basis_counts_are_carried_from_both_scans(self) -> None:
        base = scan_document()
        target = scan_document(firmware=FIRMWARE_B)
        components = compare(base, target)["components"]
        assert components["basis_counts"]["base"]["nist-mapped"] == 1
        assert components["basis_counts"]["target"]["nist-mapped"] == 1


# ──────────────────────────────────────────────
# Findings, coverage and instruments
# ──────────────────────────────────────────────


class TestFindings:
    def test_a_finding_present_only_in_the_base_is_resolved(self) -> None:
        base = scan_document(
            findings=[finding("credential.unix.empty_password", destination="credential")]
        )
        target = scan_document(firmware=FIRMWARE_B, findings=[])
        document = compare(base, target)
        assert document["findings"]["counts"]["removed"] == 1
        assert document["findings"]["resolved"][0]["rule_id"] == ("credential.unix.empty_password")

    def test_a_skipped_detector_makes_its_previous_findings_indeterminate(self) -> None:
        base = scan_document(
            findings=[finding("advisory.CVE-2024-0001", destination="advisory")],
            advisory_digest="f" * 64,
        )
        target = scan_document(
            firmware=FIRMWARE_B,
            findings=[],
            stage_overrides={"advisory": "SKIPPED"},
        )
        document = compare(base, target)
        findings = document["findings"]
        assert findings["counts"]["removed"] == 0
        assert findings["resolved"] == []
        assert findings["counts"]["indeterminate"] == 1
        assert findings["indeterminate"][0]["rule_id"] == "advisory.CVE-2024-0001"
        assert findings["by_destination"]["advisory"]["comparable"] is False
        assert any(
            "advisory" in reason for reason in findings["by_destination"]["advisory"]["reasons"]
        )

    def test_a_changed_rule_set_invalidates_rule_based_findings(self) -> None:
        base = scan_document(
            findings=[finding("credential.yara.bearer_token", destination="credential")],
            ruleset_digest="1" * 64,
        )
        target = scan_document(firmware=FIRMWARE_B, findings=[], ruleset_digest="2" * 64)
        document = compare(base, target)
        assert document["findings"]["counts"]["removed"] == 0
        assert document["findings"]["counts"]["indeterminate"] == 1
        bucket = document["findings"]["by_destination"]["credential"]
        assert bucket["comparable"] is False
        assert any("rule-set digest" in reason for reason in bucket["reasons"])

    def test_a_different_scanner_version_invalidates_every_destination(self) -> None:
        base = scan_document(
            findings=[finding("credential.unix.empty_password", destination="credential")]
        )
        target = scan_document(firmware=FIRMWARE_B, findings=[], scanner_version="2.4.0")
        document = compare(base, target)
        assert document["comparability"]["status"] == "indeterminate"
        assert document["findings"]["counts"]["indeterminate"] == 1

    def test_a_finding_that_followed_its_file_is_persistent_and_relocated(self) -> None:
        base = scan_document(
            findings=[
                finding(
                    "credential.unix.empty_password",
                    destination="credential",
                    locations=["rootfs-a/etc/shadow:1"],
                )
            ]
        )
        target = scan_document(
            firmware=FIRMWARE_B,
            findings=[
                finding(
                    "credential.unix.empty_password",
                    destination="credential",
                    locations=["rootfs-b/etc/shadow:1"],
                )
            ],
        )
        findings = compare(base, target)["findings"]
        assert findings["counts"]["persistent"] == 1
        assert findings["counts"]["removed"] == 0
        assert findings["counts"]["new"] == 0
        assert findings["persistent"][0]["relocated"] is True

    def test_a_severity_change_is_changed_not_new_and_resolved(self) -> None:
        base = scan_document(
            findings=[
                finding("credential.yara.bearer_token", destination="credential", severity="LOW")
            ]
        )
        target = scan_document(
            firmware=FIRMWARE_B,
            findings=[
                finding("credential.yara.bearer_token", destination="credential", severity="HIGH")
            ],
        )
        findings = compare(base, target)["findings"]
        assert findings["counts"]["changed"] == 1
        assert findings["changed"][0]["base_severity"] == "LOW"
        assert findings["changed"][0]["target_severity"] == "HIGH"


class TestEnvironment:
    def test_instruments_are_reported_before_differences(self) -> None:
        base = scan_document(ruleset_digest="1" * 64, advisory_digest="f" * 64)
        target = scan_document(
            firmware=FIRMWARE_B, ruleset_digest="2" * 64, advisory_digest="e" * 64
        )
        document = compare(base, target)
        changed = " | ".join(document["environment"]["changes"])
        assert "rule-set digest" in changed
        assert "advisory snapshot digest" in changed
        markdown = render_comparison(document, "markdown")
        assert markdown.index("## Instruments") < markdown.index("## Packages")

    def test_a_coverage_change_is_listed_and_never_resolved(self) -> None:
        base = scan_document(
            findings=[finding("advisory.CVE-2024-0001", destination="advisory")],
            advisory_digest="f" * 64,
        )
        target = scan_document(
            firmware=FIRMWARE_B, findings=[], stage_overrides={"advisory": "SKIPPED"}
        )
        document = compare(base, target)
        changes = document["environment"]["coverage_changes"]
        assert any(change["stage"] == "advisory" for change in changes)
        assert document["findings"]["resolved"] == []
        terminal = render_comparison(document, "terminal")
        assert "resolved advisory" not in terminal
        assert "indeterminate" in terminal


# ──────────────────────────────────────────────
# Declarations
# ──────────────────────────────────────────────


def write_manifest(path: Path, rows: list[tuple[str, str]]) -> Path:
    path.write_text("".join(f"{name} - {version}\n" for name, version in rows))
    return path


def write_cyclonedx(
    path: Path, rows: list[tuple[str, str]], *, claimed_image: str | None = None
) -> Path:
    payload: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "components": [
            {"type": "application", "name": name, "version": version} for name, version in rows
        ],
    }
    if claimed_image:
        payload["metadata"] = {
            "component": {
                "type": "firmware",
                "name": "image",
                "hashes": [{"alg": "SHA-256", "content": claimed_image}],
            }
        }
    path.write_text(json.dumps(payload))
    return path


class TestDeclarations:
    def test_the_four_outcomes_are_distinguishable(self, tmp_path: Path) -> None:
        target = scan_document(
            firmware=FIRMWARE_B,
            packages=[
                ("base-files", "1589~0123456789"),
                ("libc", "1.2.5-r4"),
                ("busybox", "1.36.1-r3"),
            ],
        )
        declaration = write_manifest(
            tmp_path / "release.manifest",
            [
                ("base-files", "1589~0123456789"),  # agreement
                ("libc", "1.2.5-r5"),  # version conflict
                ("ghost-pkg", "1.0-r1"),  # declared only
            ],
        )
        document = compare(
            scan_document(firmware=FIRMWARE_A), target, declaration_paths=[declaration]
        )
        entry = document["declarations"][0]
        assert entry["outcomes"] == {
            "agreement": 1,
            "unresolved-revision": 0,
            "version-conflict": 1,
            "declared-only": 1,
            "observed-only": 1,  # busybox is in the image and not declared
            "unbound": 0,
        }
        by_name = {row["name"]: row["state"] for row in entry["rows"]}
        assert by_name == {
            "base-files": "agreement",
            "libc": "version-conflict",
            "ghost-pkg": "declared-only",
        }
        assert [row["name"] for row in entry["observed_only"]] == ["busybox"]

    def test_a_revision_less_declaration_is_unresolved_not_a_mismatch(self, tmp_path: Path) -> None:
        target = scan_document(firmware=FIRMWARE_B, packages=[("busybox", "1.36.1-r2")])
        declaration = write_cyclonedx(tmp_path / "supplier.cdx.json", [("busybox", "1.36.1")])
        entry = compare(
            scan_document(firmware=FIRMWARE_A), target, declaration_paths=[declaration]
        )["declarations"][0]
        assert entry["outcomes"]["unresolved-revision"] == 1
        assert entry["outcomes"]["version-conflict"] == 0
        assert entry["rows"][0]["state"] == "unresolved-revision"
        assert entry["rows"][0]["declared_version"] == "1.36.1"
        assert entry["rows"][0]["observed_version"] == "1.36.1-r2"

    def test_a_build_suffix_is_also_unresolved_not_a_mismatch(self, tmp_path: Path) -> None:
        target = scan_document(
            firmware=FIRMWARE_B,
            packages=[("kernel", "6.6.73~5f0e657555378f3e0673e256ddb6fb86-r1")],
        )
        declaration = write_cyclonedx(tmp_path / "supplier.cdx.json", [("kernel", "6.6.73")])
        entry = compare(
            scan_document(firmware=FIRMWARE_A), target, declaration_paths=[declaration]
        )["declarations"][0]
        assert entry["outcomes"]["unresolved-revision"] == 1
        assert entry["outcomes"]["version-conflict"] == 0

    def test_a_different_major_version_is_still_a_conflict(self, tmp_path: Path) -> None:
        target = scan_document(firmware=FIRMWARE_B, packages=[("libc", "1.2.5-r4")])
        declaration = write_cyclonedx(tmp_path / "supplier.cdx.json", [("libc", "1.2")])
        entry = compare(
            scan_document(firmware=FIRMWARE_A), target, declaration_paths=[declaration]
        )["declarations"][0]
        assert entry["outcomes"]["version-conflict"] == 1

    def test_a_declaration_for_another_image_resolves_nothing(self, tmp_path: Path) -> None:
        target = scan_document(firmware=FIRMWARE_B, packages=[("busybox", "1.36.1-r2")])
        declaration = write_cyclonedx(
            tmp_path / "other.cdx.json",
            [("busybox", "1.36.1-r2"), ("libc", "9.9")],
            claimed_image="0" * 64,
        )
        entry = compare(
            scan_document(firmware=FIRMWARE_A), target, declaration_paths=[declaration]
        )["declarations"][0]
        assert entry["binding"]["status"] == "mismatched"
        assert entry["outcomes"]["unbound"] == 2
        assert entry["outcomes"]["agreement"] == 0
        assert entry["outcomes"]["version-conflict"] == 0
        assert entry["observed_only"] == []

    def test_a_declaration_that_claims_this_image_is_bound(self, tmp_path: Path) -> None:
        target = scan_document(firmware=FIRMWARE_B, packages=[("busybox", "1.36.1-r2")])
        declaration = write_cyclonedx(
            tmp_path / "this-image.cdx.json",
            [("busybox", "1.36.1-r2")],
            claimed_image=FIRMWARE_B,
        )
        entry = compare(
            scan_document(firmware=FIRMWARE_A), target, declaration_paths=[declaration]
        )["declarations"][0]
        assert entry["binding"]["status"] == "bound"
        assert entry["outcomes"]["agreement"] == 1

    def test_an_unclaimed_declaration_says_its_binding_is_unverified(self, tmp_path: Path) -> None:
        target = scan_document(firmware=FIRMWARE_B)
        declaration = write_manifest(tmp_path / "release.manifest", [("busybox", "1.36.1-r2")])
        entry = compare(
            scan_document(firmware=FIRMWARE_A), target, declaration_paths=[declaration]
        )["declarations"][0]
        assert entry["binding"]["status"] == "unclaimed"
        assert "unverified" in entry["binding"]["note"]
        assert entry["digest_sha256"]
        assert entry["source"] == "operator-supplied declaration, read offline"

    def test_observed_records_keep_their_provenance(self, tmp_path: Path) -> None:
        target = scan_document(
            firmware=FIRMWARE_B, packages=[("busybox", "1.36.1-r2"), ("libc", "1.2.5-r4")]
        )
        declaration = write_manifest(tmp_path / "release.manifest", [("busybox", "1.36.1-r2")])
        entry = compare(
            scan_document(firmware=FIRMWARE_A), target, declaration_paths=[declaration]
        )["declarations"][0]
        assert entry["scope"]["observed_rows"] == 2
        assert entry["observed_provenance"]["database_sha256"] == "9" * 64
        assert entry["observed_only"][0]["name"] == "libc"
        assert entry["observed_only"][0]["evidence"]["start"] == 16


# ──────────────────────────────────────────────
# Document shape, reading and exit contract
# ──────────────────────────────────────────────


class TestDocumentAndExit:
    def test_the_comparison_is_its_own_document_type(self) -> None:
        document = compare(scan_document(), scan_document(firmware=FIRMWARE_B))
        assert document["schema_version"] == COMPARISON_SCHEMA == "ihs-comparison/1"
        assert document["kind"] == "release-comparison"
        # It is a JSON document and renders in all three formats.
        assert json.loads(render_comparison(document, "json"))["schema_version"] == (
            COMPARISON_SCHEMA
        )
        for fmt in ("terminal", "markdown"):
            assert render_comparison(document, fmt)

    def test_identical_scans_exit_clean(self) -> None:
        document = compare(scan_document(), scan_document(scan_id="scan-b"))
        code, summary = decide_comparison_exit(document)
        assert code == EXIT_COMPARISON_CLEAN
        assert "no differences" in summary

    def test_a_real_difference_exits_two(self) -> None:
        base = scan_document(packages=[("busybox", "1.36.1-r2")])
        target = scan_document(firmware=FIRMWARE_B, packages=[("busybox", "1.36.1-r3")])
        code, summary = decide_comparison_exit(compare(base, target))
        assert code == EXIT_COMPARISON_DETERMINATE
        assert "differences" in summary

    def test_an_indeterminate_comparison_exits_four(self) -> None:
        base = scan_document(
            findings=[finding("credential.unix.empty_password", destination="credential")]
        )
        target = scan_document(firmware=FIRMWARE_B, findings=[], scanner_version="9.9.9")
        code, summary = decide_comparison_exit(compare(base, target))
        assert code == EXIT_COMPARISON_INDETERMINATE
        assert "indeterminate" in summary

    def test_a_detector_that_was_never_asked_does_not_change_the_exit(self) -> None:
        base = scan_document(stage_overrides={"advisory": "SKIPPED"})
        target = scan_document(firmware=FIRMWARE_B, stage_overrides={"advisory": "SKIPPED"})
        document = compare(base, target)
        assert document["comparability"]["status"] == "partial"
        assert document["findings"]["counts"]["indeterminate"] == 0
        code, _summary = decide_comparison_exit(document)
        assert code == EXIT_COMPARISON_CLEAN

    def test_an_unresolved_declaration_row_exits_four(self, tmp_path: Path) -> None:
        target = scan_document(firmware=FIRMWARE_B, packages=[("busybox", "1.36.1-r2")])
        declaration = write_cyclonedx(tmp_path / "supplier.cdx.json", [("busybox", "1.36.1")])
        document = compare(
            scan_document(firmware=FIRMWARE_A), target, declaration_paths=[declaration]
        )
        code, summary = decide_comparison_exit(document)
        assert code == EXIT_COMPARISON_INDETERMINATE
        assert "unresolved" in summary

    def test_a_document_that_is_not_a_scan_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "not-a-scan.json"
        path.write_text(json.dumps({"hello": "world"}))
        with pytest.raises(ComparisonError):
            load_scan(path)

    def test_a_future_schema_is_refused_rather_than_half_read(self, tmp_path: Path) -> None:
        payload = scan_document()
        payload["schema_version"] = 99
        path = tmp_path / "future.json"
        path.write_text(json.dumps(payload))
        with pytest.raises(ComparisonError) as excinfo:
            load_scan(path)
        assert "schema_version 99" in str(excinfo.value)

    def test_an_unreadable_json_document_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "broken.json"
        path.write_text("{not json")
        with pytest.raises(ComparisonError):
            read_json_document(path)

    def test_a_schema_four_document_is_upgraded_and_its_basis_is_absent(
        self, tmp_path: Path
    ) -> None:
        payload = scan_document()
        payload["schema_version"] = 4
        for component in payload["components"]:
            component.pop("cpe_basis", None)
        payload.pop("component_bases", None)
        path = tmp_path / "v4.json"
        path.write_text(json.dumps(payload))
        document = load_scan(path)
        assert document["schema_version"] == SCHEMA_VERSION
        assert document["component_bases"] is None
        assert "cpe_basis" not in document["components"][0]
