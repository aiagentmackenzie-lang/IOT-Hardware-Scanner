"""In-process coverage for the boot profile and its evidence paths.

The installed-CLI cases prove the public behaviour; these run the orchestrator,
the control evaluator and the renderers in-process so the new branches are
exercised where they live (a subprocess cannot report coverage to its parent).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fdt_fixtures import Node, build_fdt, build_fit, public_key_pem

from iot_hardware_scanner import __version__
from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.orchestrator import Orchestrator
from iot_hardware_scanner.scanner.assessment import collect_findings, decide_exit
from iot_hardware_scanner.scanner.bounded_reader import open_bounded
from iot_hardware_scanner.scanner.fit_dtb import (
    TrustAnchorError,
    analyse_boot,
    load_trust_anchor,
)
from iot_hardware_scanner.scanner.report_document import (
    build_document,
    render,
)


def _run(
    tmp_path: Path,
    name: str,
    data: bytes,
    *,
    anchors: list[Path] | None = None,
):
    path = tmp_path / name
    path.write_bytes(data)
    config = ScannerConfig(output_dir=tmp_path / f"out-{name}")
    config.offline_mode = True
    context = Orchestrator(config, trust_anchors=anchors or []).run(path)
    return context


def _document(context) -> dict:
    return build_document(context, version=__version__)


class TestBootProfileInProcess:
    def test_a_resolved_pair_completes_and_renders_every_format(self, tmp_path: Path) -> None:
        context = _run(tmp_path, "pair.itb", build_fit().data)
        document = _document(context)

        assert context.profile == "firmware-boot"
        assert context.assessment is not None
        assert context.assessment.completion.value == "COMPLETE"
        assert decide_exit(collect_findings(context), context.assessment).exit_code == 0
        assert document["boot"]["artifacts"][0]["default_config"] == "config-1"
        assert document["boot"]["artifacts"][0]["boot_enforcement"] == "unknown"

        terminal = render(document, "terminal")
        assert "Boot: fit" in terminal
        assert "boot enforcement: unknown" in terminal
        markdown = render(document, "markdown")
        assert "## Boot manifest — fit" in markdown
        assert "| Payload | Kind | Integrity |" in markdown
        html = render(document, "html")
        assert "<h2>Boot manifest</h2>" in html
        assert "boot enforcement" in html

    def test_a_mismatch_is_a_review_finding_not_a_critical_one(self, tmp_path: Path) -> None:
        context = _run(tmp_path, "mismatch.itb", build_fit(declare_wrong_hash=True).data)
        findings = collect_findings(context)

        assert context.assessment is not None
        assert context.assessment.completion.value == "COMPLETE"
        decision = decide_exit(findings, context.assessment)
        assert decision.exit_code == 2
        assert len(decision.reportable_findings) == 1
        assert decision.critical_findings == []
        control = next(c for c in context.controls if c.control_id == 5)
        assert control.result == "FAIL"

    def test_an_unsigned_manifest_with_matching_digests_is_review(self, tmp_path: Path) -> None:
        context = _run(tmp_path, "unsigned.itb", build_fit().data)
        control = next(c for c in context.controls if c.control_id == 5)

        assert control.status.value == "PERFORMED"
        assert control.result == "REVIEW"
        assert any("integrity, not authenticity" in item for item in control.evidence)

    def test_all_undeclared_digests_fail_the_verification_question(self, tmp_path: Path) -> None:
        context = _run(tmp_path, "undeclared.itb", build_fit(declare_hashes=False).data)
        control = next(c for c in context.controls if c.control_id == 5)

        assert control.result == "FAIL"
        assert any("declare no digest" in item for item in control.evidence)

    def test_no_referenced_payloads_is_inconclusive(self, tmp_path: Path) -> None:
        context = _run(tmp_path, "no-payloads.itb", build_fit(reference_payloads=False).data)
        control = next(c for c in context.controls if c.control_id == 5)

        assert control.status.value == "INCONCLUSIVE"
        assert control.result == "UNKNOWN"

    def test_a_declared_default_that_is_absent_is_partial(self, tmp_path: Path) -> None:
        context = _run(tmp_path, "missing-default.itb", build_fit(default_config="config-9").data)

        assert context.assessment is not None
        assert context.assessment.completion.value == "INCOMPLETE"
        stage = next(s for s in context.stages if s.stage_id.value == "boot_analysis")
        assert stage.status.value == "PARTIAL"
        assert any("config-9" in item for item in stage.omissions)
        secure = next(c for c in context.controls if c.control_id == 6)
        assert any("default" in item.lower() for item in secure.evidence)

    def test_a_fit_with_no_configurations_says_unknown(self, tmp_path: Path) -> None:
        root = Node("")
        images = Node("images")
        kernel = Node("kernel-1")
        kernel.add_str("type", "kernel")
        kernel.add_u32("data-position", 0)
        kernel.add_u32("data-size", 0)
        images.child(kernel)
        root.child(images)
        context = _run(tmp_path, "no-config.itb", build_fdt(root))

        artifact = context.boot.artifacts[0]  # type: ignore[union-attr]
        assert artifact.default_config is None
        control = next(c for c in context.controls if c.control_id == 5)
        assert control.status.value == "INCONCLUSIVE"

    def test_the_data_offset_form_is_resolved(self, tmp_path: Path) -> None:
        context = _run(tmp_path, "data-offset.itb", build_fit(use_data_offset=True).data)
        payloads = context.boot.artifacts[0].referenced_payloads  # type: ignore[union-attr]
        assert [p.integrity for p in payloads] == ["match", "match"]

    def test_memory_reservations_from_the_header_are_recorded(self, tmp_path: Path) -> None:
        root = Node("")
        root.add_str("compatible", "test,board")
        data = build_fdt(root, reservations=[(0x1000, 0x100)])
        path = tmp_path / "reserved.dtb"
        path.write_bytes(data)

        artifact, _ = analyse_boot(
            open_bounded(path),
            locator=path.name,
            digest="0" * 64,
            artifact_id="a0",
        )
        assert any(
            item["name"] == "<memory-reservation-map>" and item["base"] == 0x1000
            for item in artifact.reserved_memory
        )

    def test_a_supplied_key_sets_verification_and_check_six_stays_unknown(
        self, tmp_path: Path
    ) -> None:
        key = tmp_path / "operator.pem"
        key.write_bytes(public_key_pem())
        context = _run(
            tmp_path,
            "signed.itb",
            build_fit(sign_config="config-1").data,
            anchors=[key],
        )
        signature = context.boot.artifacts[0].configurations[0].signature  # type: ignore[union-attr]
        assert signature.verified is True
        update = next(c for c in context.controls if c.control_id == 5)
        secure = next(c for c in context.controls if c.control_id == 6)
        assert update.result == "REVIEW"
        assert secure.status.value == "INCONCLUSIVE"
        assert secure.result == "UNKNOWN"
        assert any("declares default configuration" in item for item in secure.evidence)

    def test_a_signature_over_another_config_is_not_used_by_check_five(
        self, tmp_path: Path
    ) -> None:
        key = tmp_path / "operator.pem"
        key.write_bytes(public_key_pem())
        context = _run(
            tmp_path,
            "other.itb",
            build_fit(sign_config="config-2", extra_configurations=["config-2"]).data,
            anchors=[key],
        )
        update = next(c for c in context.controls if c.control_id == 5)
        assert not any("verifies with the supplied key" in item for item in update.evidence)


class TestSignatureEdgeCases:
    @staticmethod
    def _manifest(signature: Node) -> bytes:
        configuration = Node("config-1")
        configuration.add_str("description", "config")
        configuration.child(signature)
        configurations = Node("configurations")
        configurations.add_str("default", "config-1")
        configurations.child(configuration)
        root = Node("")
        images = Node("images")
        root.child(images)
        root.child(configurations)
        return build_fdt(root)

    def test_an_unsupported_algorithm_is_unverified_with_a_reason(self, tmp_path: Path) -> None:
        key = tmp_path / "operator.pem"
        key.write_bytes(public_key_pem())
        anchor = load_trust_anchor(key)
        signature = Node("signature@1")
        signature.add_str("algo", "md5,rsa2048")
        signature.add_strings("hashed-nodes", ["/configurations/config-1"])
        signature.add("value", b"\x01" * 256)
        path = tmp_path / "unsupported.itb"
        path.write_bytes(self._manifest(signature))

        artifact, _ = analyse_boot(
            open_bounded(path),
            locator=path.name,
            digest="0" * 64,
            artifact_id="a0",
            anchors=[anchor],
        )
        result = artifact.configurations[0].signature
        assert result.present is True
        assert result.verified is None
        assert "unsupported" in result.reason

    def test_a_hashed_node_that_is_absent_is_unverified(self, tmp_path: Path) -> None:
        key = tmp_path / "operator.pem"
        key.write_bytes(public_key_pem())
        anchor = load_trust_anchor(key)
        signature = Node("signature@1")
        signature.add_str("algo", "sha256,rsa2048")
        signature.add_strings("hashed-nodes", ["/configurations/missing"])
        signature.add("value", b"\x01" * 256)
        path = tmp_path / "missing-node.itb"
        path.write_bytes(self._manifest(signature))

        artifact, _ = analyse_boot(
            open_bounded(path),
            locator=path.name,
            digest="0" * 64,
            artifact_id="a0",
            anchors=[anchor],
        )
        result = artifact.configurations[0].signature
        assert result.verified is None
        assert "not present" in result.reason


class TestTrustAnchorInput:
    def test_a_non_pem_file_is_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "not-a-key.txt"
        path.write_text("hello")

        with pytest.raises(TrustAnchorError, match="no PEM block"):
            load_trust_anchor(path)

    def test_an_oversized_file_is_rejected_without_reading_it_all(self, tmp_path: Path) -> None:
        path = tmp_path / "huge.pem"
        path.write_bytes(b"x" * (1024 * 1024 + 1))

        with pytest.raises(TrustAnchorError, match="over the"):
            load_trust_anchor(path)

    def test_a_malformed_der_body_is_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.pem"
        path.write_text("-----BEGIN PUBLIC KEY-----\nMAA=\n-----END PUBLIC KEY-----\n")

        with pytest.raises(TrustAnchorError):
            load_trust_anchor(path)
