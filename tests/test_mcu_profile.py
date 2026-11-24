"""Slice 3C — the bare-metal profile, through the orchestrator and the CLI.

What a user verifies from this file:

* an Intel HEX, S-record or UF2 image is recognised from its own content and
  selects ``firmware-mcu`` without being told;
* the run completes, with an address map, a payload digest and a set of stages
  that names what could not apply;
* a gap in the address space survives into the report as unobserved;
* a malformed image exits 4 with a named FAILED stage, never a traceback;
* no named check is settled from a bare-metal payload, and the report says so.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from mcu_fixtures import BASE, encode_ihex, encode_srec, encode_uf2, payload_ranges

from iot_hardware_scanner import __version__
from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.orchestrator import Orchestrator
from iot_hardware_scanner.scanner.assessment import collect_findings, decide_exit
from iot_hardware_scanner.scanner.report_document import build_document, render

ENCODERS = {
    "intel-hex": encode_ihex,
    "srec": encode_srec,
    "uf2": encode_uf2,
}


def _run(tmp_path: Path, name: str, data: bytes, profile: str | None = None):
    path = tmp_path / name
    path.write_bytes(data)
    config = ScannerConfig(output_dir=tmp_path / f"out-{name}")
    config.offline_mode = True
    return Orchestrator(config, profile=profile).run(path)


def _document(context) -> dict:
    return build_document(context, version=__version__)


@pytest.mark.parametrize("mcu_format", sorted(ENCODERS))
class TestMcuProfileInProcess:
    def test_the_content_selects_the_profile_and_completes(
        self, tmp_path: Path, mcu_format: str
    ) -> None:
        context = _run(
            tmp_path,
            f"board-{mcu_format}.bin",
            ENCODERS[mcu_format](payload_ranges()),
        )
        document = _document(context)

        assert context.profile == "firmware-mcu"
        assert context.input_kind.value == "mcu"
        assert context.assessment is not None
        assert context.assessment.completion.value == "COMPLETE"
        assert document["mcu"]["format"] == mcu_format
        assert document["mcu"]["payload_bytes"] == 500
        assert len(document["mcu"]["ranges"]) == 2
        assert len(document["mcu"]["gaps"]) == 1
        # A clean payload with no rule matches is exit 0, not a failed scan.
        assert decide_exit(collect_findings(context), context.assessment).exit_code == 0

    def test_a_gap_is_reported_as_unobserved(self, tmp_path: Path, mcu_format: str) -> None:
        context = _run(tmp_path, f"gap-{mcu_format}.bin", ENCODERS[mcu_format](payload_ranges()))
        gap = _document(context)["mcu"]["gaps"][0]

        assert gap["observed"] is False
        assert gap["start"] == BASE + 300
        assert any("never zero-filled" in note for note in _document(context)["mcu"]["notes"])

    def test_no_named_check_is_settled_from_a_bare_metal_payload(
        self, tmp_path: Path, mcu_format: str
    ) -> None:
        context = _run(
            tmp_path, f"controls-{mcu_format}.bin", ENCODERS[mcu_format](payload_ranges())
        )
        statuses = {control.control_id: control.status.value for control in context.controls}

        assert set(statuses) == set(range(1, 13))
        assert set(statuses.values()) == {"NOT_APPLICABLE"}
        assert context.assessment is not None
        assert context.assessment.completion.value == "COMPLETE"
        # The reason is recorded per control, not left blank.
        for control in context.controls:
            assert control.evidence
            assert "firmware-mcu" in control.evidence[0]

    def test_the_stages_that_cannot_apply_name_their_reason(
        self, tmp_path: Path, mcu_format: str
    ) -> None:
        context = _run(tmp_path, f"stages-{mcu_format}.bin", ENCODERS[mcu_format](payload_ranges()))
        stages = {stage.stage_id.value: stage for stage in context.stages}

        assert stages["mcu_analysis"].status.value == "COMPLETE"
        for stage_id in (
            "extraction",
            "root_discovery",
            "enumeration",
            "binary_inventory",
            "opkg_inventory",
            "unix_accounts",
            "service_analysis",
            "advisory",
        ):
            assert stages[stage_id].status.value == "NOT_APPLICABLE", stage_id
            assert stages[stage_id].reason, stage_id

    def test_every_renderer_carries_the_address_map(self, tmp_path: Path, mcu_format: str) -> None:
        document = _document(
            _run(tmp_path, f"render-{mcu_format}.bin", ENCODERS[mcu_format](payload_ranges()))
        )

        for fmt in ("terminal", "markdown", "html"):
            output = render(document, fmt)
            assert "0x08000000" in output, fmt
            assert "500" in output, fmt
        assert "Bare-metal" in render(document, "terminal")
        assert "Unobserved address" in render(document, "markdown")


class TestMcuFailures:
    def test_an_explicit_profile_on_the_wrong_bytes_fails_named(self, tmp_path: Path) -> None:
        context = _run(tmp_path, "random.bin", b"\x01\x02\x03\x04" * 100, profile="firmware-mcu")
        stages = {stage.stage_id.value: stage for stage in context.stages}

        assert stages["mcu_analysis"].status.value == "FAILED"
        assert "neither an Intel HEX, S-record nor UF2" in stages["mcu_analysis"].reason
        assert context.mcu is None
        assert context.assessment is not None
        assert context.assessment.completion.value != "COMPLETE"

    def test_a_truncated_hex_record_fails_named(self, tmp_path: Path) -> None:
        blob = encode_ihex(payload_ranges())
        context = _run(tmp_path, "cut.hex", blob[: len(blob) // 2], profile="firmware-mcu")
        stages = {stage.stage_id.value: stage for stage in context.stages}

        assert stages["mcu_analysis"].status.value == "FAILED"
        # A partial map would present unobserved bytes as absent ones.
        assert context.mcu is None

    def test_a_bounded_decode_stops_named(self, tmp_path: Path) -> None:
        """The record ceiling is a config knob; exceeding it is a FAILED stage."""
        blob = encode_ihex([(BASE, bytes(4096))], chunk=16)
        path = tmp_path / "big.hex"
        path.write_bytes(blob)
        config = ScannerConfig(output_dir=tmp_path / "out-big")
        config.offline_mode = True
        config.max_mcu_records = 4
        context = Orchestrator(config).run(path)
        stages = {stage.stage_id.value: stage for stage in context.stages}

        assert stages["mcu_analysis"].status.value == "FAILED"
        assert "ceiling" in stages["mcu_analysis"].reason
        assert context.mcu is None

    def test_a_missing_end_of_file_record_is_partial_not_complete(self, tmp_path: Path) -> None:
        blob = encode_ihex([(BASE, bytes(64))]).replace(b":00000001FF\r\n", b"")
        context = _run(tmp_path, "noeof.hex", blob, profile="firmware-mcu")
        stages = {stage.stage_id.value: stage for stage in context.stages}

        assert stages["mcu_analysis"].status.value == "PARTIAL"
        assert any("missing-eof" in omission for omission in stages["mcu_analysis"].omissions)
        # The bytes that were present are still mapped and the run says PARTIAL.
        assert context.mcu is not None
        assert context.assessment is not None
        assert context.assessment.completion.value != "COMPLETE"


class TestMcuFindings:
    def test_a_rule_match_becomes_a_review_finding_with_an_address(self, tmp_path: Path) -> None:
        payload = b"\x00" * 16 + b'password = "hunter2hunter2"\n' + b"\x00" * 16
        context = _run(
            tmp_path,
            "creds.hex",
            encode_ihex([(BASE, payload)]),
        )
        findings = collect_findings(context)

        assert context.mcu is not None
        assert findings, "the packaged credential rules must match this payload"
        for finding in findings:
            assert finding.rule_id.startswith("mcu.rule.")
            assert finding.locations and "@0x" in finding.locations[0]
            # A rule match in flash is never a critical-capable finding.
            assert finding.critical_qualified is False
        assert decide_exit(findings, context.assessment).exit_code == 2

    def test_the_decoded_bytes_are_never_serialised(self, tmp_path: Path) -> None:
        document = _document(_run(tmp_path, "board.hex", encode_ihex(payload_ranges())))
        serialised = str(document)

        assert "payload_ranges" not in document["mcu"]
        assert "payload_ranges" not in serialised
        assert document["mcu"]["payload_sha256"]
