"""The exit contract: one table, one implementation, both observable ways.

Every row of the precedence table is exercised against the shared decision
function, and the same rows are exercised through the installed CLI in
``test_cli.py``. Findings, completion and the process status are asserted
independently so a critical finding cannot be hidden by an incomplete scan, and
an incomplete scan cannot be disguised as a clean one.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from iot_hardware_scanner.models import (
    Assessment,
    Completion,
    ReportFinding,
    Severity,
)
from iot_hardware_scanner.scanner.assessment import (
    CRITICAL_RULE_EVIDENCE,
    decide_exit,
    finding_is_critical,
)


def finding(rule_id: str, severity: Severity, path: str = "etc/config") -> ReportFinding:
    return ReportFinding(
        rule_id=rule_id,
        severity=severity,
        title="test finding",
        description="test",
        category="password",
        locations=[path],
        critical_qualified=finding_is_critical(rule_id, severity),
    )


def assessment(
    completion: Completion = Completion.COMPLETE,
    deps: list[str] | None = None,
    reasons: list[str] | None = None,
) -> Assessment:
    return Assessment(
        profile="firmware-static",
        profile_version="3.0",
        completion=completion,
        incomplete_reasons=reasons or [],
        missing_required_dependencies=deps or [],
    )


INCOMPLETE = assessment(
    completion=Completion.INCOMPLETE, reasons=["extraction: unavailable — no backend"]
)
MISSING_DEP = assessment(
    completion=Completion.INCOMPLETE,
    deps=["extraction backend is not installed"],
    reasons=["extraction: unavailable — no backend"],
)


class TestCriticalEvidenceRules:
    def test_registry_documents_each_rule(self) -> None:
        assert CRITICAL_RULE_EVIDENCE
        for rule_id, evidence in CRITICAL_RULE_EVIDENCE.items():
            assert rule_id
            assert len(evidence) > 40, rule_id

    def test_qualified_rule_at_critical_severity_is_critical(self) -> None:
        assert finding_is_critical("credential.unix.empty_password", Severity.CRITICAL)

    def test_lookalike_severity_is_not_critical(self) -> None:
        """The same rule below CRITICAL is a review finding."""
        assert not finding_is_critical("credential.unix.empty_password", Severity.HIGH)

    def test_unqualified_rule_at_critical_severity_is_not_critical(self) -> None:
        """A heuristic indicator stays a review finding whatever its label."""
        assert not finding_is_critical("c2.domain", Severity.CRITICAL)


class TestPrecedenceTable:
    def test_row_0_complete_and_clean(self) -> None:
        decision = decide_exit([], assessment())
        assert decision.exit_code == 0
        assert decision.exit_reason == "COMPLETE_NO_FINDINGS"

    def test_row_2_complete_with_review_finding(self) -> None:
        review = finding("c2.domain", Severity.HIGH)
        decision = decide_exit([review], assessment())
        assert decision.exit_code == 2
        assert decision.reportable_findings == [review]

    def test_row_4_incomplete_analysis(self) -> None:
        decision = decide_exit([], INCOMPLETE)
        assert decision.exit_code == 4
        assert decision.exit_reason == "INCOMPLETE_ANALYSIS"

    def test_row_5_missing_dependency_outranks_incomplete(self) -> None:
        decision = decide_exit([], MISSING_DEP)
        assert decision.exit_code == 5

    def test_row_1_critical_finding(self) -> None:
        critical = finding("credential.unix.empty_password", Severity.CRITICAL)
        decision = decide_exit([critical], assessment())
        assert decision.exit_code == 1
        assert decision.critical_findings == [critical]

    def test_row_6_output_failure_outranks_a_finding(self) -> None:
        """An output failure overrides a finding exit: nobody can read it."""
        critical = finding("credential.unix.empty_password", Severity.CRITICAL)
        decision = decide_exit([critical], assessment(), output_error="disk full")
        assert decision.exit_code == 6
        # The finding is still reported in the decision, not discarded.
        assert decision.critical_findings == [critical]

    def test_row_6_outranks_missing_dependency(self) -> None:
        decision = decide_exit([], MISSING_DEP, output_error="permission denied")
        assert decision.exit_code == 6


class TestCombinedConditions:
    def test_critical_survives_an_incomplete_assessment(self) -> None:
        critical = finding("credential.regex.password", Severity.CRITICAL)
        decision = decide_exit([critical], INCOMPLETE)
        assert decision.exit_code == 1
        assert any("incomplete" in reason for reason in decision.reasons)

    def test_critical_survives_a_missing_dependency(self) -> None:
        critical = finding("credential.regex.password", Severity.CRITICAL)
        decision = decide_exit([critical], MISSING_DEP)
        assert decision.exit_code == 1

    def test_critical_and_review_together_still_exit_1(self) -> None:
        critical = finding("credential.unix.empty_password", Severity.CRITICAL)
        review = finding("c2.domain", Severity.HIGH)
        decision = decide_exit([critical, review], assessment())
        assert decision.exit_code == 1
        assert decision.reportable_findings == [review]

    def test_review_finding_with_incomplete_assessment_exits_4(self) -> None:
        """A review finding never upgrades an incomplete scan to a clean-looking 2."""
        review = finding("c2.domain", Severity.HIGH)
        assert decide_exit([review], INCOMPLETE).exit_code == 4

    def test_no_assessment_is_incomplete(self) -> None:
        assert decide_exit([], None).exit_code == 4

    def test_unqualified_critical_label_exits_2_not_1(self) -> None:
        """A CRITICAL label without a documented evidence rule is a review finding."""
        labelled = finding("credential.yara.some_rule", Severity.CRITICAL)
        decision = decide_exit([labelled], assessment())
        assert decision.exit_code == 2
        assert decision.critical_findings == []


class TestDecisionCarriesReasons:
    @pytest.mark.parametrize(
        "code,reason",
        [
            (0, "COMPLETE_NO_FINDINGS"),
            (2, "REPORTABLE_FINDING"),
            (4, "INCOMPLETE_ANALYSIS"),
            (5, "MISSING_REQUIRED_DEPENDENCY"),
            (6, "OUTPUT_FAILURE"),
        ],
    )
    def test_exit_reason_identifier_is_stable(self, code: int, reason: str) -> None:
        cases = {
            0: ([], assessment(), None),
            2: ([finding("c2.domain", Severity.MEDIUM)], assessment(), None),
            4: ([], INCOMPLETE, None),
            5: ([], MISSING_DEP, None),
            6: ([], assessment(), "cannot write"),
        }
        findings, assessment_, error = cases[code]
        decision = decide_exit(findings, assessment_, output_error=error)
        assert decision.exit_code == code
        assert decision.exit_reason == reason

    def test_locations_are_named_in_the_reason(self) -> None:
        review = finding("c2.domain", Severity.HIGH, path="etc/init.d/c2")
        decision = decide_exit([review], assessment())
        assert any("etc/init.d/c2" in reason for reason in decision.reasons)


class TestFindingsNormalization:
    def test_credential_findings_become_report_findings(self, tmp_path: Path) -> None:
        from datetime import datetime, timezone

        from iot_hardware_scanner.models import (
            CredentialFinding,
            FirmwareSizeCategory,
            ScanContext,
        )
        from iot_hardware_scanner.scanner.assessment import collect_findings

        context = ScanContext(
            scan_id="x",
            firmware_path=tmp_path / "fw.bin",
            output_dir=tmp_path,
            file_hash_sha256="a" * 64,
            file_hash_md5="b" * 32,
            file_size=1,
            file_type="bin",
            firmware_name="fw",
            size_category=FirmwareSizeCategory.SMALL,
            started_at=datetime.now(tz=timezone.utc),
        )
        context.credential_findings = [
            CredentialFinding(
                severity=Severity.CRITICAL,
                category="password",
                file_path=Path("etc/shadow"),
                line_number=2,
                rule_id="credential.unix.empty_password",
                masked_value="admin:***",
            )
        ]
        normalized = collect_findings(context)
        assert normalized[0].locations == ["etc/shadow:2"]
        assert normalized[0].critical_qualified is True

    def test_normalization_is_order_stable(self, tmp_path: Path) -> None:
        from datetime import datetime, timezone

        from iot_hardware_scanner.models import C2Finding, FirmwareSizeCategory, ScanContext
        from iot_hardware_scanner.scanner.assessment import collect_findings

        def build() -> ScanContext:
            ctx = ScanContext(
                scan_id="x",
                firmware_path=tmp_path / "fw.bin",
                output_dir=tmp_path,
                file_hash_sha256="a" * 64,
                file_hash_md5="b" * 32,
                file_size=1,
                file_type="bin",
                firmware_name="fw",
                size_category=FirmwareSizeCategory.SMALL,
                started_at=datetime.now(tz=timezone.utc),
            )
            ctx.c2_findings = [
                C2Finding(
                    severity="SUSPICIOUS",
                    indicator_type="domain",
                    value="a.example",
                    file_path=Path("z.conf"),
                ),
                C2Finding(
                    severity="SUSPICIOUS",
                    indicator_type="domain",
                    value="b.example",
                    file_path=Path("a.conf"),
                ),
            ]
            return ctx

        first = [(f.rule_id, f.locations) for f in collect_findings(build())]
        second = [(f.rule_id, f.locations) for f in collect_findings(build())]
        assert first == second
