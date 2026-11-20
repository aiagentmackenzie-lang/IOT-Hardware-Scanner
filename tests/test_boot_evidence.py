"""1F — boot evidence travels from the filesystem phase into the report.

The v1 failure this replaces: a service configured in ``inittab`` was detected
by the boot helper, then dropped, and the service control still scored a PASS
with no evidence. These tests start at the filesystem phase and finish at the
rendered document.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.models import (
    ExtractionResult,
    FirmwareSizeCategory,
    ScanContext,
    StageId,
)
from iot_hardware_scanner.orchestrator import Orchestrator
from iot_hardware_scanner.scanner.assessment import record_stage
from iot_hardware_scanner.scanner.filesystem_scanner import FilesystemScanner


def make_root(tmp_path: Path, inittab: str, scripts: dict[str, str] | None = None) -> Path:
    root = tmp_path / "rootfs"
    (root / "etc" / "init.d").mkdir(parents=True)
    (root / "etc" / "inittab").write_text(inittab)
    for name, body in (scripts or {}).items():
        (root / "etc" / "init.d" / name).write_text(body)
    return root


def context_for(root: Path, tmp_path: Path) -> ScanContext:
    ctx = ScanContext(
        scan_id="boot",
        firmware_path=tmp_path / "fw.img",
        output_dir=tmp_path,
        file_hash_sha256="a" * 64,
        file_hash_md5="b" * 32,
        file_size=1,
        file_type="image",
        firmware_name="fw",
        size_category=FirmwareSizeCategory.SMALL,
        started_at=datetime.now(tz=timezone.utc),
        extracted_rootfs=root,
        extraction_result=ExtractionResult(
            success=True, extraction_dir=root, root_filesystems=[root], file_count=1
        ),
    )
    record_stage(ctx, StageId.INGEST, "COMPLETE", inspected=1, eligible=1)
    return ctx


class TestCollectBootEvidence:
    def test_configured_respawn_is_recorded_with_its_line(self, tmp_path: Path) -> None:
        root = make_root(tmp_path, "::sysinit:/etc/init.d/rcS\n::respawn:/usr/sbin/sshd -D\n")
        evidence = FilesystemScanner(ScannerConfig()).collect_boot_evidence(root)
        respawn = [e for e in evidence if e.action == "respawn"]
        assert len(respawn) == 1
        assert respawn[0].configured is True
        assert respawn[0].source == "etc/inittab"
        assert respawn[0].line_number == 2
        assert respawn[0].program == "/usr/sbin/sshd -D"

    def test_commented_entry_is_recorded_but_not_configured(self, tmp_path: Path) -> None:
        root = make_root(tmp_path, "#::respawn:/usr/sbin/telnetd -l /bin/sh\n")
        evidence = FilesystemScanner(ScannerConfig()).collect_boot_evidence(root)
        assert len(evidence) == 1
        assert evidence[0].configured is False

    def test_init_script_start_is_evidence(self, tmp_path: Path) -> None:
        root = make_root(
            tmp_path,
            "::sysinit:/etc/init.d/rcS\n",
            {"dropbear": "#!/bin/sh\n/usr/sbin/dropbear start\n"},
        )
        evidence = FilesystemScanner(ScannerConfig()).collect_boot_evidence(root)
        starts = [e for e in evidence if e.action == "start"]
        assert starts and starts[0].program == "/usr/sbin/dropbear"

    def test_commented_start_is_not_configured(self, tmp_path: Path) -> None:
        root = make_root(tmp_path, "", {"dropbear": "#!/bin/sh\n# /usr/sbin/dropbear start\n"})
        evidence = FilesystemScanner(ScannerConfig()).collect_boot_evidence(root)
        assert [e.configured for e in evidence] == [False]

    def test_unrelated_inittab_actions_are_ignored(self, tmp_path: Path) -> None:
        root = make_root(tmp_path, "tty1::askfirst:/bin/sh\n")
        assert FilesystemScanner(ScannerConfig()).collect_boot_evidence(root) == []

    def test_root_id_comes_from_the_root_name(self, tmp_path: Path) -> None:
        root = make_root(tmp_path, "::respawn:/usr/sbin/sshd -D\n")
        evidence = FilesystemScanner(ScannerConfig()).collect_boot_evidence(root)
        assert evidence[0].root_id == "rootfs"


class TestEvidenceReachesTheControlAndTheReport:
    def test_configured_service_control_is_inconclusive_with_source(self, tmp_path: Path) -> None:
        root = make_root(tmp_path, "::respawn:/usr/sbin/sshd -D\n")
        orchestrator = Orchestrator(ScannerConfig(output_dir=tmp_path / "out"))
        ctx = context_for(root, tmp_path)

        ctx = orchestrator._phase_filesystem(ctx)
        assert ctx.filesystem_inventory is not None
        assert ctx.filesystem_inventory.boot_evidence

        orchestrator._phase_controls(ctx, advisory_assessed=False)
        service_control = next(c for c in ctx.controls if c.control_id == 2)
        assert service_control.result != "PASS"
        assert any("etc/inittab:1" in item for item in service_control.evidence)

    def test_commented_service_does_not_establish_startup(self, tmp_path: Path) -> None:
        root = make_root(tmp_path, "#::respawn:/usr/sbin/telnetd -l /bin/sh\n")
        orchestrator = Orchestrator(ScannerConfig(output_dir=tmp_path / "out"))
        ctx = context_for(root, tmp_path)

        ctx = orchestrator._phase_filesystem(ctx)
        orchestrator._phase_controls(ctx, advisory_assessed=False)
        service_control = next(c for c in ctx.controls if c.control_id == 2)
        assert service_control.result == "PASS"
        assert not any("telnetd" in item for item in service_control.evidence)

    def test_report_renders_the_configured_directive(self, tmp_path: Path) -> None:
        from iot_hardware_scanner import __version__
        from iot_hardware_scanner.scanner.report_document import build_document, render

        root = make_root(tmp_path, "::respawn:/usr/sbin/sshd -D\n")
        orchestrator = Orchestrator(ScannerConfig(output_dir=tmp_path / "out"))
        ctx = context_for(root, tmp_path)
        ctx = orchestrator._phase_filesystem(ctx)
        orchestrator._phase_controls(ctx, advisory_assessed=False)

        document = build_document(ctx, version=__version__)
        assert document["inventory"]["boot_evidence"][0]["source"] == "etc/inittab"

        markdown = render(document, "markdown")
        assert "etc/inittab" in markdown
        assert "sshd" in markdown
        html = render(document, "html")
        assert "etc/inittab" in html
