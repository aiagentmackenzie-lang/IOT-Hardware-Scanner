"""Slice 4A — rule matches have a typed destination and a reachability rule.

Every case here is about the *meaning* of a match, not about whether YARA can
find a byte sequence. The release gate needs four things, and this module
proves each one against the installed rule set:

1. the rule set is compiled **once** per run and has one digest;
2. a match is routed by its rule's own category to a credential, service,
   crypto or indicator destination, and never relabelled by a detector;
3. each shipped category has a benign **positive** case and a **lookalike
   negative** case — the negative one is the shape that raised eleven review
   findings on a stock OpenWrt image;
4. a secret is redacted before it can reach a finding, a log or a renderer.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.models import (
    C2Finding,
    CredentialFinding,
    FileCategory,
    FilesystemFinding,
    FilesystemInventory,
    FirmwareSizeCategory,
    ScanContext,
    Severity,
    StageId,
    StageStatus,
)
from iot_hardware_scanner.scanner.assessment import record_stage
from iot_hardware_scanner.scanner.c2_detector import C2Detector
from iot_hardware_scanner.scanner.credential_scanner import CredentialScanner
from iot_hardware_scanner.scanner.report_document import build_document, render
from iot_hardware_scanner.yara.yara_engine import YaraEngine, destination_for

# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────


def engine() -> YaraEngine:
    compiled = YaraEngine(ScannerConfig())
    compiled.load_rules()
    return compiled


def matches_for(path: Path, destination: str) -> list:
    found = engine()
    return [match for match in found.scan_file(path) if match.destination == destination]


def inventory_of(root: Path) -> FilesystemInventory:
    """A one-file inventory pointing into ``root``."""
    findings = []
    categories: dict[FileCategory, list[FilesystemFinding]] = {}
    for entry in sorted(root.rglob("*")):
        if not entry.is_file() or entry.is_symlink():
            continue
        relative = entry.relative_to(root)
        is_elf = entry.read_bytes()[:4] == b"\x7fELF"
        if is_elf:
            category = FileCategory.CRITICAL_BINARY
        elif relative.name in {"passwd", "shadow", "gshadow"}:
            category = FileCategory.CRITICAL_CREDENTIAL
        elif relative.name in {"inittab", "rc.local"} or relative.suffix in {
            ".conf",
            ".cfg",
            ".ini",
        }:
            category = FileCategory.CRITICAL_CONFIG
        else:
            category = FileCategory.MEDIUM_WEB
        finding = FilesystemFinding(
            path=relative,
            absolute_path=entry,
            category=category,
            file_type="ELF" if is_elf else "config",
            file_size=entry.stat().st_size,
            permissions="rw-r--r--",
            owner_uid=0,
            owner_gid=0,
            is_suid=False,
            is_world_writable=False,
            hash_sha256="0" * 64,
            format="elf" if is_elf else "other",
        )
        findings.append(finding)
        categories.setdefault(category, []).append(finding)
    inventory = FilesystemInventory(
        rootfs_path=root, total_files=len(findings), findings=findings, categories=categories
    )
    return inventory


# ──────────────────────────────────────────────
# One compile, one digest, no ambient rules
# ──────────────────────────────────────────────


class TestOneCompiledRuleSet:
    def test_a_second_load_recompiles_nothing(self) -> None:
        compiled = YaraEngine(ScannerConfig())
        first = compiled.load_rules()
        rules_object = compiled._rules
        second = compiled.load_rules()
        assert first == second > 0
        assert compiled._rules is rules_object, "the rule set was compiled more than once"

    def test_the_digest_is_independent_of_the_working_directory(self, tmp_path: Path) -> None:
        """Two directories with different ambient rule files give one digest."""
        decoy = tmp_path / "decoy.yar"
        decoy.write_text('rule ambient_rule { strings: $a = "secret" condition: $a }\n')
        first = engine()
        original = Path.cwd()
        try:
            import os

            os.chdir(tmp_path)
            second = engine()
        finally:
            os.chdir(original)
        assert first.digest == second.digest
        assert not any(record.name == "decoy.yar" for record in second.info.files)

    def test_the_digest_changes_when_a_rule_changes(self, tmp_path: Path) -> None:
        rule_dir = tmp_path / "rules"
        rule_dir.mkdir()
        (rule_dir / "extra.yar").write_text(
            'rule extra_one { meta: category = "credential" strings: $a = "zzz" condition: $a }\n'
        )
        without = YaraEngine(ScannerConfig())
        without.load_rules()
        with_extra = YaraEngine(ScannerConfig(yara_rules_dirs=[rule_dir]))
        with_extra.load_rules()
        assert without.digest != with_extra.digest

    def test_a_broken_rule_is_recorded_not_swallowed(self, tmp_path: Path) -> None:
        rule_dir = tmp_path / "rules"
        rule_dir.mkdir()
        (rule_dir / "broken.yar").write_text("rule broken { this is not yara }\n")
        compiled = YaraEngine(ScannerConfig(yara_rules_dirs=[rule_dir]))
        compiled.load_rules()
        assert compiled.diagnostics
        assert compiled.diagnostics[0]["file"] == "broken.yar"
        assert "compilation error" in compiled.diagnostics[0]["reason"]
        # The packaged rules still compiled: one bad file does not disarm the run.
        assert compiled.rule_count > 0


class TestTypedDestinations:
    def test_every_shipped_category_has_a_destination(self) -> None:
        compiled = engine()
        assert set(compiled.destinations) == {"credential", "service", "crypto", "indicator"}
        assert destination_for("malware_signature") == "indicator"
        assert destination_for("backdoor_service") == "service"
        assert destination_for("weak_crypto") == "crypto"
        assert destination_for("credential") == "credential"
        assert destination_for("unheard_of") == "indicator"

    def test_a_match_carries_namespace_offsets_and_the_ruleset_digest(self, tmp_path: Path) -> None:
        sample = tmp_path / "config.conf"
        sample.write_text('password = "Zx7!qP2mK9wR4tY6"\n')
        found = matches_for(sample, "credential")
        assert found, "the packed credential rule did not match a password assignment"
        match = found[0]
        assert match.namespace
        assert match.rule_file.endswith(".yar")
        assert match.ruleset_digest
        assert match.offsets and all(offset >= 0 for offset in match.offsets)


# ──────────────────────────────────────────────
# Benign positive / lookalike negative, per category
# ──────────────────────────────────────────────


class TestCredentialSemantics:
    def test_positive_a_real_key_in_a_config_is_a_credential(self, tmp_path: Path) -> None:
        sample = tmp_path / "settings.conf"
        sample.write_text("aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n")
        assert matches_for(sample, "credential"), "a well-formed AWS key id did not match"

    def test_negative_the_word_bearer_alone_is_protocol_vocabulary(self) -> None:
        """uhttpd_ubus ships the literal "Bearer "; that is a header name."""
        assert matches_for_text('strcmp(header, "Bearer ")') == []

    def test_negative_a_pem_header_without_key_material_is_parser_data(self) -> None:
        """mbedTLS carries the PEM header literal so it can recognise one."""
        text = 'static const char *rsa = "-----BEGIN RSA PRIVATE KEY-----";\n'
        assert matches_for_text(text, category="credential") == []

    def test_positive_a_pem_block_with_material_is_a_key(self, tmp_path: Path) -> None:
        sample = tmp_path / "id_rsa"
        sample.write_text(
            "-----BEGIN RSA PRIVATE KEY-----\n"
            + "MIIEogIBAAKCAQEA"
            + "A" * 64
            + "\n"
            + "-----END RSA PRIVATE KEY-----\n"
        )
        assert matches_for(sample, "credential"), "a real PEM block did not match"

    def test_negative_a_hash_shaped_string_in_library_data_is_not_a_credential(self) -> None:
        """The removed `unix_md5_hash` rule matched a hash example inside libc."""
        found = engine()
        assert all(
            not record.name.startswith("credentials_passwords") or record.rule_count == 1
            for record in found.info.files
        )
        assert matches_for_text("$1$abcd0123$9Qcg8DyviekV3tDGMZynJ1") == []

    def test_negative_a_bare_constant_in_a_library_never_becomes_a_credential(
        self, tmp_path: Path
    ) -> None:
        """A compiled library searching for an assignment is not a stored secret."""
        binary = tmp_path / "libexample.so"
        binary.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b'password = "Zx7!qP2mK9wR4tY6"\x00' * 4)
        inventory = inventory_of(tmp_path)
        scanner = CredentialScanner(ScannerConfig(), rule_engine=engine())
        findings = scanner.scan_inventory(inventory)
        assert not [item for item in findings if item.rule_id.startswith("credential.yara.")]
        assert scanner.suppressed, "the refusal was not recorded"


def matches_for_text(text: str, category: str = "credential") -> list:
    with __import__("tempfile").TemporaryDirectory() as directory:
        path = Path(directory) / "sample.txt"
        path.write_text(text)
        return [match for match in engine().scan_file(path) if match.destination == category]


class TestServiceSemantics:
    def test_positive_telnetd_with_a_shell_is_a_configured_service(self) -> None:
        text = "::respawn:/usr/sbin/telnetd -l /bin/sh\n"
        found = matches_for_text(text, category="service")
        assert [match.rule_name for match in found] == ["telnetd_backdoor"]

    def test_negative_telnetd_alone_configures_nothing(self) -> None:
        assert matches_for_text("the telnetd package is installed\n", category="service") == []

    def test_a_configured_service_is_not_a_listening_socket(self, tmp_path: Path) -> None:
        entry = tmp_path / "etc"
        entry.mkdir()
        (entry / "inittab").write_text("::respawn:/usr/sbin/telnetd -l /bin/sh\n")
        detector = C2Detector(ScannerConfig(), rule_engine=engine())
        findings = detector.detect_malware_signatures(inventory_of(tmp_path))
        service = [item for item in findings if item.indicator_type == "backdoor_service"]
        assert service, "a configured telnetd with a shell was not reported at all"
        assert service[0].severity == "SUSPICIOUS", (
            "configuration was reported as a listening service"
        )
        assert "requires device evidence" in service[0].description


class TestCryptoSemantics:
    def test_positive_md5_constants_next_to_its_identifier(self, tmp_path: Path) -> None:
        sample = tmp_path / "libmd.so"
        sample.write_bytes(
            b"\x7fELF\x02\x01\x01\x00"
            + bytes.fromhex("67452301efcdab8998badcfe10325476")
            + b"MD5_Init\x00MD5_Update\x00"
        )
        assert matches_for(sample, "crypto")

    def test_negative_the_md5_constant_alone_is_ordinary_data(self, tmp_path: Path) -> None:
        sample = tmp_path / "blob.bin"
        sample.write_bytes(bytes.fromhex("67452301efcdab8998badcfe10325476") * 2)
        assert matches_for(sample, "crypto") == []

    def test_negative_the_chacha20_sigma_constant_is_not_a_malware_signature(self) -> None:
        """libmbedcrypto and dropbear both carry it; it is a *strong* cipher."""
        assert matches_for_text("expand 32-byte k", category="indicator") == []

    def test_negative_an_ascending_lookup_table_is_not_rc4(self, tmp_path: Path) -> None:
        sample = tmp_path / "nls.ko"
        sample.write_bytes(b"\x7fELF\x02\x01\x01\x00" + bytes(range(16)) * 4)
        assert matches_for(sample, "crypto") == []

    def test_crypto_evidence_reaches_its_own_findings(self, tmp_path: Path) -> None:
        library = tmp_path / "libweak.so"
        library.write_bytes(
            b"\x7fELF\x02\x01\x01\x00"
            + bytes.fromhex("67452301efcdab8998badcfe10325476")
            + b"MD5_Init\x00"
        )
        detector = C2Detector(ScannerConfig(), rule_engine=engine())
        findings = detector.detect_crypto(inventory_of(tmp_path))
        assert [item.algorithm for item in findings] == ["MD5"]
        assert findings[0].strength == "weak"
        assert findings[0].ruleset_digest


class TestIndicatorSemantics:
    def test_positive_a_mirai_credential_pair_is_an_indicator(self) -> None:
        text = "root:xc3511\x00root:vizxv\x00"
        assert matches_for_text(text, category="indicator")

    def test_negative_a_single_repeated_byte_run_is_padding(self, tmp_path: Path) -> None:
        sample = tmp_path / "blob.bin"
        sample.write_bytes(b"\x37" * 64 + b"\x00" * 32)
        assert matches_for(sample, "indicator") == []

    def test_positive_the_table_next_to_the_family_string_fires(self) -> None:
        text = "\x37" * 20 + "KILLER_REJECT_TELNET\x00"
        names = [match.rule_name for match in matches_for_text(text, category="indicator")]
        assert "mirai_xor_key" in names


# ──────────────────────────────────────────────
# Domain semantics: a symbol table is not infrastructure
# ──────────────────────────────────────────────


class TestDomainReachability:
    def test_library_sonames_and_dotted_tokens_are_not_indicators(self, tmp_path: Path) -> None:
        library = tmp_path / "libustream-ssl.so"
        library.write_bytes(
            b"\x7fELF\x02\x01\x01\x00"
            + b"libc.so\x00libmbedtls.so\x00libmbedcrypto.so\x00"
            + b"connlabel.conf\x00pf.os\x00payload.offset\x00"
            + b"lucihttp.parser.urlencoded\x00s.old\x00"
        )
        detector = C2Detector(ScannerConfig(), rule_engine=engine())
        findings = detector.detect_domains(inventory_of(tmp_path))
        assert findings == [], [item.value for item in findings]
        assert detector.suppression_summary, "the refusals were not reported as coverage"
        reasons = " ".join(detector.suppression_summary)
        assert "soname" in reasons or "file or library" in reasons or "suffix" in reasons

    def test_a_real_indicator_survives_the_reachability_rules(self, tmp_path: Path) -> None:
        config = tmp_path / "etc"
        config.mkdir()
        (config / "system").write_text(
            "config system\n\toption update_url 'http://updates.firmware-vendor.su/path'\n"
        )
        detector = C2Detector(ScannerConfig(), rule_engine=engine())
        findings = detector.detect_domains(inventory_of(tmp_path))
        assert [item.value for item in findings] == ["updates.firmware-vendor.su"]

    def test_an_unlisted_suffix_is_not_guessed_at(self, tmp_path: Path) -> None:
        config = tmp_path / "etc"
        config.mkdir()
        (config / "system").write_text("option host 'admin.router.internal'\n")
        detector = C2Detector(ScannerConfig(), rule_engine=engine())
        assert detector.detect_domains(inventory_of(tmp_path)) == []


# ──────────────────────────────────────────────
# Redaction
# ──────────────────────────────────────────────


class TestRedaction:
    def test_a_synthetic_secret_never_reaches_an_output_channel(self, tmp_path: Path) -> None:
        secret = "Zx7qP2mK9wR4tY6bN3vC"
        tree = tmp_path / "tree"
        (tree / "etc").mkdir(parents=True)
        (tree / "etc" / "app.conf").write_text(f'password = "{secret}"\n')

        scanner = CredentialScanner(ScannerConfig(), rule_engine=engine())
        findings = scanner.scan_inventory(inventory_of(tree))
        assert findings, "the secret was not found, so redaction cannot be tested"
        assert secret not in json.dumps([item.__dict__ for item in findings], default=str)

        context = ScanContext(
            scan_id="redaction",
            firmware_path=tree,
            output_dir=tmp_path / "out",
            file_hash_sha256="a" * 64,
            file_hash_md5="b" * 32,
            file_size=1,
            file_type="Staged root tree",
            firmware_name="tree",
            size_category=FirmwareSizeCategory.SMALL,
            started_at=datetime.now(tz=timezone.utc),
        )
        context.profile = "firmware-tree"
        context.credential_findings = findings
        record_stage(context, StageId.INGEST, StageStatus.COMPLETE, inspected=1, eligible=1)
        record_stage(
            context, StageId.CREDENTIAL_SCAN, StageStatus.COMPLETE, inspected=1, eligible=1
        )
        document = build_document(context, version="test")
        for name in ("json", "markdown", "html", "terminal"):
            assert secret not in render(document, name), f"the secret leaked into {name}"


def test_a_credential_finding_keeps_every_occurrence() -> None:
    scanner = CredentialScanner(ScannerConfig(), rule_engine=engine())
    finding = CredentialFinding(
        severity=Severity.HIGH,
        category="password",
        file_path=Path("a.conf"),
        matched_pattern="password",
        raw_value_hash="same",
        rule_id="credential.regex.password",
        occurrences=["a.conf:1"],
    )
    other = CredentialFinding(
        severity=Severity.MEDIUM,
        category="password",
        file_path=Path("b.conf"),
        matched_pattern="password",
        raw_value_hash="same",
        rule_id="credential.regex.password",
        occurrences=["b.conf:7"],
    )
    merged = __import__(
        "iot_hardware_scanner.scanner.credential_scanner", fromlist=["_deduplicate_findings"]
    )._deduplicate_findings([finding, other])
    assert len(merged) == 1
    assert merged[0].occurrences == ["a.conf:1", "b.conf:7"]
    assert merged[0].severity is Severity.HIGH
    assert scanner is not None


def test_the_report_names_the_rule_set(tmp_path: Path) -> None:
    context = ScanContext(
        scan_id="ruleset",
        firmware_path=tmp_path / "fw.bin",
        output_dir=tmp_path,
        file_hash_sha256="a" * 64,
        file_hash_md5="b" * 32,
        file_size=1,
        file_type="x",
        firmware_name="fw",
        size_category=FirmwareSizeCategory.SMALL,
        started_at=datetime.now(tz=timezone.utc),
    )
    context.ruleset = engine().info
    document = build_document(context, version="test")
    assert document["ruleset"]["digest"] == context.ruleset.digest
    assert document["ruleset"]["rule_files"]
    assert all(record["destinations"] for record in document["ruleset"]["rule_files"])


@pytest.mark.parametrize("destination", ["credential", "service", "crypto", "indicator"])
def test_each_destination_has_shipped_rules(destination: str) -> None:
    assert destination in engine().destinations


def test_c2_finding_destination_is_typed() -> None:
    finding = C2Finding(
        severity="SUSPICIOUS",
        indicator_type="backdoor_service",
        value="x",
        file_path=Path("a"),
    )
    from iot_hardware_scanner.scanner.assessment import collect_findings

    context = ScanContext(
        scan_id="s",
        firmware_path=Path("fw"),
        output_dir=Path("out"),
        file_hash_sha256="a" * 64,
        file_hash_md5="b" * 32,
        file_size=1,
        file_type="x",
        firmware_name="fw",
        size_category=FirmwareSizeCategory.SMALL,
        started_at=datetime.now(tz=timezone.utc),
    )
    context.c2_findings = [finding]
    assert collect_findings(context)[0].destination == "service"
