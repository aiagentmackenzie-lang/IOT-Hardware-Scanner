# IOT Hardware Scanner — QA Handoff Document

**Session Date:** 2026-05-19  
**Agent Persona:** Lead Code Quality Tester  
**Branch:** `main` (pushed to origin)  
**Test Status:** 457 passed, 1 skipped

---

## Commits Made This Session

1. `c3a0a3a` — fix: path traversal vulnerability in `get_metadata` — validate before `resolve()`
2. `8a4eee7` — fix: filesystem category substring false positive — use `startswith` instead of `in`
3. `be057e5` — fix: scan all extracted root filesystems — merge inventories instead of dropping `[0]`
4. `47a4a4d` — fix: CLI exit codes now treat `LIKELY_C2` as critical (exit 1) and non-critical findings as exit 2
5. `b636e62` — security: fix credential masking — fixed-length redaction prevents prefix/suffix/length leaks
6. `bb36046` — fix: secure boot eval no longer falsely PASS based on encryption — searches filesystem indicators
7. `581ed02` — fix: wire up `extraction_depth` config to pybinwalk and subprocess binwalk

---

## Bugs Found but NOT Yet Fixed (Next Priority Queue)

These were identified during deep-dive but remain unresolved due to token/session limits.

### 🔴 P0 — Critical / Production Blockers

1. **NVD API silent failure (CVE Scanner)** — `NVDClient.query_cpe()` and `query_keyword()` return `[]` on any network/HTTP/rate-limit failure. `CVEScanner.scan_component()` cannot distinguish "no CVEs" from "API down/scanner broken." This causes false negatives and silent pipeline passes on network issues. **Fix:** Add a `NVDApiError` path or return `None` on failure and handle it upstream in `CVEScanner` with clear warning in report.

2. **OOM / Memory bomb in entropy analysis** — `orchestrator._phase_entropy()` calls `context.firmware_path.read_bytes()`, loading the entire firmware into RAM (up to 2 GB per config). For large firmware on constrained SOC analyst machines this is a denial-of-service risk. **Fix:** Memory-map or stream the file in `EntropyAnalyzer.analyze_file()`; adapt block size for large files. Never call `read_bytes()` on multi-GB files.

3. **OOM in credential scanner** — `CredentialScanner.scan_file()` calls `abs_path.read_text(errors="ignore")` on every file in the scanned categories. A 500 MB SQLite dump or log file will blow memory. **Fix:** Add a config `max_scan_file_size_mb` and skip or mmap files above it.

4. **OOM in C2 detector** — `C2Detector._extract_domains_from_file()` and `_extract_ips_from_file()` call `path.read_text()` on every non-binary file. Same OOM vector. **Fix:** Same size-limit gating or line-by-line streaming.

### 🟠 P1 — High Severity

5. **RiskScorer `_eval_encrypted_data_at_rest` logic flaw** — This control evaluates *plaintext credential findings* instead of actual data-at-rest encryption. A firmware with an encrypted FS but a hardcoded password in a script would FAIL this control even though data at rest IS encrypted. The control name and evaluation are misaligned. **Fix:** Rename control or change evaluation to check entropy profile + encrypted region presence combined with credential findings.

6. **DomainScorer benign override is weak** — If a domain is in the benign whitelist but also matches threat intel, the score computation still adds positive signals and may classify as `SUSPICIOUS`. A false-positive in threat intel should not override a known-good domain. **Fix:** Stronger benign override: if domain is benign, immediately cap score at 0 and return `INFORMATIONAL`.

7. **YARA engine skips legitimate rules** — `YaraEngine.load_rules()` skips any file containing the word `include` anywhere in the file. A rule with a comment like `// includes check for foo` or a string containing `include` would be wrongly excluded. **Fix:** Use regex `^\s*include\s+` per-line check, not substring match.

8. **`FirmwareExtractor` hard link audit missing** — The symlink audit (`_audit_symlinks`) prevents ZipSlip via symlinks, but hard links are not audited. A malicious firmware (if extracted as root) could create hard links to `/etc/shadow`. **Fix:** Add `_audit_hardlinks()` using `os.stat()` nlink detection.

9. **`NVDClient` rate-limit receives 429 but does not retry** — `_make_request()` logs a warning and returns `None` on `HTTPError`. Should implement exponential backoff for 429 / 503 / network errors. **Fix:** Add `time.sleep()` retry loop with configurable max retries.

### 🟡 P2 — Medium / Polish

10. **`ScanContext` missing `completed_at`** — Reports cannot show scan duration or detect hung phases. **Fix:** Add `completed_at: datetime | None = None` and set it in orchestrator `run()`.

11. **`DomainScorer._is_dga()` false positives on legitimate CDN subdomains** — Very long alphanumeric subdomains (e.g., CloudFront) trigger DGA detection. **Fix:** Expand benign domain list or add minimum entropy threshold before flagging DGA.

12. **`FirmwareExtractor._fmt_size()` type-safety workaround** — Uses `# type: ignore[assignment]` inside a loop. Not a functional bug but technical debt.

13. **`FilesystemScanner._check_script_for_services()` reads binaries as text** — Called on all init scripts; if a binary is mis-categorized as script, it reads potentially large files. **Fix:** Limit read size or restrict to text files only.

---

## Architecture Notes for Next Agent

- **Pipeline order:** Ingest → Extract + Filesystem → Entropy + Binary Intel → Credentials → CVE → C2 → Risk/Report.
- **`ScanContext` is the monolithic state object** threaded through all phases. Any model changes will cascade to `report_generator.py` and `cli.py` `report` command.
- **YARA is optional** — All scanner classes gracefully degrade when `yara-python` or `pybinwalk` is missing.
- **Config-driven** — `ScannerConfig` uses Pydantic dataclass; `extraction_depth` now wired through. Any new size-limit configs should follow the same pattern.
- **Exit codes:** `0` = clean, `1` = critical / `LIKELY_C2`, `2` = non-critical findings present, `3` = firmware validation error, `4+` = extraction/config errors.

---

## Where to Pick Up Next

1. Review the current `HANDOFF.md` against `git log --oneline` to confirm all commits synced.
2. Run `pytest tests/` to confirm baseline is green.
3. Address **P0 #2 (entropy OOM)** first — it is the highest production-risk item remaining.
4. Then **P0 #1 (NVD silent failure)** — false negatives in CVE scanning are dangerous for a security scanner.
5. Continue down the numbered list above.

---

*End of handoff — pushed to `main` at origin.*
