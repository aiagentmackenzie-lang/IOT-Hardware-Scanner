# IoT Hardware Scanner — Firmware Security Analysis Platform

> Defensive static analysis for IoT/embedded/OT firmware images.

## Overview

IoT Hardware Scanner automates the full static-analysis pipeline for firmware security:

**Ingest → Extract → Analyze Filesystem → Detect Credentials → Check CVEs → Find C2 Indicators → Risk Score → Report**

It does **not** exploit, emulate, or interact with live devices. Purely offline, defensive analysis.

## Install

```bash
pip install iot-hardware-scanner
```

With extraction support:
```bash
pip install iot-hardware-scanner[extraction]
```

## Quick Start

```bash
# Full scan
iot-hardware-scanner scan firmware.bin

# JSON output (CI/CD)
iot-hardware-scanner scan firmware.bin --format json

# Markdown report
iot-hardware-scanner scan firmware.bin --format markdown --out report.md

# Entropy analysis only
iot-hardware-scanner entropy firmware.bin
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No CRITICAL findings |
| 1 | CRITICAL findings detected |
| 2 | Invalid arguments |
| 3 | Firmware file not found / unreadable |
| 4 | Extraction failed |
| 5 | Dependency missing |
| 6 | Internal error |

## Architecture

7-phase modular pipeline. Every scanner is an independent module with a stable interface.

See [SDR.md](./SDR.md) for the full build specification.

## License

MIT