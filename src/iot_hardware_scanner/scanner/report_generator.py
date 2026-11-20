"""Report generator — builds one document, renders it many ways.

Every format is rendered from the same schema-2 document produced by
:mod:`iot_hardware_scanner.scanner.report_document`. The generator never reads
a neighbouring file to build another format: the HTML report is not derived
from whatever ``report.md`` happens to be sitting in the directory.
"""

from __future__ import annotations

import logging
from pathlib import Path

from iot_hardware_scanner import __version__
from iot_hardware_scanner.config import ScannerConfig
from iot_hardware_scanner.models import ScanContext
from iot_hardware_scanner.scanner.report_document import (
    build_document,
    default_filename,
    render,
    write_atomic,
)

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Render the scan's report document in the configured formats."""

    def __init__(self, config: ScannerConfig) -> None:
        self.config = config

    def document(self, context: ScanContext) -> dict:
        """Return the report document for this scan."""
        return build_document(context, version=__version__)

    def generate(self, context: ScanContext, document: dict | None = None) -> dict[str, Path]:
        """Write every configured format into the scan's output directory.

        Returns:
            Mapping of format name to the path actually written.
        """
        document = document or self.document(context)
        paths: dict[str, Path] = {}

        for fmt in self.config.report_formats:
            if fmt == "terminal":
                continue
            destination = context.output_dir / default_filename(fmt)
            paths[fmt] = write_atomic(destination, render(document, fmt))
            logger.info("%s report: %s", fmt, destination)

        return paths
