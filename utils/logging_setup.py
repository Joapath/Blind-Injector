"""Readable console and detailed file logging for the CLI."""

from __future__ import annotations

import logging
import sys
from pathlib import Path


class ConsoleFormatter(logging.Formatter):
    """Render application logs as short, scan-friendly status lines."""

    _PREFIXES = {
        logging.DEBUG: "  ·",
        logging.INFO: "  [+]",
        logging.WARNING: "  [!]",
        logging.ERROR: "  [✗]",
        logging.CRITICAL: "  [✗]",
    }

    def format(self, record: logging.LogRecord) -> str:
        prefix = self._PREFIXES.get(record.levelno, "  [?]")
        return f"{prefix} {record.getMessage()}"


class FileFormatter(logging.Formatter):
    """Preserve timestamps, level, logger and message in the log file."""

    def __init__(self) -> None:
        super().__init__(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )


def configure_logging(*, verbose: bool, log_file: Path | None = None) -> None:
    """Configure application logging without leaking dependency debug noise."""
    root = logging.getLogger()
    for handler in root.handlers[:]:
        handler.close()
    root.handlers.clear()
    root.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Normal mode keeps the terminal focused on the final result printed by
    # the CLI. Verbose mode enables progress and candidate-level diagnostics.
    console = logging.StreamHandler(sys.stderr)
    console.setLevel(logging.DEBUG if verbose else logging.WARNING)
    console.setFormatter(ConsoleFormatter())
    root.addHandler(console)

    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
        file_handler.setFormatter(FileFormatter())
        root.addHandler(file_handler)

    # Requests/urllib3 can emit one line per connection and response. The
    # transport layer already reports normalized failures, so keep dependencies
    # quiet while preserving warnings and errors.
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
