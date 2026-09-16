"""Tests for readable and detailed logging output."""

import io
import logging
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from utils.logging_setup import ConsoleFormatter, FileFormatter, configure_logging


class LoggingSetupTests(unittest.TestCase):
    def test_console_formatter_uses_readable_markers(self) -> None:
        record = logging.LogRecord("core.extractor", logging.INFO, "", 0, "Position 1/2", (), None)
        self.assertEqual(ConsoleFormatter().format(record), "  [+] Position 1/2")

    def test_file_formatter_keeps_context(self) -> None:
        record = logging.LogRecord("core.extractor", logging.DEBUG, "", 0, "candidate", (), None)
        formatted = FileFormatter().format(record)
        self.assertIn("DEBUG", formatted)
        self.assertIn("core.extractor", formatted)
        self.assertIn("candidate", formatted)

    def test_configure_logging_writes_detailed_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "logs" / "run.log"
            configure_logging(verbose=True, log_file=path)
            logging.getLogger("blind-finder-test").debug("candidate evaluated")

            content = path.read_text(encoding="utf-8")

        self.assertIn("DEBUG", content)
        self.assertIn("candidate evaluated", content)

    def test_dependency_debug_logging_is_suppressed(self) -> None:
        configure_logging(verbose=True, log_file=None)
        self.assertEqual(logging.getLogger("urllib3").level, logging.WARNING)

    def test_normal_mode_hides_progress_but_keeps_warnings(self) -> None:
        stream = io.StringIO()
        with patch("utils.logging_setup.sys.stderr", stream):
            configure_logging(verbose=False, log_file=None)
            logger = logging.getLogger("blind-finder-test")
            logger.info("position progress")
            logger.warning("recoverable warning")

        output = stream.getvalue()
        self.assertNotIn("position progress", output)
        self.assertIn("recoverable warning", output)

    def test_verbose_mode_shows_progress_and_debug(self) -> None:
        stream = io.StringIO()
        with patch("utils.logging_setup.sys.stderr", stream):
            configure_logging(verbose=True, log_file=None)
            logger = logging.getLogger("blind-finder-test")
            logger.info("position progress")
            logger.debug("candidate detail")

        output = stream.getvalue()
        self.assertIn("[+] position progress", output)
        self.assertIn("· candidate detail", output)


if __name__ == "__main__":
    unittest.main()