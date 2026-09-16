
"""CLI composition root."""

import argparse
import logging
import sys
from collections.abc import Sequence
from pathlib import Path

if __package__ in {None, ""}:
    # Support `python cli/main.py` during development without requiring an
    # editable package installation. Normal usage should prefer `python -m cli`.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from config import build_attack_engine  # noqa: E402
from exceptions import BlindFinderError  # noqa: E402
from models.target import AttackConfiguration, Target  # noqa: E402
from utils.logging_setup import configure_logging  # noqa: E402


class HelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Formatter with clearer section headings for the command-line help."""

    def start_section(self, heading: str | None) -> None:
        if heading:
            heading = heading.upper()
        super().start_section(heading)


def _key_value(value: str) -> tuple[str, str]:
    key, separator, item = value.partition("=")
    if not separator or not key:
        raise argparse.ArgumentTypeError("expected KEY=VALUE")
    return key, item


def build_parser() -> argparse.ArgumentParser:
    description = """
Blind Finder is an assessment utility for authorized security testing.

Use it only against systems for which you have explicit permission. Supply the
target, the parameter to assess, and the response signal used for detection.
"""

    epilog = """
Examples:
  %(prog)s --url "https://application.example/search" \\
      --parameter tracking --true-text "Welcome back"

  %(prog)s --url "https://application.example/search" \\
      --method POST --location body --parameter search \\
      --body "search=baseline" --detector status --expected-status 200

Tip:
  Run %(prog)s --help before an engagement to review all supported transport,
  detection, extraction, and logging options.
"""

    parser = argparse.ArgumentParser(
        prog="blind-finder",
        description=description,
        epilog=epilog,
        formatter_class=HelpFormatter,
        add_help=False,
    )

    general = parser.add_argument_group("General options")
    general.add_argument(
        "-h",
        "--help",
        action="help",
        help="show this help message and exit",
    )
    general.add_argument(
        "--verbose",
        action="store_true",
        help="enable detailed console logging",
    )
    general.add_argument(
        "--log-file",
        type=Path,
        default=Path("logs/log.log"),
        metavar="PATH",
        help="write detailed logs to PATH (default: logs/log.log)",
    )

    target = parser.add_argument_group("Target and injection point")
    target.add_argument(
        "--url",
        required=True,
        metavar="URL",
        help="target endpoint URL",
    )
    target.add_argument(
        "--method",
        choices=("GET", "POST"),
        default="GET",
        help="HTTP method (default: GET)",
    )
    target.add_argument(
        "--parameter",
        required=True,
        metavar="NAME",
        help="name of the parameter to assess",
    )
    target.add_argument(
        "--location",
        choices=("query", "body", "cookie"),
        default="query",
        help="where the parameter is sent (default: query)",
    )

    request = parser.add_argument_group("Request data")
    request.add_argument(
        "--query",
        action="append",
        type=_key_value,
        default=[],
        metavar="KEY=VALUE",
        help="query-string value; repeatable",
    )
    request.add_argument(
        "--body",
        action="append",
        type=_key_value,
        default=[],
        metavar="KEY=VALUE",
        help="request-body value; repeatable",
    )
    request.add_argument(
        "--cookie",
        action="append",
        type=_key_value,
        default=[],
        metavar="KEY=VALUE",
        help="cookie value; repeatable",
    )
    request.add_argument(
        "--header",
        action="append",
        type=_key_value,
        default=[],
        metavar="KEY=VALUE",
        help="HTTP header; repeatable",
    )
    request.add_argument(
        "--proxy",
        metavar="URL",
        help="proxy URL for outgoing requests",
    )
    request.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        metavar="SECONDS",
        help="request timeout in seconds (default: 10.0)",
    )
    request.add_argument(
        "--allow-redirects",
        action="store_true",
        help="allow HTTP redirects",
    )
    request.add_argument(
        "--max-retries",
        type=int,
        default=0,
        metavar="COUNT",
        help="number of request retries (default: 0)",
    )
    request.add_argument(
        "--retry-backoff",
        type=float,
        default=0.0,
        metavar="SECONDS",
        help="delay between retries (default: 0.0)",
    )
    request.add_argument(
        "--insecure",
        action="store_true",
        help="disable TLS certificate verification",
    )

    extraction = parser.add_argument_group("Extraction settings")
    extraction.add_argument(
        "--expression",
        action="append",
        metavar="SQL",
        help="SQL expression to extract; repeatable (default: --column)",
    )
    extraction.add_argument(
        "--strategy",
        choices=("brute", "binary"),
        default="binary",
        help="character search strategy (default: binary)",
    )
    extraction.add_argument(
        "--charset",
        default="abcdefghijklmnopqrstuvwxyz0123456789",
        metavar="CHARS",
        help="candidate character set",
    )
    extraction.add_argument(
        "--max-length",
        type=int,
        default=100,
        metavar="COUNT",
        help="maximum extracted value length (default: 100)",
    )
    extraction.add_argument(
        "--delay",
        type=float,
        default=0.0,
        metavar="SECONDS",
        help="delay between requests (default: 0.0)",
    )

    technique = parser.add_argument_group("Technique and database settings")
    technique.add_argument(
        "--technique",
        choices=("boolean", "time"),
        default="boolean",
        help="assessment technique (default: boolean)",
    )
    technique.add_argument(
        "--attack-mode",
        choices=("conditional-response", "conditional-error"),
        default="conditional-response",
        help="response evaluation mode (default: conditional-response)",
    )
    technique.add_argument(
        "--dialect",
        choices=("oracle", "mysql"),
        default="oracle",
        help="database dialect (default: oracle)",
    )
    technique.add_argument(
        "--table",
        default="users",
        metavar="NAME",
        help="default table name (default: users)",
    )
    technique.add_argument(
        "--column",
        default="password",
        metavar="NAME",
        help="default column or fallback expression (default: password)",
    )
    technique.add_argument(
        "--user-column",
        default="username",
        metavar="NAME",
        help="username column name (default: username)",
    )
    technique.add_argument(
        "--username",
        default="administrator",
        metavar="VALUE",
        help="username value used by supported conditions",
    )
    technique.add_argument(
        "--sleep-seconds",
        type=float,
        metavar="SECONDS",
        help="database delay used by the time-based technique",
    )

    detection = parser.add_argument_group("Response detection")
    detection.add_argument(
        "--detector",
        choices=("text", "length", "status", "error", "timing"),
        default="text",
        help="response signal to evaluate (default: text)",
    )
    detection.add_argument(
        "--true-text",
        metavar="TEXT",
        help="text that identifies a positive response",
    )
    detection.add_argument(
        "--expected-length",
        type=int,
        metavar="COUNT",
        help="expected response length",
    )
    detection.add_argument(
        "--expected-status",
        type=int,
        metavar="CODE",
        help="expected HTTP status code",
    )
    detection.add_argument(
        "--error-text",
        metavar="TEXT",
        help="text that identifies an error response",
    )
    detection.add_argument(
        "--error-regex",
        metavar="PATTERN",
        help="regular expression that identifies an error response",
    )
    detection.add_argument(
        "--error-status",
        type=int,
        metavar="CODE",
        help="HTTP status code that identifies an error response",
    )
    detection.add_argument(
        "--timing-threshold",
        type=float,
        metavar="SECONDS",
        help="minimum timing difference considered positive",
    )
    detection.add_argument(
        "--timing-baseline",
        type=float,
        default=0.0,
        metavar="SECONDS",
        help="expected baseline response time (default: 0.0)",
    )
    detection.add_argument(
        "--timing-tolerance",
        type=float,
        default=0.0,
        metavar="SECONDS",
        help="allowed timing variation (default: 0.0)",
    )

    return parser


def _print_banner() -> None:
    banner = r"""
   _____  ____   _          _____ _   _      _ ______ _____ _______ ____  _____
  / ____|/ __ \ | |        |_   _| \ | |    | |  ____/ ____|__   __/ __ \|  __ \
 | (___ | |  | || |          | | |  \| |    | | |__ | |       | | | |  | | |__) |
  \___ \| |  | || |          | | | . ` | _  | |  __|| |       | | | |  | | |  _  /
  ____) | |__| || |____     _| |_| |\  || |_| | |___| |____   | | | |__| | | \ \
 |_____/ \___\_\|______|   |_____|_| \_| \___/|______\_____|  |_|  \____/|_|  \_\

                           Blind SQL Injector
                    Authorized Security Assessment Tool
    """
    print(banner.strip())


def main(argv: Sequence[str] | None = None) -> int:
    _print_banner()
    args = build_parser().parse_args(argv)
    configure_logging(verbose=args.verbose, log_file=args.log_file)

    try:
        configuration = AttackConfiguration(
            target=Target(
                url=args.url,
                method=args.method,
                headers=dict(args.header),
                cookies=dict(args.cookie),
                query=dict(args.query),
                body=dict(args.body),
            ),
            charset=args.charset,
            timeout=args.timeout,
            verify_ssl=not args.insecure,
            proxy=args.proxy,
            allow_redirects=args.allow_redirects,
            max_retries=args.max_retries,
            retry_backoff=args.retry_backoff,
            delay=args.delay,
            parameter=args.parameter,
            injection_location=args.location,
            strategy=args.strategy,
            technique=args.technique,
            detector=args.detector,
            detector_value=args.true_text or "",
            expected_length=args.expected_length,
            expected_status=args.expected_status,
            max_length=args.max_length,
            attack_mode=args.attack_mode,
            dialect=args.dialect,
            sleep_seconds=args.sleep_seconds,
            timing_threshold=args.timing_threshold,
            timing_baseline=args.timing_baseline,
            timing_tolerance=args.timing_tolerance,
            table=args.table,
            column=args.column,
            user_column=args.user_column,
            username=args.username,
            error_text=args.error_text,
            error_regex=args.error_regex,
            error_status=args.error_status,
        )
        result = build_attack_engine(configuration).run(
            args.expression or [args.column]
        )
    except KeyboardInterrupt:
        logging.getLogger(__name__).warning("Attack interrupted by user")
        return 130
    except (BlindFinderError, KeyError, TypeError, ValueError) as error:
        logging.getLogger(__name__).error("Attack could not be completed: %s", error)
        return 2

    for expression, extraction in result.extractions.items():
        print(f"{expression}: {extraction.value}")
        if not extraction.complete:
            print("  extraction incomplete", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
