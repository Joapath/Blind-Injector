"""Minimal CLI composition root."""

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


def _key_value(value: str) -> tuple[str, str]:
    key, separator, item = value.partition("=")
    if not separator or not key:
        raise argparse.ArgumentTypeError("expected KEY=VALUE")
    return key, item


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Authorized Boolean-based Blind SQLi testing")
    parser.add_argument("--url", required=True)
    parser.add_argument("--method", choices=("GET", "POST"), default="GET")
    parser.add_argument("--parameter", required=True)
    parser.add_argument("--location", choices=("query", "body", "cookie"), default="query")
    parser.add_argument(
        "--expression",
        action="append",
        help="SQL expression to extract (defaults to --column)",
    )
    parser.add_argument("--query", action="append", type=_key_value, default=[])
    parser.add_argument("--body", action="append", type=_key_value, default=[])
    parser.add_argument("--cookie", action="append", type=_key_value, default=[])
    parser.add_argument("--header", action="append", type=_key_value, default=[])
    parser.add_argument("--strategy", choices=("brute", "binary"), default="binary")
    parser.add_argument(
        "--attack-mode",
        choices=("conditional-response", "conditional-error"),
        default="conditional-response",
    )
    parser.add_argument("--dialect", choices=("oracle",), default="oracle")
    parser.add_argument("--table", default="users")
    parser.add_argument("--column", default="password")
    parser.add_argument("--user-column", default="username")
    parser.add_argument("--username", default="administrator")
    parser.add_argument("--detector", choices=("text", "length", "status", "error"), default="text")
    parser.add_argument("--charset", default="abcdefghijklmnopqrstuvwxyz0123456789")
    parser.add_argument("--max-length", type=int, default=100)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--delay", type=float, default=0.0)
    parser.add_argument("--proxy")
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--true-text")
    parser.add_argument("--error-text")
    parser.add_argument("--error-regex")
    parser.add_argument("--error-status", type=int)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument(
        "--log-file",
        type=Path,
        default=Path("logs/log.log"),
        help="detailed log file path (default: logs/log.log)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
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
            delay=args.delay,
            parameter=args.parameter,
            injection_location=args.location,
            strategy=args.strategy,
            detector=args.detector,
            detector_value=args.true_text or "",
            max_length=args.max_length,
            attack_mode=args.attack_mode,
            dialect=args.dialect,
            table=args.table,
            column=args.column,
            user_column=args.user_column,
            username=args.username,
            error_text=args.error_text,
            error_regex=args.error_regex,
            error_status=args.error_status,
        )
        result = build_attack_engine(configuration).run(args.expression or [args.column])
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