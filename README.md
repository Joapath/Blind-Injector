# blind-finder

Extensible framework for authorized Boolean-based Blind SQL injection testing.

## Scope of v0.1

- GET and POST requests.
- Query, body, and cookie injection points.
- Text, length, and status-code detectors.
- Oracle conditional-error detection using explicit text, regex, or status signals.
- Brute-force and binary-search strategies.
- HTTP-independent models and unit tests without network access.

Time-based techniques, non-Oracle error payloads, concurrency, and WAF evasion
are intentionally outside the current scope.

## Technical documentation

- `Docs/Referencia_tecnica.md`: architecture, execution flow, modules, contracts, and test coverage.
- `Docs/Posibles_inconsistencias.md`: verified limitations and inconsistencies, with evidence and recommendations.

## Development

Install the project with its runtime dependency using the packaging metadata in
`pyproject.toml`. Run the CLI with `python -m cli --help`, or use the installed
`blind-finder` command. Run tests with `python -m unittest discover -s tests -v`.

Use this tool only against systems for which you have explicit authorization.

Normal mode keeps the terminal focused on the final result and only displays
warnings/errors. Verbose mode adds compact progress and candidate-level
diagnostics to the terminal, while `logs/log.log` receives a detailed
timestamped record. Use `--log-file PATH` to choose another file. Dependency
connection noise is suppressed.

### Authorized Oracle conditional-error example

The following uses placeholders for an authorized lab; replace them only with
values you are permitted to test:

`python3 -m cli --url https://LAB_HOST/filter --parameter TrackingId --location cookie --cookie TrackingId=BASE_VALUE --cookie session=SESSION_VALUE --expression password --attack-mode conditional-error --error-regex 'ORA-[0-9]+' --max-length 20`

Conditional-error mode requires an explicit error signal and never treats a
generic 5xx response as evidence by itself.
