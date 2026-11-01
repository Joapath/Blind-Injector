"""Build and write a structured report of one CLI run.

Presentation concern, same as the rest of ``cli/``: it has no idea how the
extraction happened, only how to summarize an already-finished
``AttackResult`` for a human or another tool to read later (e.g. to compare
results across PortSwigger lab runs).
"""

import csv
import json
from datetime import datetime
from pathlib import Path

from models import AttackConfiguration, AttackResult


_SUPPORTED_FORMATS = frozenset({"json", "csv"})


def build_report(
    configuration: AttackConfiguration,
    result: AttackResult,
    *,
    started_at: datetime,
    finished_at: datetime,
) -> dict:
    """Return a JSON-safe summary of one run, suitable for ``--report-file``."""
    extractions = []
    for expression, extraction in result.extractions.items():
        requests = sum(character.attempts for character in extraction.characters)
        extractions.append(
            {
                "expression": expression,
                "value": extraction.value,
                "complete": extraction.complete,
                "length": len(extraction.value),
                "requests": requests,
            }
        )
    return {
        "target": configuration.target.url,
        "parameter": configuration.parameter,
        "technique": configuration.technique,
        "detector": configuration.detector,
        "dialect": configuration.dialect,
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "duration_seconds": (finished_at - started_at).total_seconds(),
        "extractions": extractions,
    }


def write_report(report: dict, path: Path, fmt: str) -> None:
    """Write ``report`` to ``path`` as ``json`` or ``csv``."""
    if fmt not in _SUPPORTED_FORMATS:
        raise ValueError(
            f"Unsupported report format: {fmt!r}. Available: {', '.join(sorted(_SUPPORTED_FORMATS))}"
        )

    path.parent.mkdir(parents=True, exist_ok=True)

    if fmt == "json":
        path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        return

    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=["expression", "value", "complete", "length", "requests"]
        )
        writer.writeheader()
        for row in report["extractions"]:
            writer.writerow(row)
