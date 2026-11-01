"""Rich-powered terminal output for blind-finder."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

if TYPE_CHECKING:
    from models.attack import AttackResult, CharacterResult
    from models.target import AttackConfiguration

_THEME = Theme(
    {
        "info": "cyan",
        "success": "green",
        "warning": "yellow",
        "error": "red bold",
        "value": "green bold",
        "dim": "dim",
        "label": "bold",
    }
)

console = Console(theme=_THEME, highlight=False)


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

_BANNER_ART = r"""
   ___ _    ___ _  _ ___
  | _ ) |  |_ _| \| |   \
  | _ \ |__ | || .` | |) |
  |___/____|___|_|\_|___/
   ___ _  _    _ ___ ___ _____ ___  ___
  |_ _| \| |_ | | __/ __|_   _/ _ \| _ \
   | || .` | || | _| (__  | || (_) |   /
  |___|_|\_|\__/|___\___| |_| \___/|_|_\
"""


def banner() -> None:
    console.print(Text(_BANNER_ART.strip("\n"), style="bold cyan"))
    console.print(
        "  [label]Blind-Injector[/label] [dim]:: Authorized SQL Injection Assessment Tool[/dim]"
    )
    console.print("  [dim]by Joapath -> https://github.com/Joapath[/dim]")
    console.print()


# ---------------------------------------------------------------------------
# Leveled messages
# ---------------------------------------------------------------------------

def info(message: str, *, prefix: str = "*") -> None:
    console.print(f"[info]\\[{prefix}][/info] {message}")


def success(message: str) -> None:
    console.print(f"[success]\\[+][/success] {message}")


def warning(message: str) -> None:
    console.print(f"[warning]\\[!][/warning] {message}")


def error(message: str) -> None:
    console.print(f"[error]\\[✗][/error] {message}")


# ---------------------------------------------------------------------------
# Configuration summary
# ---------------------------------------------------------------------------

def config_summary(cfg: "AttackConfiguration") -> None:
    lines: list[str] = [
        f"[label]Target:[/label]    {cfg.target.url}",
        f"[label]Parameter:[/label] {cfg.parameter} ({cfg.injection_location}, {cfg.injection_mode})",
        f"[label]Technique:[/label] {cfg.technique} -> {cfg.detector} detector",
        f"[label]Strategy:[/label]  {cfg.strategy} search",
        f"[label]Dialect:[/label]   {cfg.dialect}",
    ]

    extras: list[str] = []
    extras.append(f"Threads: {cfg.max_workers}")
    if cfg.rate_limit:
        extras.append(f"Rate limit: {cfg.rate_limit} req/s")
    else:
        extras.append("Rate limit: none")
    if cfg.tampers:
        extras.append(f"Tampers: {', '.join(cfg.tampers)}")
    else:
        extras.append("Tampers: none")
    lines.append(f"[label]Options:[/label]  {' | '.join(extras)}")

    panel = Panel(
        "\n".join(lines),
        title=f"[bold]Configuration[/bold]",
        title_align="left",
        border_style="dim",
        padding=(0, 1),
    )
    console.print(panel)


# ---------------------------------------------------------------------------
# Result table
# ---------------------------------------------------------------------------

def result_table(results: "AttackResult") -> None:
    table = Table(
        title="Results",
        title_style="bold",
        border_style="dim",
        show_lines=False,
        pad_edge=True,
    )
    table.add_column("Expression", style="bold", no_wrap=True, max_width=50)
    table.add_column("Value", style="green bold")
    table.add_column("Status", justify="center")
    table.add_column("Requests", justify="right", style="dim")

    for expression, extraction in results.extractions.items():
        total_requests = sum(c.attempts for c in extraction.characters)
        status = "[success]✓[/success]" if extraction.complete else "[warning]incomplete[/warning]"
        table.add_row(
            _truncate(expression, 50),
            extraction.value or "[dim]—[/dim]",
            status,
            str(total_requests),
        )

    console.print()
    console.print(table)


def _truncate(text: str, max_len: int) -> str:
    if len(text) <= max_len:
        return text
    return text[: max_len - 1] + "…"


# ---------------------------------------------------------------------------
# Metrics summary
# ---------------------------------------------------------------------------

def metrics_summary(
    duration_seconds: float,
    total_requests: int,
    expressions_count: int,
) -> None:
    if duration_seconds > 0:
        rps = total_requests / duration_seconds
        rps_str = f"{rps:.2f} req/s"
    else:
        rps_str = "—"

    if duration_seconds >= 60:
        minutes = int(duration_seconds // 60)
        seconds = duration_seconds % 60
        time_str = f"{minutes}m{seconds:.0f}s"
    else:
        time_str = f"{duration_seconds:.1f}s"

    info(
        f"Done in {time_str} | "
        f"{total_requests} requests | "
        f"{rps_str} | "
        f"{expressions_count} expression(s)"
    )


# ---------------------------------------------------------------------------
# Extraction progress tracker
# ---------------------------------------------------------------------------

class ExtractionProgress:
    """Wraps rich.Progress to show per-expression extraction bars.

    Usage::

        tracker = ExtractionProgress(expressions, max_length)
        tracker.start()
        # ... inside on_progress callback:
        tracker.update(expression, characters, complete)
        # ... when done:
        tracker.stop()
    """

    def __init__(self, expressions: Sequence[str], max_length: int) -> None:
        self._max_length = max_length
        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=30),
            MofNCompleteColumn(),
            TextColumn("{task.fields[extracted]}"),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=console,
            transient=False,
        )
        self._tasks: dict[str, int] = {}
        for expr in expressions:
            label = _truncate(expr, 30)
            task_id = self._progress.add_task(
                label, total=max_length, extracted="", completed=0
            )
            self._tasks[expr] = task_id

    def start(self) -> None:
        self._progress.start()

    def stop(self) -> None:
        self._progress.stop()

    def update(
        self,
        expression: str,
        characters: tuple["CharacterResult", ...],
        complete: bool,
    ) -> None:
        task_id = self._tasks.get(expression)
        if task_id is None:
            return
        value = "".join(c.character or "?" for c in characters)
        done = len(characters)
        if complete:
            self._progress.update(
                task_id,
                completed=self._max_length,
                extracted=f"[value]{value}[/value]",
            )
        else:
            self._progress.update(
                task_id,
                completed=done,
                extracted=f"[dim]{value}[/dim]",
            )
