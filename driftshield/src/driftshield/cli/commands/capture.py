"""``driftshield capture``: settings, dry run and status for local session capture."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import typer

from driftshield.capture import dry_run
from driftshield.capture.config import config_path, load_settings, template

app = typer.Typer(
    help="Choose which local agent sessions may be sent, and check before anything is."
)


@app.command("init")
def init_settings(
    print_only: bool = typer.Option(
        False, "--print", help="Print the starting file instead of writing it."
    ),
) -> None:
    """Write a starting capture.toml with capture switched off."""
    if print_only:
        typer.echo(template(), nl=False)
        return
    target = config_path()
    if target.exists():
        typer.echo(f"{target} already exists; not changed")
        raise typer.Exit(1)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(template(), encoding="utf-8")
    target.chmod(0o600)
    typer.echo(
        f"wrote {target} with capture off; edit it, run `driftshield capture dry-run`, "
        "then set enabled = true"
    )


@app.command("status")
def capture_status(json_output: bool = typer.Option(False, "--json", help="Output JSON.")) -> None:
    """Show the capture settings. Blocked terms are counted, never shown."""
    settings = load_settings()
    if json_output:
        typer.echo(json.dumps(settings.to_dict(), indent=2, sort_keys=True))
        return
    for line in settings.describe():
        typer.echo(line)


@app.command("dry-run")
def capture_dry_run(
    days: int = typer.Option(
        14, "--days", min=1, help="Look at sessions written in the last N days."
    ),
    report: Path | None = typer.Option(None, "--report", help="Write the Markdown report here."),
    scrub_check: bool = typer.Option(
        True,
        "--scrub-check/--no-scrub-check",
        help="Analyse each session that would be sent and count blocked term hits (slower).",
    ),
) -> None:
    """List which sessions would be sent and why the rest are skipped. Sends nothing."""
    settings = load_settings()
    if settings.missing or settings.invalid:
        for line in settings.describe():
            typer.echo(line)
        raise typer.Exit(1)
    now = datetime.now(timezone.utc)
    rows = dry_run.evaluate(settings, days=days, now=now)
    if scrub_check:
        rows = dry_run.check_blocked_terms(rows, settings)
    text = dry_run.render(rows, settings, days=days, now=now)
    if report is None:
        typer.echo(text, nl=False)
        return
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(text, encoding="utf-8")
    sends = sum(1 for row in rows if row.sends)
    held = sum(1 for row in rows if row.verdict == dry_run.HELD)
    typer.echo(f"would send {sends}, hold {held}, of {len(rows)} sessions; report at {report}")
