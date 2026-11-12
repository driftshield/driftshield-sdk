"""``driftshield capture``: settings, dry run and status for local session capture."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

import typer

from driftshield.capture import dry_run
from driftshield.capture.config import config_path, load_settings, template
from driftshield.capture.extensions import load_extensions
from driftshield.capture.install import install_text
from driftshield.capture.ledger import Ledger, parse_iso
from driftshield.capture.service import CaptureService
from driftshield.capture.sessions import SOURCE_CLAUDE_CODE, SOURCE_CODEX
from driftshield.capture.watch import DEFAULT_IDLE_SECONDS, tick

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
    """Show the settings, extensions and what was sent. Blocked terms are counted only."""
    settings = load_settings()
    ledger = Ledger()
    extensions = load_extensions()
    revisions = sum(len(item.get("revisions") or []) for item in ledger.runs.values())
    held = [
        {"key": item["key"], "hits": item["last_decision"].get("hits")} for item in ledger.held()
    ]
    failing = [
        {
            "key": item["key"],
            **{k: item["failure"].get(k) for k in ("kind", "attempts", "next_retry_at")},
        }
        for item in ledger.failures()
    ]
    if json_output:
        payload = {
            **settings.to_dict(),
            "extensions": list(extensions.names),
            "extensions_failed": list(extensions.failed),
            "ledger": {
                "path": str(ledger.path),
                "unreadable": ledger.unreadable,
                "runs": len(ledger.runs),
                "revisions_sent": revisions,
                "held": held,
                "failing": failing,
            },
        }
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        return
    for line in settings.describe():
        typer.echo(line)
    typer.echo(
        f"extensions: {', '.join(extensions.names) or '(none)'}"
        + (f"  FAILED TO LOAD: {', '.join(extensions.failed)}" if extensions.failed else "")
    )
    if ledger.unreadable:
        typer.echo(f"LEDGER UNREADABLE at {ledger.path}: {ledger.unreadable}; nothing is sent")
    typer.echo(
        f"ledger: {len(ledger.runs)} runs, {revisions} revisions sent, "
        f"{len(held)} held, {len(failing)} failing"
    )
    for item in held:
        typer.echo(f"  HELD {item['key']} hits={item['hits']}")
    for item in failing:
        typer.echo(
            f"  FAILING {item['key']} kind={item['kind']} attempts={item['attempts']} "
            f"next_retry_at={item['next_retry_at']}"
        )


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


@app.command("watch")
def capture_watch(
    since: str | None = typer.Option(
        None, "--since", help="ISO time: also send sessions written since then (a backfill)."
    ),
    idle: int = typer.Option(
        DEFAULT_IDLE_SECONDS, "--idle", min=0, help="Quiet seconds before a subagent is sent."
    ),
    loop: bool = typer.Option(False, "--loop", help="Keep ticking every --interval seconds."),
    interval: int = typer.Option(60, "--interval", min=5),
) -> None:
    """One tick: send the finished, allowed sessions and retry due failures."""
    start = parse_iso(since) if since else None
    if since and start is None:
        typer.echo("--since is not an ISO time")
        raise typer.Exit(2)
    while True:
        settings = load_settings()
        summary = tick(CaptureService(settings, Ledger()), since=start, idle_seconds=idle)
        typer.echo(json.dumps(summary.to_dict(), sort_keys=True))
        if not loop:
            return
        time.sleep(interval)


@app.command("submit")
def capture_submit(
    path: Path = typer.Option(..., "--path", exists=True, dir_okay=False, help="Transcript file."),
    source: str = typer.Option("claude", "--source", help="claude or codex."),
    force: bool = typer.Option(False, "--force", help="Ignore a retry wait."),
) -> None:
    """Send one finished session now, through the same checks as the watch."""
    sources = {"claude": SOURCE_CLAUDE_CODE, "codex": SOURCE_CODEX}
    if source not in sources:
        typer.echo("--source must be claude or codex")
        raise typer.Exit(2)
    settings = load_settings()
    if not settings.active:
        for line in settings.describe():
            typer.echo(line)
        raise typer.Exit(1)
    outcome = CaptureService(settings, Ledger()).capture_path(
        sources[source], path.expanduser().resolve(), force=force
    )
    typer.echo(f"{outcome.status}: {outcome.detail}")
    if not outcome.sent and outcome.status != "unchanged":
        raise typer.Exit(1)


@app.command("install")
def capture_install(
    systemd: bool = typer.Option(False, "--systemd", help="Print systemd user units instead."),
    interval: int = typer.Option(60, "--interval", min=5),
) -> None:
    """Print a launchd agent (or systemd units) that runs the watch tick. Edits nothing."""
    typer.echo(install_text(systemd=systemd, log_dir=Ledger().home, interval=interval), nl=False)
