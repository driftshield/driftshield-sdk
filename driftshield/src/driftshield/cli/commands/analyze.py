"""Analyze command for DriftShield CLI."""

import os
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from driftshield.cli.output import format_summary, format_json, format_verbose_table, format_quiet
from driftshield.cli.discovery import discover_sessions, resolve_session
from driftshield.core.deterministic_matching import CHECK_FAMILIES
from driftshield.core.models import RiskClassification
from driftshield.public import NoParseableEventsError, UnsupportedFormatError, analyse_run
from driftshield.tool_map import ToolMapError, load_tool_map


console = Console(force_terminal=True)
err_console = Console(force_terminal=True, stderr=True)


def analyze(
    path: Optional[str] = typer.Argument(
        None,
        help="Session file, directory, or session ID to analyze.",
    ),
    project: bool = typer.Option(
        False,
        "--project",
        help="Analyze sessions for current project.",
    ),
    parser: str = typer.Option(
        "auto",
        "--parser",
        "-p",
        help="Parser to use (auto, claude_code, claude_desktop, codex_cli, codex_desktop, crewai, langchain, openclaw).",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show full event table.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output as JSON.",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Minimal output.",
    ),
    fail_on: Optional[str] = typer.Option(
        None,
        "--fail-on",
        help="Exit 1 if any named check fires or step risk is flagged (comma separated). "
        "Checks: " + ", ".join(CHECK_FAMILIES) + " (also accepted as mechanism:<name>). "
        "Step risks: " + ", ".join(RiskClassification.FLAG_FIELDS) + ". "
        "An unknown name exits 2.",
    ),
    fail_threshold: Optional[int] = typer.Option(
        None,
        "--fail-threshold",
        help="Exit 1 if N or more events flagged.",
    ),
    tool_map_path: Optional[str] = typer.Option(
        None,
        "--tool-map",
        help="JSON file saying what each tool does (read, check, outside_write, ...). "
        "Defaults to $DRIFTSHIELD_TOOL_MAP. Adds the tool coverage to the output. "
        "Signature hits always print; with no map the default coding map applies.",
    ),
) -> None:
    """Analyse session(s) for reasoning risks."""
    claude_home = os.environ.get("CLAUDE_HOME")
    claude_base = Path(claude_home) if claude_home else None

    fail_on_names = _parse_fail_on(fail_on)

    try:
        tool_map = load_tool_map(tool_map_path)
    except ToolMapError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)

    # Collect files to analyze
    files_to_analyze: list[Path] = []

    if project:
        sessions = discover_sessions(Path.cwd(), claude_base)
        if not sessions:
            console.print("No sessions found for this project.")
            raise typer.Exit(0)
        files_to_analyze = [s.path for s in sessions]
    elif path is not None:
        resolved = resolve_session(path, Path.cwd(), claude_base)
        if resolved is None:
            direct = Path(path).expanduser().resolve()
            if direct.exists():
                resolved = direct
            else:
                console.print(f"[red]Error:[/red] Could not find session: {path}")
                raise typer.Exit(1)
        files_to_analyze = [resolved]
    else:
        console.print("[red]Error:[/red] No path provided. Use --project or specify a file path.")
        raise typer.Exit(1)

    # Analyse each file through the door
    all_results = []
    mapped_runs = {}
    for file_path in files_to_analyze:
        try:
            run = analyse_run(
                file_path.read_bytes(),
                source=str(file_path),
                format=None if parser == "auto" else parser,
                tool_map=tool_map,
            )
        except UnsupportedFormatError as e:
            console.print(f"[red]Error:[/red] {e}")
            raise typer.Exit(1)
        except NoParseableEventsError as e:
            err_console.print(f"[yellow]Warning:[/yellow] {file_path.name}: {e}, skipping")
            continue
        except Exception as e:
            console.print(f"[red]Error:[/red] Failed to analyze {file_path.name}: {e}")
            if len(files_to_analyze) == 1:
                raise typer.Exit(1)
            continue
        for warning in run.warnings:
            err_console.print(f"[yellow]Warning:[/yellow] {file_path.name}: {warning}")
        all_results.append((file_path, run.analysis))
        mapped_runs[file_path] = run

    if not all_results:
        console.print("No sessions analyzed.")
        raise typer.Exit(1)

    # Check CI failure conditions
    should_fail = False
    fail_reasons: list[str] = []

    for file_path, result in all_results:
        for reason in _fail_on_reasons(fail_on_names, result, mapped_runs[file_path], file_path.stem):
            should_fail = True
            fail_reasons.append(reason)

        if fail_threshold is not None:
            if result.flagged_events >= fail_threshold:
                should_fail = True
                fail_reasons.append(
                    f"{result.flagged_events} flagged events in {file_path.stem} "
                    f"(threshold: {fail_threshold})"
                )

    # Output results
    if json_output:
        import json
        data = []
        for file_path, result in all_results:
            item = json.loads(format_json(result))
            item.update(_run_fields(mapped_runs[file_path], with_tool_map=tool_map is not None))
            data.append(item)
        typer.echo(json.dumps(data[0] if len(data) == 1 else data, indent=2))
    elif quiet:
        for file_path, result in all_results:
            if len(all_results) > 1:
                console.print(f"[bold]{file_path.stem}:[/bold] ", end="")
            fired = (hit.mechanism_id or hit.signature_id for hit in mapped_runs[file_path].signature_hits)
            console.print(format_quiet(result, fired))
    else:
        for i, (file_path, result) in enumerate(all_results):
            if i > 0:
                console.print()
                console.print("\u2500" * 40)
                console.print()

            if len(all_results) > 1:
                console.print(f"[bold]Session: {file_path.stem}[/bold]")
                console.print()

            console.print(format_summary(result))
            console.print()
            console.print(_hits_summary(mapped_runs[file_path], with_tool_map=tool_map is not None))

            if verbose:
                console.print()
                console.print(format_verbose_table(result))

    # Exit with failure if CI conditions met
    if should_fail:
        for reason in fail_reasons:
            err_console.print(f"[red]FAIL:[/red] {reason}", highlight=False, soft_wrap=True)
        raise typer.Exit(1)


def _run_fields(run, *, with_tool_map: bool) -> dict:
    fields: dict = {}
    if with_tool_map:
        fields["tool_coverage"] = run.tool_coverage
    fields["signature_hits"] = [
        {"signature_id": hit.signature_id, "mechanism_id": hit.mechanism_id}
        for hit in run.signature_hits
    ]
    return fields

def _parse_fail_on(fail_on: Optional[str]) -> list[str]:
    """The --fail-on names, with ``mechanism:`` stripped. An unknown name is a usage error."""
    if not fail_on:
        return []
    names = []
    for raw in fail_on.split(","):
        name = raw.strip().removeprefix("mechanism:")
        if not name:
            continue
        if name not in CHECK_FAMILIES and name not in RiskClassification.FLAG_FIELDS:
            known = ", ".join(sorted({*CHECK_FAMILIES, *RiskClassification.FLAG_FIELDS}))
            raise typer.BadParameter(f"unknown name {raw.strip()!r}. Known: {known}", param_hint="--fail-on")
        names.append(name)
    return list(dict.fromkeys(names))


def _fail_on_reasons(names: list[str], result, run, session: str) -> list[str]:
    """One line per --fail-on name that fired: a check hit, a step risk flag, or both."""
    fired_checks = {hit.mechanism_id for hit in run.signature_hits}
    reasons = []
    for name in names:
        parts = []
        if name in fired_checks:
            parts.append("check fired")
        flagged = result.risk_summary.get(name, 0) if name in RiskClassification.FLAG_FIELDS else 0
        if flagged > 0:
            parts.append(f"step risk on {flagged} event{'s' if flagged != 1 else ''}")
        if parts:
            reasons.append(f"{name} {' and '.join(parts)} in {session} (--fail-on {name})")
    return reasons


def _hits_summary(run, *, with_tool_map: bool) -> str:
    lines = []
    if with_tool_map:
        coverage = run.tool_coverage or {}
        total = coverage.get("tool_calls", 0)
        mapped = coverage.get("mapped_calls", 0)
        lines.append(f"Tool map: {mapped} of {total} tool calls checked")
        not_checked = coverage.get("not_checked_tools") or {}
        if not_checked:
            names = ", ".join(f"{name} ({count})" for name, count in not_checked.items())
            lines.append(f"Not checked (not in the tool map): {names}")
    hits = sorted({hit.signature_id for hit in run.signature_hits})
    lines.append(f"Signature hits: {', '.join(hits) if hits else 'none'}")
    return "\n".join(lines)
