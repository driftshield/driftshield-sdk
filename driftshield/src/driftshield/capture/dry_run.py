"""Dry run: which recent sessions capture would send, and why the rest stay.

Every Claude Code transcript (main sessions and subagents) in the configured
profiles and every Codex rollout written in the last N days goes through the
same scope gate the capture uses. Nothing is sent and nothing is written. A
refused session is never read past what the gate reads.

With ``scrub_check`` each session that would be sent is analysed locally the
way a submission is, and the blocked term hits in its redacted copy are
counted before and after the scrub. Counts only: no text is kept.
"""

from __future__ import annotations

import dataclasses
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

from driftshield.capture.config import CaptureSettings
from driftshield.capture.ledger import content_hash
from driftshield.capture.scope import ScopeGate
from driftshield.capture.sessions import (
    AGENT_FOR_SOURCE,
    MAIN_GLOB,
    SOURCE_CLAUDE_CODE,
    SOURCE_CODEX,
    SUBAGENT_GLOB,
    read_session,
)

WOULD_SEND = "would_send"
HELD = "held_blocked_terms"
NOT_FINISHED = "not_finished"
EMPTY = "empty"
SKIPPED = "skipped"

_REMOTE = re.compile(r"(?:github\.com[:/]|^https?://[^/]+/)(?P<repo>[^/]+/[^/]+?)(?:\.git)?/?$")


@dataclass(frozen=True, slots=True)
class Row:
    source: str
    kind: str
    path: Path
    modified: datetime
    session_id: str
    verdict: str
    reason: str
    detail: str
    cwd: str | None = None
    project: str | None = None
    agent_id: str | None = None
    hits: int | None = None
    hits_after: int | None = None
    model_name: str | None = None

    @property
    def sends(self) -> bool:
        return self.verdict == WOULD_SEND


def project_for(cwd: str | None, fallback: str | None) -> str | None:
    """``owner/name`` of the folder's ``origin`` remote, else the fallback."""
    if cwd and Path(cwd).is_dir():
        try:
            done = subprocess.run(
                ["git", "-C", cwd, "remote", "get-url", "origin"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            done = None
        if done is not None and done.returncode == 0:
            match = _REMOTE.search(done.stdout.strip())
            if match:
                return match.group("repo").lower()
    return fallback


def _modified(path: Path) -> datetime | None:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    except OSError:
        return None


def candidates(settings: CaptureSettings) -> Iterable[tuple[str, str, Path]]:
    for profile in settings.claude_profiles:
        root = Path(profile) / "projects"
        if root.is_dir():
            for path in sorted(root.glob(MAIN_GLOB)):
                yield SOURCE_CLAUDE_CODE, "main", path
            for path in sorted(root.glob(SUBAGENT_GLOB)):
                yield SOURCE_CLAUDE_CODE, "subagent", path
    codex = Path(settings.codex_sessions)
    if codex.is_dir():
        for path in sorted(codex.rglob("rollout-*.jsonl")):
            yield SOURCE_CODEX, "main", path


def denied_profile_count(settings: CaptureSettings, cutoff: datetime) -> int:
    """Transcripts in denied folders that look like Claude Code profiles,
    written since the cutoff. Counted by path; never opened."""
    count = 0
    for folder in settings.deny_folders:
        root = Path(folder) / "projects"
        if not root.is_dir():
            continue
        for pattern in (MAIN_GLOB, SUBAGENT_GLOB):
            for path in root.glob(pattern):
                when = _modified(path)
                if when is not None and when >= cutoff:
                    count += 1
    return count


def evaluate(
    settings: CaptureSettings,
    *,
    days: int,
    now: datetime | None = None,
    rules: Sequence[Any] | None = None,
) -> list[Row]:
    """Judge as if capture were on: the report is read before switching it on."""
    if settings.invalid is None:
        settings = dataclasses.replace(settings, enabled=True)
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=days)
    gate = ScopeGate(settings, rules)
    rows: list[Row] = []
    for source, kind, path in candidates(settings):
        modified = _modified(path)
        if modified is None or modified < cutoff:
            continue
        decision, session_id = gate.check_path(source, path)
        if not decision.allowed:
            rows.append(
                Row(
                    source,
                    kind,
                    path,
                    modified,
                    session_id,
                    SKIPPED,
                    decision.reason,
                    decision.detail,
                )
            )
            continue
        facts = read_session(source, path)
        decision = gate.check_facts(facts)
        if not decision.allowed:
            rows.append(
                Row(
                    source,
                    kind,
                    path,
                    modified,
                    facts.session_id,
                    SKIPPED,
                    decision.reason,
                    decision.detail,
                    facts.cwd,
                )
            )
            continue
        if source == SOURCE_CODEX and facts.is_subagent:
            rows.append(
                Row(
                    source,
                    kind,
                    path,
                    modified,
                    facts.session_id,
                    SKIPPED,
                    "codex_subagent",
                    "Codex subagent threads are not sent",
                    facts.cwd,
                )
            )
            continue
        if facts.record_count == 0:
            verdict, reason = EMPTY, "no parseable records"
        elif not facts.turn_complete:
            verdict, reason = NOT_FINISHED, "last record is not a finished turn"
        else:
            verdict, reason = WOULD_SEND, decision.reason
        rows.append(
            Row(
                source,
                kind,
                path,
                modified,
                facts.session_id,
                verdict,
                reason,
                decision.detail,
                facts.cwd,
                project_for(facts.cwd, settings.project),
                settings.agent_id(AGENT_FOR_SOURCE[source]),
                model_name=facts.model_name,
            )
        )
    return rows


def workflow_reference(agent: str, project: str | None) -> str:
    slug = project.replace("/", "-").lower() if project else "no-project"
    return f"capture/{agent}/{slug}"


def sent_identifiers(
    *,
    project: str | None,
    workflow: str,
    model_name: str | None,
    file_name: str,
    session_id: str,
    report_id: str,
    agent_id: str,
) -> list[str]:
    """Everything a submission sends beside the transcript. The capture holds a
    session with a blocked term in any of these; the dry run applies the same rule."""
    values = [project, workflow, model_name, file_name, session_id, report_id, agent_id]
    return [value for value in values if value]


def check_blocked_terms(rows: list[Row], settings: CaptureSettings) -> list[Row]:
    """Count blocked term hits in each would-send session's redacted copy."""
    if settings.blocked.empty:
        return rows
    from driftshield.public import analyse_run

    out: list[Row] = []
    for row in rows:
        if not row.sends:
            out.append(row)
            continue
        try:
            run = analyse_run(row.path.read_bytes(), source=str(row.path))
        except Exception as exc:  # noqa: BLE001 - a session that cannot be analysed is not sent either
            out.append(
                dataclasses.replace(
                    row, verdict=SKIPPED, reason="analysis_failed", detail=type(exc).__name__
                )
            )
            continue
        cleaned, hits = settings.blocked.scrub(run.redacted_transcript)
        agent = AGENT_FOR_SOURCE[row.source]
        identifiers = sent_identifiers(
            project=row.project,
            workflow=workflow_reference(agent, row.project),
            model_name=row.model_name,
            file_name=row.path.name,
            session_id=row.session_id,
            report_id=f"{row.session_id}@{content_hash(row.path)[:16]}",
            agent_id=row.agent_id or settings.agent_id(agent),
        )
        field_hits = settings.blocked.count(identifiers)
        hits += field_hits
        after = settings.blocked.count(cleaned)
        verdict = HELD if field_hits or settings.blocked.held(hits) or after else row.verdict
        out.append(dataclasses.replace(row, verdict=verdict, hits=hits, hits_after=after))
    return out


def _md(text: str | None) -> str:
    return (text or "").replace("|", "\\|")


def render(rows: list[Row], settings: CaptureSettings, *, days: int, now: datetime) -> str:
    sends = [r for r in rows if r.sends]
    held = [r for r in rows if r.verdict == HELD]
    waiting = [r for r in rows if r.verdict in (NOT_FINISHED, EMPTY)]
    skipped = [r for r in rows if r.verdict == SKIPPED]
    checked = [r for r in rows if r.hits is not None]
    lines = [
        f"# Capture dry run, last {days} days",
        "",
        f"Generated {now:%Y-%m-%d %H:%M} UTC. Nothing was sent and nothing was written.",
        "",
        "## Settings",
        "",
    ]
    if not settings.enabled:
        lines.append("    (capture is OFF in the file; this report judges as if it were on)")
    lines += [f"    {line}" for line in settings.describe()]
    lines += [
        "",
        "## Summary",
        "",
        f"- Would send: **{len(sends)}**",
        f"- Held for blocked terms: {len(held)}",
        f"- Allowed but not finished or empty: {len(waiting)}",
        f"- Skipped: {len(skipped)}",
        f"- Transcripts in denied profile folders, counted by path, never opened: "
        f"{denied_profile_count(settings, now - timedelta(days=days))}",
        "",
        "## Would send",
        "",
        "| Source | Kind | Last write (UTC) | Working folder | Project | agent_id | Session |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in sorted(sends, key=lambda r: r.modified):
        lines.append(
            f"| {row.source} | {row.kind} | {row.modified:%Y-%m-%d %H:%M} | {_md(row.cwd)} | "
            f"{_md(row.project)} | {row.agent_id} | {row.session_id[:12]} |"
        )
    if checked:
        lines += [
            "",
            "## Blocked terms after the scrub",
            "",
            "Counts only, in the redacted copy that would be sent.",
            "",
            "| Session | Project | Hits found | Left after scrub | Action |",
            "|---|---|---|---|---|",
        ]
        for row in sorted(checked, key=lambda r: (-(r.hits or 0), r.modified)):
            action = "hold" if row.verdict == HELD else ("send scrubbed" if row.hits else "send")
            lines.append(
                f"| {row.session_id[:12]} | {_md(row.project)} | {row.hits} | "
                f"{row.hits_after} | {action} |"
            )
    lines += ["", "## Skipped, by reason", ""]
    by_reason: dict[str, dict[str, int]] = {}
    for row in skipped:
        label = row.cwd or str(row.path.parent)
        group = by_reason.setdefault(row.reason, {})
        group[label] = group.get(label, 0) + 1
    for reason, groups in sorted(by_reason.items(), key=lambda kv: -sum(kv[1].values())):
        lines += [f"### {reason} ({sum(groups.values())})", ""]
        lines += [
            f"- {count} x {_md(label)}"
            for label, count in sorted(groups.items(), key=lambda kv: -kv[1])
        ]
        lines.append("")
    return "\n".join(lines) + "\n"


__all__ = ["HELD", "Row", "SKIPPED", "WOULD_SEND", "check_blocked_terms", "evaluate", "render"]
