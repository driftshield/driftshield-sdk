"""One watch tick: find finished sessions and send the allowed ones.

Each tick lists Claude Code main sessions (when ``main_sessions`` is on),
Claude Code subagents and Codex rollouts, and hands each quiet, finished one
to :class:`~driftshield.capture.service.CaptureService`. Then it retries
failures whose wait has passed.

* A window per kind starts at its first tick (kept in the ledger), so turning
  capture on never sends old sessions. ``since`` asks for older ones.
* A file is sent only after it has been quiet: ``main_idle_minutes`` for a
  main session (so a session in use is sent once it goes quiet, not after
  every turn), ``idle_seconds`` for subagents and Codex.
* A file whose size and modification time match a final decision from an
  earlier tick under the same settings is not opened again.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from driftshield.capture.ledger import LedgerUnreadable, iso, parse_iso
from driftshield.capture.scope import EXTENSION_FAILED, PARENT_UNKNOWN
from driftshield.capture.service import (
    EMPTY,
    HELD,
    NOT_FINISHED,
    REFUSED,
    SENT,
    SKIPPED_SUBAGENT,
    UNCHANGED,
    CaptureService,
)
from driftshield.capture.sessions import MAIN_GLOB, SOURCE_CLAUDE_CODE, SOURCE_CODEX, SUBAGENT_GLOB

DEFAULT_IDLE_SECONDS = 120
SETTLED_KEY = "capture_settled"
WINDOW_KEYS = {
    "main": "main_session_watch_started_at",
    "subagent": "worker_watch_started_at",
    "codex": "codex_watch_started_at",
}
# Decisions that hold until the file, the settings or the extensions change.
# An unfinished turn can only finish by writing to the file.
FINAL = frozenset({SENT, UNCHANGED, HELD, EMPTY, REFUSED, NOT_FINISHED, SKIPPED_SUBAGENT})
# Refusals that can change while the file and the settings stay the same.
UNSETTLED_REASONS = frozenset({PARENT_UNKNOWN, EXTENSION_FAILED})


@dataclass(slots=True)
class TickSummary:
    since: dict[str, str] = field(default_factory=dict)
    considered: int = 0
    before_window: int = 0
    settled: int = 0
    active: int = 0
    outcomes: dict[str, int] = field(default_factory=dict)
    sent: list[str] = field(default_factory=list)
    retried: int = 0
    skipped_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "since": dict(self.since),
            "considered": self.considered,
            "before_window": self.before_window,
            "settled": self.settled,
            "active": self.active,
            "outcomes": dict(self.outcomes),
            "sent": list(self.sent),
            "retried": self.retried,
            "skipped_reason": self.skipped_reason,
        }


def _files(service: CaptureService) -> Iterator[tuple[str, str, Path]]:
    settings = service.settings
    for profile in settings.claude_profiles:
        root = Path(profile) / "projects"
        if not root.is_dir():
            continue
        if settings.main_sessions:
            for path in sorted(root.glob(MAIN_GLOB)):
                yield "main", SOURCE_CLAUDE_CODE, path
        for path in sorted(root.glob(SUBAGENT_GLOB)):
            yield "subagent", SOURCE_CLAUDE_CODE, path
    codex = Path(settings.codex_sessions)
    if codex.is_dir():
        for path in sorted(codex.rglob("rollout-*.jsonl")):
            yield "codex", SOURCE_CODEX, path


def _fingerprint(service: CaptureService) -> str:
    """Changes with the settings or the loaded extensions, so either re-decides."""
    payload = {"settings": service.settings.to_dict(), "extensions": list(service.extension_names)}
    text = json.dumps(payload, sort_keys=True)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def tick(
    service: CaptureService,
    *,
    since: datetime | None = None,
    idle_seconds: int = DEFAULT_IDLE_SECONDS,
) -> TickSummary:
    summary = TickSummary()
    if not service.settings.active:
        summary.skipped_reason = "capture is off or the settings file is invalid"
        return summary
    now = service.now()
    try:
        with service.ledger.transaction() as ledger:
            windows: dict[str, datetime] = {}
            for kind, key in WINDOW_KEYS.items():
                recorded = parse_iso(ledger.meta.get(key))
                if recorded is None:
                    ledger.meta[key] = iso(now)
                    recorded = now
                windows[kind] = since or recorded
            settled = dict(ledger.meta.get(SETTLED_KEY) or {})
    except LedgerUnreadable:
        summary.skipped_reason = "ledger unreadable; nothing sent"
        return summary
    summary.since = {kind: iso(moment) for kind, moment in windows.items()}
    fingerprint = _fingerprint(service)
    updates: dict[str, dict[str, Any]] = {}
    for kind, source, path in _files(service):
        try:
            stat = path.stat()
        except OSError:
            continue
        modified = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
        if modified < windows[kind]:
            summary.before_window += 1
            continue
        summary.considered += 1
        marker = {"size": stat.st_size, "mtime_ns": stat.st_mtime_ns, "settings": fingerprint}
        previous = settled.get(str(path))
        if isinstance(previous, dict) and all(previous.get(k) == v for k, v in marker.items()):
            summary.settled += 1
            continue
        quiet = service.settings.main_idle_seconds if kind == "main" else idle_seconds
        if (now - modified).total_seconds() < quiet:
            summary.active += 1
            continue
        outcome = service.capture_path(source, path, trigger="watch")
        summary.outcomes[outcome.status] = summary.outcomes.get(outcome.status, 0) + 1
        if outcome.sent and outcome.submission_id:
            summary.sent.append(outcome.submission_id)
        if outcome.status in FINAL and outcome.reason not in UNSETTLED_REASONS:
            updates[str(path)] = {**marker, "outcome": outcome.status}
    summary.retried = len(service.retry_due())
    with service.ledger.transaction() as ledger:
        current = dict(ledger.meta.get(SETTLED_KEY) or {})
        current.update(updates)
        ledger.meta[SETTLED_KEY] = {k: v for k, v in current.items() if os.path.exists(k)}
    service.ledger.log(outcome="tick", **summary.to_dict())
    return summary


__all__ = ["DEFAULT_IDLE_SECONDS", "TickSummary", "WINDOW_KEYS", "tick"]
