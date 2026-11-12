"""Read what the capture needs from Claude Code transcripts and Codex rollouts.

Claude Code: ``<profile>/projects/<folder slug>/<session id>.jsonl``, with
subagents at ``<session id>/subagents/agent-<id>.jsonl``. Records carry
``sessionId`` and ``cwd``; a subagent's records are sidechains carrying the
parent's ``sessionId``.

Codex: ``<sessions>/YYYY/MM/DD/rollout-<timestamp>-<id>.jsonl``. The first
record is ``session_meta`` (thread id, cwd, optional parent); ``turn_context``
records may change the cwd; a finished turn ends with an ``event_msg`` whose
payload type is ``task_complete``.

Only working folders, ids and turn state are read. No message text is kept.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SOURCE_CLAUDE_CODE = "claude_code"
SOURCE_CODEX = "codex_cli"
AGENT_FOR_SOURCE = {SOURCE_CLAUDE_CODE: "claude-code", SOURCE_CODEX: "codex"}
SUBAGENTS_DIR = "subagents"
MAIN_GLOB = "*/*.jsonl"
SUBAGENT_GLOB = f"*/*/{SUBAGENTS_DIR}/agent-*.jsonl"
# How far a probe reads looking for the first cwd. Resumed sessions open with
# summary records that carry none.
PROBE_MAX_RECORDS = 200

_CODEX_FILE_ID = re.compile(
    r"rollout-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-(?P<id>[0-9a-fA-F-]{36})\.jsonl$"
)
_CONVERSATION = frozenset({"user", "assistant", "system", "summary"})


@dataclass(slots=True)
class SessionFacts:
    source: str
    session_id: str
    path: Path
    cwds: list[str] = field(default_factory=list)
    parent_session_id: str | None = None
    is_subagent: bool = False
    turn_complete: bool = False
    record_count: int = 0
    model_name: str | None = None
    last_timestamp: str | None = None

    @property
    def cwd(self) -> str | None:
        return self.cwds[0] if self.cwds else None

    def note_cwd(self, value: Any) -> None:
        if isinstance(value, str) and value and value not in self.cwds:
            self.cwds.append(value)


def iter_records(path: Path) -> Iterator[dict[str, Any]]:
    """Each parseable JSON object line; anything else is skipped."""
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(record, dict):
                yield record


def completed_assistant(record: dict[str, Any]) -> bool:
    """An assistant record that ends a turn: no tool call left open."""
    message = record.get("message")
    if record.get("type") != "assistant" or not isinstance(message, dict):
        return False
    if message.get("stop_reason") == "tool_use":
        return False
    content = message.get("content")
    if isinstance(content, list):
        return not any(isinstance(b, dict) and b.get("type") == "tool_use" for b in content)
    return True


def read_claude(path: Path) -> SessionFacts:
    facts = SessionFacts(source=SOURCE_CLAUDE_CODE, session_id=path.stem, path=path)
    seen_session: str | None = None
    for record in iter_records(path):
        facts.record_count += 1
        facts.note_cwd(record.get("cwd"))
        session = record.get("sessionId")
        if record.get("isSidechain") is True:
            facts.is_subagent = True
            if facts.parent_session_id is None and isinstance(session, str):
                facts.parent_session_id = session
        elif seen_session is None and isinstance(session, str):
            seen_session = session
        kind = record.get("type")
        if kind not in _CONVERSATION:
            continue
        if isinstance(record.get("timestamp"), str):
            facts.last_timestamp = record["timestamp"]
        if kind in ("user", "assistant"):
            facts.turn_complete = completed_assistant(record)
        message = record.get("message")
        if (
            kind == "assistant"
            and isinstance(message, dict)
            and isinstance(message.get("model"), str)
        ):
            facts.model_name = message["model"]
    if not facts.is_subagent and seen_session:
        facts.session_id = seen_session
    if facts.parent_session_id == facts.session_id:
        facts.parent_session_id = None
    return facts


def codex_thread_id(path: Path) -> str | None:
    match = _CODEX_FILE_ID.search(path.name)
    return match.group("id") if match else None


def codex_parent(payload: dict[str, Any], thread_id: str) -> str | None:
    parent = payload.get("parent_thread_id")
    if isinstance(parent, str) and parent and parent != thread_id:
        return parent
    source = payload.get("source")
    if isinstance(source, dict) and "subagent" in source:
        root = payload.get("session_id")
        if isinstance(root, str) and root and root != thread_id:
            return root
    return None


def read_codex(path: Path) -> SessionFacts:
    facts = SessionFacts(
        source=SOURCE_CODEX, session_id=codex_thread_id(path) or path.stem, path=path
    )
    last: dict[str, Any] | None = None
    for record in iter_records(path):
        facts.record_count += 1
        last = record
        if isinstance(record.get("timestamp"), str):
            facts.last_timestamp = record["timestamp"]
        payload = record.get("payload")
        if not isinstance(payload, dict):
            continue
        if record.get("type") == "session_meta":
            if isinstance(payload.get("id"), str):
                facts.session_id = payload["id"]
            facts.note_cwd(payload.get("cwd"))
            facts.parent_session_id = codex_parent(payload, facts.session_id)
            source = payload.get("source")
            facts.is_subagent = isinstance(source, dict) and "subagent" in source
        elif record.get("type") == "turn_context":
            facts.note_cwd(payload.get("cwd"))
            if isinstance(payload.get("model"), str):
                facts.model_name = payload["model"]
    payload = last.get("payload") if isinstance(last, dict) else None
    facts.turn_complete = (
        isinstance(last, dict)
        and last.get("type") == "event_msg"
        and isinstance(payload, dict)
        and payload.get("type") == "task_complete"
    )
    return facts


def read_session(source: str, path: Path) -> SessionFacts:
    if source == SOURCE_CLAUDE_CODE:
        return read_claude(path)
    if source == SOURCE_CODEX:
        return read_codex(path)
    raise ValueError(f"unknown capture source: {source}")


@dataclass(frozen=True, slots=True)
class Probe:
    """What a probe read: the session id, the first cwd and the parent."""

    session_id: str
    cwds: tuple[str, ...]
    parent_session_id: str | None = None
    parent_path: Path | None = None


def probe_claude(path: Path) -> Probe:
    """Read a Claude Code transcript only up to its first record with a cwd."""
    cwd: str | None = None
    record_session: str | None = None
    sidechain = False
    try:
        for index, record in enumerate(iter_records(path)):
            if index >= PROBE_MAX_RECORDS:
                break
            if isinstance(record.get("cwd"), str) and record["cwd"]:
                cwd = record["cwd"]
                session = record.get("sessionId")
                record_session = session if isinstance(session, str) else None
                sidechain = record.get("isSidechain") is True
                break
    except OSError:
        pass
    parent = record_session if sidechain and record_session != path.stem else None
    parent_path = None
    if parent and path.parent.name == SUBAGENTS_DIR:
        candidate = path.parent.parent.parent / f"{parent}.jsonl"
        parent_path = candidate if candidate.is_file() else None
    return Probe(
        path.stem if sidechain else (record_session or path.stem),
        (cwd,) if cwd else (),
        parent,
        parent_path,
    )


def probe_codex(path: Path, sessions_root: Path | None) -> Probe:
    """Read a Codex rollout's first record only: ``session_meta``."""
    thread = codex_thread_id(path) or path.stem
    first: dict[str, Any] | None = None
    try:
        first = next(iter_records(path), None)
    except OSError:
        first = None
    payload = (
        first.get("payload")
        if isinstance(first, dict) and first.get("type") == "session_meta"
        else None
    )
    if not isinstance(payload, dict):
        return Probe(thread, ())
    if isinstance(payload.get("id"), str):
        thread = payload["id"]
    cwd = payload.get("cwd")
    parent = codex_parent(payload, thread)
    parent_path = None
    if parent and sessions_root is not None and re.fullmatch(r"[0-9A-Za-z-]+", parent):
        parent_path = next(iter(sorted(sessions_root.rglob(f"rollout-*-{parent}.jsonl"))), None)
    return Probe(thread, (cwd,) if isinstance(cwd, str) and cwd else (), parent, parent_path)


__all__ = [
    "AGENT_FOR_SOURCE",
    "MAIN_GLOB",
    "Probe",
    "SOURCE_CLAUDE_CODE",
    "SOURCE_CODEX",
    "SUBAGENT_GLOB",
    "SessionFacts",
    "iter_records",
    "probe_claude",
    "probe_codex",
    "read_claude",
    "read_codex",
    "read_session",
]
