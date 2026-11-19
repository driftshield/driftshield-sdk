"""Parser for ``driftshield.events.v1``: DriftShield's own neutral event format.

JSON Lines, one event per line, for agents that have no transcript format DriftShield already
reads. Every line carries ``"schema": "driftshield.events.v1"``. Fields:

- ``session_id``: one id for the whole run.
- ``timestamp``: ISO 8601.
- ``type``: ``message``, ``tool_call``, ``tool_result``, ``confirmation`` or ``handoff``.
- ``actor``: a role, not a name: ``user``, ``agent``, ``person`` or ``system``.
- ``tool``: the tool name (``tool_call``; optional on ``confirmation`` and ``handoff``).
- ``call_id``: ties a ``tool_result`` to its ``tool_call``.
- ``input``: the tool input (optional; redacted before anything leaves the machine).
- ``output``: the tool output (optional; redacted too).
- ``status``: ``ok`` or ``error`` on a ``tool_result``.
- ``error``: error text on a failed result (optional; never uploaded).
- ``text``: the words of a ``message``, ``confirmation`` or ``handoff`` (redacted too).

See ``docs/events-v1.md``.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from driftshield.core.models import CanonicalEvent, EventType
from driftshield.core.normalization import normalize_events
from driftshield.step_facts import STEP_FACTS_KEY, sanitise_step_facts

EVENTS_V1_SCHEMA = "driftshield.events.v1"
EVENT_TYPES = frozenset({"message", "tool_call", "tool_result", "confirmation", "handoff"})


def is_events_v1_record(value: object) -> bool:
    return isinstance(value, dict) and value.get("schema") == EVENTS_V1_SCHEMA


class EventsV1Parser:
    """Parse ``driftshield.events.v1`` JSON Lines into canonical events."""

    def __init__(self) -> None:
        self.skipped_records_by_reason: dict[str, int] = {}

    @property
    def source_type(self) -> str:
        return "driftshield_events_v1"

    @property
    def skipped_record_count(self) -> int:
        return sum(self.skipped_records_by_reason.values())

    def _skip(self, reason: str) -> None:
        self.skipped_records_by_reason[reason] = self.skipped_records_by_reason.get(reason, 0) + 1

    def parse_file(self, file_path: str) -> list[CanonicalEvent]:
        return normalize_events(
            self.parse(Path(file_path).read_text()),
            source_type=self.source_type,
            source_path=file_path,
        )

    def parse(self, content: str) -> list[CanonicalEvent]:
        self.skipped_records_by_reason = {}
        events: list[CanonicalEvent] = []
        calls: dict[str, CanonicalEvent] = {}
        session_id: str | None = None
        previous: UUID | None = None

        for line in content.strip().split("\n"):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                self._skip("not_json")
                continue
            if not isinstance(record, dict):
                self._skip("not_an_object")
                continue
            if not is_events_v1_record(record):
                self._skip("not_events_v1")
                continue
            kind = record.get("type")
            if kind not in EVENT_TYPES:
                self._skip("unknown_type")
                continue
            if session_id is None and isinstance(record.get("session_id"), str):
                session_id = record["session_id"]

            if kind == "tool_result":
                call = calls.get(str(record.get("call_id") or ""))
                if call is None:
                    self._skip("result_without_call")
                    continue
                failed = record.get("status") == "error"
                outputs: dict[str, Any] = {"result": record.get("output", ""), "is_error": failed}
                if failed and record.get("error"):
                    outputs["error"] = str(record["error"])
                call.outputs = outputs
                continue

            if kind == "tool_call" and not _name(record.get("tool")):
                self._skip("tool_call_without_tool")
                continue

            event = self._event(record, kind, session_id or "unknown", previous)
            events.append(event)
            previous = event.id
            call_id = record.get("call_id")
            if kind == "tool_call" and isinstance(call_id, str) and call_id:
                calls[call_id] = event

        return normalize_events(events, source_type=self.source_type)

    def _event(
        self, record: dict[str, Any], kind: str, session_id: str, parent: UUID | None
    ) -> CanonicalEvent:
        actor = record.get("actor") if isinstance(record.get("actor"), str) else None
        timestamp = _timestamp(record.get("timestamp"))
        metadata: dict[str, Any] = {"source_type": self.source_type, "raw_action": kind}
        call_id = record.get("call_id")
        if isinstance(call_id, str) and call_id:
            metadata["tool_call_id"] = call_id

        if kind == "message":
            text = record.get("text")
            agent = actor if actor in {"user", "system"} else "agent"
            metadata["semantic_action_category"] = "user_input" if agent == "user" else "reasoning"
            return CanonicalEvent(
                id=uuid4(),
                session_id=session_id,
                timestamp=timestamp,
                event_type=EventType.OUTPUT,
                agent_id=agent,
                action="user_message" if agent == "user" else "assistant_text",
                parent_event_id=parent,
                inputs={},
                outputs={"text": text if isinstance(text, str) else ""},
                metadata=metadata,
            )

        name = _name(record.get("tool")) or kind
        event_type = {
            "tool_call": EventType.TOOL_CALL,
            "confirmation": EventType.CONSTRAINT_CHECK,
            "handoff": EventType.HANDOFF,
        }[kind]
        metadata["raw_action"] = name
        metadata["semantic_action_category"] = kind if kind != "tool_call" else "other"
        facts = sanitise_step_facts(record.get(STEP_FACTS_KEY))
        if facts is not None:
            metadata[STEP_FACTS_KEY] = facts
        raw_input = record.get("input")
        inputs = raw_input if isinstance(raw_input, dict) else ({} if raw_input is None else {"value": raw_input})
        outputs: dict[str, Any] = {}
        if kind != "tool_call" and isinstance(record.get("text"), str):
            outputs["text"] = record["text"]
        return CanonicalEvent(
            id=uuid4(),
            session_id=session_id,
            timestamp=timestamp,
            event_type=event_type,
            agent_id="agent",
            action=name,
            parent_event_id=parent,
            inputs=inputs,
            outputs=outputs,
            metadata=metadata,
        )


def _name(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _timestamp(value: object) -> datetime:
    if isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return datetime.fromtimestamp(0, tz=timezone.utc)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return datetime.fromtimestamp(0, tz=timezone.utc)
