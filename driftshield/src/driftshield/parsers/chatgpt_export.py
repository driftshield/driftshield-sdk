"""Parser for a ChatGPT conversation export (``conversations.json``), one conversation."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from driftshield.core.models import CanonicalEvent, EventType
from driftshield.core.normalization import normalize_events
from driftshield.parsers.protocol import NoSkipCountMixin

_AGENT_ID = "chatgpt"
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class ChatGPTExportParser(NoSkipCountMixin):
    """Read the branch ending at ``current_node`` of a single exported conversation."""

    @property
    def source_type(self) -> str:
        return "chatgpt_export"

    def parse_file(self, file_path: str) -> list[CanonicalEvent]:
        return self._read(Path(file_path).read_text(), source_path=file_path)

    def parse(self, content: str) -> list[CanonicalEvent]:
        return self._read(content, source_path=None)

    def _read(self, content: str, *, source_path: str | None) -> list[CanonicalEvent]:
        payload = json.loads(content)
        conversations = payload if isinstance(payload, list) else [payload]
        conversations = [c for c in conversations if isinstance(c, dict)]
        if len(conversations) > 1:
            raise ValueError(
                f"export holds {len(conversations)} conversations; "
                "splitting is not supported yet, export a single conversation"
            )
        if not conversations:
            return []
        events = self._parse_conversation(conversations[0])
        return normalize_events(events, source_type=self.source_type, source_path=source_path)

    def _parse_conversation(self, conversation: dict[str, Any]) -> list[CanonicalEvent]:
        session_id = str(
            conversation.get("conversation_id") or conversation.get("id") or "unknown"
        )
        mapping = conversation.get("mapping")
        if not isinstance(mapping, dict):
            return []

        branch: list[dict[str, Any]] = []
        seen: set[str] = set()
        node_id = conversation.get("current_node")
        while isinstance(node_id, str) and node_id in mapping and node_id not in seen:
            seen.add(node_id)
            node = mapping[node_id]
            if not isinstance(node, dict):
                break
            branch.append(node)
            node_id = node.get("parent")
        branch.reverse()

        events: list[CanonicalEvent] = []
        pending_call: CanonicalEvent | None = None
        previous_id: UUID | None = None
        last_time = self._timestamp(conversation.get("create_time"), _EPOCH)

        for index, node in enumerate(branch):
            message = node.get("message")
            if not isinstance(message, dict):
                continue
            role = (message.get("author") or {}).get("role")
            text = self._text(message.get("content"))
            if not text:
                continue
            timestamp = self._timestamp(message.get("create_time"), last_time)
            last_time = timestamp

            if role == "tool":
                if pending_call is not None:
                    pending_call.outputs = {"result": text}
                    pending_call = None
                continue
            if role not in {"user", "assistant"}:
                continue

            recipient = message.get("recipient") or "all"
            if role == "assistant" and recipient != "all":
                event = CanonicalEvent(
                    id=uuid4(),
                    session_id=session_id,
                    timestamp=timestamp,
                    event_type=EventType.TOOL_CALL,
                    agent_id=_AGENT_ID,
                    action=str(recipient),
                    parent_event_id=previous_id,
                    inputs={"input": text},
                    outputs={},
                    metadata={
                        "source_message_index": index,
                        "semantic_action_category": "other",
                        "raw_action": str(recipient),
                    },
                )
                pending_call = event
            else:
                is_user = role == "user"
                event = CanonicalEvent(
                    id=uuid4(),
                    session_id=session_id,
                    timestamp=timestamp,
                    event_type=EventType.OUTPUT,
                    agent_id="user" if is_user else _AGENT_ID,
                    action="user_message" if is_user else "assistant_narrative",
                    parent_event_id=previous_id,
                    inputs={},
                    outputs={"text": text},
                    metadata={
                        "source_message_index": index,
                        "semantic_action_category": "user_input" if is_user else "reasoning",
                        "raw_action": "text",
                    },
                )
            if event.event_type != EventType.TOOL_CALL:
                pending_call = None
            events.append(event)
            previous_id = event.id

        return events

    @staticmethod
    def _text(content: Any) -> str:
        if not isinstance(content, dict):
            return ""
        parts = content.get("parts")
        if isinstance(parts, list):
            joined = "\n".join(p.strip() for p in parts if isinstance(p, str) and p.strip())
            if joined:
                return joined
        text = content.get("text")
        return text.strip() if isinstance(text, str) else ""

    @staticmethod
    def _timestamp(value: Any, fallback: datetime) -> datetime:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return datetime.fromtimestamp(value, tz=timezone.utc)
        return fallback
