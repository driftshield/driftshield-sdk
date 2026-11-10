"""Tests for the ChatGPT conversation export parser."""

import json
from typing import Any

from datetime import datetime, timezone

import pytest

from driftshield import analyse_run
from driftshield.core.models import CanonicalEvent, EventType
from driftshield.parsers.registry import PARSERS, get_parser
from driftshield.public import NoParseableEventsError


def _msg(
    role: str,
    parts: list[str] | None,
    *,
    t: float | None,
    recipient: str = "all",
    content_type: str = "text",
    text: str | None = None,
) -> dict[str, Any]:
    content: dict[str, Any] = {"content_type": content_type}
    if text is not None:
        content["text"] = text
    else:
        content["parts"] = parts
    return {
        "id": f"m-{t}",
        "author": {"role": role},
        "create_time": t,
        "content": content,
        "recipient": recipient,
    }


def _conversation(
    chain: list[tuple[str, str | None, dict[str, Any] | None]],
    *,
    current: str,
    conv_id: str = "conv-1",
    extra: list[tuple[str, str | None, dict[str, Any] | None]] | None = None,
    create_time: float | None = None,
) -> dict[str, Any]:
    """chain: list of (node_id, parent_id, message-or-None)."""
    mapping: dict[str, Any] = {}
    for node_id, parent, message in chain + (extra or []):
        mapping[node_id] = {"id": node_id, "message": message, "parent": parent, "children": []}
    return {
        "id": conv_id,
        "conversation_id": conv_id,
        "title": "t",
        "create_time": create_time,
        "current_node": current,
        "mapping": mapping,
    }


def _parse(conversations: list[dict[str, Any]]) -> list[CanonicalEvent]:
    return get_parser("chatgpt_export").parse(json.dumps(conversations))


def test_parser_is_registered() -> None:
    from driftshield.parsers.chatgpt_export import ChatGPTExportParser

    assert PARSERS["chatgpt_export"] is ChatGPTExportParser
    conv = _conversation(
        [("root", None, None), ("u", "root", _msg("user", ["hi"], t=1.0))], current="u"
    )
    run = analyse_run(json.dumps([conv]), format="chatgpt_export")
    assert run.detected_format == "chatgpt_export"


def test_only_the_current_branch_is_read() -> None:
    conv = _conversation(
        [
            ("root", None, None),
            ("u", "root", _msg("user", ["question"], t=1.0)),
            ("a-old", "u", _msg("assistant", ["discarded reply"], t=2.0)),
            ("a-new", "u", _msg("assistant", ["kept reply"], t=3.0)),
            ("u2", "a-new", _msg("user", ["follow up"], t=4.0)),
        ],
        current="u2",
    )
    events = _parse([conv])
    assert [e.outputs["text"] for e in events] == ["question", "kept reply", "follow up"]


def test_user_and_assistant_messages_map_to_output_events() -> None:
    conv = _conversation(
        [
            ("root", None, None),
            ("u", "root", _msg("user", ["hello"], t=1700000000.0)),
            ("a", "u", _msg("assistant", ["hi there"], t=1700000060.0)),
        ],
        current="a",
        conv_id="abc-123",
    )
    user, assistant = _parse([conv])
    assert user.event_type == EventType.OUTPUT
    assert (user.agent_id, user.action) == ("user", "user_message")
    assert assistant.event_type == EventType.OUTPUT
    assert assistant.action == "assistant_narrative"
    assert user.session_id == assistant.session_id == "abc-123"
    assert user.timestamp == datetime(2023, 11, 14, 22, 13, 20, tzinfo=timezone.utc)
    assert assistant.timestamp == datetime(2023, 11, 14, 22, 14, 20, tzinfo=timezone.utc)


def test_tool_message_fills_the_call_result() -> None:
    conv = _conversation(
        [
            ("root", None, None),
            ("u", "root", _msg("user", ["add 2 and 2"], t=1.0)),
            ("c", "u", _msg("assistant", None, t=2.0, recipient="python",
                            content_type="code", text="print(2+2)")),
            ("r", "c", _msg("tool", ["4"], t=3.0, recipient="all")),
            ("a", "r", _msg("assistant", ["It is 4."], t=4.0)),
        ],
        current="a",
    )
    events = _parse([conv])
    assert [e.event_type for e in events] == [
        EventType.OUTPUT,
        EventType.TOOL_CALL,
        EventType.OUTPUT,
    ]
    call = events[1]
    assert call.action == "python"
    assert call.outputs["result"] == "4"


def test_hidden_and_empty_messages_are_skipped() -> None:
    conv = _conversation(
        [
            ("root", None, None),
            ("s", "root", _msg("system", ["You are helpful."], t=1.0)),
            ("e", "s", _msg("assistant", ["   "], t=2.0)),
            ("n", "e", _msg("assistant", [], t=3.0)),
            ("u", "n", _msg("user", ["real"], t=4.0)),
        ],
        current="u",
    )
    events = _parse([conv])
    assert [e.outputs["text"] for e in events] == ["real"]


def test_multi_conversation_export_is_refused_plainly() -> None:
    one = _conversation(
        [("root", None, None), ("u", "root", _msg("user", ["a"], t=1.0))], current="u"
    )
    two = _conversation(
        [("root", None, None), ("u", "root", _msg("user", ["b"], t=1.0))],
        current="u",
        conv_id="conv-2",
    )
    with pytest.raises(NoParseableEventsError) as info:
        analyse_run(json.dumps([one, two]))
    assert info.value.reason == "parse_failed"
    message = str(info.value)
    assert "2 conversations" in message
    assert "splitting is not supported yet" in message


def test_ac5_text_between_call_and_tool_message_clears_the_pending_call() -> None:
    conv = _conversation(
        [
            ("root", None, None),
            ("c", "root", _msg("assistant", None, t=1.0, recipient="python",
                               content_type="code", text="print(1)")),
            ("a", "c", _msg("assistant", ["thinking aloud"], t=2.0)),
            ("r", "a", _msg("tool", ["stale"], t=3.0)),
        ],
        current="r",
    )
    call = _parse([conv])[0]
    assert call.action == "python"
    assert "result" not in call.outputs


def test_ac4_missing_create_time_falls_back_deterministically() -> None:
    conv = _conversation(
        [
            ("root", None, None),
            ("u", "root", _msg("user", ["first"], t=1700000000.0)),
            ("a", "u", _msg("assistant", ["second"], t=None)),
        ],
        current="a",
        create_time=1600000000.0,
    )
    first, second = _parse([conv])
    assert second.timestamp == first.timestamp
    lone = _conversation(
        [("root", None, None), ("u", "root", _msg("user", ["x"], t=None))],
        current="u",
        create_time=1600000000.0,
    )
    assert _parse([lone])[0].timestamp == datetime(2020, 9, 13, 12, 26, 40, tzinfo=timezone.utc)
    bare = _conversation(
        [("root", None, None), ("u", "root", _msg("user", ["x"], t=None))], current="u"
    )
    assert _parse([bare])[0].timestamp == datetime(1970, 1, 1, tzinfo=timezone.utc)
