"""Step facts and the redactor must survive any JSON shape in a transcript.

A transcript carries tool definitions and tool inputs whose ``type`` keys are
JSON schema values (lists, objects, numbers), not block names. A set lookup on
such a value raises ``TypeError``, which used to stop the whole analysis.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from driftshield import analyse_run
from driftshield.recursive_redactor import redact
from driftshield.step_facts import compute_step_facts, is_one_of

ODD_TYPES: list[Any] = [
    ["a", "b"],
    ["string", "null"],
    [],
    [["nested"]],
    {"kind": "object"},
    {},
    7,
    1.5,
    True,
    None,
    "",
]


@pytest.mark.parametrize("odd", ODD_TYPES, ids=lambda v: json.dumps(v))
def test_a_non_string_type_is_never_a_block_type(odd: Any):
    payload = {"events": [{"type": odd, "name": "Bash", "input": {"command": "ls"}}]}
    assert compute_step_facts(payload) == {}
    assert redact(payload).payload["events"][0]["type"] == odd or odd == {}


@pytest.mark.parametrize("odd", ODD_TYPES, ids=lambda v: json.dumps(v))
def test_a_nested_non_string_type_does_not_stop_the_walk(odd: Any):
    payload = {
        "tools": [
            {"name": "t", "input_schema": {"type": "object", "properties": {"p": {"type": odd}}}}
        ],
        "events": [
            {
                "type": "assistant",
                "message": {
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "a",
                            "name": "Bash",
                            "input": {"command": "git push origin main", "schema": {"type": odd}},
                        },
                        {"type": odd, "id": "b", "name": "Bash", "input": {"command": "ls"}},
                    ]
                },
            },
            {
                "type": "user",
                "message": {
                    "content": [
                        {"type": "tool_result", "tool_use_id": "a", "is_error": True},
                        {"type": odd},
                    ]
                },
            },
        ],
    }
    facts = compute_step_facts(payload)
    assert len(facts) == 1
    (only,) = facts.values()
    assert (only["command_kind"], only["target_kind"], only["exit_status"]) == (
        "git_push",
        "main_branch",
        "failure",
    )
    redact(payload)


@pytest.mark.parametrize("value", [["x"], {"a": 1}, 3, None, True, "text"])
def test_is_one_of_never_raises(value: Any):
    assert is_one_of(value, {"text", "x"}) is (value == "text")


def _jsonl(records: list[dict[str, Any]]) -> str:
    return "\n".join(json.dumps(record) for record in records)


def _schema(odd: Any) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "a": {"type": odd},
            "b": {"type": ["string", "null"]},
            "c": {"type": {"deep": [odd, {"type": odd}]}},
            "d": {"anyOf": [{"type": odd}, {"type": 3}]},
        },
    }


def claude_code(odd: Any) -> str:
    return _jsonl(
        [
            {
                "type": odd,
                "sessionId": "s1",
                "tools": [{"name": "Bash", "input_schema": _schema(odd)}],
            },
            {
                "type": "user",
                "sessionId": "s1",
                "timestamp": "2026-09-01T09:00:00.000Z",
                "message": {"role": "user", "content": "go"},
            },
            {
                "type": "assistant",
                "sessionId": "s1",
                "timestamp": "2026-09-01T09:00:01.000Z",
                "tools": [{"name": "Bash", "input_schema": _schema(odd)}],
                "message": {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "t1",
                            "name": "Bash",
                            "input": {
                                "command": "pytest -q",
                                "options": _schema(odd),
                                "list": [odd, [odd]],
                            },
                            "step_facts": odd,
                        },
                        {"type": odd, "text": "ignored"},
                    ],
                },
            },
            {
                "type": "user",
                "sessionId": "s1",
                "timestamp": "2026-09-01T09:00:02.000Z",
                "message": {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "t1",
                            "is_error": odd,
                            "content": [{"type": odd, "text": "x"}],
                        }
                    ],
                },
            },
        ]
    )


def openclaw(odd: Any) -> str:
    return _jsonl(
        [
            {
                "type": "session",
                "id": "s1",
                "timestamp": "2026-09-01T09:00:00.000Z",
                "tools": [_schema(odd)],
            },
            {
                "type": "message",
                "id": "a1",
                "timestamp": "2026-09-01T09:00:01.000Z",
                "message": {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "toolCall",
                            "id": "c1",
                            "name": "exec",
                            "arguments": {
                                "command": "git push origin main",
                                "schema": _schema(odd),
                            },
                            "step_facts": [odd],
                        },
                        {"type": odd, "id": "c9", "name": "exec"},
                    ],
                },
            },
            {
                "type": "message",
                "id": "r1",
                "timestamp": "2026-09-01T09:00:02.000Z",
                "message": {
                    "role": "toolResult",
                    "toolCallId": "c1",
                    "isError": odd,
                    "content": [{"type": odd}],
                    "details": {"status": odd, "exitCode": odd},
                },
            },
        ]
    )


def codex(odd: Any) -> str:
    return _jsonl(
        [
            {
                "timestamp": "2026-09-11T09:00:00.000Z",
                "type": "session_meta",
                "payload": {
                    "session_id": "c1",
                    "id": "c1",
                    "cwd": "/w",
                    "originator": "codex_cli_rs",
                    "tools": [_schema(odd)],
                },
            },
            {
                "timestamp": "2026-09-11T09:00:00.100Z",
                "type": "turn_context",
                "payload": {"turn_id": "t", "cwd": "/w", "model": "m"},
            },
            {
                "timestamp": "2026-09-11T09:00:01.000Z",
                "type": "response_item",
                "payload": {"type": odd, "name": "exec_command", "call_id": "x"},
            },
            {
                "timestamp": "2026-09-11T09:00:02.000Z",
                "type": "response_item",
                "payload": {
                    "type": "function_call",
                    "name": "exec_command",
                    "call_id": "c1",
                    "arguments": json.dumps({"cmd": "ls", "s": _schema(odd)}),
                    "step_facts": {"command_kind": odd},
                },
            },
            {
                "timestamp": "2026-09-11T09:00:03.000Z",
                "type": "response_item",
                "payload": {
                    "type": "function_call_output",
                    "call_id": "c1",
                    "output": [{"type": odd, "text": "Process exited with code 0"}, odd],
                },
            },
            {"timestamp": "2026-09-11T09:00:04.000Z", "type": odd, "payload": {"type": odd}},
        ]
    )


@pytest.mark.parametrize("odd", ODD_TYPES, ids=lambda v: json.dumps(v))
@pytest.mark.parametrize(
    ("build", "fmt"), [(claude_code, "claude_code"), (openclaw, "openclaw"), (codex, "codex_cli")]
)
def test_analyse_run_never_raises_on_odd_json_shapes(build, fmt, odd: Any):
    body = build(odd)
    for forced in (fmt, None):
        run = analyse_run(body, format=forced)
        assert run.events
        json.dumps(run.redacted_transcript)  # stays plain JSON
        analyse_run(json.dumps(run.redacted_transcript), format=forced)


def test_a_failure_while_computing_facts_never_stops_the_analysis(monkeypatch: pytest.MonkeyPatch):
    import driftshield.recursive_redactor as redactor

    def boom(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("unexpected shape")

    monkeypatch.setattr(redactor, "compute_step_facts", boom)
    run = analyse_run(claude_code(["a"]), format="claude_code")
    assert run.events
    assert "step_facts" not in json.dumps(run.redacted_transcript)
