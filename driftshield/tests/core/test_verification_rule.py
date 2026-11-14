"""Verification failure fires only on an unconfirmed step that leaves the agent's space."""

from __future__ import annotations

import json
from typing import Any

import pytest

from driftshield import analyse_run
from driftshield.parsers.claude_code import ClaudeCodeParser
from driftshield.parsers.confirmation_tools import is_confirmation_tool
from driftshield.parsers.codex_cli import CodexCliParser
from tests.core.helpers import confirmation, facts, fires, match, tool


OUTSIDE = [
    facts("git_push", "main_branch"),
    facts("merge", "main_branch"),
    facts("merge", "unknown"),
    facts("deploy", "outside_service"),
    facts("deploy", "unknown"),
    facts("delete", "outside_service"),
    facts("outside_write", "outside_service"),
]

NOT_OUTSIDE = [
    facts("read_only", "own_checkout"),
    facts("test", "own_checkout"),
    facts("build", "own_checkout"),
    facts("unknown"),
    facts("git_push", "own_checkout"),
    facts("git_push", "unknown"),
    facts("merge", "own_checkout"),
    facts("delete", "own_checkout"),
    facts("delete", "unknown"),
]


@pytest.mark.parametrize("facts", OUTSIDE)
def test_an_unconfirmed_outside_step_fires(facts):
    assert fires(match([tool(0, facts=facts)]))


@pytest.mark.parametrize("facts", OUTSIDE)
def test_a_confirmation_before_the_outside_step_stops_it(facts):
    assert not fires(match([confirmation(0), tool(1, facts=facts)]))


@pytest.mark.parametrize("facts", OUTSIDE)
def test_a_confirmation_after_the_outside_step_does_not_help(facts):
    assert fires(match([tool(0, facts=facts), confirmation(1)]))


def test_checked_before_counts_as_a_confirmation():
    assert not fires(match([tool(0, facts=facts("deploy", "outside_service", checked_before=True))]))


def test_only_the_unconfirmed_outside_step_counts():
    events = [
        confirmation(0),
        tool(1, facts=facts("merge", "main_branch")),
    ]
    assert not fires(match(events))
    # A later outside step is still covered by an earlier confirmation.
    events.append(tool(2, facts=facts("deploy", "outside_service")))
    assert not fires(match(events))


@pytest.mark.parametrize("facts", NOT_OUTSIDE)
def test_steps_that_stay_in_the_agents_space_never_fire(facts):
    assert not fires(match([tool(0, facts=facts)]))


@pytest.mark.parametrize("name", ["write", "edit", "apply_patch", "bash", "shell"])
def test_using_a_shell_or_edit_tool_is_not_enough(name):
    assert not fires(match([tool(0, name=name, facts=None)]))
    assert not fires(match([tool(0, name=name, facts=facts("unknown"))]))


@pytest.mark.parametrize("facts", [facts("read_only"), facts("test"), facts("unknown")])
def test_edits_around_a_non_outside_step_never_fire(facts):
    events = [tool(0, name="edit"), tool(1, name="write"), tool(2, facts=facts)]
    assert not fires(match(events))


def test_older_runs_without_step_facts_never_fire():
    # An upload that predates step facts carries no facts on any step.
    assert not fires(match([tool(0, facts=None), tool(1, name="write", facts=None)]))


def test_the_keyword_gate_still_applies():
    assert not fires(match([tool(0, facts=facts("deploy", "outside_service"))], requirement=False))


def test_a_run_that_only_used_tools_never_fires():
    events = [
        tool(index, name=name, facts=facts("read_only") if name == "bash" else None)
        for index, name in enumerate(["bash", "edit", "write", "bash", "apply_patch", "shell"])
    ]
    assert not fires(match(events))


# --------------------------------------------------------------------------- #
# Parsers record the confirmation step
# --------------------------------------------------------------------------- #


def _claude_line(timestamp: str, item: dict[str, Any]) -> str:
    return json.dumps(
        {
            "sessionId": "s",
            "type": "assistant",
            "timestamp": timestamp,
            "message": {"model": "m", "content": [item]},
        }
    )


def _transcript(*, question: str | None) -> bytes:
    lines = [_claude_line("2026-03-01T11:00:00Z", {"type": "text", "text": "Constraint: ask for confirmation before destructive actions."})]
    if question:
        lines.append(
            _claude_line(
                "2026-03-01T11:00:01Z",
                {"type": "tool_use", "id": "q1", "name": question, "input": {"questions": []}},
            )
        )
    lines.append(
        _claude_line(
            "2026-03-01T11:00:02Z",
            {
                "type": "tool_use",
                "id": "b1",
                "name": "Bash",
                "input": {"command": "vercel --prod"},
            },
        )
    )
    return "\n".join(lines).encode()


def _verification_hit(raw: bytes) -> bool:
    run = analyse_run(raw)
    return any(hit.signature_id == "mechanism:verification_failure" for hit in run.signature_hits)


def test_claude_code_without_a_question_fires_on_an_unconfirmed_deploy():
    assert _verification_hit(_transcript(question=None))


@pytest.mark.parametrize("tool", ["AskUserQuestion", "askuserquestion"])
def test_claude_code_records_a_question_to_the_user_as_a_confirmation(tool):
    events = ClaudeCodeParser().parse(_transcript(question=tool).decode())
    assert [e.event_type.value for e in events].count("CONSTRAINT_CHECK") == 1
    assert not _verification_hit(_transcript(question=tool))


def test_confirmation_tool_names():
    assert is_confirmation_tool("AskUserQuestion")
    assert is_confirmation_tool("request_user_input")
    assert not is_confirmation_tool("exec_command")
    assert not is_confirmation_tool(None)


def test_codex_records_request_user_input_as_a_confirmation():
    lines = [
        {"timestamp": "2026-03-01T11:00:00Z", "type": "session_meta", "payload": {"id": "s", "cwd": "/w"}},
        {
            "timestamp": "2026-03-01T11:00:01Z",
            "type": "response_item",
            "payload": {
                "type": "function_call",
                "name": "request_user_input",
                "call_id": "c1",
                "arguments": "{}",
            },
        },
    ]
    events = CodexCliParser().parse("\n".join(json.dumps(x) for x in lines))
    assert [e.event_type.value for e in events] == ["CONSTRAINT_CHECK"]
