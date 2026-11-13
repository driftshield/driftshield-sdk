"""Verification failure fires only on an unconfirmed step that leaves the agent's space."""

from __future__ import annotations

import json
from typing import Any

import pytest

from driftshield import analyse_run
from driftshield.core.deterministic_matching import build_deterministic_match
from driftshield.parsers.claude_code import ClaudeCodeParser
from driftshield.parsers.confirmation_tools import is_confirmation_tool
from driftshield.parsers.codex_cli import CodexCliParser

from tests.core.test_deterministic_matching import _analysis_result

_REQUIREMENT = {"constraint": "Ask for confirmation before destructive changes."}


def _facts(kind: str, target: str = "unknown", checked_before: bool = False) -> dict[str, Any]:
    return {
        "command_kind": kind,
        "target_kind": target,
        "exit_status": "success",
        "checked_before": checked_before,
    }


def _tool(index: int, *, name: str = "bash", facts: dict[str, Any] | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "tool_name": name,
        "tool_category": "shell",
        "safety_relevant_flags": ["executes_shell"]
        if name in {"bash", "shell"}
        else ["mutates_state"],
    }
    if facts is not None:
        payload["step_facts"] = facts
    family = "state_write" if name in {"write", "edit"} else "tool_call"
    return {
        "event_id": f"evt-{index}",
        "sequence_index": index,
        "event_family": family,
        "structured_payload": payload,
    }


def _confirmation(index: int) -> dict[str, Any]:
    return {
        "event_id": f"evt-{index}",
        "sequence_index": index,
        "event_family": "confirmation_checkpoint",
        "structured_payload": {},
    }


def _match(events: list[dict[str, Any]], *, requirement: bool = True) -> dict[str, Any]:
    canonical = {
        "analysis_session": {"integrity_status": "complete", "source_provenance": {"source_type": "x"}},
        "normalized_events": events,
        "run_context": {},
        "policy_and_instruction_context": {
            "system_constraints": [_REQUIREMENT] if requirement else [],
            "developer_constraints": [],
            "user_constraints": [],
            "derived_operational_constraints": [],
            "conflict_or_shadowing_notes": [],
        },
        "expected_vs_actual_delta": {"delta_types": [], "supporting_event_ids": []},
        "extraction_quality_summary": {
            "overall_quality_band": "usable",
            "ordering_confidence": 1.0,
            "ambiguity_count": 0,
        },
    }
    return build_deterministic_match(canonical_analysis=canonical, result=_analysis_result())


def _fires(payload: dict[str, Any]) -> bool:
    rules = {rule["rule_id"] for rule in payload["matched_rules"]}
    sequences = {seq["sequence_id"] for seq in payload["matched_sequence_patterns"]}
    # The rule and the sequence pattern must always agree.
    assert ("R-VER-001" in rules) == ("SEQ-VER-001" in sequences)
    return "R-VER-001" in rules


OUTSIDE = [
    _facts("git_push", "main_branch"),
    _facts("merge", "main_branch"),
    _facts("merge", "unknown"),
    _facts("deploy", "outside_service"),
    _facts("deploy", "unknown"),
    _facts("delete", "outside_service"),
    _facts("outside_write", "outside_service"),
]

NOT_OUTSIDE = [
    _facts("read_only", "own_checkout"),
    _facts("test", "own_checkout"),
    _facts("build", "own_checkout"),
    _facts("unknown"),
    _facts("git_push", "own_checkout"),
    _facts("git_push", "unknown"),
    _facts("merge", "own_checkout"),
    _facts("delete", "own_checkout"),
    _facts("delete", "unknown"),
]


@pytest.mark.parametrize("facts", OUTSIDE)
def test_an_unconfirmed_outside_step_fires(facts):
    assert _fires(_match([_tool(0, facts=facts)]))


@pytest.mark.parametrize("facts", OUTSIDE)
def test_a_confirmation_before_the_outside_step_stops_it(facts):
    assert not _fires(_match([_confirmation(0), _tool(1, facts=facts)]))


@pytest.mark.parametrize("facts", OUTSIDE)
def test_a_confirmation_after_the_outside_step_does_not_help(facts):
    assert _fires(_match([_tool(0, facts=facts), _confirmation(1)]))


def test_checked_before_counts_as_a_confirmation():
    assert not _fires(_match([_tool(0, facts=_facts("deploy", "outside_service", checked_before=True))]))


def test_only_the_unconfirmed_outside_step_counts():
    events = [
        _confirmation(0),
        _tool(1, facts=_facts("merge", "main_branch")),
    ]
    assert not _fires(_match(events))
    # A later outside step is still covered by an earlier confirmation.
    events.append(_tool(2, facts=_facts("deploy", "outside_service")))
    assert not _fires(_match(events))


@pytest.mark.parametrize("facts", NOT_OUTSIDE)
def test_steps_that_stay_in_the_agents_space_never_fire(facts):
    assert not _fires(_match([_tool(0, facts=facts)]))


@pytest.mark.parametrize("name", ["write", "edit", "apply_patch", "bash", "shell"])
def test_using_a_shell_or_edit_tool_is_not_enough(name):
    assert not _fires(_match([_tool(0, name=name, facts=None)]))
    assert not _fires(_match([_tool(0, name=name, facts=_facts("unknown"))]))


@pytest.mark.parametrize("facts", [_facts("read_only"), _facts("test"), _facts("unknown")])
def test_edits_around_a_non_outside_step_never_fire(facts):
    events = [_tool(0, name="edit"), _tool(1, name="write"), _tool(2, facts=facts)]
    assert not _fires(_match(events))


def test_older_runs_without_step_facts_never_fire():
    # An upload that predates step facts carries no facts on any step.
    assert not _fires(_match([_tool(0, facts=None), _tool(1, name="write", facts=None)]))


def test_the_keyword_gate_still_applies():
    assert not _fires(_match([_tool(0, facts=_facts("deploy", "outside_service"))], requirement=False))


def test_a_run_that_only_used_tools_never_fires():
    events = [
        _tool(index, name=name, facts=_facts("read_only") if name == "bash" else None)
        for index, name in enumerate(["bash", "edit", "write", "bash", "apply_patch", "shell"])
    ]
    assert not _fires(_match(events))


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
                "input": {"command": "x"},
                "step_facts": _facts("deploy", "outside_service"),
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
