"""State conflict fires only on a write the system rejected after an earlier read.

Also pins that a failed unconfirmed outside step still counts for verification failure.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from driftshield import analyse_run

from tests.core.helpers import facts, match, tool


def _read(index: int) -> dict[str, Any]:
    return {
        "event_id": f"evt-{index}",
        "sequence_index": index,
        "event_family": "state_read",
        "structured_payload": {"tool_name": "read"},
    }


def _write(
    index: int, *, failure: str | None = None, error_class: str | None = "other"
) -> dict[str, Any]:
    """A write event. ``error_class`` is what the step facts say; ``None`` means no facts."""
    payload: dict[str, Any] = {"tool_name": "write"}
    if failure is not None:
        payload["failure_context"] = {"status": failure, "error": "boom" if failure == "error" else None}
        if error_class is not None:
            payload["step_facts"] = {
                **facts("unknown"),
                "exit_status": "failure",
                "error_class": error_class,
            }
    return {
        "event_id": f"evt-{index}",
        "sequence_index": index,
        "event_family": "state_write",
        "structured_payload": payload,
    }


def _state_fires(events: list[dict[str, Any]]) -> bool:
    payload = match(events, requirement=False)
    rules = {rule["rule_id"] for rule in payload["matched_rules"]}
    sequences = {seq["sequence_id"] for seq in payload["matched_sequence_patterns"]}
    assert ("R-STA-001" in rules) == ("SEQ-STA-001" in sequences)
    return "R-STA-001" in rules


@pytest.mark.parametrize("error_class", ["conflict", "other"])
def test_a_rejected_write_after_a_read_fires_for_a_conflict_or_an_unexplained_failure(error_class):
    assert _state_fires([_read(0), _write(1, failure="error", error_class=error_class)])


@pytest.mark.parametrize(
    "error_class", ["precondition_failed", "permission_denied", "not_found", "timeout", "none"]
)
def test_an_edit_the_tool_refused_or_a_failure_that_wrote_nothing_never_fires(error_class):
    assert not _state_fires([_read(0), _write(1, failure="error", error_class=error_class)])


def test_a_rejected_write_with_no_step_facts_does_not_fire():
    # An upload from before error classes exists: the reason is unknown, so rather miss.
    assert not _state_fires([_read(0), _write(1, failure="error", error_class=None)])


def test_a_rejected_write_without_an_earlier_read_does_not_fire():
    assert not _state_fires([_write(0, failure="error", error_class="conflict")])
    assert not _state_fires([_write(0, failure="error", error_class="conflict"), _read(1)])


def test_a_successful_write_after_a_read_does_not_fire():
    assert not _state_fires([_read(0), _write(1)])


def test_failure_wording_alone_never_fires():
    # failure_context status "warning" is what failure wording in text produces.
    assert not _state_fires([_read(0), _write(1, failure="warning")])


def test_a_failed_read_alone_never_fires():
    failed_read = _read(0)
    failed_read["structured_payload"]["failure_context"] = {"status": "error", "error": "ENOENT"}
    assert not _state_fires([failed_read])
    assert not _state_fires([failed_read, _write(1)])


# --------------------------------------------------------------------------- #
# End to end through the parser
# --------------------------------------------------------------------------- #


def _line(t: str, item: dict[str, Any]) -> str:
    return json.dumps(
        {"sessionId": "s", "type": "assistant", "timestamp": t, "message": {"model": "m", "content": [item]}}
    )


def _result(t: str, tool_id: str, content: str, is_error: bool) -> str:
    return json.dumps(
        {
            "sessionId": "s",
            "type": "user",
            "timestamp": t,
            "message": {
                "content": [
                    {"type": "tool_result", "tool_use_id": tool_id, "content": content, "is_error": is_error}
                ]
            },
        }
    )


def _call(t: str, tool_id: str, name: str, **extra: Any) -> str:
    return _line(
        t,
        {"type": "tool_use", "id": tool_id, "name": name, "input": {"file_path": "/a.py"}, **extra},
    )


def _conflict_hit(*lines: str) -> bool:
    run = analyse_run("\n".join(lines).encode())
    return any(hit.signature_id == "mechanism:state_conflict" for hit in run.signature_hits)


def _read_then_failed_write(write_result: str, tool: str = "Write") -> bool:
    return _conflict_hit(
        _call("2026-03-01T11:00:00Z", "r", "Read"),
        _result("2026-03-01T11:00:01Z", "r", "contents", False),
        _call("2026-03-01T11:00:02Z", "w", tool),
        _result("2026-03-01T11:00:03Z", "w", write_result, True),
    )


@pytest.mark.parametrize(
    "message",
    [
        "CONFLICT: the file already exists",
        "HTTP 409 version mismatch",
        "something unexpected happened",
    ],
)
def test_read_then_a_write_that_fails_as_a_conflict_or_unexplained_is_a_conflict(message):
    assert _read_then_failed_write(message)


@pytest.mark.parametrize(
    "message",
    [
        "String to replace not found in file.",
        "File has been modified since read, either by the user or by a linter.",
        "File has not been read yet. Read it first before writing to it.",
        "Claude requested permissions to write to a.py, but you haven't granted it yet.",
        "Permission to use Edit has been denied.",
        "ENOENT: no such file or directory",
        "Command timed out",
    ],
)
@pytest.mark.parametrize("tool", ["Edit", "Write"])
def test_an_edit_the_tool_refused_is_not_a_conflict(message, tool):
    assert not _read_then_failed_write(message, tool)


STRAY = (
    "    at retry (/app/dist/timeout-stale.js:404:12)\n"
    "  // handle the conflict, the stale cache, a timeout and permission denied here\n"
)


def test_stray_words_below_the_lead_line_do_not_hide_a_real_failure():
    # An unexplained failure stays `other` and still fires, whatever the stack frames say.
    assert _read_then_failed_write("Error: unexpected failure writing the file\n" + STRAY)
    assert _read_then_failed_write("Error: bad state at line 404\n" + STRAY)


def test_stray_words_below_the_lead_line_do_not_turn_a_refusal_into_a_conflict():
    assert not _read_then_failed_write(
        "<tool_use_error>String to replace not found in file.\n" + STRAY + "</tool_use_error>", "Edit"
    )


def _openclaw_read_then_failed_write(write_result: str) -> bool:
    records = [
        {"type": "session", "id": "s1", "timestamp": "2026-09-01T09:00:00.000Z"},
        {"type": "message", "id": "a0", "timestamp": "2026-09-01T09:01:00.000Z",
         "message": {"role": "assistant", "content": [
             {"type": "toolCall", "id": "r", "name": "read", "arguments": {"path": "/a.py"}}]}},
        {"type": "message", "id": "r0", "timestamp": "2026-09-01T09:01:01.000Z",
         "message": {"role": "toolResult", "toolCallId": "r", "isError": False,
                     "content": [{"type": "text", "text": "x"}], "details": {"status": "completed"}}},
        {"type": "message", "id": "a1", "timestamp": "2026-09-01T09:02:00.000Z",
         "message": {"role": "assistant", "content": [
             {"type": "toolCall", "id": "w", "name": "edit",
              "arguments": {"path": "/a.py", "oldText": "a", "newText": "b"}}]}},
        {"type": "message", "id": "r1", "timestamp": "2026-09-01T09:02:01.000Z",
         "message": {"role": "toolResult", "toolCallId": "w", "isError": True,
                     "content": [{"type": "text", "text": write_result}],
                     "details": {"status": "error"}}},
    ]
    run = analyse_run("\n".join(json.dumps(r) for r in records).encode(), format="openclaw")
    return any(hit.signature_id == "mechanism:state_conflict" for hit in run.signature_hits)


@pytest.mark.parametrize(
    ("message", "fires"),
    [
        ("CONFLICT: the file already exists", True),
        ("something unexpected happened", True),
        ("Could not find the exact text in a.py. String to replace not found in file.", False),
        ("Permission denied", False),
    ],
)
def test_openclaw_edits_follow_the_same_rule(message, fires):
    assert _openclaw_read_then_failed_write(message) is fires


def test_a_failed_read_then_a_good_write_is_not_a_conflict():
    assert not _conflict_hit(
        _call("2026-03-01T11:00:00Z", "r", "Read"),
        _result("2026-03-01T11:00:01Z", "r", "ENOENT: no such file", True),
        _call("2026-03-01T11:00:02Z", "w", "Write"),
        _result("2026-03-01T11:00:03Z", "w", "created", False),
    )


def test_failure_wording_in_a_successful_result_is_not_a_conflict():
    assert not _conflict_hit(
        _call("2026-03-01T11:00:00Z", "r", "Read"),
        _result("2026-03-01T11:00:01Z", "r", "error: failed to parse, exception raised", False),
        _call("2026-03-01T11:00:02Z", "w", "Write"),
        _result("2026-03-01T11:00:03Z", "w", "write failed earlier but this one succeeded", False),
    )


# --------------------------------------------------------------------------- #
# A failed unconfirmed outside step still fires verification failure
# --------------------------------------------------------------------------- #
#
# Decision (recommended and pinned here): the rule is about the safeguard being skipped,
# not about the step succeeding. A push to main that was rejected was still attempted
# with nobody asked first. A failed call is classed error_or_exception by the canonical
# layer, so the matcher reads outside steps from both families.


def test_a_failed_unconfirmed_outside_step_still_fires():
    failed = tool(0, facts=facts("merge", "outside_service", unread_own_merge=True))
    failed["event_family"] = "error_or_exception"
    payload = match([failed])
    assert {rule["rule_id"] for rule in payload["matched_rules"]} >= {"R-VER-001"}
    assert {seq["sequence_id"] for seq in payload["matched_sequence_patterns"]} >= {"SEQ-VER-001"}


def test_a_failed_step_that_stays_inside_still_does_not_fire():
    failed = tool(0, facts=facts("read_only"))
    failed["event_family"] = "error_or_exception"
    assert not {rule["rule_id"] for rule in match([failed])["matched_rules"]} & {"R-VER-001"}


@pytest.mark.parametrize("is_error", [False, True])
def test_an_unread_own_merge_fires_whether_or_not_it_failed(is_error):
    lines = [
        _line(
            "2026-03-01T11:00:00Z",
            {"type": "text", "text": "Constraint: ask for confirmation before destructive actions."},
        ),
        _line(
            "2026-03-01T11:00:01Z",
            {
                "type": "tool_use",
                "id": "b",
                "name": "Bash",
                "input": {"command": "git push origin fix && gh pr merge fix --squash"},
            },
        ),
        _result("2026-03-01T11:00:02Z", "b", "denied" if is_error else "ok", is_error),
    ]
    run = analyse_run("\n".join(lines).encode())
    assert any(hit.signature_id == "mechanism:verification_failure" for hit in run.signature_hits)
