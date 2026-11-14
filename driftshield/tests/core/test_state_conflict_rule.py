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


def _write(index: int, *, failure: str | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {"tool_name": "write"}
    if failure is not None:
        payload["failure_context"] = {"status": failure, "error": "boom" if failure == "error" else None}
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


def test_a_rejected_write_after_a_read_fires():
    assert _state_fires([_read(0), _write(1, failure="error")])


def test_a_rejected_write_without_an_earlier_read_does_not_fire():
    assert not _state_fires([_write(0, failure="error")])
    assert not _state_fires([_write(0, failure="error"), _read(1)])


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


def test_read_then_a_write_that_errors_is_a_conflict():
    assert _conflict_hit(
        _call("2026-03-01T11:00:00Z", "r", "Read"),
        _result("2026-03-01T11:00:01Z", "r", "contents", False),
        _call("2026-03-01T11:00:02Z", "w", "Write"),
        _result("2026-03-01T11:00:03Z", "w", "file has been modified since read", True),
    )


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
    failed = tool(0, facts=facts("git_push", "main_branch"))
    failed["event_family"] = "error_or_exception"
    payload = match([failed])
    assert {rule["rule_id"] for rule in payload["matched_rules"]} >= {"R-VER-001"}
    assert {seq["sequence_id"] for seq in payload["matched_sequence_patterns"]} >= {"SEQ-VER-001"}


def test_a_failed_step_that_stays_inside_still_does_not_fire():
    failed = tool(0, facts=facts("read_only"))
    failed["event_family"] = "error_or_exception"
    assert not {rule["rule_id"] for rule in match([failed])["matched_rules"]} & {"R-VER-001"}


@pytest.mark.parametrize("is_error", [False, True])
def test_a_bash_deploy_fires_whether_or_not_it_failed(is_error):
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
                "input": {"command": "x"},
                "step_facts": facts("deploy", "outside_service"),
            },
        ),
        _result("2026-03-01T11:00:02Z", "b", "denied" if is_error else "ok", is_error),
    ]
    run = analyse_run("\n".join(lines).encode())
    assert any(hit.signature_id == "mechanism:verification_failure" for hit in run.signature_hits)
