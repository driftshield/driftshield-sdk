import json
from pathlib import Path

from driftshield import analyse_run
from driftshield.core.models import EventType
from driftshield.parsers.events_v1 import EventsV1Parser
from driftshield.parsers.registry import detect_format
from driftshield.tool_map import load_tool_map

ROOT = Path(__file__).parents[2]
FIXTURE = Path(__file__).parent / "fixtures" / "transcripts" / "events_v1" / "insurance_claims.jsonl"
FIXTURE_MAP = Path(__file__).parent / "fixtures" / "tool_maps" / "insurance_claims.json"
EXAMPLE = ROOT / "docs" / "examples" / "insurance-claims"
S = "driftshield.events.v1"


def _lines(*records):
    return "\n".join(json.dumps({"schema": S, "session_id": "s", "timestamp": "2026-11-12T10:00:00Z", **r}) for r in records)


def test_the_docs_example_is_the_fixture():
    assert (EXAMPLE / "session.jsonl").read_text() == FIXTURE.read_text()
    assert (EXAMPLE / "tool_map.json").read_text() == FIXTURE_MAP.read_text()


def test_detected_from_content_whatever_the_path():
    assert detect_format(FIXTURE.read_text(), path_hint="x/.claude/projects/a.jsonl") == ("driftshield_events_v1", None)


def test_parser_reads_every_type():
    text = _lines(
        {"type": "message", "actor": "user", "text": "pay claim 1"},
        {"type": "tool_call", "tool": "issue_payment", "call_id": "c1", "input": {"amount": 5}},
        {"type": "tool_result", "call_id": "c1", "status": "error", "error": "gateway timed out"},
        {"type": "confirmation", "actor": "person", "text": "yes"},
        {"type": "handoff", "tool": "transfer_to_human"},
        {"type": "tool_result", "call_id": "nope", "status": "ok"},
        {"type": "launch"},
        {"type": "tool_call", "call_id": "c2"},
    )
    parser = EventsV1Parser()
    events = parser.parse(text + "\nnot json\n[1]\n" + json.dumps({"type": "message"}))
    assert [(e.event_type, e.action) for e in events] == [
        (EventType.OUTPUT, "user_message"),
        (EventType.TOOL_CALL, "issue_payment"),
        (EventType.CONSTRAINT_CHECK, "confirmation"),
        (EventType.HANDOFF, "transfer_to_human"),
    ]
    assert events[0].actor["role"] == "user"
    assert events[1].inputs == {"amount": 5}
    assert events[1].outputs["is_error"] is True
    assert events[1].failure_context["status"] == "error"
    assert parser.skipped_records_by_reason == {
        "result_without_call": 1,
        "unknown_type": 1,
        "tool_call_without_tool": 1,
        "not_json": 1,
        "not_an_object": 1,
        "not_events_v1": 1,
    }


def test_a_failed_mapped_call_carries_its_error_class():
    text = _lines(
        {"type": "tool_call", "tool": "issue_payment", "call_id": "c1", "input": {}},
        {"type": "tool_result", "call_id": "c1", "status": "error", "error": "Permission denied"},
    )
    tool_map = load_tool_map(FIXTURE_MAP)
    run = analyse_run(text, tool_map=tool_map)
    facts = run.redacted_transcript["events"][0]["step_facts"]
    assert facts["exit_status"] == "failure"
    assert facts["error_class"] == "permission_denied"
    assert "Permission denied" not in json.dumps(run.redacted_transcript)


def test_shell_steps_in_events_v1_are_classified_like_any_shell_step():
    text = _lines({"type": "tool_call", "tool": "bash", "call_id": "c1", "input": {"command": "git push origin main"}})
    run = analyse_run(text)
    facts = run.redacted_transcript["events"][0]["step_facts"]
    assert (facts["command_kind"], facts["target_kind"]) == ("git_push", "main_branch")


def test_the_worked_example_fires_as_the_doc_says():
    plain = analyse_run(FIXTURE.read_bytes(), source=FIXTURE.name)
    assert plain.detected_format == "driftshield_events_v1"
    assert plain.signature_hits == []
    mapped = analyse_run(FIXTURE.read_bytes(), source=FIXTURE.name, tool_map=load_tool_map(FIXTURE_MAP))
    assert [h.signature_id for h in mapped.signature_hits] == ["mechanism:verification_failure"]
    assert mapped.tool_coverage["mapped_calls"] == 7
    assert mapped.tool_coverage["not_checked_tools"] == {"fetch_weather_report": 1}
    flagged = {
        r["tool"]
        for r in mapped.redacted_transcript["events"]
        if r.get("step_facts", {}).get("unchecked_tool_step")
    }
    assert flagged == {"issue_payment", "email_broker"}
    redacted = json.dumps(mapped.redacted_transcript)
    for secret in ("CLM-1042", "broker@example.com", "POL-9", "AB1 2CD"):
        assert secret not in redacted


def test_a_confirmation_line_excuses_a_later_mapped_outside_call_in_the_step_facts():
    text = _lines(
        {"type": "confirmation", "actor": "person", "text": "go ahead"},
        {"type": "tool_call", "tool": "cancel_policy", "call_id": "c1", "input": {}},
    )
    tool_map = load_tool_map(FIXTURE_MAP)
    run = analyse_run(text, tool_map=tool_map)
    assert run.redacted_transcript["events"][1]["step_facts"]["unchecked_tool_step"] is False
    assert run.signature_hits == []
    again = analyse_run(json.dumps(run.redacted_transcript), format=run.detected_format)
    assert again.signature_hits == []


def test_a_person_message_is_human_words_not_agent_reasoning():
    events = EventsV1Parser().parse(_lines({"type": "message", "actor": "person", "text": "approved"}))
    assert events[0].actor["role"] == "user"


def test_tool_names_are_read_as_written_by_parser_and_step_facts_alike():
    tool_map = load_tool_map(FIXTURE_MAP)
    run = analyse_run(
        _lines(
            {"type": "tool_call", "tool": " issue_payment", "call_id": "c1"},
            {"type": "tool_call", "tool": "  ", "call_id": "c2"},
        ),
        tool_map=tool_map,
    )
    assert [e.action for e in run.events] == [" issue_payment"]
    assert "step_facts" not in run.redacted_transcript["events"][0]
    assert "step_facts" not in run.redacted_transcript["events"][1]
    assert run.tool_coverage["not_checked_tools"] == {" issue_payment": 1}
