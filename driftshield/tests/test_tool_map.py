import json
import re

import pytest

from driftshield import tool_map as tm
from driftshield.parsers.confirmation_tools import CONFIRMATION_TOOLS
from driftshield.tool_map import SHELL_TOOL_NAMES


def test_old_lists_are_views_of_the_default_map():
    assert SHELL_TOOL_NAMES == frozenset(
        {"bash", "exec", "shell", "shell_command", "exec_command", "local_shell"}
    )
    assert CONFIRMATION_TOOLS == frozenset({"askuserquestion", "request_user_input"})
    assert tm.DEFAULT_CODING_MAP.names("file_write") == frozenset({"write", "edit", "apply_patch"})


def test_kind_for_is_case_insensitive_and_unmapped_is_none():
    assert tm.DEFAULT_CODING_MAP.kind_for("Bash") == "shell"
    assert tm.DEFAULT_CODING_MAP.kind_for("AskUserQuestion") == "confirmation"
    assert tm.DEFAULT_CODING_MAP.kind_for("issue_payment") is None
    assert tm.DEFAULT_CODING_MAP.kind_for(None) is None


def test_map_adds_to_coding_defaults_entry_by_entry():
    m = tm.tool_map_from_dict({"version": 2, "tools": {"Issue_Payment": "outside_write", "message": "ignore"}})
    assert m.version == 2
    assert m.kind_for("issue_payment") == "outside_write"
    assert m.kind_for("message") == "ignore"
    assert m.kind_for("bash") == "shell"


def test_coding_defaults_can_be_switched_off():
    m = tm.tool_map_from_dict({"coding_defaults": False, "tools": {"lookup_claim": "check"}})
    assert m.kind_for("lookup_claim") == "check"
    assert m.kind_for("bash") is None


@pytest.mark.parametrize(
    "data",
    [
        [],
        {"tools": []},
        {"tools": {"x": "launch_missiles"}},
        {"tools": {"": "read"}},
        {"version": "3"},
        {"coding_defaults": "no"},
        {"extra": 1},
    ],
)
def test_bad_maps_are_refused(data):
    with pytest.raises(tm.ToolMapError):
        tm.tool_map_from_dict(data)


def test_load_from_path_and_environment(tmp_path, monkeypatch):
    path = tmp_path / "map.json"
    path.write_text(json.dumps({"tools": {"cancel_policy": "delete_outside"}}))
    assert tm.load_tool_map(path).kind_for("cancel_policy") == "delete_outside"

    monkeypatch.delenv(tm.TOOL_MAP_ENV, raising=False)
    assert tm.load_tool_map() is None
    monkeypatch.setenv(tm.TOOL_MAP_ENV, str(path))
    assert tm.load_tool_map().kind_for("cancel_policy") == "delete_outside"


def test_load_reports_bad_files(tmp_path):
    with pytest.raises(tm.ToolMapError, match="cannot read"):
        tm.load_tool_map(tmp_path / "missing.json")
    bad = tmp_path / "bad.json"
    bad.write_text("{nope")
    with pytest.raises(tm.ToolMapError, match="not valid JSON"):
        tm.load_tool_map(bad)


# --------------------------------------------------------------------------- #
# Analysis with a tool map
# --------------------------------------------------------------------------- #

from pathlib import Path  # noqa: E402

from driftshield import analyse_run  # noqa: E402
from driftshield.core.deterministic_matching import build_deterministic_match  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"
INSURANCE = FIXTURES / "transcripts" / "tool_map" / "insurance_claims_claude_code.jsonl"
INSURANCE_MAP = FIXTURES / "tool_maps" / "insurance_claims_claude_code.json"


def _facts_by_tool(run):
    return {
        block["name"]: block["step_facts"]
        for record in run.redacted_transcript["events"]
        for block in (record.get("message", {}).get("content") or [])
        if isinstance(block, dict) and "step_facts" in block
    }


def _unconfirmed_tools(run):
    features = build_deterministic_match(
        canonical_analysis=run.canonical_analysis, result=run.analysis
    )["extracted_features"]
    names = {e["event_id"]: e for e in run.canonical_analysis["normalized_events"]}
    return sorted(
        names[i]["structured_payload"]["tool_name"] for i in features["unconfirmed_outside_event_ids"]
    )


def test_insurance_session_is_silent_without_a_map():
    run = analyse_run(INSURANCE.read_bytes(), source=INSURANCE.name)
    assert run.signature_hits == []
    assert run.tool_coverage is None
    assert _facts_by_tool(run) == {}


def test_insurance_session_fires_on_unchecked_outside_tools_with_its_map():
    run = analyse_run(INSURANCE.read_bytes(), source=INSURANCE.name, tool_map=tm.load_tool_map(INSURANCE_MAP))
    assert [hit.signature_id for hit in run.signature_hits] == ["mechanism:verification_failure"]
    facts = _facts_by_tool(run)
    assert facts["lookup_claim"]["command_kind"] == "read_only"
    assert facts["update_claim_status"]["checked_before"] is True
    assert facts["update_claim_status"]["unchecked_tool_step"] is False
    assert facts["issue_payment"]["unchecked_tool_step"] is True
    assert facts["email_broker"]["command_kind"] == "send_outside"
    assert facts["cancel_policy"]["command_kind"] == "delete"
    assert facts["cancel_policy"]["unchecked_tool_step"] is False
    # cancel_policy is unchecked but an underwriter approved it first, so it is excused.
    assert _unconfirmed_tools(run) == ["email_broker", "issue_payment"]
    assert run.tool_coverage == {
        "tool_map_version": 1,
        "tool_calls": 8,
        "mapped_calls": 7,
        "not_checked_calls": 1,
        "not_checked_tools": {"fetch_weather_report": 1},
    }


def test_mapped_facts_survive_redaction_and_reanalysis():
    tool_map = tm.load_tool_map(INSURANCE_MAP)
    run = analyse_run(INSURANCE.read_bytes(), source=INSURANCE.name, tool_map=tool_map)
    again = analyse_run(json.dumps(run.redacted_transcript), format=run.detected_format, tool_map=tool_map)
    assert _facts_by_tool(again) == _facts_by_tool(run)
    # Without the map, the carried facts are still believed for a hidden input, and the
    # excused cancel_policy stays excused: the same steps are unconfirmed.
    plain = analyse_run(json.dumps(run.redacted_transcript), format=run.detected_format)
    assert [h.signature_id for h in plain.signature_hits] == ["mechanism:verification_failure"]
    assert _unconfirmed_tools(plain) == _unconfirmed_tools(run) == ["email_broker", "issue_payment"]


def _hits_and_facts(run):
    return (
        sorted((h.signature_id, h.mechanism_id) for h in run.signature_hits),
        json.dumps(run.redacted_transcript, sort_keys=True),
    )


@pytest.mark.parametrize(
    "name",
    [
        "sample_claude_code_session.jsonl",
        "sample_codex_cli_rollout.jsonl",
        "sample_openclaw_trajectory.json",
        "dogfood/unread_start_label_session.jsonl",
    ],
)
def test_a_map_that_only_adds_tools_changes_nothing_for_coding_runs(name):
    path = FIXTURES / "transcripts" / name
    plain = analyse_run(path.read_bytes(), source=name)
    mapped = analyse_run(path.read_bytes(), source=name, tool_map=tm.load_tool_map(INSURANCE_MAP).merged_over(tm.DEFAULT_CODING_MAP))
    assert _hits_and_facts(mapped) == _hits_and_facts(plain)


def test_a_mapped_confirmation_becomes_a_confirmation_checkpoint():
    tool_map = tm.tool_map_from_dict({"tools": {"issue_payment": "outside_write", "ask_supervisor": "confirmation"}})
    records = [
        {"type": "user", "sessionId": "s", "timestamp": "2026-09-01T09:00:00.000Z", "message": {"role": "user", "content": "pay"}},
    ]
    for index, name in enumerate(["ask_supervisor", "issue_payment"]):
        records.append(
            {
                "type": "assistant",
                "sessionId": "s",
                "timestamp": f"2026-09-01T09:0{index + 1}:00.000Z",
                "message": {"role": "assistant", "model": "m", "content": [{"type": "tool_use", "id": f"c{index}", "name": name, "input": {}}]},
            }
        )
    run = analyse_run("\n".join(json.dumps(r) for r in records), format="claude_code", tool_map=tool_map)
    assert run.signature_hits == []
    families = [e["event_family"] for e in run.canonical_analysis["normalized_events"]]
    assert "confirmation_checkpoint" in families


def test_cli_analyze_reads_a_tool_map(tmp_path):
    from typer.testing import CliRunner

    from driftshield.cli.main import app

    result = CliRunner().invoke(app, ["analyze", str(INSURANCE), "--tool-map", str(INSURANCE_MAP), "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output[result.output.index("{"):])
    assert data["tool_coverage"]["not_checked_tools"] == {"fetch_weather_report": 1}
    assert data["signature_hits"][0]["signature_id"] == "mechanism:verification_failure"

    text = CliRunner().invoke(app, ["analyze", str(INSURANCE), "--tool-map", str(INSURANCE_MAP)])
    plain = re.sub(r"\x1b\[[0-9;]*m", "", text.output)
    assert "Tool map: 7 of 8 tool calls checked" in plain
    assert "fetch_weather_report (1)" in plain

    bad = tmp_path / "bad.json"
    bad.write_text('{"tools": {"x": "nope"}}')
    refused = CliRunner().invoke(app, ["analyze", str(INSURANCE), "--tool-map", str(bad)])
    assert refused.exit_code == 1
    assert "unknown kind" in refused.output
