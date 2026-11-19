import json

import pytest

from driftshield import tool_map as tm
from driftshield.parsers.confirmation_tools import CONFIRMATION_TOOLS
from driftshield.step_facts import SHELL_TOOL_NAMES


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
