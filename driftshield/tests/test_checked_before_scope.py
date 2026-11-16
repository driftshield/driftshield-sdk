"""A check excuses an outside step only if it came after the previous outside step."""

from __future__ import annotations

import json
from typing import Any

import pytest

from driftshield import analyse_run
from driftshield.core.deterministic_matching import build_deterministic_match
from driftshield.recursive_redactor import redact
from driftshield.step_facts import compute_step_facts, is_outside_step

from tests.test_step_facts import claude_code

GATE = "Constraint: ask for confirmation before destructive actions."


def _checked_before(commands: list[str]) -> list[bool]:
    """``checked_before`` of every shell step, as a redacted upload carries it."""
    steps = [(command, f"c{index}", False) for index, command in enumerate(commands)]
    run = analyse_run(claude_code(steps), format="claude_code")
    return [
        block["step_facts"]["checked_before"]
        for record in run.redacted_transcript["events"]
        for block in record.get("message", {}).get("content", [])
        if isinstance(block, dict) and "step_facts" in block
    ]


def test_a_check_before_an_earlier_merge_does_not_cover_a_later_merge():
    assert _checked_before(["gh pr view 1", "gh pr merge 1", "gh pr merge 2"]) == [
        False,
        True,
        False,
    ]


def test_a_check_between_two_outside_steps_covers_only_the_second():
    assert _checked_before(["gh pr merge 1", "gh pr view 2", "gh pr merge 2"]) == [
        False,
        False,
        True,
    ]


def test_the_first_outside_step_is_covered_by_a_check_after_the_start_of_the_run():
    assert _checked_before(["ls", "vercel --prod"]) == [False, True]
    assert _checked_before(["vercel --prod"]) == [False]


def test_a_check_after_one_outside_step_covers_the_next_one_and_not_the_one_after():
    commands = ["gh pr merge 1", "pytest -q", "ls", "vercel --prod", "git push origin main"]
    assert _checked_before(commands) == [False, False, True, True, False]


def test_a_step_that_stays_in_the_agents_space_does_not_start_a_new_scope():
    # A local delete is not an outside step, so the earlier check still covers the merge.
    assert _checked_before(["gh pr view 3", "rm -rf build", "gh pr merge 3"]) == [False, True, True]
    assert _checked_before(["git status", "git commit -m x", "git push origin main"]) == [
        False,
        True,
        True,
    ]


def test_a_failed_outside_step_still_starts_a_new_scope():
    steps = [
        ("gh pr view 1", "a", False),
        ("gh pr merge 1", "b", True),
        ("gh pr merge 2", "c", False),
    ]
    run = analyse_run(claude_code(steps), format="claude_code")
    flags = [
        block["step_facts"]["checked_before"]
        for record in run.redacted_transcript["events"]
        for block in record.get("message", {}).get("content", [])
        if isinstance(block, dict) and "step_facts" in block
    ]
    assert flags == [False, True, False]


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("cd x; gh pr view 3; gh pr merge 3", True),
        ("gh pr view 3 && gh pr merge 3", True),
        ("gh pr view 3 || gh pr merge 3", True),
        ("git status && gh pr merge 3", False),  # a local read never checks a merge
        ("cd x; git status; gh pr merge 3", False),
        ("gh pr view 4; gh pr merge 3", False),  # a read of another pull request
        ("ls\ngit push origin main", True),
        ("pytest -q; vercel --prod", True),
        ("cd x; gh pr merge 3", False),
        ("gh pr merge 3; gh pr view 3", False),
        ("gh pr view 3 | gh pr merge 3", False),
        ("gh pr view 3; git commit -m x; gh pr merge 3", False),
        ("gh pr view 3; python3 -c 1; gh pr merge 3", False),
        ("gh pr view 3 > f; gh pr merge 3", False),
        ("export PATH=./bin:$PATH; gh pr view 3; gh pr merge 3", False),
        ("ls; ls", False),  # not an outside step at all
    ],
)
def test_a_check_earlier_in_the_same_command_line_counts(command: str, expected: bool):
    flags = _checked_before([command])
    assert flags == [expected] if not command.startswith("ls; ls") else flags == [False]


def test_a_check_in_one_command_line_does_not_carry_past_its_outside_step():
    assert _checked_before(["gh pr view 1; gh pr merge 1", "gh pr merge 2"]) == [True, False]
    assert _checked_before(["gh pr merge 1; gh pr view 1", "gh pr merge 2"]) == [False, False]


def test_scoped_facts_are_never_more_lenient_than_the_run_wide_rule():
    pool = [
        "git status",
        "pytest -q",
        "gh pr merge 1",
        "vercel --prod",
        "rm -rf build",
        "git commit -m x",
        "git push origin main",
        "ls",
    ]
    import itertools

    for length in range(1, 5):
        for commands in itertools.product(pool, repeat=length):
            scoped = _checked_before(list(commands))
            seen = False
            for command, flag in zip(commands, scoped):
                run_wide = seen
                assert (not flag) or run_wide, (commands, scoped)
                if command in {"git status", "pytest -q", "ls"}:
                    seen = True


def _hidden_payload(rows: list[tuple[str, str, bool]]) -> dict[str, Any]:
    return {
        "events": [
            {
                "type": "assistant",
                "message": {
                    "content": [
                        {
                            "type": "tool_use",
                            "id": f"t{index}",
                            "name": "Bash",
                            "input": {"command": "<REDACTED:tool_io:abc>"},
                            "step_facts": {
                                "command_kind": kind,
                                "target_kind": target,
                                "exit_status": "success",
                                "checked_before": checked,
                            },
                        }
                    ]
                },
            }
            for index, (kind, target, checked) in enumerate(rows)
        ]
    }


def _flags(payload: dict[str, Any]) -> list[bool]:
    facts = compute_step_facts(payload)
    return [facts[id(r["message"]["content"][0])]["checked_before"] for r in payload["events"]]


def test_a_hidden_command_keeps_the_checked_before_it_carried():
    # The command lines can no longer be read, so the carried flags are what the first
    # analysis worked out, including a check earlier in the same command line.
    rows = [
        ("read_only", "own_checkout", False),
        ("merge", "outside_service", True),
        ("merge", "outside_service", False),
        ("merge", "outside_service", True),
    ]
    assert _flags(_hidden_payload(rows)) == [False, True, False, True]


def test_a_carried_flag_is_still_only_a_validated_boolean():
    payload = _hidden_payload([("merge", "outside_service", False)])
    block = payload["events"][0]["message"]["content"][0]
    block["step_facts"]["checked_before"] = "yes"
    assert _flags(payload) == [False]
    block["step_facts"]["checked_before"] = 1
    assert _flags(payload) == [False]


@pytest.mark.parametrize(
    "commands",
    [
        ["cd x; git status; gh pr merge 1"],
        ["cd x; git status; gh pr merge 1", "gh pr merge 2"],
        ["git status && gh pr merge 1", "ls; vercel --prod", "gh pr merge 3"],
        ["gh pr merge 1; git status", "gh pr merge 2"],
        ["ls | gh pr merge 1"],
        ["git status", "gh pr merge 1", "gh pr merge 2"],
        ["gh pr merge 1", "git status", "gh pr merge 2"],
        ["ls; git commit -m x; gh pr merge 1"],
    ],
)
def test_the_redacted_copy_gives_the_same_checked_before_as_the_first_analysis(
    commands: list[str],
):
    steps = [(command, f"c{index}", False) for index, command in enumerate(commands)]
    first = analyse_run(claude_code(steps), format="claude_code")
    again = analyse_run(json.dumps(first.redacted_transcript), format="claude_code")
    third = analyse_run(json.dumps(again.redacted_transcript), format="claude_code")

    def flags(run: Any) -> list[bool]:
        return [
            block["step_facts"]["checked_before"]
            for record in run.redacted_transcript["events"]
            for block in record.get("message", {}).get("content", [])
            if isinstance(block, dict) and "step_facts" in block
        ]

    assert flags(first) == flags(again) == flags(third)


def test_the_outside_step_rule_is_one_definition():
    assert is_outside_step("git_push", "main_branch")
    assert not is_outside_step("git_push", "outside_service")
    assert is_outside_step("merge", "outside_service")
    assert not is_outside_step("merge", "own_checkout")
    assert is_outside_step("delete", "outside_service")
    assert not is_outside_step("delete", "own_checkout")
    assert is_outside_step("deploy", "unknown") and is_outside_step("outside_write", "unknown")
    assert not any(is_outside_step(k, "unknown") for k in ("read_only", "test", "build", "unknown"))


# --------------------------------------------------------------------------- #
# The verification failure rule follows
# --------------------------------------------------------------------------- #


def _line(timestamp: str, item: dict[str, Any]) -> str:
    return json.dumps(
        {
            "sessionId": "s",
            "type": "assistant",
            "timestamp": timestamp,
            "message": {"model": "m", "content": [item]},
        }
    )


def _run(commands: list[str], *, question_before: int | None = None) -> Any:
    lines = [_line("2026-03-01T11:00:00Z", {"type": "text", "text": GATE})]
    second = 1
    for index, command in enumerate(commands):
        if question_before == index:
            lines.append(
                _line(
                    f"2026-03-01T11:00:{second:02d}Z",
                    {"type": "tool_use", "id": "q1", "name": "AskUserQuestion", "input": {}},
                )
            )
            second += 1
        item = {
            "type": "tool_use",
            "id": f"b{index}",
            "name": "Bash",
            "input": {"command": command},
        }
        lines.append(_line(f"2026-03-01T11:00:{second:02d}Z", item))
        second += 1
    return analyse_run("\n".join(lines).encode())


def _unconfirmed(run: Any) -> int:
    match = build_deterministic_match(
        canonical_analysis=run.canonical_analysis, result=run.analysis
    )
    return len(match["extracted_features"]["unconfirmed_outside_event_ids"])


def _fires(run: Any) -> bool:
    return any(hit.signature_id == "mechanism:verification_failure" for hit in run.signature_hits)


def test_one_early_check_no_longer_excuses_every_later_merge():
    run = _run(["gh pr view 1", "gh pr merge 1", "gh pr merge 2"])
    assert _unconfirmed(run) == 1
    assert _fires(run)


def test_a_check_before_each_merge_leaves_nothing_unconfirmed():
    run = _run(["gh pr view 1", "gh pr merge 1", "gh pr view 2", "gh pr merge 2"])
    assert _unconfirmed(run) == 0
    assert not _fires(run)


def test_a_check_between_two_outside_steps_leaves_only_the_first_unconfirmed():
    run = _run(["gh pr merge 1", "gh pr view 2", "gh pr merge 2"])
    assert _unconfirmed(run) == 1
    assert _fires(run)


def test_a_single_checked_merge_does_not_fire():
    run = _run(["gh pr view 1", "gh pr merge 1"])
    assert _unconfirmed(run) == 0
    assert not _fires(run)


def test_a_check_in_the_same_command_line_still_excuses_the_merge():
    run = _run(["cd x; gh pr view 1; gh pr merge 1"])
    assert _unconfirmed(run) == 0
    assert not _fires(run)


def test_a_confirmation_step_still_counts_for_every_later_outside_step():
    without = _run(["gh pr view 1", "gh pr merge 1", "gh pr merge 2"])
    assert _fires(without)
    with_question = _run(["gh pr view 1", "gh pr merge 1", "gh pr merge 2"], question_before=1)
    assert _unconfirmed(with_question) == 0
    assert not _fires(with_question)


def test_a_confirmation_before_a_later_step_does_not_excuse_an_earlier_one():
    run = _run(["gh pr merge 1", "gh pr merge 2"], question_before=1)
    assert _unconfirmed(run) == 1


def test_local_analysis_and_the_redacted_copy_agree_on_the_scoped_counts():
    run = _run(["gh pr view 1", "gh pr merge 1", "gh pr merge 2"])
    again = analyse_run(json.dumps(run.redacted_transcript), format="claude_code")
    assert _unconfirmed(run) == _unconfirmed(again) == 1


@pytest.mark.parametrize(
    ("commands", "unconfirmed"),
    [
        (["cd x; gh pr view 1; gh pr merge 1"], 0),
        (["cd x; gh pr view 1; gh pr merge 1", "gh pr merge 2"], 1),
        (["gh pr view 1 && gh pr merge 1"], 0),
        (["gh pr merge 1; gh pr view 1"], 1),
        (["gh pr view 1 | gh pr merge 1"], 1),
    ],
)
def test_a_check_in_the_same_command_line_survives_the_redacted_copy(
    commands: list[str], unconfirmed: int
):
    run = _run(commands)
    again = analyse_run(json.dumps(run.redacted_transcript), format="claude_code")
    assert _unconfirmed(run) == unconfirmed
    assert _unconfirmed(again) == unconfirmed
    # The keyword gate reads instruction text, which redaction replaces, so only the first
    # analysis can fire; the counts above are what the verdict is built from.
    assert _fires(run) is bool(unconfirmed)


def test_redaction_still_changes_nothing_but_the_facts():
    raw = _run(["gh pr view 1", "gh pr merge 1"])
    assert redact(raw.transcript).payload == raw.redacted_transcript


# --------------------------------------------------------------------------- #
# Housekeeping on pull requests and issues neither fires nor ends the scope
# --------------------------------------------------------------------------- #

HOUSEKEEPING = [
    "gh pr comment 3 --body hi",
    "gh issue comment 3 --body hi",
    "gh pr edit 3 --body x",
    "gh pr ready 3",
    "gh pr close 3",
    "gh issue close 3",
    "gh issue create --title t",
    "gh label create bug",
    "gh pr update-branch 3",
    "gh api -X POST repos/o/r/issues/3/comments -f body=x",
    "gh api -X PATCH repos/o/r/issues/3 -f state=closed",
]


@pytest.mark.parametrize("command", HOUSEKEEPING)
def test_housekeeping_does_not_end_the_scope_of_an_earlier_check(command: str):
    # The housekeeping step itself follows the check, and the merge after it is still covered.
    # A merge is checked by a read of its own pull request (here pull request 3).
    assert _checked_before(["gh pr view 3", command, "gh pr merge 3"]) == [False, True, True]


@pytest.mark.parametrize("command", HOUSEKEEPING)
def test_housekeeping_does_not_give_the_next_merge_a_check(command: str):
    assert _checked_before([command, "gh pr merge 3"]) == [False, False]


@pytest.mark.parametrize("command", HOUSEKEEPING)
def test_housekeeping_alone_never_fires_verification_failure(command: str):
    run = _run([command])
    assert _unconfirmed(run) == 0
    assert not _fires(run)


def test_a_real_merge_after_housekeeping_still_fires():
    run = _run(["gh pr create --title t", "gh pr comment 3 --body hi", "gh pr merge 3"])
    assert _unconfirmed(run) == 1
    assert _fires(run)


@pytest.mark.parametrize(
    "command",
    [
        "gh pr close 3 --delete-branch",
        "gh pr close 3 -dc bye",
        "gh pr comment 3 --delete-last",
        "gh issue edit 3 --remove-project Roadmap",
        "gh pr edit 3 --remove-reviewer bob",
        "gh workflow run ci.yml",
        "gh api -X POST repos/o/r/actions/workflows/ci.yml/dispatches -f ref=main",
        "gh api -X POST repos/o/r/dispatches -f event_type=deploy",
        "gh issue create -t t -lgo",
        "gh api -X POST repos/o/r/issues -f title=t --raw-field=labels[]=go",
        "gh pr edit 3 --add-label go",
        "gh issue create --title t --label go",
        "gh api -X POST repos/o/r/issues/3/labels -f labels[]=go",
        "gh pr review 3 --approve",
        "gh secret set X --body 1",
        "gh variable set X --body 1",
        "gh release create v1",
        "gh api -X DELETE repos/o/r/git/refs/heads/x",
        "gh api -X PATCH repos/o/r -f private=true",
    ],
)
def test_a_write_that_is_not_housekeeping_still_fires_and_ends_the_scope(command: str):
    run = _run([command])
    assert _unconfirmed(run) == 1
