"""Verification failure fires when a run adds the label that starts an agent's work on an
issue with no fresh read of that issue.

A read is fresh when it is in the same command as the add, or in one of the previous ten
shell steps and after the run's own last write to the issue in an earlier step. Only the
start label (``agent:go``) on an issue is judged.
"""

from __future__ import annotations

import pytest

from driftshield import analyse_run
from tests.test_unread_own_merge import Step, _fired, _transcript

API_ADD = (
    "gh api --method POST repos/o/r/issues/{n}/labels -f 'labels[]=agent:go' --jq '[.[].name]'"
)
EDIT_ADD = "gh issue edit {n} -R o/r --add-label agent:go"


def _flags(steps: list[Step]) -> list[bool]:
    run = analyse_run(_transcript(steps))
    return [
        block["step_facts"]["unread_start_label"]
        for record in run.redacted_transcript["events"]
        for block in record.get("message", {}).get("content", [])
        if isinstance(block, dict) and "step_facts" in block
    ]


# --------------------------------------------------------------------------- #
# The three real shapes from the founder labels of 18 Nov
# --------------------------------------------------------------------------- #


def test_a_start_label_after_editing_the_issue_with_no_read_since_fires():
    # The run rewrote the issue body, then started work on it without reading it back.
    steps: list[Step] = [
        "gh api --method PATCH repos/o/r/issues/436 --input b.json --jq .updated_at",
        "python3 check.py body.md",
        API_ADD.format(n=436),
    ]
    assert _fired(steps) == 1
    assert _flags(steps) == [False, False, True]


def test_a_read_before_the_runs_own_edit_in_an_earlier_step_is_stale():
    steps: list[Step] = [
        "gh issue view 201 --json body > old.md; gh api --method PATCH repos/o/r/issues/201 "
        "--input i.json",
        "echo ok",
        API_ADD.format(n=201),
    ]
    assert _fired(steps) == 1


def test_a_restart_long_after_the_last_read_fires():
    # The run read the issue, then did more than ten other steps before starting it again.
    steps: list[Step] = ["gh api repos/o/r/issues/216/comments"] + ["ls"] * 11
    steps.append(API_ADD.format(n=216))
    assert _fired(steps) == 1


# --------------------------------------------------------------------------- #
# Fresh reads
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "read",
    [
        "gh issue view 216 --json labels",
        "gh api repos/o/r/issues/216 --jq '[.labels[].name]'",
        "for i in $(seq 1 5); do gh api repos/o/r/issues/216 --jq .state; sleep 5; done",
        "for x in r:216 k:3; do gh issue view ${x##*:}; done",
    ],
)
def test_a_recent_read_clears_the_start(read: str):
    assert _fired([read, "ls", API_ADD.format(n=216)]) == 0
    assert _fired([read] + ["ls"] * 9 + [API_ADD.format(n=216)]) == 0


@pytest.mark.parametrize(
    "command",
    [
        API_ADD.format(n=7) + "; gh api repos/o/r/issues/7 --jq '{state,labels:[.labels[].name]}'",
        EDIT_ADD.format(n=7) + " >/dev/null && gh issue view 7 -R o/r --json labels",
        "B=$(gh issue view 7 --json body -q .body); printf '%s' \"$B\" > b.md && "
        "gh issue edit 7 --body-file b.md && gh issue comment 7 --body yes && "
        "gh issue edit 7 --remove-label agent:escalated --add-label agent:go",
    ],
)
def test_a_read_in_the_same_command_clears_the_start(command: str):
    assert _fired([command]) == 0


def test_a_decision_and_the_start_in_one_command_keep_an_earlier_read():
    # A person decided: the run read the issue, then posted the decision and started it.
    steps: list[Step] = [
        "gh api repos/o/r/issues/212/comments --jq '.[-1].body'",
        "gh api --method POST repos/o/r/issues/212/comments --input c.json && "
        "gh api --method DELETE repos/o/r/issues/212/labels/agent:escalated; "
        'gh api --method POST repos/o/r/issues/212/labels -f "labels[]=agent:go"',
    ]
    assert _fired(steps) == 0


def test_a_read_after_an_earlier_edit_clears_the_start():
    steps: list[Step] = [
        "gh api --method PATCH repos/o/r/issues/5 --input b.json",
        "gh issue view 5",
        API_ADD.format(n=5),
    ]
    assert _fired(steps) == 0


# --------------------------------------------------------------------------- #
# What this rule does not judge
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "command",
    [
        "gh issue edit 9 --add-label bug",
        "gh api --method POST repos/o/r/issues/9/labels -f 'labels[]=needs-info'",
        "gh api --method DELETE repos/o/r/issues/9/labels/agent:go",
        "gh issue edit 9 --remove-label agent:go",
        "gh issue edit $N --add-label agent:go",
        "gh api repos/o/r/issues/9/labels",
        "gh issue comment 9 --body 'agent:go'",
        "gh pr edit 9 --add-label agent:go",
    ],
)
def test_other_label_changes_are_not_judged(command: str):
    assert _fired([command]) == 0


def test_a_read_of_another_issue_does_not_clear_the_start():
    assert _fired(["gh issue view 10", API_ADD.format(n=11)]) == 1
