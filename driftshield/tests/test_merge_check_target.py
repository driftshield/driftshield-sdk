"""A merge counts as checked only when that same pull request was read.

Reading the state, checks, reviews or comments of a pull request checks a merge of that pull
request: since the previous outside step on it, or earlier in the same command line, inside a
safe ``$(...)`` or a loop that is only reads. A local read, a test, a build and a read of a
different pull request never do. The number is worked out on the machine and only the
``checked_before`` boolean leaves.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from driftshield import analyse_run
from driftshield.core.deterministic_matching import build_deterministic_match
from driftshield.step_facts import classify_command
from driftshield.step_facts_pr import (
    _UNSAFE,
    clear_reads,
    command_pr_reads,
    command_pr_refs,
    gh_pr_target,
    merge_tied_check,
)

from tests.test_step_facts import ALLOWLISTED_CHECKS, CHECK_KINDS, DANGEROUS_PARTS, claude_code

GATE = "Constraint: ask for confirmation before destructive actions."
NONE: frozenset[tuple[str, str]] = frozenset()


def _tied(command: str, reads: frozenset[tuple[str, str]] = NONE) -> bool | None:
    """``merge_tied_check`` with the command kind the classifier gives the command."""
    return merge_tied_check(command, reads, command_kind=classify_command(command)[0])


def _flags(commands: list[str], failed: set[int] | None = None) -> list[bool]:
    """``checked_before`` of every shell step, as a redacted upload carries it."""
    steps = [(c, f"c{i}", i in (failed or set())) for i, c in enumerate(commands)]
    run = analyse_run(claude_code(steps), format="claude_code")
    return [
        block["step_facts"]["checked_before"]
        for record in run.redacted_transcript["events"]
        for block in record.get("message", {}).get("content", [])
        if isinstance(block, dict) and "step_facts" in block
    ]


def _line(timestamp: str, item: dict[str, Any]) -> str:
    return json.dumps(
        {
            "sessionId": "s",
            "type": "assistant",
            "timestamp": timestamp,
            "message": {"model": "m", "content": [item]},
        }
    )


def _fires(commands: list[str]) -> bool:
    lines = [_line("2026-03-01T11:00:00Z", {"type": "text", "text": GATE})]
    for index, command in enumerate(commands):
        lines.append(
            _line(
                f"2026-03-01T11:00:{index + 1:02d}Z",
                {
                    "type": "tool_use",
                    "id": f"b{index}",
                    "name": "Bash",
                    "input": {"command": command},
                },
            )
        )
    run = analyse_run("\n".join(lines).encode())
    match = build_deterministic_match(
        canonical_analysis=run.canonical_analysis, result=run.analysis
    )
    return bool(match["extracted_features"]["unconfirmed_outside_event_ids"])


# --------------------------------------------------------------------------- #
# Which pull request a command names
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("tokens", "expected"),
    [
        (["gh", "pr", "merge", "5", "--squash"], (("", "5"), "pr:merge")),
        (["gh", "pr", "view", "5", "--json", "state", "-q", ".state"], (("", "5"), "pr:view")),
        (["gh", "pr", "view", "5", "-R", "O/R"], (("o/r", "5"), "pr:view")),
        (["gh", "pr", "view", "5", "--repo=o/r"], (("o/r", "5"), "pr:view")),
        (["gh", "pr", "merge", "https://github.com/O/R/pull/7"], (("o/r", "7"), "pr:merge")),
        (["gh", "pr", "checks", "o/r#9"], (("o/r", "9"), "pr:checks")),
        (["gh", "api", "repos/o/r/pulls/5/reviews"], (("o/r", "5"), "api:pulls/reviews")),
        (["gh", "api", "-X", "PUT", "repos/o/r/pulls/5/merge"], (("o/r", "5"), "api:pulls/merge")),
        (["gh", "api", "repos/{owner}/{repo}/pulls/5"], (("", "5"), "api:pulls/")),
        (
            ["gh", "api", "repos/o/r/issues/5/comments?per_page=5"],
            (("o/r", "5"), "api:issues/comments"),
        ),
    ],
)
def test_the_pull_request_a_gh_command_names(tokens, expected):
    assert gh_pr_target(tokens) == expected


@pytest.mark.parametrize(
    "tokens",
    [
        ["gh", "pr", "merge"],  # the current branch: no literal number
        ["gh", "pr", "merge", "$N"],
        ["gh", "pr", "merge", "SUBST"],
        ["gh", "pr", "view", "main"],
        ["gh", "api", "graphql", "-f", "query=mutation { mergePullRequest(input: {}) { x } }"],
        ["gh", "api", "repos/o/r/pulls"],
        ["git", "pr", "merge", "5"],
    ],
)
def test_a_command_that_names_no_literal_pull_request_has_no_target(tokens):
    assert gh_pr_target(tokens) is None


# --------------------------------------------------------------------------- #
# The check, step by step across a run
# --------------------------------------------------------------------------- #


def test_a_read_of_the_same_pull_request_checks_its_merge():
    assert _flags(["gh pr view 1", "gh pr merge 1"]) == [False, True]
    assert _flags(["gh pr checks 1", "gh pr merge 1"]) == [False, True]
    assert _flags(
        ["gh api repos/o/r/pulls/1/reviews", "gh api -X PUT repos/o/r/pulls/1/merge"]
    ) == [
        False,
        True,
    ]
    assert _flags(["gh pr view 1 --comments", "gh pr merge 1 --squash"]) == [False, True]


@pytest.mark.parametrize(
    "unrelated",
    [
        "git log -1",
        "git status",
        "ls",
        "pytest -q",
        "npm run build",
        "aws s3 ls s3://bucket",
        "cat README.md",
    ],
)
def test_an_unrelated_read_never_clears_a_merge(unrelated):
    assert _flags([unrelated, "gh pr merge 1"]) == [False, False]
    # Not even when the pull request itself was never read but something else was, twice.
    assert _flags([unrelated, unrelated, "gh pr merge 1"])[-1] is False


def test_a_read_of_a_different_pull_request_does_not_count():
    assert _flags(["gh pr view 2", "gh pr merge 1"]) == [False, False]
    assert _flags(["gh pr view 1 -R other/repo", "gh pr merge 1"]) == [False, False]
    assert _flags(["gh pr view 1 -R o/r", "gh pr merge 1"]) == [False, False]
    assert _flags(["gh pr view 1", "gh pr merge 1 -R o/r"]) == [False, False]


def test_a_read_counts_only_until_the_next_outside_step_on_that_pull_request():
    assert _flags(["gh pr view 1", "gh pr merge 1", "gh pr merge 1"]) == [False, True, False]
    # A merge of another pull request does not use up the read of this one.
    # (the second read is not an outside step, so its own flag is the scoped one.)
    assert _flags(["gh pr view 1", "gh pr view 2", "gh pr merge 2", "gh pr merge 1"]) == [
        False,
        True,
        True,
        True,
    ]
    # A failed merge still ends the scope.
    assert _flags(["gh pr view 1", "gh pr merge 1", "gh pr merge 1"], failed={1}) == [
        False,
        True,
        False,
    ]


def test_a_pull_request_created_then_merged_with_no_read_is_not_checked():
    # The real case: the merge of a pull request created two steps earlier.
    created = "gh pr create --title t --body b"
    assert _flags([created, "gh pr merge 3"]) == [False, False]
    assert _flags([created, "aws s3 ls s3://bucket", "gh pr merge 3"]) == [False, False, False]
    assert _fires([created, "gh pr merge 3"])
    assert _fires([created, "aws s3 ls s3://bucket", "git log -1", "gh pr merge 3"])


def test_a_merge_whose_number_cannot_be_worked_out_is_not_checked():
    assert _flags(["gh pr view 1", "gh pr merge"]) == [False, False]
    assert _flags(["gh pr view $N", "gh pr merge $N"]) == [False, False]
    assert _flags(["gh pr view 1", "gh pr merge $(echo 1)"]) == [False, False]


def test_other_outside_steps_keep_the_scoped_rule():
    # A local read still checks a deploy or a push to main, as before.
    assert _flags(["ls", "vercel --prod"]) == [False, True]
    assert _flags(["pytest -q", "git push origin main"]) == [False, True]
    assert _flags(["gh pr view 1", "vercel --prod", "git push origin main"]) == [False, True, False]


# --------------------------------------------------------------------------- #
# Reads in the same command line, in substitutions and in loops
# --------------------------------------------------------------------------- #

SAFE_SAME_LINE = [
    "gh pr view 5; gh pr merge 5",
    "cd x && gh pr view 5 --json state && gh pr merge 5 --squash",
    "gh pr view 5 | head; gh pr merge 5",
    "gh pr view 5 || gh pr merge 5",
    "gh pr merge 5 --match-head-commit $(gh pr view 5 --json headRefOid -q .headRefOid)",
    "sha=$(gh pr view 5 --json headRefOid -q .headRefOid); gh pr merge 5 --match-head-commit $sha",
    "state=$(gh pr view 5 --json mergeStateStatus -q .mergeStateStatus) && gh pr merge 5",
    # polling loops that only read the pull request
    "until gh pr checks 5 | grep -q pass; do sleep 10; done; gh pr merge 5",
    "while ! gh pr view 5 --json state -q .state; do sleep 5; done; gh pr merge 5",
    'until [ "$(gh pr view 5 --json mergeStateStatus -q .mergeStateStatus)" = CLEAN ]; do sleep 10; done; gh pr merge 5',
    "for i in 1 2 3; do gh pr view 5 --json state; sleep 5; done; gh pr merge 5",
    "for i in 1 2 3\ndo\n  gh pr checks 5\n  sleep 5\ndone\ngh pr merge 5",
    "gh api repos/o/r/pulls/5/reviews && gh api -X PUT repos/o/r/pulls/5/merge",
]


@pytest.mark.parametrize("command", SAFE_SAME_LINE)
def test_a_read_of_the_same_pull_request_earlier_in_the_command_line_counts(command):
    assert _tied(command) is True
    assert _flags([command]) == [True]


@pytest.mark.parametrize("command", SAFE_SAME_LINE)
def test_the_same_command_line_does_not_check_a_merge_of_another_pull_request(command):
    other = command.replace("5", "6", 1)  # the read changes, the merge does not
    assert _tied(other) is False


UNCHECKED_SAME_LINE = [
    "gh pr merge 5; gh pr view 5",  # the read comes after
    "gh pr view 5 | gh pr merge 5",  # a read piped into the merge runs with it
    "git log -1; gh pr merge 5",
    "ls && gh pr merge 5",
    "pytest -q && gh pr merge 5",
    "gh pr view 5 > f; gh pr merge 5",
    "gh pr view 5; export PATH=./bin:$PATH; gh pr merge 5",
    "PATH=./bin; gh pr view 5; gh pr merge 5",
    "gh pr view 5; python3 x.py; gh pr merge 5",
    "gh pr view 5; git commit -m x; gh pr merge 5",
    "gh pr view 5; ./check.sh; gh pr merge 5",
    # a read inside a substitution or loop that does anything else
    "gh pr merge 5 --match-head-commit $(gh pr view 5 > f)",
    "gh pr merge 5 --match-head-commit $(gh pr view 5; rm -rf x)",
    "gh pr merge 5 --match-head-commit $(echo $(gh pr view 5))",
    "gh pr merge 5 $(git push origin main)",
    "x=$(rm -rf y); gh pr view 5; gh pr merge 5",
    "x=$(gh pr view 5; python3 -c 1); gh pr merge 5",
    "while ! gh pr view 5 --json state; do git push origin main; done; gh pr merge 5",
    "until gh pr checks 5; do ./wait.sh; done; gh pr merge 5",
    "until gh pr checks 5; do sleep 5; echo x > f; done; gh pr merge 5",
    "until gh pr checks 5; do cd /tmp; done; gh pr merge 5",
    "for i in 1 2; do gh pr view 5; gh pr merge 5; done",
    "for i in 1 2; do gh pr view 5; done > f; gh pr merge 5",
    "for i in $(rm -rf x); do gh pr view 5; done; gh pr merge 5",
    "while true; do for j in 1; do gh pr view 5; done; done; gh pr merge 5",
    "gh pr view 5; PATH=./evil gh pr merge 5",
    "gh pr view 5; echo `rm -rf x`; gh pr merge 5",
    "gh pr view 5; (gh pr merge 5)",
    "gh pr view 5 &\ngh pr merge 5",
    "for i in 1 2; do gh pr view 5; sleep 1; gh pr merge 5",  # no done
    "gh pr view 5; cat <<EOF\nx\nEOF\ngh pr merge 5",
]


@pytest.mark.parametrize("command", UNCHECKED_SAME_LINE)
def test_a_read_that_is_not_plainly_a_read_of_that_pull_request_never_checks_a_merge(command):
    assert _tied(command) is not True, command
    assert _flags([command])[-1] is False, command


def test_a_read_in_an_earlier_unknown_looking_step_counts_only_if_it_is_only_reads():
    loop = "until gh pr checks 5 | grep -q pass; do sleep 5; done"
    assert _flags([loop, "gh pr merge 5"]) == [False, True]
    assert command_pr_reads(loop) == {("", "5")}
    # The same loop with a write in it reads nothing for later steps.
    risky = "until gh pr checks 5 | grep -q pass; do git push origin x; done"
    assert command_pr_reads(risky) == set()
    assert _flags([risky, "gh pr merge 5"])[-1] is False
    assert _flags(["gh pr view 5; rm -rf x", "gh pr merge 5"])[-1] is False


def test_a_write_hidden_in_a_loop_or_substitution_is_found_as_its_own_write_kind():
    assert classify_command("while ! gh pr view 3 --json state; do git push origin main; done") == (
        "git_push",
        "main_branch",
    )
    assert classify_command("for i in 1 2; do rm -rf build; done")[0] == "delete"
    assert classify_command("until gh pr checks 3; do vercel --prod; done")[0] == "deploy"
    assert classify_command("if ls; then git push origin main; fi") == ("git_push", "main_branch")
    assert classify_command("echo $(gh pr merge 3)")[0] == "merge"
    assert classify_command("x=$(git push origin main)") == ("git_push", "main_branch")
    # A loop on its own is never a check, however harmless its parts are.
    for loop in (
        "for i in 1 2; do ls; done",
        "while true; do ls; done",
        "until gh pr checks 3; do sleep 5; done",
        "if ls; then ls; fi",
    ):
        assert classify_command(loop)[0] not in CHECK_KINDS, loop


# --------------------------------------------------------------------------- #
# Property: a dangerous part hidden in a substitution or a loop body
# --------------------------------------------------------------------------- #

_HIDDEN_WRITES = [
    "rm -rf x",
    "git push origin main",
    "gh pr merge 3",
    "vercel --prod",
    "curl -X POST https://example.com/u -d a=b",
]
_PARTS = [p for p in DANGEROUS_PARTS if "\n" not in p and "<<" not in p]


def _contexts(check: str, part: str) -> list[str]:
    return [
        f"echo $({part})",
        f"x=$({part})",
        f"{check} $({part})",
        f"for i in a b; do {part}; done",
        f"for i in a b; do {check}; {part}; done",
        f"while {check}; do {part}; done",
        f"until {check}; do {part}; sleep 1; done",
        f"{check}; while true; do {part}; done",
        f"while {part}; do sleep 1; done",
        f"if {check}; then {part}; fi",
    ]


def test_a_dangerous_part_hidden_in_a_substitution_or_loop_is_never_a_check():
    for check in ALLOWLISTED_CHECKS[:15]:
        for part in _PARTS:
            for command in _contexts(check, part):
                assert classify_command(command)[0] not in CHECK_KINDS, repr(command)


def test_a_write_hidden_in_a_substitution_or_loop_keeps_its_own_kind():
    for check in ALLOWLISTED_CHECKS[:15]:
        for part in _HIDDEN_WRITES:
            own = classify_command(part)
            for command in _contexts(check, part):
                assert classify_command(command)[0] == own[0], repr(command)


def test_a_dangerous_part_in_a_substitution_or_loop_never_lets_a_read_check_a_merge():
    read = "gh pr view 3 --json state"
    for part in _PARTS:
        for command in (
            f"x=$({read}; {part}); gh pr merge 3",
            f"gh pr merge 3 --match-head-commit $({read}; {part})",
            f"gh pr merge 3 --match-head-commit $({read} | {part})",
            f"while ! {read}; do {part}; done; gh pr merge 3",
            f"until {read}; do {part}; sleep 1; done; gh pr merge 3",
            f"for i in 1 2; do {read}; {part}; done; gh pr merge 3",
            f"for i in 1 2; do {part}; {read}; done; gh pr merge 3",
        ):
            assert _tied(command) is not True, repr(command)
            assert command_pr_reads(command) == set(), repr(command)


# --------------------------------------------------------------------------- #
# Bookkeeping that clears reads, and the redacted copy
# --------------------------------------------------------------------------- #


def test_every_pull_request_a_command_names_is_cleared_by_an_outside_step_on_it():
    assert command_pr_refs("gh pr merge 5 && gh pr comment 6 -b x") == {("", "5"), ("", "6")}
    assert command_pr_refs("git push origin main") == set()
    # A review on a pull request is an outside step on it, so it ends the scope of a read.
    assert _flags(["gh pr view 5", "gh pr review 5 --approve -b ok", "gh pr merge 5"])[-1] is False
    # A comment is housekeeping (low risk): it neither fires nor ends the scope of a read.
    assert _flags(["gh pr view 5", "gh pr comment 5 -b ok", "gh pr merge 5"])[-1] is True


@pytest.mark.parametrize(
    "commands",
    [
        ["gh pr view 1", "gh pr merge 1"],
        ["gh pr view 2", "gh pr merge 1"],
        ["until gh pr checks 5 | grep -q pass; do sleep 5; done", "gh pr merge 5"],
        ["gh pr merge 5 --match-head-commit $(gh pr view 5 --json headRefOid -q .headRefOid)"],
        ["gh pr view 1", "gh pr merge 1", "gh pr merge 1"],
        ["gh pr create --title t --body b", "gh pr merge 3"],
    ],
)
def test_the_redacted_copy_gives_the_same_flags_as_the_first_analysis(commands):
    steps = [(c, f"c{i}", False) for i, c in enumerate(commands)]
    first = analyse_run(claude_code(steps), format="claude_code")
    again = analyse_run(json.dumps(first.redacted_transcript), format="claude_code")

    def flags(run: Any) -> list[bool]:
        return [
            block["step_facts"]["checked_before"]
            for record in run.redacted_transcript["events"]
            for block in record.get("message", {}).get("content", [])
            if isinstance(block, dict) and "step_facts" in block
        ]

    assert flags(first) == flags(again)


def test_nothing_but_the_boolean_leaves():
    steps = [
        ("gh pr view 12345", "c0", False),
        ("gh pr merge 12345 -R secret-org/secret-repo", "c1", False),
    ]
    run = analyse_run(claude_code(steps), format="claude_code")
    dumped = json.dumps(run.redacted_transcript) + json.dumps(run.redaction_manifest)
    for fragment in ("12345", "secret-org", "secret-repo"):
        assert fragment not in dumped
    facts = [
        block["step_facts"]
        for record in run.redacted_transcript["events"]
        for block in record.get("message", {}).get("content", [])
        if isinstance(block, dict) and "step_facts" in block
    ]
    assert all(
        set(f) == {"command_kind", "target_kind", "exit_status", "checked_before", "error_class"}
        for f in facts
    )


# --------------------------------------------------------------------------- #
# Review round 1: other outside steps keep the scoped rule exactly as before
# --------------------------------------------------------------------------- #

# Non merge outside steps whose command the pull request reader cannot parse: a file redirect,
# a subshell, brackets, a lone & and a comment. A check in an earlier step must still count.
UNPARSEABLE_OUTSIDE = [
    "vercel --prod > deploy.log",
    "(cd app && vercel --prod)",
    "[ -f app/package.json ] && vercel --prod",
    "[[ -f x ]] && git push origin main",
    "vercel --prod &",
    "git push origin main # ship it",
    "git push origin main > push.log",
    "gh pr review 5 --approve -b done > out.txt",
    "{ vercel --prod; }",
    "if ls; then git push origin main; fi",
    "if [ -f x ]; then vercel --prod; fi",
    "for i in 1; do vercel --prod; done",
    "while true; do git push origin main; done",
    "echo $(vercel --prod)",
    "x=`vercel --prod`",
    "git push origin main <<EOF\nx\nEOF",
]


@pytest.mark.parametrize("command", UNPARSEABLE_OUTSIDE)
def test_a_non_merge_outside_step_keeps_the_scoped_rule_whatever_its_command_looks_like(command):
    kind = classify_command(command)[0]
    assert kind in {"deploy", "git_push", "outside_write"}, (command, kind)
    assert merge_tied_check(command, NONE, command_kind=kind) is None
    # A check in an earlier step counts for it, and without one it is not checked.
    assert _flags(["ls", command]) == [False, True], command
    assert _flags(["git status", command]) == [False, True], command
    assert _flags(["gh pr view 1", command]) == [False, True], command


@pytest.mark.parametrize(
    "kind", ["deploy", "git_push", "delete", "outside_write", "unknown", "read_only"]
)
def test_the_tie_does_not_apply_to_any_step_that_is_not_a_merge(kind):
    for command in ("vercel --prod", "ls; vercel --prod", "(vercel --prod)", ""):
        assert merge_tied_check(command, NONE, command_kind=kind) is None


def test_a_merge_in_a_command_it_cannot_parse_is_not_checked():
    # The scoped rule would let a local read excuse it, so it stays unchecked.
    for command in (
        "ls; (gh pr merge 5)",
        "ls && [ -f x ] && gh pr merge 5",
        "gh pr view 5; gh pr merge 5 > log",
    ):
        assert classify_command(command)[0] == "merge", command
        assert _tied(command) is False, command
        assert _flags([command])[-1] is False, command


def test_a_write_in_an_if_block_is_found_as_its_kind_and_an_earlier_check_still_counts():
    block = "if ls; then git push origin main; fi"
    assert classify_command(block) == ("git_push", "main_branch")
    # Both ways: with a check in an earlier step it is checked ...
    assert _flags(["ls", "if [ -f x ]; then git push origin main; fi"]) == [False, True]
    assert _flags(["pytest -q", "if true; then vercel --prod; fi"]) == [False, True]
    assert _flags(["ls", block]) == [False, True]
    # ... and with nothing before it, and a condition that is not a check, it is not.
    assert _flags(["if true; then git push origin main; fi"]) == [False]
    assert _flags(["if true; then vercel --prod; fi"]) == [False]
    assert _flags(["git commit -m x", "if true; then git push origin main; fi"]) == [False, False]
    # A condition that is a check counts as one, as it does for any command line.
    assert _flags([block]) == [True]
    assert _fires(["if true; then git push origin main; fi"])
    assert not _fires(["ls", "if true; then git push origin main; fi"])


def test_a_stale_read_does_not_survive_a_merge_written_in_another_repository_form():
    assert _flags(["gh pr view 5", "gh pr merge 5 -R o/r", "gh pr merge 5"])[-1] is False
    assert _flags(["gh pr view 5 -R o/r", "gh pr merge 5", "gh pr merge 5 -R o/r"])[-1] is False
    assert (
        _flags(["gh pr view 5 -R o/r", "gh pr merge 5 -R o/r", "gh pr merge 5 -R o/r"])[-1] is False
    )
    assert _flags(["gh pr view 5", "gh pr merge 5", "gh pr merge 5"])[-1] is False
    # A merge of another number leaves it alone.
    assert _flags(["gh pr view 5", "gh pr merge 6 -R o/r", "gh pr merge 5"])[-1] is True
    # Two different repositories stay apart for the check itself.
    assert _flags(["gh pr view 5 -R a/b", "gh pr merge 5 -R c/d"])[-1] is False


def test_clearing_reads_matches_the_same_or_an_unknown_repository():
    reads = {("", "5"), ("o/r", "5"), ("x/y", "5"), ("", "6")}
    assert clear_reads(reads, {("o/r", "5")}) == {("x/y", "5"), ("", "6")}
    assert clear_reads(reads, {("", "5")}) == {("", "6")}
    assert clear_reads(reads, {("o/r", "7")}) == reads
    assert clear_reads(set(), {("", "5")}) == set()


def test_the_unsafe_analysis_cannot_be_changed_by_a_caller():
    import dataclasses

    assert isinstance(_UNSAFE.reads, frozenset) and isinstance(_UNSAFE.sub_reads, frozenset)
    with pytest.raises(dataclasses.FrozenInstanceError):
        _UNSAFE.state = "safe"  # type: ignore[misc]
    leaked = set(_UNSAFE.reads)
    leaked.add(("", "1"))
    assert not _UNSAFE.reads


# --------------------------------------------------------------------------- #
# A merge chained with another write is decided by the write parts, not the step's kind
# --------------------------------------------------------------------------- #


def test_a_merge_chained_with_a_deploy_is_not_checked_by_an_unrelated_read():
    assert _flags(["ls", "gh pr merge 5 && vercel --prod"])[-1] is False
    assert _flags(["pytest -q", "gh pr merge 5; vercel --prod"])[-1] is False
    assert _flags(["git status", "gh pr merge 5 || vercel --prod"])[-1] is False
    # A read of the same pull request still checks it, and the deploy keeps the scoped rule.
    assert _flags(["gh pr view 5", "gh pr merge 5 && vercel --prod"])[-1] is True
    # The deploy alone keeps the scoped rule.
    assert _flags(["ls", "vercel --prod"]) == [False, True]


def test_a_merge_after_another_write_in_the_same_step_is_still_tied():
    assert _flags(["ls", "vercel --prod && gh pr merge 5"])[-1] is False
    assert _flags(["ls", "git push origin main; gh pr merge 5"])[-1] is False
    assert _flags(["gh pr view 5", "vercel --prod && gh pr merge 5"])[-1] is True
    # Every merge among the write parts must be tied, to its own pull request.
    assert _flags(["gh pr view 5", "gh pr merge 5 && gh pr merge 6 && vercel --prod"])[-1] is False
    assert _flags(["gh pr view 5", "gh pr view 6", "gh pr merge 5; gh pr merge 6; vercel --prod"])[
        -1
    ] is True


def test_a_merge_chained_with_a_push_or_a_delete_is_tied_too():
    assert _flags(["ls", "gh pr merge 5 && git push origin main"])[-1] is False
    assert _flags(["ls", "gh pr merge 5; gh api -X DELETE repos/o/r/git/refs/heads/x"])[-1] is False
    assert _flags(["gh pr view 5", "gh pr merge 5 && git push origin main"])[-1] is True


def test_the_merge_tie_in_a_chain_is_read_by_the_write_parts_of_the_step():
    for command, reads, expected in (
        ("gh pr merge 5 && vercel --prod", NONE, False),
        ("gh pr merge 5 && vercel --prod", frozenset({("", "5")}), None),
        ("vercel --prod && gh pr merge 5", frozenset({("", "5")}), None),
        ("gh pr merge 5", frozenset({("", "5")}), True),
        ("gh pr merge 5", NONE, False),
        ("gh pr merge 5 && gh pr merge 5", frozenset({("", "5")}), False),
        ("vercel --prod", NONE, None),
    ):
        assert merge_tied_check(command, reads, command_kind="deploy") == expected, command


def test_a_chain_this_reader_cannot_parse_is_unchecked_only_if_it_mentions_a_merge():
    assert merge_tied_check("(vercel --prod; gh pr merge 5)", NONE, command_kind="deploy") is False
    assert merge_tied_check("(vercel --prod)", NONE, command_kind="deploy") is None


# --------------------------------------------------------------------------- #
# Housekeeping that changes what gets merged clears an earlier read of that pull request
# --------------------------------------------------------------------------- #

HEAD_CHANGING = [
    "gh pr update-branch 5",
    "gh pr update-branch 5 --rebase",
    "gh pr edit 5 --base release",
    "gh pr edit 5 -B release",
    "gh pr edit 5 --title t --base=release",
    "gh api -X PUT repos/o/r/pulls/5/update-branch",
    "gh api -X PATCH repos/o/r/pulls/5 -f base=release",
    "gh pr view 5 && gh pr update-branch 5",
]


@pytest.mark.parametrize("command", HEAD_CHANGING)
def test_a_step_that_changes_the_head_or_base_clears_an_earlier_read(command: str):
    assert _flags(["gh pr view 5", command, "gh pr merge 5"])[-1] is False


@pytest.mark.parametrize("command", HEAD_CHANGING[:-1])
def test_a_read_after_the_head_or_base_change_checks_the_merge_again(command: str):
    assert _flags(["gh pr view 5", command, "gh pr view 5", "gh pr merge 5"])[-1] is True


@pytest.mark.parametrize(
    "command",
    [
        "gh pr edit 5 --body x",
        "gh pr edit 5 --title t",
        "gh pr comment 5 --body hi",
        "gh pr ready 5",
        "gh pr close 5",
        "gh pr edit 6 --base release",
        "gh pr update-branch 6",
    ],
)
def test_other_housekeeping_or_another_pull_request_keeps_the_read(command: str):
    assert _flags(["gh pr view 5", command, "gh pr merge 5"])[-1] is True
