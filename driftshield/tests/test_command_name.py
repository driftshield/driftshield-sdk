"""``command_name`` step fact: the program and subcommand a step ran, never an argument."""

from __future__ import annotations

import json
from typing import Any

import pytest

from driftshield import analyse_run
from driftshield.step_facts import classify_command, sanitise_step_facts
from driftshield.step_facts_command_name import (
    COMMAND_NAME_SHAPE,
    checked_command_name,
    shell_command_name,
    tool_command_name,
)
from driftshield.tool_map import tool_map_from_dict
from tests.test_step_facts import claude_code


def name(command: str) -> str:
    return shell_command_name(command, classify_command(command)[0])


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("gh pr merge 12 --squash", "gh pr merge"),
        ("gh pr view 7 --json reviews", "gh pr view"),
        ("gh api repos/o/r/pulls/3/merge -X PUT", "gh api"),
        ("git push origin main", "git push"),
        ("git push --force origin feat/x", "git push"),
        ("git worktree add ../wt -b feat/x origin/main", "git worktree add"),
        ("pytest -q tests/test_a.py", "pytest"),
        ("npm test", "npm test"),
        ("npm run build", "npm run build"),
        ("uv run pytest tests/x.py", "pytest"),
        ("python -m pytest tests", "pytest"),
        ("docker compose up -d", "docker compose up"),
        ("kubectl -n prod delete pod web-1", "kubectl delete"),
        ("aws --profile prod cloudformation describe-stacks", "aws cloudformation describe-stacks"),
        ("/usr/bin/git status", "git status"),
        ("sleep 5; gh pr checks 3", "gh pr checks"),
    ],
)
def test_names_keep_program_and_subcommand_only(command: str, expected: str) -> None:
    assert name(command) == expected


SECRET = "sk-live-4f9a8b7c6d5e4f3a2b1c"


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        # secrets in environment assignments, flags, bodies and URLs
        (f"GITHUB_TOKEN={SECRET} gh pr merge 5", "gh pr merge"),
        (f"env API_KEY={SECRET} curl https://api.example.com", "curl"),
        (f"curl -H 'Authorization: Bearer {SECRET}' https://x.example/a?token={SECRET}", "curl"),
        (f"git commit -m 'rotate {SECRET}'", "git commit"),
        (f"export TOKEN={SECRET}", "export"),
        # paths and directories
        ("cd /Users/someone/private-repo && git push", "git push"),
        ("cd ~/clients/acme; ls", "ls"),
        ("git -C /srv/customer-repo push", "git push"),
        ("gh -R acme/secret-repo pr merge 9", "gh pr merge"),
        ("./scripts/deploy-acme.sh prod", "other"),
        ("bin/release --customer acme", "other"),
        ("~/bin/tool run", "other"),
        # heredocs: the body never becomes the name
        (f"cat <<'EOF' > notes.md\n{SECRET}\nacme confidential\nEOF", "cat"),
        (f"python3 - <<EOF\nprint('{SECRET}')\nEOF", "python3"),
        (f"<<EOF\n{SECRET}\nEOF", "other"),
        # pipes and chains: no argument from any part
        (f"echo {SECRET} | gh secret set TOKEN", "gh secret set"),
        ("cat ids.txt | xargs -n1 gh pr close", "cat"),
        ("for pr in 1 2 3; do gh pr merge $pr; done", "gh pr merge"),
        # user chosen words that are not listed subcommands
        ("make acme-secret-target", "make"),
        ("npm run deploy:acme", "npm run"),
        ("git acme-alias", "git"),
        ("gh acme-extension do-thing", "gh"),
        ("aws --profile acme-prod s3 cp f s3://acme-bucket/key", "aws s3 cp"),
        ("aws acmeservice do-x", "aws"),
        # unknown programs, odd case and oversized words
        ("hunter2", "other"),
        ("acmecorp-internal-cli sync", "other"),
        ("GIT push", "other"),
        ("", "other"),
        ("x" * 20_000, "other"),
    ],
)
def test_hostile_commands_leak_nothing_but_the_name(command: str, expected: str) -> None:
    got = name(command)
    assert got == expected
    assert COMMAND_NAME_SHAPE.fullmatch(got)
    for secret_word in (SECRET, "acme", "Users", "someone", "confidential", "token"):
        assert secret_word not in got


def test_a_name_never_has_more_than_three_words() -> None:
    assert len(name("gh pr merge 12 --squash --delete-branch").split()) == 3


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("gh pr merge", "gh pr merge"),
        ("issue_payment", "issue_payment"),
        ("gh pr merge 12", "other"),
        ("git push origin main", "other"),
        ("Git push", "other"),
        ("a/b", "other"),
        ("x" * 33, "other"),
        ("", "other"),
        (None, "other"),
        (12, "other"),
        (" gh", "other"),
        ("gh  pr", "other"),
        ("gh\npr", "other"),
    ],
)
def test_carried_names_are_checked_against_the_shape(value: Any, expected: str) -> None:
    assert checked_command_name(value) == expected
    assert sanitise_step_facts({"command_name": value})["command_name"] == expected


@pytest.mark.parametrize(
    ("tool", "expected"),
    [
        ("issue_payment", "issue_payment"),
        ("Read", "read"),
        ("mcp__github__create_pull_request_review", "other"),  # longer than 32 characters
        ("send email to bob", "other"),
        ("", "other"),
        (None, "other"),
    ],
)
def test_tool_names(tool: Any, expected: str) -> None:
    assert tool_command_name(tool) == expected


def _facts(run: Any) -> list[dict[str, Any]]:
    return [
        block["step_facts"]
        for record in run.redacted_transcript["events"]
        for block in record.get("message", {}).get("content", [])
        if isinstance(block, dict) and "step_facts" in block
    ]


def test_redacted_upload_carries_the_name_and_none_of_the_arguments() -> None:
    commands = [
        f"cd /Users/someone/acme && GITHUB_TOKEN={SECRET} gh pr merge 41 --squash",
        f"git commit -m 'acme {SECRET}'",
        "pytest -q tests/test_acme.py",
        f"cat <<EOF\n{SECRET}\nEOF",
    ]
    run = analyse_run(
        claude_code([(c, f"c{i}", False) for i, c in enumerate(commands)]), format="claude_code"
    )
    assert [f["command_name"] for f in _facts(run)] == [
        "gh pr merge",
        "git commit",
        "pytest",
        "cat",
    ]
    text = json.dumps(run.redacted_transcript)
    assert SECRET not in text
    assert "acme" not in text


def test_reanalysing_a_redacted_copy_keeps_the_names() -> None:
    commands = ["gh pr merge 41", "git push origin main", "npm test"]
    first = analyse_run(
        claude_code([(c, f"c{i}", False) for i, c in enumerate(commands)]), format="claude_code"
    )
    again = analyse_run(json.dumps(first.redacted_transcript), format="claude_code")
    assert [f["command_name"] for f in _facts(again)] == ["gh pr merge", "git push", "npm test"]


def test_mapped_and_failed_tool_steps_carry_their_tool_name() -> None:
    tool_map = tool_map_from_dict({"tools": {"issue_payment": "outside_write"}})
    records: list[dict[str, Any]] = [
        {
            "type": "user",
            "sessionId": "s1",
            "timestamp": "2026-09-01T09:00:00.000Z",
            "message": {"role": "user", "content": "pay"},
        },
        {
            "type": "assistant",
            "sessionId": "s1",
            "timestamp": "2026-09-01T09:01:00.000Z",
            "message": {
                "role": "assistant",
                "model": "m",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "c1",
                        "name": "issue_payment",
                        "input": {"claim": f"acme {SECRET}"},
                    }
                ],
            },
        },
    ]
    run = analyse_run(
        "\n".join(json.dumps(r) for r in records), format="claude_code", tool_map=tool_map
    )
    assert [f["command_name"] for f in _facts(run)] == ["issue_payment"]
    assert SECRET not in json.dumps(run.redacted_transcript)
