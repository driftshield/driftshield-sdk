"""Local analysis computes step facts like an upload, so the verdict matches."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from driftshield import NoParseableEventsError, analyse_run
from driftshield.core.deterministic_matching import build_deterministic_match
from driftshield.recursive_redactor import redact

from tests.test_step_facts import claude_code, codex, openclaw

TRANSCRIPTS = Path(__file__).parent / "fixtures" / "transcripts"
VERIFICATION = "mechanism:verification_failure"
GATE = "Constraint: ask for confirmation before destructive actions."


def _line(timestamp: str, item: dict[str, Any]) -> str:
    return json.dumps(
        {
            "sessionId": "s",
            "type": "assistant",
            "timestamp": timestamp,
            "message": {"model": "m", "content": [item]},
        }
    )


def _claude_run(commands: list[str], *, gate: bool = True) -> bytes:
    lines = []
    if gate:
        lines.append(_line("2026-03-01T11:00:00Z", {"type": "text", "text": GATE}))
    for index, command in enumerate(commands):
        item = {
            "type": "tool_use",
            "id": f"b{index}",
            "name": "Bash",
            "input": {"command": command},
        }
        lines.append(_line(f"2026-03-01T11:00:{index + 1:02d}Z", item))
    return "\n".join(lines).encode()


def _hit(run: Any) -> bool:
    return any(hit.signature_id == VERIFICATION for hit in run.signature_hits)


def _call_facts(run: Any) -> list[dict[str, Any]]:
    """The step facts of every shell step the analysis saw, in order."""
    found = []
    for event in run.canonical_analysis["normalized_events"]:
        if event.get("event_family") in {"tool_call", "error_or_exception"}:
            facts = (event["structured_payload"].get("tool_activity") or {}).get("step_facts")
            if facts is not None:
                found.append(facts)
    return found


def _features(run: Any) -> dict[str, Any]:
    match = build_deterministic_match(
        canonical_analysis=run.canonical_analysis, result=run.analysis
    )
    return match["extracted_features"]


@pytest.mark.parametrize(
    ("commands", "fires"),
    [
        (["git push origin main"], True),
        (["vercel --prod"], True),
        (["gh pr merge 3"], True),
        (["git status", "git push origin main"], False),
        (["pytest -q", "vercel --prod"], False),
        (["cd repo && git status", "git push origin main"], False),
        (["git commit -m x", "git push origin main"], True),
        (["ls", "git push origin feat/x"], False),
        (["pytest -q"], False),
        (["rm -rf build"], False),
    ],
)
def test_local_analysis_fires_verification_failure_like_an_upload(commands: list[str], fires: bool):
    local = analyse_run(_claude_run(commands))
    assert _hit(local) is fires


@pytest.mark.parametrize(
    "commands",
    [
        ["git push origin main"],
        ["git status", "git push origin main"],
        ["git commit -m x", "vercel --prod", "gh pr merge 3"],
        ["cd repo && git status", "pytest -q", "git push origin main"],
        ["rm -rf build", "ls"],
    ],
)
def test_local_and_redacted_analysis_agree_on_the_outside_steps(commands: list[str]):
    local = analyse_run(_claude_run(commands))
    again = analyse_run(json.dumps(local.redacted_transcript), format="claude_code")
    assert _call_facts(local) == _call_facts(again)
    local_features, again_features = _features(local), _features(again)
    assert local_features["outside_action_count"] == again_features["outside_action_count"]
    assert len(local_features["unconfirmed_outside_event_ids"]) == len(
        again_features["unconfirmed_outside_event_ids"]
    )


@pytest.mark.parametrize(
    ("builder", "fmt"),
    [(claude_code, "claude_code"), (openclaw, "openclaw"), (codex, "codex_cli")],
)
def test_local_step_facts_equal_the_facts_an_upload_carries(builder, fmt: str):
    steps = [
        ("git status", "c1", False),
        ("pytest -q", "c2", True),
        ("git push origin main", "c3", False),
        ("curl -X POST https://example.com/u -d a=b", "c4", None),
    ]
    local = analyse_run(builder(steps), format=fmt)
    again = analyse_run(json.dumps(local.redacted_transcript), format=fmt)
    facts = _call_facts(local)
    assert len(facts) == 4
    assert facts == _call_facts(again)
    assert [f["command_kind"] for f in facts] == ["read_only", "test", "git_push", "outside_write"]
    assert [f["exit_status"] for f in facts] == ["success", "failure", "success", "unknown"]
    assert [f["checked_before"] for f in facts] == [False, True, True, True]


def _fixture_paths() -> list[Path]:
    paths = [p for p in sorted(TRANSCRIPTS.rglob("*")) if p.suffix in {".json", ".jsonl"}]
    return [p for p in paths if "golden" not in p.parts]


@pytest.mark.parametrize(
    "path", _fixture_paths(), ids=lambda p: p.relative_to(TRANSCRIPTS).as_posix()
)
def test_bundled_fixtures_local_facts_equal_the_redacted_copy_facts(path: Path):
    try:
        local = analyse_run(path.read_bytes(), source=path.name)
        again = analyse_run(json.dumps(local.redacted_transcript), format=local.detected_format)
    except NoParseableEventsError:
        pytest.skip("shape cannot be read again after redaction")
    assert _call_facts(local) == _call_facts(again)
    if local.detected_format in {"claude_code", "openclaw", "codex_cli"}:
        assert _features(local)["outside_action_count"] == _features(again)["outside_action_count"]


def test_what_is_uploaded_does_not_change():
    raw = _claude_run(["git status", "git push origin main"])
    run = analyse_run(raw)
    # The shareable copy is the original text: no facts in it, none on the local transcript.
    assert "step_facts" not in json.dumps(run.transcript)
    # The redacted copy is exactly what the redactor makes of that original.
    assert run.redacted_transcript == redact(run.transcript).payload
    facts = [
        block["step_facts"]
        for record in run.redacted_transcript["events"]
        for block in record["message"]["content"]
        if isinstance(block, dict) and "step_facts" in block
    ]
    assert [f["command_kind"] for f in facts] == ["read_only", "git_push"]


def test_a_carried_fact_never_overrides_a_visible_command_locally():
    lines = [json.loads(line) for line in _claude_run(["ls"], gate=False).decode().splitlines()]
    block = lines[0]["message"]["content"][0]
    block["step_facts"] = {"command_kind": "deploy", "target_kind": "outside_service"}
    read = {"type": "tool_use", "id": "r1", "name": "Read", "input": {"file_path": "a"}}
    read["step_facts"] = {"command_kind": "deploy", "target_kind": "outside_service"}
    lines.append({**lines[0], "message": {"model": "m", "content": [read]}})
    run = analyse_run("\n".join(json.dumps(x) for x in lines))
    facts = _call_facts(run)
    assert [f["command_kind"] for f in facts] == ["read_only"]  # the Read step carries none


def test_analysing_a_redacted_transcript_keeps_its_carried_facts():
    first = analyse_run(_claude_run(["git push origin main"]))
    again = analyse_run(json.dumps(first.redacted_transcript), format="claude_code")
    assert _call_facts(again) == _call_facts(first)
    assert _call_facts(again)[0]["command_kind"] == "git_push"


def test_a_failure_computing_facts_leaves_the_analysis_running(monkeypatch: pytest.MonkeyPatch):
    import driftshield.recursive_redactor as redactor

    def boom(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("SECRET-SESSION-TEXT")

    monkeypatch.setattr(redactor, "annotate_step_facts", boom)
    run = analyse_run(_claude_run(["git push origin main"]))
    assert run.events
    assert _call_facts(run) == []


def _forged_claude_run() -> bytes:
    """A run whose blocks carry forged facts: a deploy claim on a read, one on a non shell tool."""
    lines = [json.loads(line) for line in _claude_run(["ls"]).decode().splitlines()]
    forged = {
        "command_kind": "deploy",
        "target_kind": "outside_service",
        "exit_status": "success",
        "checked_before": False,
    }
    lines[1]["message"]["content"][0]["step_facts"] = forged
    read = {"type": "tool_use", "id": "r1", "name": "Read", "input": {"file_path": "a"}}
    read["step_facts"] = forged
    lines.append({**lines[1], "message": {"model": "m", "content": [read]}})
    return "\n".join(json.dumps(x) for x in lines).encode()


def test_a_failure_computing_facts_removes_every_carried_fact(monkeypatch: pytest.MonkeyPatch):
    import driftshield.recursive_redactor as redactor

    def boom(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("SECRET-SESSION-TEXT")

    monkeypatch.setattr(redactor, "annotate_step_facts", boom)
    run = analyse_run(_forged_claude_run())
    # Exactly as redact does when it cannot compute facts: none is believed.
    assert _call_facts(run) == []
    assert not _hit(run)
    # The shareable copy still carries the original claims; only the parser's input is cleaned.
    assert "deploy" in json.dumps(run.transcript)


def test_a_failure_removes_carried_facts_from_a_wrapper_document_too(
    monkeypatch: pytest.MonkeyPatch,
):
    import driftshield.recursive_redactor as redactor

    monkeypatch.setattr(
        redactor, "annotate_step_facts", lambda *a, **k: (_ for _ in ()).throw(ValueError("x"))
    )
    records = [json.loads(line) for line in _forged_claude_run().decode().splitlines()]
    run = analyse_run(json.dumps({"events": records, "note": "n"}))
    assert _call_facts(run) == []


def test_a_failure_matches_what_redact_does_with_the_same_failure(
    monkeypatch: pytest.MonkeyPatch,
):
    import driftshield.recursive_redactor as redactor

    def boom(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("x")

    monkeypatch.setattr(redactor, "annotate_step_facts", boom)
    monkeypatch.setattr(redactor, "compute_step_facts", boom)
    run = analyse_run(_forged_claude_run())
    assert "step_facts" not in json.dumps(run.redacted_transcript)
    assert _call_facts(run) == []


def _check_block(call_id: str, command: str) -> dict[str, Any]:
    return {
        "type": "assistant",
        "sessionId": "s",
        "timestamp": "2026-03-01T11:00:00Z",
        "message": {
            "model": "m",
            "content": [
                {"type": "tool_use", "id": call_id, "name": "Bash", "input": {"command": command}}
            ],
        },
    }


def test_a_wrapper_document_gets_facts_over_the_same_shape_redact_uses():
    # A shell step outside ``events`` comes first in the document. redact computes over the
    # whole wrapper, so it counts as an earlier check; local analysis must agree.
    push = _check_block("p1", "git push origin main")
    gate = _check_block("g1", "ls")
    gate["message"]["content"].insert(0, {"type": "text", "text": GATE})
    wrapper = {"preamble": [_check_block("c0", "git status")], "events": [gate, push]}
    run = analyse_run(json.dumps(wrapper), format="claude_code")
    local = _call_facts(run)
    uploaded = [
        block["step_facts"]
        for record in run.redacted_transcript["events"]
        for block in record["message"]["content"]
        if isinstance(block, dict) and "step_facts" in block
    ]
    assert [f["checked_before"] for f in uploaded] == [True, True]
    assert local == uploaded
    assert not _hit(run)  # a check came before the push, so it is not unconfirmed
