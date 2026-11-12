"""driftshield capture: settings, scope gate, scrub and dry run. All synthetic."""

from __future__ import annotations

import dataclasses
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from driftshield.capture import dry_run
from driftshield.capture.config import CONFIG_ENV, CaptureSettings, load_settings, template
from driftshield.capture.scope import (
    DENIED,
    NOT_ALLOWED,
    OFF,
    ScopeGate,
    decide_folders,
)
from driftshield.capture.scrub import BlockedTerms
from driftshield.capture.sessions import read_claude, read_codex
from driftshield.cli.main import app

runner = CliRunner()


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def claude_lines(cwd: str, session: str = "s1", *, finished: bool = True, sidechain: bool = False) -> str:
    def rec(kind: str, content: Any, **extra: Any) -> dict[str, Any]:
        return {
            "type": kind,
            "sessionId": session,
            "cwd": cwd,
            "isSidechain": sidechain,
            "timestamp": "2026-11-01T10:00:00.000Z",
            "message": {"role": kind, "content": content, **extra},
            **({"uuid": f"{kind}-1"}),
        }

    records = [rec("user", "please tidy the readme")]
    if finished:
        records.append(rec("assistant", [{"type": "text", "text": "done"}], model="test-model"))
    else:
        records.append(rec("assistant", [{"type": "tool_use", "id": "t1", "name": "Read", "input": {}}]))
    return "\n".join(json.dumps(r) for r in records) + "\n"


def settings_for(root: Path, **overrides: Any) -> CaptureSettings:
    values: dict[str, Any] = dict(
        path=root / "capture.toml",
        enabled=True,
        allow_folders=(str(root / "work" / "project"),),
        deny_folders=(str(root / "work" / "project" / "private"),),
        claude_profiles=(str(root / "profile"),),
        codex_sessions=str(root / "codex"),
    )
    values.update(overrides)
    return CaptureSettings(**values)


# --- settings file ---------------------------------------------------------------------------


def test_missing_file_means_off(tmp_path: Path) -> None:
    settings = load_settings(tmp_path / "capture.toml")
    assert settings.missing and not settings.active


def test_template_parses_and_starts_off(tmp_path: Path) -> None:
    settings = load_settings(_write(tmp_path / "capture.toml", template()))
    assert settings.invalid is None
    assert settings.enabled is False
    assert settings.allow_folders == ()
    assert settings.agent_id("claude-code") == "driftshield-capture:claude-code"


def test_full_file_loads(tmp_path: Path) -> None:
    (tmp_path / "repos" / "secret-repo").mkdir(parents=True)
    (tmp_path / "repos" / "tools").mkdir()
    text = f"""
enabled = true
workspace = "ws"
project = "org/proj"
[allow]
folders = ["{tmp_path / 'work'}"]
[deny]
folders = ["{tmp_path / 'work' / 'private'}"]
[sources]
main_idle_minutes = 5
[scrub]
terms = ["acme"]
terms_from_folders = ["{tmp_path / 'repos'}"]
ignore = ["tools"]
hold_over = 2
[upload]
agent_id_prefix = "my-capture"
"""
    settings = load_settings(_write(tmp_path / "capture.toml", text))
    assert settings.invalid is None and settings.active
    assert settings.allow_folders == (str(tmp_path / "work"),)
    assert settings.blocked.terms == ("acme",)
    assert settings.blocked.folder_terms == ("secret-repo",)
    assert settings.main_idle_seconds == 300
    assert settings.agent_id("codex") == "my-capture:codex"
    shown = json.dumps(settings.to_dict()) + "\n".join(settings.describe())
    assert "acme" not in shown and "secret-repo" not in shown


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ('level = "full"', "level"),
        ("colour = 1", "unknown key"),
        ("enabled = 1", "enabled"),
        ('[allow]\nfolders = ["relative"]', "absolute"),
        ('[allow]\nfolders = ["~"]', "home folder"),
        ('[allow]\nfolders = ["/"]', "home folder"),
        ('[deny]\nfolders = ["relative"]', "absolute"),
        ("[sources]\nmain_idle_minutes = 0", "main_idle_minutes"),
        ('[scrub]\nterms = ["blocked"]\ntoken = "[blocked]"', "token"),
        ('[upload]\nagent_id_prefix = "Has Spaces"', "agent_id_prefix"),
        ('project = "no-slash"', "project"),
        ("not toml [", "not TOML"),
    ],
)
def test_bad_values_turn_capture_off(tmp_path: Path, text: str, expected: str) -> None:
    settings = load_settings(_write(tmp_path / "capture.toml", text + "\n"))
    assert settings.invalid is not None and expected in settings.invalid
    assert not settings.active


# --- scope gate --------------------------------------------------------------------------------


def test_allowed_denied_and_outside(tmp_path: Path) -> None:
    settings = settings_for(tmp_path)
    project = tmp_path / "work" / "project"
    assert decide_folders(settings, [str(project / "sub")]).allowed
    assert decide_folders(settings, [str(project / "private" / "x")]).reason == DENIED
    assert decide_folders(settings, [str(tmp_path / "elsewhere")]).reason == NOT_ALLOWED


def test_off_refuses_everything(tmp_path: Path) -> None:
    settings = settings_for(tmp_path, enabled=False)
    assert decide_folders(settings, [str(tmp_path / "work" / "project")]).reason == OFF


def test_one_bad_folder_refuses_the_session(tmp_path: Path) -> None:
    settings = settings_for(tmp_path)
    project = tmp_path / "work" / "project"
    verdict = decide_folders(settings, [str(project), str(tmp_path / "elsewhere")])
    assert not verdict.allowed and "2 of 2" in verdict.detail


def test_symlink_out_of_an_allowed_folder_is_refused(tmp_path: Path) -> None:
    settings = settings_for(tmp_path)
    (tmp_path / "work" / "project").mkdir(parents=True)
    (tmp_path / "elsewhere").mkdir()
    link = tmp_path / "work" / "project" / "link"
    os.symlink(tmp_path / "elsewhere", link)
    assert not decide_folders(settings, [str(link)]).allowed


def test_transcript_outside_profiles_or_in_denied_folder_is_never_opened(tmp_path: Path) -> None:
    settings = settings_for(tmp_path, deny_folders=(str(tmp_path / "other-profile"),))
    gate = ScopeGate(settings)
    outside = _write(tmp_path / "loose" / "s.jsonl", "not json")
    denied = _write(tmp_path / "other-profile" / "projects" / "x" / "s.jsonl", "not json")
    assert gate.check_path("claude_code", outside)[0].reason == "outside_claude_profiles"
    assert gate.check_path("claude_code", denied)[0].reason == DENIED


def test_subagent_follows_its_parent(tmp_path: Path) -> None:
    settings = settings_for(tmp_path)
    gate = ScopeGate(settings)
    project_dir = tmp_path / "profile" / "projects" / "p"
    allowed = str(tmp_path / "work" / "project")
    _write(project_dir / "parent.jsonl", claude_lines(str(tmp_path / "elsewhere"), "parent"))
    sub = _write(
        project_dir / "parent" / "subagents" / "agent-a1.jsonl",
        claude_lines(allowed, "parent", sidechain=True),
    )
    decision, session = gate.check_path("claude_code", sub)
    assert session == "agent-a1"
    assert decision.reason == "parent_refused"


# --- session readers --------------------------------------------------------------------------


def test_claude_reader_tracks_turn_state(tmp_path: Path) -> None:
    done = read_claude(_write(tmp_path / "a.jsonl", claude_lines("/x", "a")))
    busy = read_claude(_write(tmp_path / "b.jsonl", claude_lines("/x", "b", finished=False)))
    assert (done.turn_complete, busy.turn_complete) == (True, False)
    assert done.cwds == ["/x"] and done.session_id == "a"


def test_codex_reader_collects_every_cwd(tmp_path: Path) -> None:
    records = [
        {"type": "session_meta", "payload": {"id": "c1", "cwd": "/one"}},
        {"type": "turn_context", "payload": {"cwd": "/two", "model": "m"}},
        {"type": "event_msg", "payload": {"type": "task_complete"}},
    ]
    facts = read_codex(_write(tmp_path / "r.jsonl", "\n".join(json.dumps(r) for r in records)))
    assert facts.cwds == ["/one", "/two"] and facts.turn_complete and facts.session_id == "c1"


# --- scrub ------------------------------------------------------------------------------------


def test_scrub_replaces_hits_in_keys_and_values() -> None:
    blocked = BlockedTerms(terms=("acme",), folder_terms=("widget-api",))
    cleaned, hits = blocked.scrub({"a": "ACME's plan", "acme-key": ["widget-api", {"n": 1}]})
    assert hits == 3 and blocked.count(cleaned) == 0
    assert cleaned["a"] == "[blocked-term]'s plan"


def test_folder_terms_are_whole_words_and_terms_match_word_starts() -> None:
    blocked = BlockedTerms(terms=("acme",), folder_terms=("widget-api",))
    assert blocked.count("widget-apis mywidget-api") == 0
    assert blocked.count("acmes xacme") == 1
    assert blocked.held(4) and not blocked.held(3)


# --- dry run ----------------------------------------------------------------------------------


def test_dry_run_lists_sends_and_skips_and_writes_nothing(tmp_path: Path) -> None:
    allowed = tmp_path / "work" / "project"
    allowed.mkdir(parents=True)
    (tmp_path / "elsewhere").mkdir()
    profile = tmp_path / "profile" / "projects"
    _write(profile / "a" / "s-ok.jsonl", claude_lines(str(allowed), "s-ok"))
    _write(profile / "a" / "s-busy.jsonl", claude_lines(str(allowed), "s-busy", finished=False))
    _write(profile / "b" / "s-out.jsonl", claude_lines(str(tmp_path / "elsewhere"), "s-out"))
    _write(tmp_path / "work" / "project" / "private" / "projects" / "c" / "x.jsonl", "never opened")
    settings = settings_for(tmp_path, enabled=False, project="org/proj")
    before = sorted(p for p in tmp_path.rglob("*"))
    now = datetime.now(timezone.utc)
    rows = dry_run.evaluate(settings, days=14, now=now)
    text = dry_run.render(rows, settings, days=14, now=now)
    after = sorted(p for p in tmp_path.rglob("*"))
    verdicts = {r.session_id: r.verdict for r in rows}
    assert verdicts == {"s-ok": dry_run.WOULD_SEND, "s-busy": "not_finished", "s-out": dry_run.SKIPPED}
    assert before == after
    assert "Would send: **1**" in text
    assert "capture is OFF" in text
    assert "driftshield-capture:claude-code" in text
    assert "never opened: 1" in text


def test_dry_run_ignores_old_sessions(tmp_path: Path) -> None:
    allowed = tmp_path / "work" / "project"
    allowed.mkdir(parents=True)
    old = _write(tmp_path / "profile" / "projects" / "a" / "s.jsonl", claude_lines(str(allowed), "s"))
    stamp = (datetime.now(timezone.utc) - timedelta(days=30)).timestamp()
    os.utime(old, (stamp, stamp))
    assert dry_run.evaluate(settings_for(tmp_path), days=14) == []


def test_scrub_check_holds_sessions_over_the_limit(tmp_path: Path) -> None:
    @dataclasses.dataclass(frozen=True)
    class FakeRun:
        redacted_transcript: dict[str, Any]

    row = dry_run.Row(
        "claude_code", "main", tmp_path / "s.jsonl", datetime.now(timezone.utc), "s", dry_run.WOULD_SEND, "", ""
    )
    _write(row.path, "x")
    settings = settings_for(tmp_path, blocked=BlockedTerms(terms=("acme",), hold_over=1))
    import driftshield.public as public

    texts = iter(["acme once", "acme and acme"])

    def fake(_content: bytes, source: str | None = None) -> FakeRun:
        return FakeRun({"t": next(texts)})

    original = public.analyse_run
    public.analyse_run = fake  # type: ignore[assignment]
    try:
        once, twice = dry_run.check_blocked_terms([row, row], settings)
    finally:
        public.analyse_run = original  # type: ignore[assignment]
    assert (once.verdict, once.hits, once.hits_after) == (dry_run.WOULD_SEND, 1, 0)
    assert (twice.verdict, twice.hits) == (dry_run.HELD, 2)


# --- cli --------------------------------------------------------------------------------------


def test_cli_init_writes_once_and_status_never_shows_terms(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "capture.toml"
    monkeypatch.setenv(CONFIG_ENV, str(target))
    assert runner.invoke(app, ["capture", "init"]).exit_code == 0
    assert runner.invoke(app, ["capture", "init"]).exit_code == 1
    target.write_text(target.read_text().replace("terms = []", 'terms = ["acme"]', 1))
    status = runner.invoke(app, ["capture", "status", "--json"])
    assert status.exit_code == 0
    payload = json.loads(status.stdout)
    assert payload["blocked_terms"]["listed"] == 1
    assert "acme" not in status.stdout


def test_cli_dry_run_refuses_without_settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(CONFIG_ENV, str(tmp_path / "missing.toml"))
    result = runner.invoke(app, ["capture", "dry-run", "--no-scrub-check"])
    assert result.exit_code == 1 and "OFF" in result.stdout
