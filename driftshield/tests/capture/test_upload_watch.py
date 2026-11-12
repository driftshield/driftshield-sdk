"""driftshield capture: ledger, upload with the scrub, watch tick, extensions. Synthetic."""

from __future__ import annotations

import dataclasses
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from driftshield.capture import service as svc
from driftshield.capture.config import CONFIG_ENV, CaptureSettings
from driftshield.capture.ledger import Ledger, content_hash
from driftshield.capture.scope import DENIED, Decision, ScopeGate
from driftshield.capture.scrub import BlockedTerms
from driftshield.capture.service import CaptureService, Held, SendFailed, SendRequest
from driftshield.capture.watch import WINDOW_KEYS, tick
from driftshield.cli.main import app
from tests.capture.test_capture import _write, claude_lines, settings_for

NOW = datetime(2026, 11, 12, 12, 0, tzinfo=timezone.utc)


class FakeSender:
    def __init__(self, error: Exception | None = None) -> None:
        self.requests: list[SendRequest] = []
        self.error = error

    def send(
        self, request: SendRequest, settings: CaptureSettings, key: str
    ) -> tuple[str, str | None]:
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        return f"sub_{len(self.requests)}", "accepted"


def build(
    tmp_path: Path,
    *,
    sender: FakeSender | None = None,
    key: str | None = "key-123456",
    hooks: list[Any] | None = None,
    rules: tuple[Any, ...] = (),
    now: datetime = NOW,
    **overrides: Any,
) -> tuple[CaptureService, FakeSender, Ledger]:
    settings = settings_for(tmp_path, project="org/proj", **overrides)
    ledger = Ledger(tmp_path / "home")
    sender = sender or FakeSender()
    service = CaptureService(
        settings,
        ledger,
        sender=sender,
        gate=ScopeGate(settings, rules),
        after_submit=hooks or [],
        key=lambda: key,
        now=lambda: now,
        project=lambda cwd, fallback: fallback,
    )
    return service, sender, ledger


def session(
    tmp_path: Path, name: str = "s1", *, finished: bool = True, folder: str | None = None
) -> Path:
    cwd = folder or str(tmp_path / "work" / "project")
    Path(cwd).mkdir(parents=True, exist_ok=True)
    return _write(
        tmp_path / "profile" / "projects" / "p" / f"{name}.jsonl",
        claude_lines(cwd, name, finished=finished),
    )


# --- capture ---------------------------------------------------------------------------------


def test_sends_once_with_the_marker_and_project(tmp_path: Path) -> None:
    service, sender, ledger = build(tmp_path)
    path = session(tmp_path)
    first = service.capture_path("claude_code", path)
    second = service.capture_path("claude_code", path)
    assert (first.status, second.status) == ("submitted", "unchanged")
    request = sender.requests[0]
    assert request.agent_id == "driftshield-capture:claude-code"
    assert request.project_reference == "org/proj"
    assert request.workflow_reference == "capture/claude-code/org-proj"
    assert request.source_report_id.startswith("s1@")
    assert len(Ledger(ledger.home).runs["claude_code:s1"]["revisions"]) == 1


def test_refused_and_unfinished_sessions_are_never_sent(tmp_path: Path) -> None:
    service, sender, _ = build(tmp_path)
    outside = session(tmp_path, "out", folder=str(tmp_path / "elsewhere"))
    busy = session(tmp_path, "busy", finished=False)
    assert service.capture_path("claude_code", outside).status == "refused"
    assert service.capture_path("claude_code", busy).status == "not_finished"
    assert sender.requests == []


def test_held_session_is_recorded_and_never_retried(tmp_path: Path) -> None:
    service, sender, ledger = build(tmp_path, sender=FakeSender(Held(9)))
    path = session(tmp_path)
    assert service.capture_path("claude_code", path).status == "held_blocked_terms"
    assert service.capture_path("claude_code", path, force=True).status == "held_blocked_terms"
    assert len(sender.requests) == 1
    item = Ledger(ledger.home).runs["claude_code:s1"]
    assert item["last_decision"]["hits"] == 9 and item["revisions"] == []
    assert [i["key"] for i in Ledger(ledger.home).held()] == ["claude_code:s1"]


def test_failure_backs_off_then_retries(tmp_path: Path) -> None:
    clock = [NOW]
    settings = settings_for(tmp_path)
    ledger = Ledger(tmp_path / "home")
    sender = FakeSender(SendFailed("network", "down"))
    service = CaptureService(
        settings,
        ledger,
        sender=sender,
        gate=ScopeGate(settings, ()),
        after_submit=[],
        key=lambda: "key-123456",
        now=lambda: clock[0],
        project=lambda c, f: f,
    )
    path = session(tmp_path)
    assert service.capture_path("claude_code", path).status == "failed"
    assert service.capture_path("claude_code", path).status == "retry_wait"
    sender.error = None
    clock[0] = NOW + timedelta(seconds=61)
    assert [o.status for _, o in service.retry_due()] == ["submitted"]


def test_missing_key_sends_nothing(tmp_path: Path) -> None:
    service, sender, _ = build(tmp_path, key=None)
    assert service.capture_path("claude_code", session(tmp_path)).status == "api_key_missing"
    assert sender.requests == []


def test_unreadable_ledger_sends_nothing(tmp_path: Path) -> None:
    service, sender, ledger = build(tmp_path)
    ledger.home.mkdir(parents=True)
    ledger.path.write_text("{broken")
    assert service.capture_path("claude_code", session(tmp_path)).status == "ledger_unreadable"
    assert sender.requests == []


def test_old_session_is_marked_backfill(tmp_path: Path) -> None:
    service, sender, _ = build(tmp_path, now=datetime(2026, 11, 20, tzinfo=timezone.utc))
    service.capture_path("claude_code", session(tmp_path))
    assert sender.requests[0].backfill is True


def test_after_submit_hook_runs_and_its_failure_is_swallowed(tmp_path: Path) -> None:
    seen: list[dict[str, Any]] = []

    def broken(_record: dict[str, Any]) -> None:
        raise RuntimeError("boom")

    service, _, _ = build(tmp_path, hooks=[broken, seen.append])
    assert service.capture_path("claude_code", session(tmp_path)).status == "submitted"
    assert seen[0]["submission_id"] == "sub_1" and seen[0]["project_reference"] == "org/proj"


def test_extension_rule_can_allow_but_deny_still_wins(tmp_path: Path) -> None:
    extra = tmp_path / "tool-data" / "thread-1"

    def rule(_settings: CaptureSettings, cwd: str) -> Decision | None:
        if cwd.startswith(str(tmp_path / "tool-data")):
            return Decision(True, "extension", "tool folder for this project")
        return None

    service, sender, _ = build(tmp_path, rules=(rule,))
    assert service.capture_path("claude_code", session(tmp_path, "t1", folder=str(extra))).sent
    denied = tmp_path / "work" / "project" / "private"
    assert (
        service.capture_path("claude_code", session(tmp_path, "t2", folder=str(denied))).reason
        == DENIED
    )
    assert len(sender.requests) == 1


def test_failing_extension_rule_refuses(tmp_path: Path) -> None:
    def rule(_settings: CaptureSettings, _cwd: str) -> Decision | None:
        raise RuntimeError("helper is down")

    service, sender, _ = build(tmp_path, rules=(rule,))
    assert service.capture_path("claude_code", session(tmp_path)).reason == "extension_failed"
    assert sender.requests == []


# --- the SDK sender scrubs the exact payload ------------------------------------------------


def test_sdk_sender_scrubs_before_submit_and_holds_over_the_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import driftshield.public as public

    @dataclasses.dataclass(frozen=True)
    class FakeRun:
        redacted_transcript: dict[str, Any]

    texts = iter(["acme here", "acme acme acme"])
    sent: list[dict[str, Any]] = []

    @dataclasses.dataclass(frozen=True)
    class Receipt:
        submission_id: str = "sub_x"
        processing_status: str = "accepted"

    monkeypatch.setattr(public, "analyse_run", lambda *a, **k: FakeRun({"t": next(texts)}))
    monkeypatch.setattr(
        public, "submit", lambda run, **k: sent.append(run.redacted_transcript) or Receipt()
    )
    settings = settings_for(tmp_path, blocked=BlockedTerms(terms=("acme",), hold_over=2))
    path = _write(tmp_path / "s.jsonl", "x")
    request = SendRequest(path, svc.RUN_ID_NAMESPACE, "s", "s@1", "w", None, "a:b", None, False)
    assert svc.SdkSender().send(request, settings, "key-123456") == ("sub_x", "accepted")
    assert sent == [{"t": "[blocked-term] here"}]
    with pytest.raises(Held):
        svc.SdkSender().send(request, settings, "key-123456")
    assert len(sent) == 1


# --- ledger written by another tool ---------------------------------------------------------


def test_existing_ledger_is_read_in_place_and_its_extra_fields_kept(tmp_path: Path) -> None:
    path = session(tmp_path)
    home = tmp_path / "home"
    home.mkdir()
    existing = {
        "version": 1,
        "meta": {"worker_watch_started_at": "2026-11-12T09:00:00+00:00", "other_tool": {"x": 1}},
        "runs": [
            {
                "key": "claude_code:s1",
                "source": "claude_code",
                "session_id": "s1",
                "path": str(path),
                "revisions": [
                    {
                        "content_hash": content_hash(path),
                        "revision": 1,
                        "submission_id": "sub_old",
                        "submitted_at": "2026-11-12T09:30:00+00:00",
                        "source_report_id": "s1@x",
                        "work_identity": {"kept": True},
                    }
                ],
                "scope": {"status": "in_scope"},
                "pending": None,
            }
        ],
    }
    (home / "ledger.json").write_text(json.dumps(existing))
    service, sender, ledger = build(tmp_path)
    assert service.capture_path("claude_code", path).status == "unchanged"
    other = session(tmp_path, "s2")
    assert service.capture_path("claude_code", other).sent
    saved = json.loads((home / "ledger.json").read_text())
    assert saved["meta"]["other_tool"] == {"x": 1}
    first = next(r for r in saved["runs"] if r["key"] == "claude_code:s1")
    assert first["scope"] == {"status": "in_scope"}
    assert first["revisions"][0]["work_identity"] == {"kept": True}
    assert sender.requests[0].source_session_id == "s2"


# --- watch tick -----------------------------------------------------------------------------


def _age(path: Path, seconds: float, now: datetime = NOW) -> None:
    stamp = (now - timedelta(seconds=seconds)).timestamp()
    os.utime(path, (stamp, stamp))


def test_tick_starts_its_window_now_and_waits_for_quiet(tmp_path: Path) -> None:
    service, sender, ledger = build(tmp_path, main_idle_seconds=600)
    old = session(tmp_path, "old")
    _age(old, 3600)
    ledger.home.mkdir(parents=True)
    ledger.path.write_text(
        json.dumps(
            {
                "meta": {
                    k: (NOW - timedelta(seconds=1800)).isoformat() for k in WINDOW_KEYS.values()
                },
                "runs": [],
            }
        )
    )
    busy = session(tmp_path, "busy")
    _age(busy, 60)
    quiet = session(tmp_path, "quiet")
    _age(quiet, 900)
    summary = tick(service)
    assert summary.before_window == 1
    assert summary.active == 1
    assert summary.outcomes == {"submitted": 1}
    assert [r.source_session_id for r in sender.requests] == ["quiet"]
    again = tick(service)
    assert again.settled == 1 and again.outcomes == {}


def test_tick_does_nothing_when_off(tmp_path: Path) -> None:
    service, sender, _ = build(tmp_path, enabled=False)
    _age(session(tmp_path), 900)
    assert tick(service).skipped_reason is not None
    assert sender.requests == []


def test_first_tick_sends_nothing_older(tmp_path: Path) -> None:
    service, sender, _ = build(tmp_path)
    _age(session(tmp_path), 900)
    assert tick(service).before_window == 1
    assert sender.requests == []


# --- cli --------------------------------------------------------------------------------------


def test_install_prints_and_status_counts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DRIFTSHIELD_HOME", str(tmp_path))
    monkeypatch.setenv(CONFIG_ENV, str(tmp_path / "capture.toml"))
    plist = runner_invoke(["capture", "install"])
    assert "capture</string>" in plist and "watch</string>" in plist
    assert "OnUnitActiveSec=60" in runner_invoke(["capture", "install", "--systemd"])
    status = json.loads(runner_invoke(["capture", "status", "--json"]))
    assert status["ledger"]["runs"] == 0 and status["extensions"] == []


def test_submit_refuses_when_off(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(CONFIG_ENV, str(tmp_path / "missing.toml"))
    path = _write(tmp_path / "s.jsonl", "x")
    result = CliRunner().invoke(app, ["capture", "submit", "--path", str(path)])
    assert result.exit_code == 1 and "OFF" in result.stdout


def runner_invoke(args: list[str]) -> str:
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 0, result.stdout
    return result.stdout
