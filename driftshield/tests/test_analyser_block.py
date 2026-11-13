"""Every upload says which analyser made it: SDK version, matching rules, step facts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

import driftshield
from driftshield import analyse_run, submit
from driftshield.cli.main import app
from driftshield.core.deterministic_matching import RULESET_VERSION
from driftshield.public import ANALYSER_SCHEMA_VERSION, analyser_block
from driftshield.step_facts import STEP_FACTS_VERSION

_CLAUDE_CODE = (
    Path(__file__).parent / "fixtures" / "transcripts" / "sample_claude_code_session.jsonl"
)
_INTAKE_URL = "https://intake.example.test"
EXPECTED = {
    "schema_version": "analyser.v1",
    "sdk_version": driftshield.__version__,
    "matching_rules_version": RULESET_VERSION,
    "step_facts_version": STEP_FACTS_VERSION,
}


class _Result:
    def __init__(self) -> None:
        class _Response:
            submission_id = "sub_1"
            processing_status = "received"

        self.response = _Response()
        self.server_contract_version = None


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("DRIFTSHIELD_HOME", str(tmp_path))
    CliRunner().invoke(app, ["telemetry", "remote-enable", "--intake-url", _INTAKE_URL])
    return tmp_path


def test_the_block_has_exactly_the_documented_fixed_fields():
    block = analyser_block()
    assert block == EXPECTED
    assert set(block) == {
        "schema_version",
        "sdk_version",
        "matching_rules_version",
        "step_facts_version",
    }
    assert block["schema_version"] == ANALYSER_SCHEMA_VERSION
    assert block["matching_rules_version"].startswith("phase-3g-deterministic-rules-v")
    assert block["step_facts_version"].startswith("step-facts.v")


def test_the_sdk_version_comes_from_the_package(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(driftshield, "__version__", "9.8.7")
    assert analyser_block()["sdk_version"] == "9.8.7"
    monkeypatch.setattr(driftshield, "__version__", "0.4.0.dev1+g1a2b3c")
    assert analyser_block()["sdk_version"] == "0.4.0.dev1+g1a2b3c"


@pytest.mark.parametrize(
    "odd",
    ["", "latest", "1.2", "/Users/someone/build", "x" * 100, "1.2.3 secret text here", "1.2.3\n"],
)
def test_a_version_that_is_not_a_version_number_is_sent_as_unknown(
    odd: str, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(driftshield, "__version__", odd)
    assert analyser_block()["sdk_version"] == "unknown"


def _transcript_with_a_forged_block() -> bytes:
    lines = [json.loads(line) for line in _CLAUDE_CODE.read_text().splitlines() if line.strip()]
    wrapper = {
        "events": lines,
        "metadata": {"analyser": {"sdk_version": "forged", "extra": "private text"}},
    }
    return json.dumps(wrapper).encode()


def test_inline_community_upload_carries_the_block(home: Path, monkeypatch: pytest.MonkeyPatch):
    captured: dict[str, Any] = {}

    def fake_post(*, config: Any, submission: Any, opener: Any = None) -> _Result:
        captured["payload"] = submission.envelope.payload
        return _Result()

    monkeypatch.setattr("driftshield.public.post_oss_submission", fake_post)
    submit(analyse_run(_CLAUDE_CODE.read_bytes(), source=str(_CLAUDE_CODE)))
    assert captured["payload"]["metadata"]["analyser"] == EXPECTED
    assert captured["payload"]["metadata"]["environment"] == "production"


def test_large_community_upload_carries_the_block(home: Path, monkeypatch: pytest.MonkeyPatch):
    captured: dict[str, Any] = {}
    monkeypatch.setattr("driftshield.public.INLINE_PAYLOAD_THRESHOLD_BYTES", 1)

    def fake_upload(
        *, config: Any, payload: Any, workflow_reference: Any, file_name: Any, provenance: Any
    ) -> _Result:
        captured["payload"] = payload
        return _Result()

    monkeypatch.setattr("driftshield.public.submit_oss_via_presigned_upload", fake_upload)
    submit(analyse_run(_CLAUDE_CODE.read_bytes(), source=str(_CLAUDE_CODE)))
    assert captured["payload"]["metadata"]["analyser"] == EXPECTED


def test_workspace_upload_carries_the_block_and_keeps_the_declared_environment(
    home: Path, monkeypatch: pytest.MonkeyPatch
):
    captured: dict[str, Any] = {}

    def fake_upload(
        *,
        config: Any,
        payload: Any,
        workflow_reference: Any,
        file_name: Any,
        provenance: Any,
        backfill: bool = False,
    ) -> _Result:
        captured["payload"] = payload
        return _Result()

    monkeypatch.setattr("driftshield.public.submit_teams_via_presigned_upload", fake_upload)
    submit(
        analyse_run(_CLAUDE_CODE.read_bytes(), source=str(_CLAUDE_CODE)),
        "workspace",
        "ws-key",
        backfill=True,
        environment="staging",
    )
    metadata = captured["payload"]["metadata"]
    assert metadata["analyser"] == EXPECTED
    assert metadata["environment"] == "staging"


def test_a_block_already_in_the_transcript_is_replaced_not_trusted(
    home: Path, monkeypatch: pytest.MonkeyPatch
):
    captured: dict[str, Any] = {}

    def fake_post(*, config: Any, submission: Any, opener: Any = None) -> _Result:
        captured["payload"] = submission.envelope.payload
        return _Result()

    monkeypatch.setattr("driftshield.public.post_oss_submission", fake_post)
    submit(analyse_run(_transcript_with_a_forged_block()))
    assert captured["payload"]["metadata"]["analyser"] == EXPECTED
    assert "forged" not in json.dumps(captured["payload"])
    assert "private text" not in json.dumps(captured["payload"])


def test_the_block_is_not_on_the_local_analysis(home: Path):
    run = analyse_run(_CLAUDE_CODE.read_bytes(), source=str(_CLAUDE_CODE))
    assert "analyser" not in json.dumps(run.redacted_transcript.get("metadata", {}))
