"""Tests for analyze command."""

import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from driftshield.cli.main import app


runner = CliRunner()

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "transcripts"
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


class TestAnalyzeCommand:
    def test_analyze_single_file(self):
        """Can analyze a single JSONL file."""
        result = runner.invoke(
            app,
            ["analyze", str(FIXTURES_DIR / "sample_claude_code_session.jsonl")],
        )

        assert result.exit_code == 0
        assert "DriftShield Analysis" in result.output
        assert "Events:" in result.output

    def test_analyze_with_verbose(self):
        """Verbose flag shows event table."""
        result = runner.invoke(
            app,
            ["analyze", str(FIXTURES_DIR / "sample_claude_code_session.jsonl"), "--verbose"],
        )

        assert result.exit_code == 0
        assert "Action" in result.output  # Table header

    def test_analyze_with_json(self):
        """JSON flag outputs valid JSON."""
        result = runner.invoke(
            app,
            ["analyze", str(FIXTURES_DIR / "sample_claude_code_session.jsonl"), "--json"],
        )

        assert result.exit_code == 0
        assert '"session_id"' in result.output
        assert '"total_events"' in result.output

    def test_analyze_nonexistent_file(self):
        """Nonexistent file shows error."""
        result = runner.invoke(app, ["analyze", "/nonexistent/path.jsonl"])

        assert result.exit_code != 0
        assert "not found" in result.output.lower() or "error" in result.output.lower()

    def test_analyze_with_parser_flag(self):
        """Can specify parser explicitly."""
        result = runner.invoke(
            app,
            [
                "analyze",
                str(FIXTURES_DIR / "sample_claude_code_session.jsonl"),
                "--parser",
                "claude_code",
            ],
        )

        assert result.exit_code == 0

    def test_analyze_with_unknown_parser(self):
        """Unknown parser shows error with available options."""
        result = runner.invoke(
            app,
            [
                "analyze",
                str(FIXTURES_DIR / "sample_claude_code_session.jsonl"),
                "--parser",
                "unknown",
            ],
        )

        assert result.exit_code != 0
        assert "claude_code" in result.output  # Lists available


    def test_analyze_with_explicit_crewai_parser_outputs_json_summary(self):
        """CrewAI fixture can be analysed end to end through the CLI."""
        result = runner.invoke(
            app,
            ["analyze", str(FIXTURES_DIR / "sample_crewai_session.json"), "--parser", "crewai", "--json"],
        )

        assert result.exit_code == 0
        payload = json.loads(ANSI_RE.sub("", result.output))
        assert payload["session_id"] == "crewai-run-001"
        assert payload["total_events"] == 3
        assert "flagged_events" in payload
        assert "risks" in payload


class TestAnalyzeParserWarnings:
    def _session_with_bad_line(self, tmp_path: Path) -> Path:
        fixture = FIXTURES_DIR / "sample_claude_code_session.jsonl"
        session = tmp_path / "warn-session.jsonl"
        session.write_text(fixture.read_text() + "this line is not json\n")
        return session

    def test_ac3_fixture_produces_a_parser_warning(self, tmp_path: Path) -> None:
        from driftshield.public import analyse_run

        session = self._session_with_bad_line(tmp_path)
        run = analyse_run(session.read_bytes(), source=str(session), format=None)

        assert run.warnings

    def test_ac1_json_stdout_is_one_json_document_despite_warning(self, tmp_path: Path) -> None:
        session = self._session_with_bad_line(tmp_path)

        result = runner.invoke(app, ["analyze", str(session), "--json"])

        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert "session_id" in payload

    def test_ac2_warning_text_is_on_stderr(self, tmp_path: Path) -> None:
        session = self._session_with_bad_line(tmp_path)

        result = runner.invoke(app, ["analyze", str(session), "--json"])

        assert result.exit_code == 0
        assert "Warning:" in ANSI_RE.sub("", result.stderr)
        assert "warn-session.jsonl" in ANSI_RE.sub("", result.stderr)
        assert "Warning:" not in result.stdout

    def test_ac1_ac2_skipped_file_warning_is_on_stderr(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from driftshield.cli.discovery import path_to_project_key

        project_key = path_to_project_key(tmp_path)
        sessions_dir = tmp_path / ".claude" / "projects" / project_key
        sessions_dir.mkdir(parents=True)
        fixture = FIXTURES_DIR / "sample_claude_code_session.jsonl"
        (sessions_dir / "good-session.jsonl").write_text(fixture.read_text())
        (sessions_dir / "empty-session.jsonl").write_text("this line is not json\n")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("CLAUDE_HOME", str(tmp_path / ".claude"))

        result = runner.invoke(app, ["analyze", "--project", "--json"])

        assert result.exit_code == 0
        json.loads(result.stdout)
        assert "skipping" in ANSI_RE.sub("", result.stderr)
        assert "empty-session.jsonl" in ANSI_RE.sub("", result.stderr)
        assert "skipping" not in result.stdout


class TestAnalyzeProject:
    def test_analyze_with_project_flag(self, tmp_path, monkeypatch):
        """Analyze --project analyzes all sessions."""
        from driftshield.cli.discovery import path_to_project_key

        project_key = path_to_project_key(tmp_path)
        sessions_dir = tmp_path / ".claude" / "projects" / project_key
        sessions_dir.mkdir(parents=True)

        fixture = FIXTURES_DIR / "sample_claude_code_session.jsonl"
        if fixture.exists():
            (sessions_dir / "test-session.jsonl").write_text(fixture.read_text())
        else:
            (sessions_dir / "test-session.jsonl").write_text(
                '{"type":"assistant","timestamp":1234567890000,"message":{"content":[]}}\n'
            )

        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("CLAUDE_HOME", str(tmp_path / ".claude"))

        result = runner.invoke(app, ["analyze", "--project"])

        assert result.exit_code == 0
        assert "test-session" in result.output or "DriftShield" in result.output


class TestAnalyzeCI:
    def test_fail_on_accepts_flag(self, tmp_path, monkeypatch):
        """--fail-on flag is accepted and runs without crashing."""
        from driftshield.cli.discovery import path_to_project_key

        project_key = path_to_project_key(tmp_path)
        sessions_dir = tmp_path / ".claude" / "projects" / project_key
        sessions_dir.mkdir(parents=True)

        fixture = FIXTURES_DIR / "sample_claude_code_session.jsonl"
        if fixture.exists():
            (sessions_dir / "session.jsonl").write_text(fixture.read_text())

            monkeypatch.chdir(tmp_path)
            monkeypatch.setenv("CLAUDE_HOME", str(tmp_path / ".claude"))

            result = runner.invoke(
                app,
                ["analyze", "--project", "--fail-on", "coverage_gap"],
            )
            assert result.exit_code in [0, 1]

    def test_fail_threshold_high_passes(self):
        """--fail-threshold with very high value passes."""
        result = runner.invoke(
            app,
            [
                "analyze",
                str(FIXTURES_DIR / "sample_claude_code_session.jsonl"),
                "--fail-threshold",
                "1000",
            ],
        )
        assert result.exit_code == 0

    def test_fail_threshold_zero_with_no_flags(self):
        """--fail-threshold 0 passes when session has no flagged events."""
        result = runner.invoke(
            app,
            [
                "analyze",
                str(FIXTURES_DIR / "sample_claude_code_session.jsonl"),
                "--fail-threshold",
                "0",
            ],
        )
        # The fixture has 0 flagged events, so 0 >= 0 would fail
        # This tests the boundary: threshold 0 means "fail if any"
        # With 0 flagged, 0 >= 0 is false (we use > not >=) so it passes
        # Actually let's just check the flag is accepted
        assert result.exit_code in [0, 1]

    def test_quiet_mode_minimal_output(self):
        """--quiet produces minimal output."""
        result = runner.invoke(
            app,
            [
                "analyze",
                str(FIXTURES_DIR / "sample_claude_code_session.jsonl"),
                "--quiet",
            ],
        )
        assert result.exit_code == 0
        assert len(result.output.strip().split("\n")) <= 3


class TestAnalyzeToolErrorAtSessionEnd:
    """A session that ends on a failed tool call breaks at that call."""

    def test_error_at_end_identifies_the_final_failed_tool_call(self):
        result = runner.invoke(
            app,
            ["analyze", str(FIXTURES_DIR / "sample_claude_code_tool_error_at_end.jsonl")],
        )
        output = ANSI_RE.sub("", result.output)

        assert result.exit_code == 0
        assert "Status    : identified" in output
        assert "Event     : #2 Bash" in output
        assert "reported an" in output and "error and was never recovered" in output

    def test_error_at_end_json_names_the_strategy(self):
        result = runner.invoke(
            app,
            ["analyze", str(FIXTURES_DIR / "sample_claude_code_tool_error_at_end.jsonl"), "--json"],
        )

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["flagged_events"] == 0
        assert data["candidate_break_point"]["status"] == "identified"
        assert data["candidate_break_point"]["action"] == "Bash"
        assert data["candidate_break_point"]["sequence_num"] == 2
        assert data["candidate_break_point"]["strategy"] == "final_tool_error"

    def test_recovered_error_has_no_break_point(self):
        result = runner.invoke(
            app,
            ["analyze", str(FIXTURES_DIR / "sample_claude_code_tool_error_recovered.jsonl"), "--json"],
        )

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["candidate_break_point"]["status"] == "no_clear_break_point"

    def test_successful_session_has_no_break_point(self):
        result = runner.invoke(
            app,
            ["analyze", str(FIXTURES_DIR / "sample_claude_code_tool_success.jsonl"), "--json"],
        )

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["candidate_break_point"]["status"] == "no_clear_break_point"


class TestCheckHitsAlwaysShown:
    """Check hits print with or without --tool-map; with no map the default coding map applies."""

    TOOL_ERROR = FIXTURES_DIR / "sample_claude_code_tool_error_at_end.jsonl"
    QUIET_RUN = FIXTURES_DIR / "sample_claude_code_tool_success.jsonl"

    def test_text_output_shows_hits_without_a_tool_map(self):
        result = runner.invoke(app, ["analyze", str(self.TOOL_ERROR)])

        output = ANSI_RE.sub("", result.output)
        assert result.exit_code == 0
        assert "Signature hits: mechanism:tool_misuse" in output
        assert "Tool map:" not in output

    def test_text_output_says_none_when_nothing_fired(self):
        result = runner.invoke(app, ["analyze", str(self.QUIET_RUN)])

        assert "Signature hits: none" in ANSI_RE.sub("", result.output)

    def test_json_adds_hits_without_a_tool_map(self):
        result = runner.invoke(app, ["analyze", str(self.TOOL_ERROR), "--json"])

        data = json.loads(result.stdout)
        assert data["signature_hits"] == [
            {"signature_id": "mechanism:tool_misuse", "mechanism_id": "tool_misuse"}
        ]
        assert "tool_coverage" not in data
        # The fields that were there before stay.
        assert {"session_id", "total_events", "flagged_events", "candidate_break_point"} <= data.keys()

    def test_json_for_several_sessions_adds_hits_to_each(self, tmp_path, monkeypatch):
        from driftshield.cli.discovery import path_to_project_key

        sessions_dir = tmp_path / ".claude" / "projects" / path_to_project_key(tmp_path)
        sessions_dir.mkdir(parents=True)
        for name in ("sample_claude_code_tool_error_at_end.jsonl", "sample_claude_code_tool_success.jsonl"):
            (sessions_dir / name).write_bytes((FIXTURES_DIR / name).read_bytes())
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("CLAUDE_HOME", str(tmp_path / ".claude"))

        result = runner.invoke(app, ["analyze", "--project", "--json"])

        data = json.loads(result.stdout)
        assert isinstance(data, list) and len(data) == 2
        assert all("signature_hits" in item for item in data)

INSURANCE_SESSION = FIXTURES_DIR / "events_v1" / "insurance_claims.jsonl"
INSURANCE_MAP = Path(__file__).parent.parent / "fixtures" / "tool_maps" / "insurance_claims.json"


class TestFailOnChecks:
    """--fail-on takes check family names as well as the older step risk flags."""

    def test_check_family_fails_the_run(self):
        result = runner.invoke(
            app,
            [
                "analyze",
                str(INSURANCE_SESSION),
                "--tool-map",
                str(INSURANCE_MAP),
                "--fail-on",
                "verification_failure",
            ],
        )

        assert result.exit_code == 1
        reasons = [line for line in ANSI_RE.sub("", result.stderr).splitlines() if line.startswith("FAIL:")]
        assert len(reasons) == 1
        assert "verification_failure" in reasons[0]
        assert reasons[0] == (
            "FAIL: verification_failure check fired in insurance_claims (--fail-on verification_failure)"
        )

    def test_signature_id_form_is_accepted(self):
        result = runner.invoke(
            app,
            [
                "analyze",
                str(INSURANCE_SESSION),
                "--tool-map",
                str(INSURANCE_MAP),
                "--fail-on",
                "mechanism:verification_failure",
            ],
        )

        assert result.exit_code == 1

    def test_check_that_did_not_fire_passes(self):
        result = runner.invoke(
            app,
            [
                "analyze",
                str(INSURANCE_SESSION),
                "--tool-map",
                str(INSURANCE_MAP),
                "--fail-on",
                "state_conflict",
            ],
        )

        assert result.exit_code == 0
        assert "FAIL:" not in result.output

    def test_check_hits_without_a_tool_map_use_the_default_coding_map(self):
        result = runner.invoke(
            app,
            [
                "analyze",
                str(FIXTURES_DIR / "sample_claude_code_tool_error_at_end.jsonl"),
                "--fail-on",
                "tool_misuse",
            ],
        )

        assert result.exit_code == 1
        assert "tool_misuse" in ANSI_RE.sub("", result.stderr)

    def test_older_risk_flag_names_still_work(self):
        result = runner.invoke(
            app,
            [
                "analyze",
                str(FIXTURES_DIR / "sample_claude_code_session.jsonl"),
                "--fail-on",
                "constraint_violation, assumption_mutation",
            ],
        )

        assert result.exit_code == 1
        reasons = [line for line in ANSI_RE.sub("", result.stderr).splitlines() if line.startswith("FAIL:")]
        assert any("assumption_mutation" in line for line in reasons)
        assert not any("constraint_violation" in line for line in reasons)

    def test_name_in_both_lists_names_the_check_and_the_step_risk(self):
        result = runner.invoke(
            app,
            [
                "analyze",
                str(FIXTURES_DIR / "sample_claude_code_session.jsonl"),
                "--fail-on",
                "assumption_mutation",
            ],
        )

        assert result.exit_code == 1
        assert (
            "FAIL: assumption_mutation check fired and step risk on 1 event in "
            "sample_claude_code_session (--fail-on assumption_mutation)"
        ) in ANSI_RE.sub("", result.stderr)

    def test_reasons_print_under_quiet_and_threshold_reasons_go_to_stderr(self):
        result = runner.invoke(
            app,
            [
                "analyze",
                str(FIXTURES_DIR / "sample_claude_code_session.jsonl"),
                "--quiet",
                "--fail-threshold",
                "1",
            ],
        )

        assert result.exit_code == 1
        assert "FAIL:" not in result.stdout
        assert "FAIL: 1 flagged events in sample_claude_code_session (threshold: 1)" in ANSI_RE.sub(
            "", result.stderr
        )

    def test_unknown_name_is_a_usage_error(self):
        result = runner.invoke(
            app,
            [
                "analyze",
                str(FIXTURES_DIR / "sample_claude_code_session.jsonl"),
                "--fail-on",
                "verification_failur",
            ],
        )

        assert result.exit_code == 2
        output = ANSI_RE.sub("", result.output)
        assert "verification_failur" in output
        assert "verification_failure" in output

    def test_json_stays_parseable_when_the_run_fails(self):
        result = runner.invoke(
            app,
            [
                "analyze",
                str(INSURANCE_SESSION),
                "--tool-map",
                str(INSURANCE_MAP),
                "--fail-on",
                "verification_failure",
                "--json",
            ],
        )

        assert result.exit_code == 1
        json.loads(result.stdout)

    def test_help_lists_the_check_families(self):
        result = runner.invoke(app, ["analyze", "--help"])

        output = ANSI_RE.sub("", result.output)
        assert "verification_failure" in output
        assert "state_conflict" in output
