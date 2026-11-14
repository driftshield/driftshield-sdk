"""Shared builders for the rule tests: canonical events, step facts and a matcher call."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from driftshield.core.analysis.session import AnalysisResult
from driftshield.core.deterministic_matching import build_deterministic_match
from driftshield.core.graph.models import LineageGraph
from driftshield.core.models import CanonicalEvent, EventType, RiskClassification


def analysis_result(*, risk: RiskClassification | None = None) -> AnalysisResult:
    event = CanonicalEvent(
        id=uuid.uuid4(),
        session_id="session-1",
        timestamp=datetime.now(timezone.utc),
        event_type=EventType.TOOL_CALL,
        agent_id="agent-1",
        action="test",
        risk_classification=risk,
    )
    return AnalysisResult(
        events=[event],
        graph=LineageGraph(session_id="session-1"),
        inflection_node=None,
        total_events=1,
        flagged_events=1 if risk and risk.has_any_flag() else 0,
        inflection_explanation=None,
    )


REQUIREMENT = {"constraint": "Ask for confirmation before destructive changes."}


def facts(kind: str, target: str = "unknown", checked_before: bool = False) -> dict[str, Any]:
    return {
        "command_kind": kind,
        "target_kind": target,
        "exit_status": "success",
        "checked_before": checked_before,
    }


def tool(index: int, *, name: str = "bash", facts: dict[str, Any] | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "tool_name": name,
        "tool_category": "shell",
        "safety_relevant_flags": ["executes_shell"]
        if name in {"bash", "shell"}
        else ["mutates_state"],
    }
    if facts is not None:
        payload["step_facts"] = facts
    family = "state_write" if name in {"write", "edit"} else "tool_call"
    return {
        "event_id": f"evt-{index}",
        "sequence_index": index,
        "event_family": family,
        "structured_payload": payload,
    }


def confirmation(index: int) -> dict[str, Any]:
    return {
        "event_id": f"evt-{index}",
        "sequence_index": index,
        "event_family": "confirmation_checkpoint",
        "structured_payload": {},
    }


def match(events: list[dict[str, Any]], *, requirement: bool = True) -> dict[str, Any]:
    canonical = {
        "analysis_session": {"integrity_status": "complete", "source_provenance": {"source_type": "x"}},
        "normalized_events": events,
        "run_context": {},
        "policy_and_instruction_context": {
            "system_constraints": [REQUIREMENT] if requirement else [],
            "developer_constraints": [],
            "user_constraints": [],
            "derived_operational_constraints": [],
            "conflict_or_shadowing_notes": [],
        },
        "expected_vs_actual_delta": {"delta_types": [], "supporting_event_ids": []},
        "extraction_quality_summary": {
            "overall_quality_band": "usable",
            "ordering_confidence": 1.0,
            "ambiguity_count": 0,
        },
    }
    return build_deterministic_match(canonical_analysis=canonical, result=analysis_result())


def fires(payload: dict[str, Any]) -> bool:
    rules = {rule["rule_id"] for rule in payload["matched_rules"]}
    sequences = {seq["sequence_id"] for seq in payload["matched_sequence_patterns"]}
    # The rule and the sequence pattern must always agree.
    assert ("R-VER-001" in rules) == ("SEQ-VER-001" in sequences)
    return "R-VER-001" in rules
