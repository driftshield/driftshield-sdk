"""The analyser versions must move when the behaviour they name moves.

Intel stores the matching rules version and the step facts version of every upload so
that a verdict made by older rules can be told from a newer one. That only works if the
version changes whenever behaviour does. This pins the behaviour per version:

* ``matching``: the signature hits of every bundled fixture, analysed raw and after
  redaction (the redacted copy carries step facts, which the verification rules read).
* ``step_facts``: the classification of a frozen set of shell commands.

If one of these tests fails because behaviour changed, do not edit the stored entry for the
current version. Bump ``RULESET_VERSION`` (matching rules) or ``STEP_FACTS_VERSION`` (step
facts) and add a new entry for the new version with::

    PYTHONPATH=src python -m tests.test_analyser_versions --write

If only a new fixture or command was added and no existing behaviour moved, run the same
command: it adds the new entries to the current version without touching existing ones.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from driftshield import NoParseableEventsError, analyse_run
from driftshield.core.deterministic_matching import RULESET_VERSION
from driftshield.step_facts import STEP_FACTS_VERSION, classify_command, classify_error

FIXTURES = Path(__file__).parent / "fixtures"
GOLDEN = FIXTURES / "transcripts" / "golden" / "analyser_behaviour.json"
_TRANSCRIPTS = FIXTURES / "transcripts"


def _fixture_paths() -> list[Path]:
    paths = [p for p in sorted(_TRANSCRIPTS.rglob("*")) if p.suffix in {".json", ".jsonl"}]
    return [p for p in paths if "golden" not in p.parts]


def _hits(run: Any) -> list[list[Any]]:
    return sorted(
        [h.signature_id, h.mechanism_id, h.confidence_band, h.confidence]
        for h in run.signature_hits
    )


def matching_behaviour() -> dict[str, list[list[Any]]]:
    """Signature hits per fixture, raw and after redaction."""
    out: dict[str, list[list[Any]]] = {}
    for path in _fixture_paths():
        name = path.relative_to(_TRANSCRIPTS).as_posix()
        try:
            raw = analyse_run(path.read_bytes(), source=name)
        except NoParseableEventsError:
            continue
        out[f"{name}|raw"] = _hits(raw)
        try:
            redacted = analyse_run(json.dumps(raw.redacted_transcript), format=raw.detected_format)
        except NoParseableEventsError:
            continue  # a shape whose redacted copy cannot be read again carries no facts to pin
        out[f"{name}|redacted"] = _hits(redacted)
    return out


def _frozen_commands() -> list[str]:
    from tests.test_step_facts import CLASSIFICATION_TABLE

    return [command for command, _, _ in CLASSIFICATION_TABLE]


def step_facts_behaviour(commands: list[str]) -> dict[str, list[str]]:
    return {command: list(classify_command(command)) for command in commands}


def _frozen_error_texts() -> list[str]:
    from tests.test_error_class import MULTI_LINE, NOT_STATUS_TOKENS, STATUS_TOKENS, ERROR_TABLE

    texts = [text for text, _ in ERROR_TABLE + STATUS_TOKENS + MULTI_LINE]
    return texts + list(NOT_STATUS_TOKENS)


def error_class_behaviour(texts: list[str]) -> dict[str, str]:
    return {text: str(classify_error(text)) for text in texts}


# Sequences of shell steps whose ``checked_before`` flags are pinned per step facts version.
# ``checked_before`` depends on the order of steps, so a single command cannot pin it.
SEQUENCES: list[list[str]] = [
    ["ls"],
    ["git status", "gh pr merge 1"],
    ["git status", "gh pr merge 1", "gh pr merge 2"],
    ["gh pr merge 1", "git status", "gh pr merge 2"],
    ["gh pr merge 1", "gh pr merge 2"],
    ["git status", "vercel --prod", "pytest -q", "git push origin main"],
    ["git status", "rm -rf build", "gh pr merge 3"],
    ["git status", "git commit -m x", "git push origin main"],
    ["cd x; git status; gh pr merge 3"],
    ["git status && gh pr merge 3"],
    ["gh pr merge 3; git status"],
    ["ls | gh pr merge 3"],
    ["ls; git commit -m x; gh pr merge 3"],
    ["ls; gh pr merge 1", "gh pr merge 2"],
    ["ls", "curl -X POST https://example.com/u -d a=b", "ls", "curl -X POST https://example.com/u"],
    ["git status", "gh pr comment 3 --body hi", "gh pr merge 3"],
    ["gh pr merge 1", "gh issue comment 2 --body x", "gh pr merge 3"],
    ["git status", "gh pr edit 3 --add-label go", "gh pr merge 3"],
    ["git status", "gh pr close 3 --delete-branch", "gh pr merge 4"],
    ["git status", "gh pr comment 3 --delete-last", "gh pr merge 4"],
]


def step_fact_sequences_behaviour() -> dict[str, list[bool]]:
    """``checked_before`` of every step of each frozen sequence, as an upload carries it."""
    from tests.test_step_facts import claude_code

    out: dict[str, list[bool]] = {}
    for commands in SEQUENCES:
        steps = [(command, f"c{index}", False) for index, command in enumerate(commands)]
        run = analyse_run(claude_code(steps), format="claude_code")
        out[json.dumps(commands)] = [
            block["step_facts"]["checked_before"]
            for record in run.redacted_transcript["events"]
            for block in record.get("message", {}).get("content", [])
            if isinstance(block, dict) and "step_facts" in block
        ]
    return out


def _load() -> dict[str, dict[str, dict[str, Any]]]:
    return json.loads(GOLDEN.read_text())


def test_the_matching_rules_version_has_a_pinned_behaviour():
    pinned = _load()["matching"]
    assert RULESET_VERSION in pinned, (
        f"RULESET_VERSION is {RULESET_VERSION!r} but no behaviour is pinned for it. "
        "Add it with: PYTHONPATH=src python -m tests.test_analyser_versions --write"
    )


def test_matching_behaviour_matches_the_pinned_one_for_the_current_version():
    pinned = _load()["matching"][RULESET_VERSION]
    current = matching_behaviour()
    changed = sorted(k for k in pinned if current.get(k) != pinned[k])
    assert not changed, (
        f"Matching behaviour changed for {changed} but RULESET_VERSION is still "
        f"{RULESET_VERSION!r}. Bump RULESET_VERSION in core/deterministic_matching.py and pin the "
        "new behaviour (see the module docstring); never edit the entry of a released version."
    )


def test_every_released_matching_version_stays_pinned_and_distinct():
    pinned = _load()["matching"]
    assert len(pinned) >= 1
    # Two versions with identical behaviour mean the bump changed nothing it claims to.
    assert len({json.dumps(v, sort_keys=True) for v in pinned.values()}) == len(pinned)


def test_the_step_facts_version_has_a_pinned_classification():
    pinned = _load()["step_facts"]
    assert STEP_FACTS_VERSION in pinned, (
        f"STEP_FACTS_VERSION is {STEP_FACTS_VERSION!r} but no classification is pinned for it. "
        "Add it with: PYTHONPATH=src python -m tests.test_analyser_versions --write"
    )


def test_step_fact_classification_matches_the_pinned_one_for_the_current_version():
    pinned = _load()["step_facts"][STEP_FACTS_VERSION]
    current = step_facts_behaviour(list(pinned))
    changed = sorted(c for c in pinned if current[c] != pinned[c])
    assert not changed, (
        f"Step fact classification changed for {changed} but STEP_FACTS_VERSION is still "
        f"{STEP_FACTS_VERSION!r}. Bump STEP_FACTS_VERSION in step_facts.py and pin the new "
        "classification (see the module docstring); never edit the entry of a released version."
    )


def test_the_pinned_commands_cover_every_kind_the_table_documents():
    pinned = _load()["step_facts"][STEP_FACTS_VERSION]
    kinds = {value[0] for value in pinned.values()}
    assert {"read_only", "test", "build", "git_push", "merge", "deploy", "delete"} <= kinds
    assert {"outside_write", "unknown"} <= kinds


def test_the_step_facts_version_has_pinned_error_classes():
    pinned = _load()["error_classes"]
    assert STEP_FACTS_VERSION in pinned, (
        f"STEP_FACTS_VERSION is {STEP_FACTS_VERSION!r} but no error classes are pinned for it. "
        "Add them with: PYTHONPATH=src python -m tests.test_analyser_versions --write"
    )


def test_the_step_facts_version_has_pinned_sequences():
    pinned = _load()["step_fact_sequences"]
    assert STEP_FACTS_VERSION in pinned, (
        f"STEP_FACTS_VERSION is {STEP_FACTS_VERSION!r} but no step sequences are pinned for it. "
        "Add them with: PYTHONPATH=src python -m tests.test_analyser_versions --write"
    )


def test_checked_before_matches_the_pinned_sequences_for_the_current_version():
    pinned = _load()["step_fact_sequences"][STEP_FACTS_VERSION]
    current = step_fact_sequences_behaviour()
    changed = sorted(k for k in pinned if current.get(k) != pinned[k])
    assert not changed, (
        f"checked_before changed for {changed} but STEP_FACTS_VERSION is still "
        f"{STEP_FACTS_VERSION!r}. Bump STEP_FACTS_VERSION in step_facts.py and pin the new "
        "behaviour (see the module docstring); never edit the entry of a released version."
    )


def test_error_classes_match_the_pinned_ones_for_the_current_version():
    pinned = _load()["error_classes"][STEP_FACTS_VERSION]
    current = error_class_behaviour(list(pinned))
    changed = sorted(t for t in pinned if current[t] != pinned[t])
    assert not changed, (
        f"Error classes changed for {changed} but STEP_FACTS_VERSION is still "
        f"{STEP_FACTS_VERSION!r}. Bump STEP_FACTS_VERSION in step_facts.py and pin the new "
        "classes; never edit the entry of a released version."
    )


def test_the_golden_file_is_stable_json():
    text = GOLDEN.read_text()
    assert text == json.dumps(json.loads(text), indent=1, sort_keys=True) + "\n"


def _write() -> None:
    data = json.loads(GOLDEN.read_text()) if GOLDEN.exists() else {"matching": {}, "step_facts": {}}
    data.setdefault("error_classes", {})
    matching = data["matching"].setdefault(RULESET_VERSION, {})
    for key, value in matching_behaviour().items():
        matching.setdefault(key, value)
    facts = data["step_facts"].setdefault(STEP_FACTS_VERSION, {})
    # Every command pinned for an earlier version is classified again, so the new entry
    # shows exactly what changed from the old one.
    earlier = {c for version, pinned in data["step_facts"].items() for c in pinned}
    for command, value in step_facts_behaviour(sorted(set(_frozen_commands()) | earlier)).items():
        facts.setdefault(command, value)
    classes = data["error_classes"].setdefault(STEP_FACTS_VERSION, {})
    for text, value in error_class_behaviour(_frozen_error_texts()).items():
        classes.setdefault(text, value)
    sequences = data.setdefault("step_fact_sequences", {}).setdefault(STEP_FACTS_VERSION, {})
    for key, value in step_fact_sequences_behaviour().items():
        sequences.setdefault(key, value)
    GOLDEN.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n")


if __name__ == "__main__":
    if "--write" not in sys.argv:
        raise SystemExit("usage: python -m tests.test_analyser_versions --write")
    _write()
    pytest.main([__file__, "-q"])
