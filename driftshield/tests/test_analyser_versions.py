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
from driftshield.step_facts import STEP_FACTS_VERSION, classify_command

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


def test_the_golden_file_is_stable_json():
    text = GOLDEN.read_text()
    assert text == json.dumps(json.loads(text), indent=1, sort_keys=True) + "\n"


def _write() -> None:
    data = json.loads(GOLDEN.read_text()) if GOLDEN.exists() else {"matching": {}, "step_facts": {}}
    matching = data["matching"].setdefault(RULESET_VERSION, {})
    for key, value in matching_behaviour().items():
        matching.setdefault(key, value)
    facts = data["step_facts"].setdefault(STEP_FACTS_VERSION, {})
    for command, value in step_facts_behaviour(_frozen_commands()).items():
        facts.setdefault(command, value)
    GOLDEN.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n")


if __name__ == "__main__":
    if "--write" not in sys.argv:
        raise SystemExit("usage: python -m tests.test_analyser_versions --write")
    _write()
    pytest.main([__file__, "-q"])
