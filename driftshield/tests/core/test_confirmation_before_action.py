"""``confirmation_before_action`` means a confirmation came before the first outside step.

It feeds the ``confirmation_present_before_destructive_action`` contradiction. It used to
mean a confirmation before the first shell, write or edit call, which no longer matches
what verification failure looks at.
"""

from __future__ import annotations

from typing import Any

from tests.core.helpers import confirmation, facts, match, tool

FLAG = "confirmation_present_before_destructive_action"
DEPLOY = facts("deploy", "outside_service")


def _flags(payload: dict[str, Any]) -> list[str]:
    return [item["flag"] for item in payload["global_contradictions"]]


def test_a_confirmation_before_the_first_outside_step_sets_it_and_the_flag():
    payload = match([confirmation(0), tool(1, facts=DEPLOY)])
    assert payload["extracted_features"]["confirmation_before_action"] is True
    assert FLAG in _flags(payload)


def test_a_confirmation_only_after_the_outside_step_does_not():
    payload = match([tool(0, facts=DEPLOY), confirmation(1)])
    assert payload["extracted_features"]["confirmation_before_action"] is False
    assert FLAG not in _flags(payload)


def test_only_the_first_outside_step_decides_it():
    # Confirmed before the first one, nothing between the two: still true.
    payload = match([confirmation(0), tool(1, facts=DEPLOY), tool(2, facts=DEPLOY)])
    assert payload["extracted_features"]["confirmation_before_action"] is True
    # A confirmation that falls between two outside steps comes after the first.
    payload = match([tool(0, facts=DEPLOY), confirmation(1), tool(2, facts=DEPLOY)])
    assert payload["extracted_features"]["confirmation_before_action"] is False


def test_a_confirmation_before_a_step_that_is_not_outside_does_not():
    # The old meaning counted any shell or edit call. A read only command, an edit and
    # a run with no step facts are not outside steps, so there is nothing to confirm.
    for step in (
        tool(1, facts=facts("read_only")),
        tool(1, name="edit"),
        tool(1, facts=None),
    ):
        payload = match([confirmation(0), step])
        assert payload["extracted_features"]["confirmation_before_action"] is False
        assert FLAG not in _flags(payload)


def test_no_confirmation_at_all_does_not():
    payload = match([tool(0, facts=DEPLOY)])
    assert payload["extracted_features"]["confirmation_before_action"] is False
    assert FLAG not in _flags(payload)
