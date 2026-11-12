"""Safe checks on values taken from parsed JSON."""

from __future__ import annotations

from collections.abc import Collection


def is_one_of(value: object, choices: Collection[str]) -> bool:
    """``value in choices`` that never raises: only a string can be a member.

    A set lookup on a list or a dict (a JSON schema ``"type": ["string",
    "null"]``, say) raises ``TypeError``, so every check of a value taken from a
    transcript against a set of names goes through here.
    """
    return isinstance(value, str) and value in choices
