"""Blocked terms: the last check on the text that would leave the machine.

The scope gate decides which sessions are read, on their working folders
only. A session that passes can still mention a name its owner never wants
sent. So the redacted transcript (the only text a submission carries) is
scrubbed: every hit of a blocked term becomes a neutral token. A session
with more than ``hold_over`` hits is held instead of sent.

* ``terms`` match case insensitively wherever they start a word, so a term
  also catches its plural and possessive.
* ``folder_terms`` (the names of the folders under ``terms_from_folders``)
  match as whole words only.

Hits are only ever counted. Their text is never logged or printed.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_TOKEN = "[blocked-term]"
DEFAULT_HOLD_OVER = 3
_WORD = "A-Za-z0-9"


@dataclass(frozen=True, slots=True)
class BlockedTerms:
    terms: tuple[str, ...] = ()
    folder_terms: tuple[str, ...] = ()
    token: str = DEFAULT_TOKEN
    hold_over: int = DEFAULT_HOLD_OVER

    @property
    def empty(self) -> bool:
        return not self.terms and not self.folder_terms

    def pattern(self) -> re.Pattern[str] | None:
        starts = sorted(set(self.terms), key=len, reverse=True)
        words = sorted(set(self.folder_terms), key=len, reverse=True)
        parts = [rf"(?<![{_WORD}]){re.escape(term)}" for term in starts]
        parts += [rf"(?<![{_WORD}]){re.escape(term)}(?![{_WORD}])" for term in words]
        return re.compile("|".join(parts), re.IGNORECASE) if parts else None

    def scrub(self, value: Any) -> tuple[Any, int]:
        """A scrubbed copy of ``value`` (dict keys included) and the hit count."""
        pattern = self.pattern()
        if pattern is None:
            return value, 0
        hits = 0

        def walk(item: Any) -> Any:
            nonlocal hits
            if isinstance(item, str):
                new, count = pattern.subn(self.token, item)
                hits += count
                return new
            if isinstance(item, dict):
                return {
                    (walk(key) if isinstance(key, str) else key): walk(val)
                    for key, val in item.items()
                }
            if isinstance(item, (list, tuple)):
                return [walk(val) for val in item]
            return item

        return walk(value), hits

    def count(self, value: Any) -> int:
        return self.scrub(value)[1]

    def held(self, hits: int) -> bool:
        return hits > self.hold_over

    def fingerprint(self) -> str:
        """Changes when the list does and says nothing about what is on it."""
        parts = sorted(self.terms) + ["--"] + sorted(self.folder_terms)
        text = "\n".join(parts + [self.token, str(self.hold_over)])
        return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]

    def describe(self) -> str:
        if self.empty:
            return "blocked terms: none"
        return (
            f"blocked terms: {len(self.terms)} listed + {len(self.folder_terms)} folder names "
            f"(replaced with {self.token}; more than {self.hold_over} hits holds the session)"
        )


def folder_names(folders: tuple[str, ...], ignore: tuple[str, ...]) -> tuple[str, ...]:
    """The names of the folders directly under each of ``folders``."""
    skip = {name.lower() for name in ignore}
    names: set[str] = set()
    for folder in folders:
        root = Path(os.path.expanduser(folder))
        if not root.is_dir():
            continue
        for child in root.iterdir():
            if child.is_dir() and not child.name.startswith(".") and child.name.lower() not in skip:
                names.add(child.name)
    return tuple(sorted(names))


__all__ = ["BlockedTerms", "DEFAULT_HOLD_OVER", "DEFAULT_TOKEN", "folder_names"]
