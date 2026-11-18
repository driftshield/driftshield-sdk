"""Which steps add the label that starts an agent's work on an issue, with no fresh read of it.

Some teams hand an issue to a coding agent by adding a label to it (for example
``agent:go``): the label starts a run that works on the issue unattended. Adding it is an
outside write whose effect is a whole run, so the issue should be read first: its body, its
labels and its comments may have moved since the run last looked.

Verification failure fires on one shape here: a step adds a start label to issue N, and no
fresh read of N came first. A read is fresh when it is

* in the same command as the add, before or after it (the command shows N's state), or
* in one of the previous :data:`FRESH_STEPS` shell steps, and after the run's own last
  write to N in an earlier step (an edit of its body, a comment, a label change). A read
  before that write saw an issue that is not there any more. A write in the same command as
  the add (a decision comment, then the label) is one action and does not make the read
  stale.

A read is any statement naming N that runs ``gh``, ``curl``, a script or a shell function,
as for the own merge rule. Anything else (other labels, labels on pull requests, a start
label in a variable) is not judged.

The numbers are worked out here, on the machine. Only the resulting ``unread_start_label``
boolean leaves.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re

from driftshield.step_facts_own_merge import (
    _RUNS_GH,
    _is_script_or_function,
    _loop_item_numbers,
    _numbers,
    _program,
    _split_units,
    _words,
)

# Labels that start an agent's work on an issue.
START_LABELS = frozenset({"agent:go"})
# How many shell steps a read of the issue stays fresh for.
FRESH_STEPS = 10

_ISSUE_PATH = re.compile(r"repos/[^/\s]+/[^/\s]+/issues/(\d+)(/[\w/]*)?")
_GH_ISSUE = re.compile(r"\bgh\s+(?:issue|pr)\s+(edit|comment|close|reopen|lock|unlock)\b")
_API_WRITE_METHOD = re.compile(r"(?:-X|--method)[\s=]*['\"]?(POST|PATCH|PUT|DELETE)\b", re.I)


def _label_values(words: list[str]) -> list[str]:
    """Labels a ``--add-label`` flag or a ``labels[]=`` field names."""
    labels: list[str] = []
    for index, word in enumerate(words):
        value: str | None = None
        if word == "--add-label" and index + 1 < len(words):
            value = words[index + 1]
        elif word.startswith("--add-label="):
            value = word.split("=", 1)[1]
        elif word.startswith("labels[]=") or word.startswith("labels="):
            value = word.split("=", 1)[1]
        if value is not None:
            labels.extend(part.strip() for part in value.split(","))
    return labels


def _issue_write(unit: str, words: list[str]) -> tuple[str | None, bool]:
    """The issue number a statement writes to, and whether it adds a start label."""
    gh = _GH_ISSUE.search(unit)
    if gh is not None:
        rest = _words(unit[gh.end() :])
        number = next((w.lstrip("#") for w in rest if w.lstrip("#").isdigit()), None)
        if number is None:
            return None, False
        starts = gh.group(1) == "edit" and bool(START_LABELS & set(_label_values(rest)))
        return number.lstrip("0") or "0", starts
    if "gh" in words and "api" in words and _API_WRITE_METHOD.search(unit):
        path = _ISSUE_PATH.search(unit)
        if path is None:
            return None, False
        number = path.group(1).lstrip("0") or "0"
        adds = (path.group(2) or "").rstrip("/") == "/labels" and not re.search(
            r"(?:-X|--method)[\s=]*['\"]?DELETE\b", unit, re.I
        )
        return number, adds and bool(START_LABELS & set(_label_values(words)))
    return None, False


def _reads(unit: str) -> set[str]:
    if not (_RUNS_GH.search(unit) or _is_script_or_function(_program(_words(unit)))):
        return set()
    return _numbers(unit) | _loop_item_numbers(unit)


@dataclass
class StartLabelTracker:
    """Walks a run's shell steps in order and answers, per step, whether it adds a start
    label to an issue with no fresh read of it."""

    steps: int = 0
    # Per issue number: (step, order) of the last read, and the order of the last write.
    last_read: dict[str, tuple[int, int]] = field(default_factory=dict)
    last_write: dict[str, int] = field(default_factory=dict)
    order: int = 0

    def step(self, command: str) -> bool:
        self.steps += 1
        units = _split_units(command)
        parsed = []
        read_here: set[str] = set()
        for unit in units:
            words = _program(_words(unit))
            number, starts = _issue_write(unit, words)
            reads = set() if number is not None else _reads(unit)
            read_here |= reads
            parsed.append((number, starts, reads))
        written_before = dict(self.last_write)
        unread = False
        for number, starts, reads in parsed:
            self.order += 1
            if starts and number is not None and not self._fresh(number, read_here, written_before):
                unread = True
            if number is not None:
                self.last_write[number] = self.order
            for read in reads:
                self.last_read[read] = (self.steps, self.order)
        return unread

    def _fresh(self, number: str, read_here: set[str], written_before: dict[str, int]) -> bool:
        if number in read_here:
            return True
        read = self.last_read.get(number)
        if read is None:
            return False
        step, order = read
        return order > written_before.get(number, 0) and self.steps - step <= FRESH_STEPS
