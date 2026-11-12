"""The scope gate: a session may be read only when every working folder passes.

Checked in this order, before a transcript is read further than needed:

1. The settings file is present, valid and switched on.
2. A Claude Code transcript sits inside a configured Claude Code profile and
   outside every denied folder. Refused on its path alone, never opened.
3. The first working folder (a Claude Code transcript is read up to its
   first record with a ``cwd``; a Codex rollout only to ``session_meta``).
4. A subagent follows its parent: the parent must pass too.
5. Once read in full, every working folder the session recorded must pass,
   so a session that moved outside the allowed folders part way through is
   refused.

A working folder passes when it is an absolute path, sits outside every
denied folder and inside an allowed folder (symlinks resolved; a deleted
folder is judged by its path). Denied wins over allowed. When scope cannot
be established the session is refused, never guessed.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from driftshield.capture.config import CaptureSettings
from driftshield.capture.sessions import (
    SOURCE_CLAUDE_CODE,
    SOURCE_CODEX,
    SessionFacts,
    probe_claude,
    probe_codex,
)

IN_ALLOWED_FOLDER = "allowed_folder"
OFF = "capture_off"
INVALID = "settings_invalid"
DENIED = "denied_folder"
NOT_ALLOWED = "not_allowed"
NO_FOLDER = "no_working_folder"
NOT_ABSOLUTE = "working_folder_not_absolute"
OUTSIDE_PROFILES = "outside_claude_profiles"
PARENT_REFUSED = "parent_refused"
PARENT_UNKNOWN = "parent_unknown"
MAX_PARENT_DEPTH = 3


@dataclass(frozen=True, slots=True)
class Decision:
    allowed: bool
    reason: str
    detail: str


def _real(path: str | Path) -> Path:
    return Path(os.path.realpath(os.path.expanduser(str(path))))


def _within(path: Path, root: Path) -> bool:
    return path == root or path.is_relative_to(root)


def _lexical(path: str) -> Path:
    return Path(os.path.normpath(os.path.expanduser(path)))


def _denied_by(path: str, folder: str) -> bool:
    """Either the resolved or the written path under the folder: deny wins."""
    return _within(_real(path), _real(folder)) or _within(_lexical(path), Path(folder))


def _allowed_by(path: str, folder: str) -> bool:
    """The resolved path, so a symlink pointing out of the folder is refused.
    A folder that no longer exists (a removed worktree) is judged by its path."""
    real = _real(path)
    if not real.exists():
        return _within(_lexical(path), Path(folder)) or _within(real, _real(folder))
    return _within(real, _real(folder))


def _off(settings: CaptureSettings) -> Decision | None:
    if settings.invalid:
        return Decision(False, INVALID, f"settings file {settings.path} is invalid: {settings.invalid}")
    if not settings.enabled:
        return Decision(False, OFF, "capture is switched off")
    return None


def decide_folder(settings: CaptureSettings, cwd: str) -> Decision:
    text = cwd.strip()
    if "\x00" in text or not os.path.isabs(text):
        return Decision(False, NOT_ABSOLUTE, "working folder is not an absolute path")
    for folder in settings.deny_folders:
        if _denied_by(text, folder):
            return Decision(False, DENIED, f"working folder is under the denied folder {folder}")
    for folder in settings.allow_folders:
        if _allowed_by(text, folder):
            return Decision(True, IN_ALLOWED_FOLDER, f"working folder is under {folder}")
    return Decision(False, NOT_ALLOWED, "working folder is outside every allowed folder")


def decide_folders(settings: CaptureSettings, cwds: Sequence[str | None]) -> Decision:
    """Allowed only when there is a working folder and every one passes."""
    off = _off(settings)
    if off is not None:
        return off
    unique = list(dict.fromkeys(c for c in cwds if isinstance(c, str) and c.strip()))
    if not unique:
        return Decision(False, NO_FOLDER, "no working folder recorded, so scope cannot be established")
    first: Decision | None = None
    for index, cwd in enumerate(unique, start=1):
        verdict = decide_folder(settings, cwd)
        if not verdict.allowed:
            if len(unique) > 1:
                return Decision(False, verdict.reason, f"working folder {index} of {len(unique)}: {verdict.detail}")
            return verdict
        first = first or verdict
    assert first is not None
    return first


class ScopeGate:
    def __init__(self, settings: CaptureSettings) -> None:
        self.settings = settings

    def path_refusal(self, source: str, path: Path) -> Decision | None:
        off = _off(self.settings)
        if off is not None:
            return off
        for folder in self.settings.deny_folders:
            if _denied_by(str(path), folder):
                return Decision(False, DENIED, "transcript is under a denied folder")
        if source == SOURCE_CLAUDE_CODE and not any(
            _within(_real(path), _real(profile)) for profile in self.settings.claude_profiles
        ):
            return Decision(False, OUTSIDE_PROFILES, "transcript is outside every configured Claude Code profile")
        return None

    def check_path(self, source: str, path: Path, _depth: int = 0) -> tuple[Decision, str]:
        """Decide on the path and the first working folder. Returns the
        decision and the session id the transcript belongs to."""
        refusal = self.path_refusal(source, path)
        if source == SOURCE_CLAUDE_CODE:
            if refusal is not None:
                return refusal, path.stem
            probe = probe_claude(path)
        elif source == SOURCE_CODEX:
            if refusal is not None:
                return refusal, path.stem
            probe = probe_codex(path, Path(self.settings.codex_sessions))
        else:
            raise ValueError(f"unknown capture source: {source}")
        if probe.parent_session_id:
            parent = self._parent(source, probe.parent_session_id, probe.parent_path, _depth)
            if not parent.allowed:
                return parent, probe.session_id
        return decide_folders(self.settings, probe.cwds), probe.session_id

    def check_facts(self, facts: SessionFacts) -> Decision:
        """Decide on a fully read session: every working folder it recorded."""
        refusal = self.path_refusal(facts.source, facts.path)
        if refusal is not None:
            return refusal
        return decide_folders(self.settings, facts.cwds)

    def _parent(self, source: str, parent_id: str, parent_path: Path | None, depth: int) -> Decision:
        if parent_path is None or depth >= MAX_PARENT_DEPTH:
            return Decision(False, PARENT_UNKNOWN, f"parent session {parent_id} was not found")
        decision, _ = self.check_path(source, parent_path, depth + 1)
        if decision.allowed:
            return decision
        return Decision(False, PARENT_REFUSED, f"parent session {parent_id} is refused ({decision.reason})")


__all__ = [
    "DENIED",
    "Decision",
    "INVALID",
    "IN_ALLOWED_FOLDER",
    "NOT_ALLOWED",
    "OFF",
    "ScopeGate",
    "SOURCE_CODEX",
    "decide_folder",
    "decide_folders",
]
