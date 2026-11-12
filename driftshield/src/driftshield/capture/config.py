"""The capture settings file: ``$DRIFTSHIELD_HOME/capture.toml``.

``DRIFTSHIELD_HOME`` defaults to ``~/.driftshield``; ``DRIFTSHIELD_CAPTURE_CONFIG``
points at another file. Missing file means capture is off. A file that does
not parse, or holds a value that cannot be used, turns capture off and says
why: nothing ever falls back to a wider default.

    enabled = false
    workspace = "my-workspace"
    level = "default"
    project = "my-org/my-project"

    [allow]
    folders = ["~/code/my-project"]

    [deny]
    folders = ["~/code/my-project/private"]

    [sources]
    claude_profiles = ["~/.claude"]
    codex_sessions = "~/.codex/sessions"
    main_sessions = true
    main_idle_minutes = 30

    [scrub]
    terms = []
    terms_from_folders = []
    ignore = []
    token = "[blocked-term]"
    hold_over = 3

    [upload]
    agent_id_prefix = "driftshield-capture"

The API key is never in this file.
"""

from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from driftshield.capture.scrub import DEFAULT_HOLD_OVER, DEFAULT_TOKEN, BlockedTerms, folder_names

CONFIG_ENV = "DRIFTSHIELD_CAPTURE_CONFIG"
FILE_NAME = "capture.toml"
LEVEL_DEFAULT = "default"
# Only today's level exists; more levels are a later change.
LEVELS = (LEVEL_DEFAULT,)
DEFAULT_AGENT_ID_PREFIX = "driftshield-capture"
DEFAULT_CLAUDE_PROFILES = ("~/.claude",)
DEFAULT_CODEX_SESSIONS = "~/.codex/sessions"
DEFAULT_MAIN_IDLE_MINUTES = 30

_KEYS: dict[str, set[str]] = {
    "": {"enabled", "workspace", "level", "project", "allow", "deny", "sources", "scrub", "upload"},
    "allow": {"folders"},
    "deny": {"folders"},
    "sources": {"claude_profiles", "codex_sessions", "main_sessions", "main_idle_minutes"},
    "scrub": {"terms", "terms_from_folders", "ignore", "token", "hold_over"},
    "upload": {"agent_id_prefix"},
}
_PROJECT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9._-]+$")
_PREFIX = re.compile(r"^[a-z0-9][a-z0-9._-]{0,47}$")


def capture_home() -> Path:
    configured = os.environ.get("DRIFTSHIELD_HOME")
    return Path(configured).expanduser() if configured else Path.home() / ".driftshield"


def config_path() -> Path:
    configured = os.environ.get(CONFIG_ENV, "").strip()
    return Path(configured).expanduser() if configured else capture_home() / FILE_NAME


def _expand(path: str) -> str:
    return os.path.expanduser(path.strip())


@dataclass(frozen=True, slots=True)
class CaptureSettings:
    path: Path
    enabled: bool = False
    # Set when the file could not be used. Set, every session is refused.
    invalid: str | None = None
    missing: bool = False
    workspace: str | None = None
    level: str = LEVEL_DEFAULT
    project: str | None = None
    allow_folders: tuple[str, ...] = ()
    deny_folders: tuple[str, ...] = ()
    claude_profiles: tuple[str, ...] = tuple(_expand(p) for p in DEFAULT_CLAUDE_PROFILES)
    codex_sessions: str = _expand(DEFAULT_CODEX_SESSIONS)
    main_sessions: bool = True
    main_idle_seconds: int = DEFAULT_MAIN_IDLE_MINUTES * 60
    blocked: BlockedTerms = field(default_factory=BlockedTerms)
    agent_id_prefix: str = DEFAULT_AGENT_ID_PREFIX

    @property
    def active(self) -> bool:
        return self.enabled and self.invalid is None

    def agent_id(self, agent: str) -> str:
        return f"{self.agent_id_prefix}:{agent}"

    def describe(self) -> list[str]:
        if self.missing:
            return [f"Capture: OFF (no settings file at {self.path}; `driftshield capture init` writes one)"]
        if self.invalid:
            return [f"Capture: OFF, settings file {self.path} is invalid: {self.invalid}"]
        return [
            f"Capture: {'ON' if self.enabled else 'OFF'}  settings: {self.path}",
            f"  workspace: {self.workspace or '(not named)'}  level: {self.level}  "
            f"project: {self.project or '(from git)'}",
            f"  allowed folders: {', '.join(self.allow_folders) or '(none: nothing is read)'}",
            f"  denied folders: {', '.join(self.deny_folders) or '(none)'}",
            f"  Claude Code profiles: {', '.join(self.claude_profiles) or '(none)'}",
            f"  Codex sessions: {self.codex_sessions}",
            f"  main sessions: {'yes' if self.main_sessions else 'no'} "
            f"(sent after {self.main_idle_seconds // 60} quiet minutes)",
            f"  {self.blocked.describe()}",
            f"  agent_id: {self.agent_id('<agent>')}",
        ]

    def to_dict(self) -> dict[str, Any]:
        """Everything but the blocked terms, which are counted, never shown."""
        return {
            "path": str(self.path),
            "enabled": self.enabled,
            "active": self.active,
            "invalid": self.invalid,
            "missing": self.missing,
            "workspace": self.workspace,
            "level": self.level,
            "project": self.project,
            "allow_folders": list(self.allow_folders),
            "deny_folders": list(self.deny_folders),
            "claude_profiles": list(self.claude_profiles),
            "codex_sessions": self.codex_sessions,
            "main_sessions": self.main_sessions,
            "main_idle_seconds": self.main_idle_seconds,
            "blocked_terms": {
                "listed": len(self.blocked.terms),
                "folder_names": len(self.blocked.folder_terms),
                "hold_over": self.blocked.hold_over,
                "fingerprint": self.blocked.fingerprint(),
            },
            "agent_id_prefix": self.agent_id_prefix,
        }


class _Invalid(Exception):
    pass


def _strings(table: dict[str, Any], key: str, name: str, default: list[str]) -> tuple[str, ...]:
    value = table.get(key, default)
    if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
        raise _Invalid(f"{name} must be a list of non empty strings")
    return tuple(v.strip() for v in value)


def _folders(table: dict[str, Any], key: str, name: str) -> tuple[str, ...]:
    out = []
    for item in _strings(table, key, name, []):
        expanded = _expand(item)
        if not os.path.isabs(expanded):
            raise _Invalid(f"{name} entry {item!r} is not an absolute path")
        out.append(expanded)
    return tuple(out)


def _bool(table: dict[str, Any], key: str, name: str, default: bool) -> bool:
    value = table.get(key, default)
    if not isinstance(value, bool):
        raise _Invalid(f"{name} must be true or false")
    return value


def _int(table: dict[str, Any], key: str, name: str, default: int, minimum: int) -> int:
    value = table.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise _Invalid(f"{name} must be a whole number, at least {minimum}")
    return value


def _parse(path: Path, data: dict[str, Any]) -> CaptureSettings:
    tables: dict[str, dict[str, Any]] = {"": data}
    for name in ("allow", "deny", "sources", "scrub", "upload"):
        table = data.get(name, {})
        if not isinstance(table, dict):
            raise _Invalid(f"[{name}] is not a table")
        tables[name] = table
    for name, table in tables.items():
        extra = sorted(set(table) - _KEYS[name])
        if extra:
            where = f"[{name}]" if name else "the top level"
            raise _Invalid(f"unknown key(s) in {where}: {', '.join(extra)}")
    top, allow, deny = tables[""], tables["allow"], tables["deny"]
    sources, scrub, upload = tables["sources"], tables["scrub"], tables["upload"]

    level = top.get("level", LEVEL_DEFAULT)
    if level not in LEVELS:
        raise _Invalid(f"level {level!r} is not one of {', '.join(LEVELS)}")
    workspace = top.get("workspace")
    if workspace is not None and not isinstance(workspace, str):
        raise _Invalid("workspace must be a string")
    project = top.get("project")
    if project is not None and (not isinstance(project, str) or not _PROJECT.match(project)):
        raise _Invalid("project must be owner/name")

    allow_folders = _folders(allow, "folders", "allow.folders")
    home = os.path.realpath(Path.home())
    for folder in allow_folders:
        real = os.path.realpath(folder)
        if real == os.sep or home.startswith(real.rstrip(os.sep) + os.sep) or real == home:
            raise _Invalid(f"allow.folders entry {folder!r} contains the home folder")
    deny_folders = _folders(deny, "folders", "deny.folders")

    profiles = tuple(
        _expand(p) for p in _strings(sources, "claude_profiles", "sources.claude_profiles", list(DEFAULT_CLAUDE_PROFILES))
    )
    codex = sources.get("codex_sessions", DEFAULT_CODEX_SESSIONS)
    if not isinstance(codex, str) or not os.path.isabs(_expand(codex)):
        raise _Invalid("sources.codex_sessions must be an absolute path")

    token = scrub.get("token", DEFAULT_TOKEN)
    if not isinstance(token, str) or not token.strip():
        raise _Invalid("scrub.token must be a non empty string")
    blocked = BlockedTerms(
        terms=_strings(scrub, "terms", "scrub.terms", []),
        folder_terms=folder_names(
            _folders(scrub, "terms_from_folders", "scrub.terms_from_folders"),
            _strings(scrub, "ignore", "scrub.ignore", []),
        ),
        token=token,
        hold_over=_int(scrub, "hold_over", "scrub.hold_over", DEFAULT_HOLD_OVER, 0),
    )
    pattern = blocked.pattern()
    if pattern is not None and pattern.search(token):
        raise _Invalid("scrub.token contains a blocked term")

    prefix = upload.get("agent_id_prefix", DEFAULT_AGENT_ID_PREFIX)
    if not isinstance(prefix, str) or not _PREFIX.match(prefix):
        raise _Invalid("upload.agent_id_prefix must be lower case letters, digits, '.', '_' or '-'")

    return CaptureSettings(
        path=path,
        enabled=_bool(top, "enabled", "enabled", False),
        workspace=workspace.strip() or None if isinstance(workspace, str) else None,
        level=level,
        project=project,
        allow_folders=allow_folders,
        deny_folders=deny_folders,
        claude_profiles=profiles,
        codex_sessions=_expand(codex),
        main_sessions=_bool(sources, "main_sessions", "sources.main_sessions", True),
        main_idle_seconds=60
        * _int(sources, "main_idle_minutes", "sources.main_idle_minutes", DEFAULT_MAIN_IDLE_MINUTES, 1),
        blocked=blocked,
        agent_id_prefix=prefix,
    )


def load_settings(path: Path | None = None) -> CaptureSettings:
    path = path or config_path()
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return CaptureSettings(path=path, missing=True)
    except (OSError, UnicodeDecodeError) as exc:
        return CaptureSettings(path=path, invalid=f"unreadable: {type(exc).__name__}")
    try:
        return _parse(path, tomllib.loads(text))
    except tomllib.TOMLDecodeError as exc:
        return CaptureSettings(path=path, invalid=f"not TOML: {exc}")
    except _Invalid as exc:
        return CaptureSettings(path=path, invalid=str(exc))


def template() -> str:
    return '''# DriftShield capture settings. Only sessions whose working folders are all
# under [allow] are ever read; [deny] wins over [allow]. Check what this lets
# through before switching it on, with nothing sent:
#   driftshield capture dry-run --days 14

enabled = false                        # the on/off switch
workspace = ""                         # a label for the workspace your API key points at
level = "default"                      # capture level; only "default" exists today
# project = "my-org/my-project"        # sent as the project when a folder is no git repo

[allow]
folders = []                           # e.g. ["~/code/my-project"]

[deny]
folders = []                           # folders never read, even inside an allowed one

[sources]
claude_profiles = ["~/.claude"]        # Claude Code config folders to read transcripts from
codex_sessions = "~/.codex/sessions"
main_sessions = true                   # whole sessions, not only subagents
main_idle_minutes = 30                 # wait this long after the last write

[scrub]
# Applied to the redacted copy just before upload. Each hit becomes `token`;
# a session with more than `hold_over` hits is held, not sent.
terms = []                             # names you never want sent
terms_from_folders = []                # every folder name in these is a blocked word
ignore = []                            # folder names that are ordinary words
token = "[blocked-term]"
hold_over = 3

[upload]
agent_id_prefix = "driftshield-capture"
'''


__all__ = [
    "CONFIG_ENV",
    "CaptureSettings",
    "DEFAULT_AGENT_ID_PREFIX",
    "LEVELS",
    "capture_home",
    "config_path",
    "load_settings",
    "template",
]
