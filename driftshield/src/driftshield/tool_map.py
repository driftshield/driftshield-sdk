"""What each tool an agent calls does, by tool name.

A tool map is a table from a tool name (lower case, exact match) to one kind. The engine
only judges a step it can place: a shell command is classified from its command line, and
any other tool is judged by the kind its map gives it. A tool with no entry is not checked;
it is never treated as safe.

Kinds:

- ``read``: looks at something and changes nothing.
- ``check``: reads the thing about to be changed, so it counts as checking first.
- ``outside_write``: changes a system of record outside the agent's own space.
- ``outside_send``: sends data beyond the owner's own systems.
- ``delete_outside``: deletes or cancels something outside the agent's own space.
- ``confirmation``: a person was asked and answered.
- ``handoff``: work passed to a person or another agent.
- ``ignore``: never judged.
- ``shell``: runs a shell command; the command line decides what the step does.
- ``file_write``: edits a file in the agent's own checkout.

:data:`DEFAULT_CODING_MAP` holds the tools of the supported coding agents. A map file can
add to it entry by entry, or switch it off with ``"coding_defaults": false``::

    {"version": 3, "coding_defaults": false,
     "tools": {"lookup_claim": "check", "issue_payment": "outside_write"}}

Only tool names are read, never arguments, so a map works on redacted transcripts too.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any

TOOL_MAP_ENV = "DRIFTSHIELD_TOOL_MAP"

KINDS: tuple[str, ...] = (
    "read",
    "check",
    "outside_write",
    "outside_send",
    "delete_outside",
    "confirmation",
    "handoff",
    "ignore",
    "shell",
    "file_write",
)


class ToolMapError(ValueError):
    """A tool map that cannot be read: bad JSON, a wrong shape or an unknown kind."""


@dataclass(frozen=True)
class ToolMap:
    """Tool name (lower case) to kind. Build one with :func:`load_tool_map` or :func:`tool_map_from_dict`."""

    tools: Mapping[str, str] = field(default_factory=dict)
    version: int | None = None

    def __post_init__(self) -> None:
        clean: dict[str, str] = {}
        for name, kind in self.tools.items():
            if not isinstance(name, str) or not name.strip():
                raise ToolMapError("tool names must be non empty strings")
            if kind not in KINDS:
                raise ToolMapError(f"unknown kind {kind!r} for tool {name!r}; known kinds: {', '.join(KINDS)}")
            clean[name.strip().lower()] = kind
        object.__setattr__(self, "tools", MappingProxyType(clean))

    def kind_for(self, name: object) -> str | None:
        """The kind of tool ``name``, or ``None`` when the map does not name it."""
        if not isinstance(name, str):
            return None
        return self.tools.get(name.lower())

    def names(self, *kinds: str) -> frozenset[str]:
        """Every tool name whose kind is one of ``kinds``."""
        return frozenset(name for name, kind in self.tools.items() if kind in kinds)

    def merged_over(self, base: ToolMap) -> ToolMap:
        """This map's entries on top of ``base``, entry by entry."""
        return ToolMap(tools={**base.tools, **self.tools}, version=self.version)


DEFAULT_CODING_MAP = ToolMap(
    tools={
        # Shell tools across the supported agents: Claude Code Bash, OpenClaw exec and bash, Codex.
        "bash": "shell",
        "exec": "shell",
        "shell": "shell",
        "shell_command": "shell",
        "exec_command": "shell",
        "local_shell": "shell",
        # A person is asked a question or for approval.
        "askuserquestion": "confirmation",
        "request_user_input": "confirmation",
        # File edits in the own checkout.
        "write": "file_write",
        "edit": "file_write",
        "apply_patch": "file_write",
        # Reads and searches.
        "read": "read",
        "read_file": "read",
        "cat": "read",
        "grep": "read",
        "glob": "read",
        "search": "read",
        "web_search": "read",
        "web_fetch": "read",
        "memory_search": "read",
        "memory_get": "read",
        # Work passed to a person or another agent.
        "message": "handoff",
        "sessions_send": "handoff",
        "sessions_spawn": "handoff",
        "subagents": "handoff",
        "agent": "handoff",
    }
)

# Views of the default map that the coding rules read.
SHELL_TOOL_NAMES = DEFAULT_CODING_MAP.names("shell")
CONFIRMATION_TOOLS = DEFAULT_CODING_MAP.names("confirmation")


def tool_map_from_dict(data: object) -> ToolMap:
    """Build a map from its JSON shape: ``{"version": n, "coding_defaults": bool, "tools": {...}}``.

    ``coding_defaults`` (default true) puts the entries on top of :data:`DEFAULT_CODING_MAP`.
    """
    if not isinstance(data, Mapping):
        raise ToolMapError("a tool map is a JSON object")
    unknown = set(data) - {"version", "coding_defaults", "tools"}
    if unknown:
        raise ToolMapError(f"unknown tool map keys: {', '.join(sorted(map(str, unknown)))}")
    tools = data.get("tools", {})
    if not isinstance(tools, Mapping):
        raise ToolMapError("'tools' must be an object of tool name to kind")
    version = data.get("version")
    if version is not None and (not isinstance(version, int) or isinstance(version, bool)):
        raise ToolMapError("'version' must be an integer")
    defaults = data.get("coding_defaults", True)
    if not isinstance(defaults, bool):
        raise ToolMapError("'coding_defaults' must be true or false")
    own = ToolMap(tools=dict(tools), version=version)
    return own.merged_over(DEFAULT_CODING_MAP) if defaults else own


def load_tool_map(path: str | os.PathLike[str] | None = None) -> ToolMap | None:
    """Read a map file, or the file named by ``DRIFTSHIELD_TOOL_MAP`` when ``path`` is None.

    Returns ``None`` when neither is given.
    """
    chosen = path if path is not None else os.environ.get(TOOL_MAP_ENV) or None
    if chosen is None:
        return None
    try:
        data: Any = json.loads(Path(chosen).read_text(encoding="utf-8"))
    except OSError as error:
        raise ToolMapError(f"cannot read tool map {chosen}: {error.strerror or error}") from error
    except json.JSONDecodeError as error:
        raise ToolMapError(f"tool map {chosen} is not valid JSON: {error.msg}") from error
    return tool_map_from_dict(data)
