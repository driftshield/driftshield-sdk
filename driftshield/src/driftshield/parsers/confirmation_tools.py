"""Tool calls that ask the user a question or for approval.

A call to one of these is recorded as a confirmation checkpoint, so the
verification rules can see that a person was asked before an outside step.
The names come from the default coding tool map.
"""

from __future__ import annotations

from driftshield.tool_map import CONFIRMATION_TOOLS


def is_confirmation_tool(name: object) -> bool:
    return isinstance(name, str) and name.lower() in CONFIRMATION_TOOLS
