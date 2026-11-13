"""Tool calls that ask the user a question or for approval.

A call to one of these is recorded as a confirmation checkpoint, so the
verification rules can see that a person was asked before an outside step.
Names are lower case.
"""

from __future__ import annotations

CONFIRMATION_TOOLS = frozenset({"askuserquestion", "request_user_input"})


def is_confirmation_tool(name: object) -> bool:
    return isinstance(name, str) and name.lower() in CONFIRMATION_TOOLS
