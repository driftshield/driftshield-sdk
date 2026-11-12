"""Local session capture: which agent sessions on this machine may be sent.

One settings file (``capture.toml``) names the folders whose sessions may be
read, the folders that never are, and the terms scrubbed from the redacted
copy before anything leaves the machine. ``driftshield capture dry-run``
lists what would be sent and why everything else is skipped, without
sending anything. See ``docs/capture.md``.
"""

from driftshield.capture.config import (
    CONFIG_ENV,
    CaptureSettings,
    config_path,
    load_settings,
    template,
)
from driftshield.capture.scope import Decision, ScopeGate, decide_folders
from driftshield.capture.scrub import BlockedTerms

__all__ = [
    "BlockedTerms",
    "CONFIG_ENV",
    "CaptureSettings",
    "Decision",
    "ScopeGate",
    "config_path",
    "decide_folders",
    "load_settings",
    "template",
]
