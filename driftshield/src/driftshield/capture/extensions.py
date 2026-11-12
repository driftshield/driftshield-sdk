"""Capture extensions: optional hooks another package registers.

An extension is any object registered under the ``driftshield.capture.extensions``
entry point group. It may define either hook:

* ``scope_rule(settings, cwd) -> Decision | None``: asked for each working
  folder after the denied folders and before the allowed ones. Return a
  Decision to allow or refuse that folder, or None to leave it to the
  allowed folders. A denied folder is refused before any extension is asked.
* ``after_submit(record) -> None``: called after a submission is accepted,
  with a dict holding the session id, source, path, working folders,
  submission id and project. A failure here never fails the capture.

The SDK ships with no extensions. One that cannot be loaded is skipped and
reported by ``driftshield capture status``; skipping one can only refuse
more, never allow more.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from importlib.metadata import entry_points
from typing import Any

GROUP = "driftshield.capture.extensions"


@dataclass(frozen=True, slots=True)
class Extensions:
    loaded: tuple[tuple[str, Any], ...] = ()
    failed: tuple[str, ...] = field(default_factory=tuple)

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(name for name, _ in self.loaded)

    def scope_rules(self) -> tuple[Any, ...]:
        return tuple(
            obj.scope_rule for _, obj in self.loaded if callable(getattr(obj, "scope_rule", None))
        )

    def after_submit_hooks(self) -> tuple[Any, ...]:
        return tuple(
            obj.after_submit
            for _, obj in self.loaded
            if callable(getattr(obj, "after_submit", None))
        )


NONE = Extensions()


def load_extensions() -> Extensions:
    loaded: list[tuple[str, Any]] = []
    failed: list[str] = []
    for entry in entry_points(group=GROUP):
        try:
            obj = entry.load()
        except Exception:  # noqa: BLE001 - a broken extension is skipped and reported
            failed.append(entry.name)
            continue
        loaded.append((entry.name, obj))
    return Extensions(tuple(loaded), tuple(failed))


__all__ = ["Extensions", "GROUP", "NONE", "load_extensions"]
