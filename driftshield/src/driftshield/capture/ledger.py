"""Durable capture state in ``$DRIFTSHIELD_HOME/capture/``.

* ``ledger.json``: one entry per run (``<source>:<session id>``) with the
  revisions sent (content hash, submission id), the current failure with
  its retry time, the last decision that sent nothing, and an in flight
  marker. Entries are kept as plain dicts and unknown fields are written
  back untouched, so a ledger written by another tool keeps its extra state.
* ``status.jsonl``: append only, one line per decision or attempt. Counts,
  ids and reasons only; never transcript text and never a blocked term.

Retries back off 60 s, 120 s, 240 s, ... up to one hour. A failure stays
until a later attempt succeeds. An unreadable ledger is reported, never
treated as empty, and nothing is sent while it is unreadable.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import tempfile
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from driftshield.capture.config import capture_home

LEDGER_VERSION = 1
RETRY_BASE_SECONDS = 60
RETRY_CAP_SECONDS = 3600
IN_FLIGHT_STALE_SECONDS = 15 * 60


def ledger_home() -> Path:
    configured = os.environ.get("DRIFTSHIELD_CAPTURE_HOME")
    return Path(configured).expanduser() if configured else capture_home() / "capture"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat(timespec="seconds")


def parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def content_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class Ledger:
    def __init__(self, home: Path | None = None) -> None:
        self.home = home or ledger_home()
        self.path = self.home / "ledger.json"
        self.status_path = self.home / "status.jsonl"
        self.lock_path = self.home / "ledger.lock"
        self.meta: dict[str, Any] = {}
        self.runs: dict[str, dict[str, Any]] = {}
        self.extra: dict[str, Any] = {}
        self.unreadable: str | None = None
        self._load()

    # -- file ------------------------------------------------------------------------------

    def _load(self) -> None:
        self.meta, self.runs, self.extra, self.unreadable = {}, {}, {}, None
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            self.unreadable = f"{type(exc).__name__}"
            return
        if not isinstance(data, dict):
            self.unreadable = "ledger is not a JSON object"
            return
        self.meta = dict(data["meta"]) if isinstance(data.get("meta"), dict) else {}
        self.extra = {k: v for k, v in data.items() if k not in ("meta", "runs", "version")}
        for item in data.get("runs", []):
            if isinstance(item, dict) and isinstance(item.get("key"), str):
                self.runs[item["key"]] = item

    def _save(self) -> None:
        self.home.mkdir(parents=True, exist_ok=True)
        payload = {
            **self.extra,
            "version": LEDGER_VERSION,
            "meta": self.meta,
            "runs": list(self.runs.values()),
        }
        fd, temp = tempfile.mkstemp(dir=self.home, prefix=".ledger-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=1, sort_keys=True)
                handle.write("\n")
            os.chmod(temp, 0o600)
            os.replace(temp, self.path)
        finally:
            if os.path.exists(temp):
                os.unlink(temp)

    @contextlib.contextmanager
    def transaction(self) -> Iterator[Ledger]:
        """Re-read under an exclusive lock, yield, write back."""
        self.home.mkdir(parents=True, exist_ok=True)
        with open(self.lock_path, "a", encoding="utf-8") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                self._load()
                if self.unreadable:
                    raise LedgerUnreadable(self.unreadable)
                yield self
                self._save()
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def log(self, **fields: Any) -> None:
        self.home.mkdir(parents=True, exist_ok=True)
        record = {"at": iso(utc_now()), **{k: v for k, v in fields.items() if v is not None}}
        with self.status_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")

    def read_status(self, limit: int) -> list[dict[str, Any]]:
        if not self.status_path.exists() or limit <= 0:
            return []
        with self.status_path.open("rb") as handle:
            handle.seek(0, 2)
            handle.seek(max(0, handle.tell() - 256 * 1024))
            lines = handle.read().decode("utf-8", errors="replace").splitlines()
        out: list[dict[str, Any]] = []
        for line in lines[-limit:]:
            with contextlib.suppress(json.JSONDecodeError):
                record = json.loads(line)
                if isinstance(record, dict):
                    out.append(record)
        return out

    # -- entries ---------------------------------------------------------------------------

    def entry(self, source: str, session_id: str, path: Path) -> dict[str, Any]:
        key = f"{source}:{session_id}"
        item = self.runs.setdefault(
            key,
            {
                "key": key,
                "source": source,
                "session_id": session_id,
                "path": str(path),
                "revisions": [],
            },
        )
        item["path"] = str(path)
        item.setdefault("revisions", [])
        return item

    @staticmethod
    def has_revision(item: dict[str, Any], digest: str) -> bool:
        return any(
            isinstance(r, dict) and r.get("content_hash") == digest
            for r in item.get("revisions", [])
        )

    @staticmethod
    def in_flight(item: dict[str, Any], digest: str, now: datetime) -> bool:
        marker = item.get("in_flight")
        if not isinstance(marker, dict) or marker.get("content_hash") != digest:
            return False
        started = parse_iso(marker.get("started_at"))
        return started is not None and (now - started).total_seconds() < IN_FLIGHT_STALE_SECONDS

    @staticmethod
    def record_failure(
        item: dict[str, Any], digest: str, kind: str, error: str, now: datetime
    ) -> dict[str, Any]:
        previous = item.get("failure") if isinstance(item.get("failure"), dict) else None
        attempts = (
            int(previous.get("attempts", 0)) + 1
            if previous and previous.get("content_hash") == digest
            else 1
        )
        delay = min(RETRY_CAP_SECONDS, RETRY_BASE_SECONDS * 2 ** (attempts - 1))
        failure = {
            "content_hash": digest,
            "attempts": attempts,
            "kind": kind,
            "last_error": error[:500],
            "last_attempt_at": iso(now),
            "next_retry_at": iso(now + timedelta(seconds=delay)),
        }
        item["failure"] = failure
        return failure

    @staticmethod
    def record_success(
        item: dict[str, Any],
        digest: str,
        submission_id: str,
        status: str | None,
        report_id: str,
        now: datetime,
    ) -> dict[str, Any]:
        revisions = item.setdefault("revisions", [])
        revision = {
            "content_hash": digest,
            "revision": len(revisions) + 1,
            "submission_id": submission_id,
            "processing_status": status,
            "submitted_at": iso(now),
            "source_report_id": report_id,
        }
        revisions.append(revision)
        item["failure"] = None
        item["in_flight"] = None
        item["last_decision"] = None
        return revision

    def failures(self) -> list[dict[str, Any]]:
        return [item for item in self.runs.values() if isinstance(item.get("failure"), dict)]

    def held(self) -> list[dict[str, Any]]:
        return [
            item
            for item in self.runs.values()
            if isinstance(item.get("last_decision"), dict)
            and item["last_decision"].get("status") == "held_blocked_terms"
        ]


class LedgerUnreadable(RuntimeError):
    pass


__all__ = [
    "Ledger",
    "LedgerUnreadable",
    "content_hash",
    "iso",
    "ledger_home",
    "parse_iso",
    "utc_now",
]
