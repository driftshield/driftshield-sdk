"""Capture one session: decide, scrub, send, record.

:meth:`CaptureService.capture_path` is the only way in. In order:

1. the scope gate on the path and first working folder, then every working
   folder once the session is read (``scope.py``); a refusal sends nothing,
2. Codex subagent threads, empty sessions and unfinished turns wait,
3. the content hash: content already sent, on the wire, held, or inside a
   retry wait is not sent again,
4. the API key (``DRIFTSHIELD_API_KEY`` or ``API_KEY``, else the telemetry
   config's ``remote_api_key``),
5. :func:`driftshield.public.analyse_run`, then the blocked terms scrub on the
   redacted copy; over ``hold_over`` hits, or anything left after the scrub,
   holds the session and it is never retried for that content,
6. :func:`driftshield.public.submit` on the workspace lane, with
   ``agent_id`` ``<prefix>:<agent>`` and the folder's project,
7. the outcome in the ledger and the status log, then extension hooks.
"""

from __future__ import annotations

import dataclasses
import os
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from driftshield.capture.config import CaptureSettings
from driftshield.capture.dry_run import project_for
from driftshield.capture.ledger import (
    Ledger,
    LedgerUnreadable,
    content_hash,
    iso,
    parse_iso,
    utc_now,
)
from driftshield.capture.scope import Decision, ScopeGate
from driftshield.capture.sessions import AGENT_FOR_SOURCE, SOURCE_CODEX, SessionFacts, read_session

SENT = "submitted"
UNCHANGED = "unchanged"
IN_FLIGHT = "in_flight"
RETRY_WAIT = "retry_wait"
FAILED = "failed"
HELD = "held_blocked_terms"
REFUSED = "refused"
NOT_FINISHED = "not_finished"
EMPTY = "empty"
SKIPPED_SUBAGENT = "skipped_codex_subagent"
NO_KEY = "api_key_missing"
LEDGER_UNREADABLE = "ledger_unreadable"
UNREADABLE = "transcript_unreadable"
BACKFILL_AFTER_HOURS = 24
# Stable per revision: the same content always analyses to the same run id.
RUN_ID_NAMESPACE = uuid.UUID("0b6f1c62-9a3e-5d47-8e2b-3c4d5e6f7a81")
API_KEY_ENV_VARS = ("DRIFTSHIELD_API_KEY", "API_KEY")


@dataclass(frozen=True, slots=True)
class Outcome:
    status: str
    detail: str
    submission_id: str | None = None
    reason: str | None = None
    hits: int | None = None

    @property
    def sent(self) -> bool:
        return self.status == SENT


@dataclass(frozen=True, slots=True)
class SendRequest:
    path: Path
    run_id: uuid.UUID
    source_session_id: str
    source_report_id: str
    workflow_reference: str
    project_reference: str | None
    agent_id: str
    model_name: str | None
    backfill: bool


class Held(Exception):
    def __init__(self, hits: int) -> None:
        super().__init__(f"{hits} blocked term hits")
        self.hits = hits


class SendFailed(Exception):
    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind


class Sender(Protocol):
    def send(
        self, request: SendRequest, settings: CaptureSettings, key: str
    ) -> tuple[str, str | None]:
        """Analyse, scrub and submit. Returns (submission id, processing status).
        Raises Held or SendFailed."""
        ...


def _scrub_secret(text: str, key: str) -> str:
    return text.replace(key, "[redacted]") if key and len(key) >= 4 else text


class SdkSender:
    """The public API: ``analyse_run`` then ``submit(visibility="workspace")``."""

    def send(
        self, request: SendRequest, settings: CaptureSettings, key: str
    ) -> tuple[str, str | None]:
        from driftshield.public import (
            NoParseableEventsError,
            SubmitError,
            UnsupportedFormatError,
            analyse_run,
            submit,
        )

        try:
            run = analyse_run(
                request.path.read_bytes(), source=request.path.name, run_id=request.run_id
            )
        except (NoParseableEventsError, UnsupportedFormatError) as exc:
            raise SendFailed("shape", _scrub_secret(str(exc), key)) from exc
        except OSError as exc:
            raise SendFailed("unreadable", type(exc).__name__) from exc
        cleaned, hits = settings.blocked.scrub(run.redacted_transcript)
        # Identifiers sent beside the transcript are not rewritten: a hit
        # in any of them holds the session whatever the limit.
        fields = [
            request.project_reference,
            request.workflow_reference,
            request.model_name,
            request.path.name,
            request.source_session_id,
            request.source_report_id,
            request.agent_id,
        ]
        field_hits = settings.blocked.count([f for f in fields if f])
        if field_hits or settings.blocked.held(hits) or settings.blocked.count(cleaned):
            raise Held(hits + field_hits)
        if hits:
            run = dataclasses.replace(run, redacted_transcript=cleaned)
        try:
            receipt = submit(
                run,
                visibility="workspace",
                key=key,
                source_session_id=request.source_session_id,
                workflow_reference=request.workflow_reference,
                project_reference=request.project_reference,
                source_report_id=request.source_report_id,
                agent_id=request.agent_id,
                model_name=request.model_name,
                backfill=request.backfill,
                include_analysis=True,
            )
        except SubmitError as exc:
            raise SendFailed("network", _scrub_secret(str(exc), key)) from exc
        return receipt.submission_id, receipt.processing_status


def resolve_key(environ: dict[str, str] | None = None) -> str | None:
    env = os.environ if environ is None else environ
    for name in API_KEY_ENV_VARS:
        value = env.get(name, "").strip()
        if value:
            return value
    from driftshield.telemetry import TelemetryService

    return TelemetryService().load_config().remote_api_key


def workflow_reference(agent: str, project: str | None) -> str:
    slug = project.replace("/", "-").lower() if project else "no-project"
    return f"capture/{agent}/{slug}"


class CaptureService:
    def __init__(
        self,
        settings: CaptureSettings,
        ledger: Ledger,
        *,
        sender: Sender | None = None,
        gate: ScopeGate | None = None,
        after_submit: Sequence[Callable[[dict[str, Any]], None]] | None = None,
        key: Callable[[], str | None] = resolve_key,
        now: Callable[[], datetime] = utc_now,
        project: Callable[[str | None, str | None], str | None] = project_for,
    ) -> None:
        self.settings = settings
        self.ledger = ledger
        self.sender = sender or SdkSender()
        from driftshield.capture.extensions import NONE, load_extensions

        extensions = load_extensions() if gate is None or after_submit is None else NONE
        self.gate = gate or ScopeGate(settings, extensions.scope_rules())
        if after_submit is None:
            after_submit = extensions.after_submit_hooks()
        self.after_submit = tuple(after_submit)
        # Part of the watch tick's settle fingerprint: a change decides again.
        self.extension_names: tuple[str, ...] = extensions.names
        self.key = key
        self.now = now
        self.project = project

    def capture_path(
        self, source: str, path: Path, *, trigger: str = "manual", force: bool = False
    ) -> Outcome:
        decision, session_id = self.gate.check_path(source, path)
        if not decision.allowed:
            return self._refused(source, session_id, path, decision, trigger)
        try:
            facts = read_session(source, path)
        except OSError as exc:
            return self._unreadable(source, session_id, exc, trigger)
        decision = self.gate.check_facts(facts)
        if not decision.allowed:
            return self._refused(source, facts.session_id, path, decision, trigger)
        return self._capture(facts, trigger, force)

    # -- internals -------------------------------------------------------------------------

    def _unreadable(self, source: str, session_id: str, exc: OSError, trigger: str) -> Outcome:
        self.ledger.log(
            source=source,
            session_id=session_id,
            outcome=UNREADABLE,
            detail=type(exc).__name__,
            trigger=trigger,
        )
        return Outcome(UNREADABLE, f"transcript unreadable: {type(exc).__name__}")

    def _refused(
        self, source: str, session_id: str, path: Path, decision: Decision, trigger: str
    ) -> Outcome:
        self.ledger.log(
            source=source,
            session_id=session_id,
            outcome=REFUSED,
            reason=decision.reason,
            trigger=trigger,
        )
        return Outcome(REFUSED, f"{decision.reason}: {decision.detail}", reason=decision.reason)

    def _note(
        self, facts: SessionFacts, status: str, detail: str, trigger: str, **extra: Any
    ) -> Outcome:
        self.ledger.log(
            source=facts.source,
            session_id=facts.session_id,
            outcome=status,
            trigger=trigger,
            **extra,
        )
        return Outcome(
            status, detail, **{k: v for k, v in extra.items() if k in ("submission_id", "hits")}
        )

    def _capture(self, facts: SessionFacts, trigger: str, force: bool) -> Outcome:
        if facts.source == SOURCE_CODEX and facts.is_subagent:
            return self._note(
                facts, SKIPPED_SUBAGENT, "Codex subagent threads are not sent", trigger
            )
        if facts.record_count == 0:
            return self._note(facts, EMPTY, "no parseable records", trigger)
        if not facts.turn_complete:
            return self._note(facts, NOT_FINISHED, "last record is not a finished turn", trigger)
        try:
            digest = content_hash(facts.path)
        except OSError as exc:
            return self._unreadable(facts.source, facts.session_id, exc, trigger)
        now = self.now()
        key: str | None = None
        try:
            with self.ledger.transaction() as ledger:
                item = ledger.entry(facts.source, facts.session_id, facts.path)
                last = item.get("last_decision")
                decision: dict[str, Any] = last if isinstance(last, dict) else {}
                if decision.get("content_hash") == digest and decision.get("status") == HELD:
                    hits = decision.get("hits")
                    return Outcome(HELD, f"held: {hits} blocked term hits", hits=hits)
                if ledger.has_revision(item, digest):
                    return Outcome(UNCHANGED, "this content was already sent")
                if ledger.in_flight(item, digest, now):
                    return Outcome(IN_FLIGHT, "this content is being sent")
                failure = item.get("failure") if isinstance(item.get("failure"), dict) else None
                if failure and failure.get("content_hash") == digest and not force:
                    retry = parse_iso(failure.get("next_retry_at"))
                    if retry is not None and now < retry:
                        return Outcome(RETRY_WAIT, f"next retry at {failure.get('next_retry_at')}")
                key = self.key()
                if key:
                    item["in_flight"] = {"content_hash": digest, "started_at": iso(now)}
                else:
                    ledger.record_failure(item, digest, NO_KEY, "no API key", now)
        except LedgerUnreadable as exc:
            return Outcome(LEDGER_UNREADABLE, f"ledger unreadable ({exc}); nothing sent")
        if not key:
            detail = "set DRIFTSHIELD_API_KEY or the telemetry remote_api_key"
            return self._note(facts, NO_KEY, detail, trigger)
        request = self._request(facts, digest, now)
        try:
            submission_id, status = self.sender.send(request, self.settings, key)
        except Held as held:
            with self.ledger.transaction() as ledger:
                item = ledger.entry(facts.source, facts.session_id, facts.path)
                item["in_flight"] = None
                item["failure"] = None
                item["last_decision"] = {"content_hash": digest, "status": HELD, "hits": held.hits}
            detail = f"held: {held.hits} blocked term hits"
            return self._note(facts, HELD, detail, trigger, hits=held.hits)
        except SendFailed as failed:
            return self._failed(facts, digest, failed.kind, str(failed), trigger)
        except Exception as exc:  # noqa: BLE001 - one bad session must never end the tick
            return self._failed(facts, digest, "unexpected", type(exc).__name__, trigger)
        with self.ledger.transaction() as ledger:
            item = ledger.entry(facts.source, facts.session_id, facts.path)
            ledger.record_success(
                item, digest, submission_id, status, request.source_report_id, self.now()
            )
        outcome = self._note(
            facts,
            SENT,
            f"submission_id={submission_id}",
            trigger,
            submission_id=submission_id,
            project_reference=request.project_reference,
            agent_id=request.agent_id,
        )
        record = {
            "source": facts.source,
            "session_id": facts.session_id,
            "path": str(facts.path),
            "cwds": list(facts.cwds),
            "is_subagent": facts.is_subagent,
            "parent_session_id": facts.parent_session_id,
            "submission_id": submission_id,
            "project_reference": request.project_reference,
            "content_hash": digest,
        }
        for hook in self.after_submit:
            try:
                hook(record)
            except Exception as exc:  # noqa: BLE001 - the submission already landed
                self.ledger.log(
                    session_id=facts.session_id,
                    outcome="extension_failed",
                    detail=type(exc).__name__,
                )
        return outcome

    def _failed(
        self, facts: SessionFacts, digest: str, kind: str, error: str, trigger: str
    ) -> Outcome:
        with self.ledger.transaction() as ledger:
            item = ledger.entry(facts.source, facts.session_id, facts.path)
            item["in_flight"] = None
            record = ledger.record_failure(item, digest, kind, error, self.now())
        return self._note(
            facts,
            FAILED,
            f"{kind}: {error}",
            trigger,
            kind=kind,
            attempts=record["attempts"],
            next_retry_at=record["next_retry_at"],
        )

    def _request(self, facts: SessionFacts, digest: str, now: datetime) -> SendRequest:
        agent = AGENT_FOR_SOURCE[facts.source]
        agent_id = self.settings.agent_id(agent)
        project = self.project(facts.cwd, self.settings.project)
        report_id = f"{facts.session_id}@{digest[:16]}"
        last = parse_iso(facts.last_timestamp)
        return SendRequest(
            path=facts.path,
            run_id=uuid.uuid5(RUN_ID_NAMESPACE, f"{agent_id}:{report_id}"),
            source_session_id=facts.session_id,
            source_report_id=report_id,
            workflow_reference=workflow_reference(agent, project),
            project_reference=project,
            agent_id=agent_id,
            model_name=facts.model_name,
            backfill=last is not None and now - last > timedelta(hours=BACKFILL_AFTER_HOURS),
        )

    def retry_due(self, *, trigger: str = "retry") -> list[tuple[str, Outcome]]:
        now = self.now()
        due = []
        for item in self.ledger.failures():
            retry = parse_iso(item["failure"].get("next_retry_at"))
            if retry is None or now >= retry:
                due.append(item)
        out = []
        for item in due:
            path = Path(str(item.get("path")))
            source = str(item.get("source"))
            if not path.exists() or source not in AGENT_FOR_SOURCE:
                continue
            out.append((str(item["key"]), self.capture_path(source, path, trigger=trigger)))
        return out


__all__ = [
    "CaptureService",
    "FAILED",
    "HELD",
    "Held",
    "Outcome",
    "REFUSED",
    "SENT",
    "SdkSender",
    "SendFailed",
    "SendRequest",
    "Sender",
    "UNCHANGED",
    "resolve_key",
]
