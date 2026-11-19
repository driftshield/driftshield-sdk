# `driftshield.events.v1`: the neutral event format

For an agent that writes none of the transcript formats DriftShield already reads (Claude
Code, Codex, OpenClaw, CrewAI, LangChain and the others in `docs/public-api.md`). Write your
agent's log in this shape once; after that, telling DriftShield what your tools do is a
settings file (a tool map), not code.

## The format

JSON Lines: one JSON object per line, in the order things happened. Every line carries
`"schema": "driftshield.events.v1"`, which is also how the format is detected.

| Field | Required | Meaning |
|-------|----------|---------|
| `schema` | yes | Always `driftshield.events.v1`. |
| `session_id` | yes | One id for the whole run. |
| `timestamp` | yes | ISO 8601, for example `2026-11-12T10:02:00Z`. |
| `type` | yes | `message`, `tool_call`, `tool_result`, `confirmation` or `handoff`. |
| `actor` | no | A role, never a person's name: `user`, `agent`, `person` or `system`. |
| `tool` | on `tool_call` | The tool name, exactly as the tool map names it (case does not matter, spaces do). Optional on `confirmation` and `handoff`. |
| `call_id` | on `tool_call` and `tool_result` | Ties a result to its call. |
| `input` | no | The tool input, any JSON value. |
| `output` | no | The tool output, any JSON value. |
| `status` | on `tool_result` | `ok` or `error`. |
| `error` | no | Error text on a failed result. |
| `text` | no | The words of a `message`, `confirmation` or `handoff`. |

- `message`: something a user, the system or the agent said. A `person` (an underwriter, a
  claims handler) is read as a human, like `user`.
- `tool_call` and `tool_result`: the agent called a tool, and what came back. A result with no
  earlier call of the same `call_id` is skipped.
- `confirmation`: a person was asked and answered. A tool the tool map calls `confirmation`
  counts the same.
- `handoff`: work passed to a person or another agent.

Lines that are not JSON, not objects, carry no `schema` or have an unknown `type` are skipped
and counted, never fatal.

## Privacy

Before anything leaves your machine (`driftshield submit`), `input`, `output` and `text` are
replaced with placeholders and `error` is dropped, as for every other format. What stays:
`schema`, `session_id`, `timestamp`, `type`, `actor`, `tool`, `call_id`, `status`, and the
fixed list `step_facts` the tool map gives each mapped tool call. Tool names are kept, so do
not put personal data in a tool name.

## Worked example: an insurance claims agent

[`examples/insurance-claims/session.jsonl`](examples/insurance-claims/session.jsonl) is a
claims assistant settling a claim. Its tool map,
[`examples/insurance-claims/tool_map.json`](examples/insurance-claims/tool_map.json), says what
each tool does:

```json
{"version": 1, "coding_defaults": false,
 "tools": {"lookup_claim": "check", "update_claim_status": "outside_write",
           "issue_payment": "outside_write", "email_broker": "outside_send",
           "cancel_policy": "delete_outside", "request_underwriter_approval": "confirmation",
           "transfer_to_human": "handoff", "log_note": "ignore", "search_documents": "read"}}
```

```console
$ driftshield analyze docs/examples/insurance-claims/session.jsonl \
    --tool-map docs/examples/insurance-claims/tool_map.json
...
Tool map: 7 of 8 tool calls checked
Not checked (not in the tool map): fetch_weather_report (1)
Signature hits: mechanism:verification_failure
```

What it found, step by step:

1. `lookup_claim` is a check.
2. `update_claim_status` came right after that check: checked, fine.
3. `issue_payment` came after another outside write with no new check: **unchecked**.
4. `email_broker` sends data outside, again with no check: **unchecked**.
5. `fetch_weather_report` is not in the map, so it is **not checked**. It is never counted as
   safe.
6. `cancel_policy` had no check either, but an underwriter approved it first
   (`request_underwriter_approval`), so it is excused.

Verification failure fires on steps 3 and 4. Without the tool map the same session has no
findings at all, because nothing says what `issue_payment` does: that silence is what the
coverage line makes visible.

To fail a CI job on it, add `--fail-on verification_failure`: the run exits 1 and prints
`FAIL: verification_failure check fired in ...` on stderr.

In Python:

```python
from driftshield import analyse_run
from driftshield.tool_map import load_tool_map

run = analyse_run(
    open("session.jsonl", "rb").read(),
    tool_map=load_tool_map("tool_map.json"),
)
run.signature_hits   # verification_failure
run.tool_coverage    # {"tool_calls": 8, "mapped_calls": 7, "not_checked_tools": {...}, ...}
```

See the README section on the tool map for every kind and how a check, an outside step and a
confirmation are judged.
