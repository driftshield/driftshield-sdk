# How DriftShield checks a run

```
Transcript → Parser → Canonical Events → Decision Graph → Risk Heuristics → Report
```

1. **Parsers** read raw transcripts and produce a sequence of canonical events (tool calls, outputs, branches, handoffs, assumptions, constraint checks)
2. **Graph builder** connects events into a decision tree with parent/child relationships
3. **Risk heuristics** scan every node for failure patterns
4. **Inflection detection** scores points in the session where the agent's trajectory changed
5. **Reports** present findings as Markdown, JSON, or through the web dashboard

## Tools that are not shell commands: the tool map

A shell step is judged from its command line. Any other tool (`issue_payment`,
`cancel_policy`, `email_broker`) is judged only if a tool map says what it does. A tool map is
a JSON file from tool name to kind:

```json
{
  "version": 1,
  "coding_defaults": false,
  "tools": {
    "lookup_claim": "check",
    "search_documents": "read",
    "update_claim_status": "outside_write",
    "issue_payment": "outside_write",
    "email_broker": "outside_send",
    "cancel_policy": "delete_outside",
    "request_underwriter_approval": "confirmation",
    "transfer_to_human": "handoff",
    "log_note": "ignore"
  }
}
```

Kinds: `read` (changes nothing), `check` (reads the thing about to be changed),
`outside_write`, `outside_send` (sends data beyond your own systems), `delete_outside`,
`confirmation` (a person was asked and answered), `handoff`, `ignore`, and for coding agents
`shell` and `file_write`. The coding agent tools above are in the default map; a map file adds
to it entry by entry, or switches it off with `"coding_defaults": false`. Pass it with
`driftshield analyze --tool-map map.json` (or `DRIFTSHIELD_TOOL_MAP`), or
`analyse_run(..., tool_map=load_tool_map("map.json"))`.

A mapped tool gets `step_facts` from its name alone: `check` is `read_only`, `outside_write`
stays `outside_write`, `outside_send` is `send_outside` and `delete_outside` is `delete`, all
on an `outside_service`. A check counts like a read in a shell step for `checked_before`.
`unchecked_tool_step` is true for a mapped outside call with no check since the previous
outside step and no confirmation earlier in the run; the verification failure check fires on it. It
needs no stated safeguard in the instructions, since the map already says the tool is risky.
The analysis reports how many tool calls the map named and lists any tools it did not
name, so you can add them. Only tool names are read, never arguments.

## What counts as a failure

A run qualifies as a failure (`qualification_state` is `qualified_failure`) when the
transcript reads cleanly and shows a material gap between what was asked and what
happened. Two kinds of evidence count:

- A risk detector fired on at least one step (see the table below).
- The session ended on a tool call that reported an error and no later tool call
  completed. This is the failure signal for coding agent sessions such as Claude
  Code, which rarely carry the inputs the risk detectors need. The verdict names the
  reason `unrecovered_tool_error_at_session_end` and the break point is that final
  failed call.

A tool error the agent recovered from is not a failure on its own, but recovery needs
evidence tied to the failure: a later completed call of the same tool on the same
command or target (the failed test rerun and passing, the file that failed to write
written). A later call that merely succeeded at something else clears nothing. The
failed event records the recovering call as `recovered_by`, or a `recovery_reason`
code saying why none counted. A failure the run carried on past without recovering
also qualifies, with that failed call as the break point. A run with neither kind of
evidence is `unclassified`, not a success claim.

## OSS scope and product boundary

This public repo is the OSS recognition and investigation layer.

It includes:

- transcript parsing and ingestion
- per-run investigation and reporting
- community signature-pack support
- public-safe dashboards, CLI flows, and API paths for failed-run analysis

It does not by itself claim to provide:

- controlled cross-run recurrence tracking
- organisation-level prioritisation or ranking
- governance, assurance, or enterprise workflow policy layers

If a public sentence sounds like a bundled promise about what repeats across runs or what matters most across an organisation, it is too strong for this OSS surface.
