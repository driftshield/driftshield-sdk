# Choosing which local sessions may be sent

`driftshield capture` decides which agent sessions on your machine may ever be
sent to your DriftShield workspace. Today it covers the settings, the checks and
a dry run. The upload and the background watch arrive in a later release.

Nothing is read until you list a folder, and nothing is sent until you switch
capture on.

## Start

```sh
driftshield capture init        # writes ~/.driftshield/capture.toml, capture off
driftshield capture status      # shows what the file says
driftshield capture dry-run --days 14 --report capture-dry-run.md
```

`DRIFTSHIELD_HOME` moves the folder; `DRIFTSHIELD_CAPTURE_CONFIG` points at
another settings file.

## The settings file

```toml
enabled = false                  # the on/off switch; a missing file means off
workspace = "my-workspace"       # a label for the workspace your API key points at
level = "default"                # only "default" exists today
project = "my-org/my-project"    # sent as the project when a folder is no git repo

[allow]
folders = ["~/code/my-project"]  # the only folders whose sessions are read

[deny]
folders = ["~/code/my-project/private", "~/.claude-other-profile"]

[sources]
claude_profiles = ["~/.claude"]  # Claude Code config folders to read
codex_sessions = "~/.codex/sessions"
main_sessions = true             # whole sessions, not only subagents
main_idle_minutes = 30           # wait this long after the last write

[scrub]
terms = ["my-client"]            # names you never want sent
terms_from_folders = ["~/clients"]  # every folder name in here is a blocked word
ignore = ["notes"]               # folder names that are ordinary words
token = "[blocked-term]"
hold_over = 3

[upload]
agent_id_prefix = "driftshield-capture"
```

A file that does not parse, an unknown key, a relative path or an allowed folder
that contains your whole home folder turns capture off and `status` says why.
Nothing falls back to a wider default. The API key is never in this file.

## How a session is judged

1. A Claude Code transcript must sit inside a listed profile and outside every
   denied folder. Otherwise it is refused on its path and never opened.
2. The first working folder is read: the first record with a `cwd` for Claude
   Code, `session_meta` for Codex.
3. A subagent follows its parent: the parent session must pass too.
4. Once read in full, every working folder the session recorded must pass. A
   session that moved outside the allowed folders part way through is refused.

A working folder passes when it is outside every denied folder and inside an
allowed one. Symlinks are resolved, so a link that points out of an allowed
folder does not pass. Only working folders decide; the text of a session never
does.

## Blocked terms

The redacted transcript is the only text a submission carries. Before it would
be sent, every blocked term in it is replaced with the token. `terms` match
wherever they start a word, so a term also catches its plural. Folder names from
`terms_from_folders` match as whole words. A session with more than `hold_over`
hits is held instead of sent.

Blocked terms are never printed. `status` and the dry run show how many there
are and a fingerprint of the list, and the dry run counts hits per session.

## The dry run

`dry-run` judges every session written in the last N days as if capture were on,
writes nothing and sends nothing. The report lists:

- the sessions that would be sent, with their working folder, project and
  `agent_id`,
- blocked term hits per session before and after the scrub, and which would be
  held (`--no-scrub-check` skips this slower step),
- every skipped session grouped by reason,
- how many transcripts sit in denied profile folders, counted by path without
  opening them.

Read it before setting `enabled = true`.
