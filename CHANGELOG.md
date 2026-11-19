# Changelog

All notable changes to `driftshield` are recorded here. The GitHub release
notes for each tag are taken from the matching section of this file.

## Unreleased

- `driftshield analyze` prints its signature hits (`Signature hits: mechanism:...`, or `none`)
  for every session, not only with `--tool-map`; with no map the default coding map applies,
  as in the rules. `--json` gains a `signature_hits` list for every session, with the same
  shape as before; no field is renamed or removed, and `tool_coverage` still appears only with
  a tool map.

## 0.3.6 - 2026-11-19

### Tool maps, a neutral event format and two false alarms fewer

In short: a tool map tells DriftShield what each tool of a non coding agent does, so
verification failure can judge those tools too, and a new neutral event format lets any agent
send its runs. With no map, results are the same as 0.3.5 apart from two false alarms fewer:
a pull request read after a heredoc in the same step is now seen. Rules version
`phase-3g-deterministic-rules-v6`, step facts `step-facts.v7`.

- New `driftshield.tool_map` module: a table from tool name to what the tool does (`read`,
  `check`, `outside_write`, `outside_send`, `delete_outside`, `confirmation`, `handoff`,
  `ignore`, `shell`, `file_write`). `DEFAULT_CODING_MAP` holds the tools of the supported
  coding agents; the shell tool list, the confirmation tool list and the file edit tool list
  are now read from it. No change to any result.
- Rules and step facts read an optional tool map: `analyse_run(..., tool_map=...)` and
  `driftshield analyze --tool-map map.json` (or `DRIFTSHIELD_TOOL_MAP`). A tool the map names
  as `check`, `outside_write`, `outside_send` or `delete_outside` gets step facts from its name;
  verification failure fires on a mapped outside call with no check since the previous outside
  step and no confirmation before it. Tools the map does not name are reported as not checked
  (`AnalysedRun.tool_coverage`). Step facts version `step-facts.v7` (new command kind
  `send_outside`, new field `unchecked_tool_step`) and rules version
  `phase-3g-deterministic-rules-v6`. With no map, every flag and every step fact is the same as
  0.3.5 apart from the new `unchecked_tool_step: false` key, checked on 96 local sessions.
- New neutral event format `driftshield.events.v1` (JSON Lines, format name
  `driftshield_events_v1`) for agents with no transcript format DriftShield reads: messages,
  tool calls and results, confirmations and handoffs. Detected from content, redacted like every
  other format. `docs/events-v1.md` describes it, with a worked insurance claims session and its
  tool map in `docs/examples/insurance-claims/`. No change to existing formats or results.
- A pull request read that follows a heredoc in the same shell step now counts. An apostrophe
  in a heredoc body (a pull request description) opened a quote that hid the statements after
  it, so a `gh pr view` loop just before a merge was missed and the merge was flagged. Heredoc
  bodies fed to anything but a shell are now skipped as text, and their words no longer count
  as reads. Step facts stay `step-facts.v7`, which no release has sent yet. On 138 local
  sessions this removes two founder labelled false alarms and keeps all 9 labelled real
  failures (#315).

## 0.3.5 - 2026-11-19

### Verification failure: fewer false alarms, one more shape

In short: three false alarms from the 0.3.4 session gate are gone, a merge through
`gh api -i` is judged, and the check now also fires when a run starts an agent's work on an
issue without reading it first. On the same 131 local sessions it catches all 8 failures a
person labelled real, with no false alarms.

- A loop over list items such as `repo:157`, `repo/157` or `owner/repo/157` now names that
  pull request for the read inside the loop. The 0.3.4 session gate had three false alarms
  where the verdict was read this way just before the merge.
- A bare `git push` after `cd` into another checkout pushes that checkout's branch, not the
  pull request the run last opened. In one of the three false alarms, a docs fix pushed to a
  different pull request's checkout made the merged one look unread again.
- A merge through `gh api -i .../pulls/N/merge` is judged. `-i` there is `--include` and no
  longer swallows the endpoint.
- New: verification failure also fires when a run adds the label that starts an agent's work
  on an issue (`agent:go`) with no fresh read of that issue. A read is fresh when it is in
  the same command, or in the previous ten shell steps and after the run's own last edit,
  comment or label change on that issue in an earlier step. Three steps in the 0.3.4 gate
  sessions, labelled real failures by a person, have this shape. Other labels, labels in a
  variable and removals are not judged. A start label added to a pull request
  (`gh pr edit N --add-label agent:go`) is not judged either, only one added to an issue;
  it still counts as a write to N for freshness. New step fact `unread_start_label`
  (`true` or `false`); only the boolean leaves.
- The step facts version is now `step-facts.v6` and the matching rules version is
  `phase-3g-deterministic-rules-v5`.

## 0.3.4 - 2026-11-18

### Findings you can trust: checks, merges and refused edits

- A check now only excuses the next outside step after it. One recognised check early in a
  run no longer excuses every later merge, deploy or push to main, so the verification
  failure check can fire on long sessions.
- A merge counts as checked only when that same pull request was read since its last
  outside step. A read of another pull request, a local read, a test or a build no longer
  checks it, and moving the pull request's base or head clears the earlier read.
- Housekeeping on pull requests and issues (comments, body edits, closing, labels and the
  like) is low risk and no longer counts as an outside write. Two classifier slips are
  fixed, and Claude Code auto mode denials count as refused edits.
- State conflict ignores edits the tool refused. The SDK sorts each tool error into a fixed
  list (`none`, `precondition_failed`, `permission_denied`, `conflict`, `not_found`,
  `timeout`, `other`) on your machine, and only the label is sent.
- The matching rules version is now `phase-3g-deterministic-rules-v4` and the step facts
  version is `step-facts.v5`. Every upload says which versions made it, so findings from the
  earlier rules can be told apart from these.

### Verification failure fires only on an unread merge of the run's own pull request

- The 0.3.4 session gate showed the broad check firing on 153 steps in 44 sessions at 3.3%
  precision: most flags were checks the SDK cannot see (a verdict watcher script, release
  smoke scripts, merge command shapes). The check now judges one shape: a merge of pull
  request N when the run opened N (`gh pr create`, whose result shows N's link) or pushed to
  N's branch, and no read of N came between the last open or push and the merge.
- A read is generous: any statement naming N (by number, link or branch) that runs `gh`,
  `curl`, a script or a shell function, inside loops and `$(...)` too, and a read earlier in
  the merge command itself. A diff of N is not a read.
- Deploys, pushes to main, deletes, other outside writes and merges of a pull request the run
  did not open or push to no longer fire this check. A confirmation before the merge still
  excuses it. `checked_before` is still worked out and sent as before.
- New step fact `unread_own_merge` (`true` or `false`); only the boolean leaves. Part of
  `step-facts.v5` and `phase-3g-deterministic-rules-v4`, both unreleased. Intel reads step
  facts from a fixed key list and ignores the new key.

### Housekeeping is low risk, two classifier slips, and auto mode denials

- Housekeeping on a pull request or an issue, including someone else's, is `unknown` and no
  longer `outside_write`, so it neither fires the verification check nor ends the scope of
  an earlier check: a comment, a body edit, closing or reopening, a draft toggle, creating an
  issue or a label, a sub issue link and a branch update, through `gh`
  or `gh api`. A merge, a deploy, a push to main, a release, a delete, a secret or variable
  change, a repo, ruleset, ref or collaborator change, a review, a workflow dispatch and
  adding a label in any written form (both can start an automated run) keep their kind.
  A flag that deletes makes the call a `delete`: `gh pr close --delete-branch` (or `-d`, also
  combined as `-dc msg`) deletes the remote head branch, and `gh pr comment` or
  `gh issue comment` with `--delete-last` deletes a comment. Taking a project, milestone,
  assignee or reviewer off (`--remove-project`, `--remove-milestone`, `--remove-assignee`,
  `--remove-reviewer`) is `outside_write`; `--remove-label` stays housekeeping.
- `aws s3 cp` from S3 to a local path is `read_only`, not `outside_write`. `gh api -X GET`
  stays `read_only` even with `-f` or `-F` fields, which are query parameters there.
- A permission refusal worded "permission for this action was denied" or "denied by the
  auto mode classifier" (the Claude Code auto mode) is read as `permission_denied`, so a
  refused edit is not a state conflict. A remote or hook rejection that only says "denied
  by" is not a permission refusal.
- No new value is added to any fixed list.

### A check excuses an outside step only until the next outside step

- Before, one recognised check anywhere earlier in a run excused every later merge, deploy
  or push to main, so the verification failure check rarely fired on long sessions. Now a
  check counts only if it came after the previous outside step, or after the start of the run
  for the first one, or earlier in the same command line (`cd x; git status; vercel --prod`).
  `gh pr view 1`, then merge 1, then merge 2 leaves merge 2 unconfirmed. A confirmation step
  before an outside step still counts.
- A step that stays in the agent's own space (a local delete or commit) does not start a new
  scope, and a failed outside step does.
- `checked_before` changed, which is part of step facts `v5`.

### Three narrow bypasses closed

- A merge chained with another write is checked by a read of its own pull request, whatever
  the step's kind is. `gh pr merge 5 && vercel --prod` after `ls` is unchecked (it was a
  deploy, so any earlier read excused it). Every merge among the write parts must be tied to
  its own pull request, also when it comes after the other write
  (`vercel --prod && gh pr merge 5`); the other write keeps the scoped rule. A step with no
  merge is read no further than that.
- `gh pr update-branch N` and `gh pr edit N --base X` (also `-B`, `gh api` `update-branch` and
  a `base` field) can change what gets merged, so they clear an earlier read of pull
  request N: a merge after them is unchecked until the pull request is read again. They stay
  housekeeping (they do not fire or end the scope of an outside step).
- A GraphQL mutation cannot hide behind commas or `#` comments: strings and comments are
  told apart in one pass (a `#` inside a string is text, and a quote inside a comment is
  text), the mutation fields are read after removing them, an alias does not hide the field
  behind it, and a document the reader cannot place (unbalanced, an unterminated string, no
  mutation, only fragment spreads) is not housekeeping and keeps `outside_write`.
- A GraphQL mutation that moves the base or the head of a pull request (`baseRefName`,
  `headRefName`, `updatePullRequestBranch`) names it by node id, so it clears every earlier
  read of any pull request: the next merge is unchecked until its pull request is read again.
  Only a `gh api graphql` mutation does this: a plain read that asks for those fields
  (`gh pr view 6 --json headRefName,baseRefName`) keeps every other read. A head or base
  change (`gh pr edit --base`, `gh pr update-branch`, a `gh api` update-branch or base field)
  that names no pull request or that the reader cannot parse clears every read. A base flag on
  a command that changes no pull request (`gh pr list --base main`, `gh pr create --base
  main`) keeps every read.
- A merge is never left to the scoped check rule: a merge statement the reader calls unsafe
  (`PATH=./evil gh pr merge 5`, a `$(...)` in the body), a merge inside a substitution or a
  merge step with no statement it can read as one is unchecked, even after an unrelated step.
- No value is added to any fixed list.

### A merge is checked only by a read of its own pull request

- A merge (`gh pr merge N`, `gh api .../pulls/N/merge`) now counts as checked only when that
  same pull request's state, checks, reviews or comments were read since the previous outside
  step on it, or earlier in the same command line. That includes inside `$(...)` or a loop that
  is only reads (`until gh pr checks 5 | grep -q pass; do sleep 10; done; gh pr merge 5`, or
  `gh pr merge 5 --match-head-commit $(gh pr view 5 --json headRefOid -q .headRefOid)`).
  A local read (`git log`, `ls`), a test, a build, a read of another pull request, and a custom
  script never check a merge. A pull request created and merged with nothing reading it in
  between still fires.
- Inside `$(...)` or a loop only allowlisted reads and `sleep` count. Another command, a
  redirect to a file, a nested substitution or a write makes that part unsafe, and nothing
  before the merge is trusted. A merge whose number cannot be read from the command (a
  variable, `$(...)`, the current branch) is not checked.
- The number is worked out on your machine from the command and only the `checked_before`
  boolean leaves. No value was added to any fixed step facts list.
- The tie applies to merges only. Every other outside step (a deploy, a push to main, a
  delete, an outside write) keeps the scoped rule whatever its command looks like, so a check
  in an earlier step still counts for a deploy written with a redirect, a subshell, brackets or
  an `if` block. A merge in a command the reader cannot parse is not checked.
- A merge of pull request N in any repository form (`gh pr merge 5 -R o/r`) clears an earlier
  read of N with the same or an unknown repository, so a stale read does not check a later
  merge.
- A write inside a loop body or an `if` branch is now found as its own write kind
  (`while ...; do git push origin main; done` is a `git_push`). Before, it was `unknown`.
  Other outside steps keep the scoped rule above.

### State conflict ignores edits the tool refused

- A Claude Code `Edit` refused because the text to replace was not found, a write that
  was blocked by permissions, a missing file and a timeout all wrote nothing, but each
  counted as a state conflict if the run had read a file earlier. State conflict now fires
  only on a rejected write whose reason is a conflict or one the fixed lists do not name
  (`other`). It never fires on `precondition_failed` or `permission_denied`.
- To tell them apart after redaction, step facts carry a new field, `error_class`, picked
  from a fixed list: `none`, `precondition_failed`, `permission_denied`, `conflict`,
  `not_found`, `timeout`, `other`. It is read from the failed result's text on your
  machine before redaction, and only the label leaves. Every shell step carries it. Any
  other tool call gets step facts only when its result was an error. No error text, path
  or hash is sent. The README lists the values.
- The class is read only from the lead line, from later lines that start like an error and
  from the error fields of a JSON result, so a stray word such as "timeout" or "stale" in a
  quoted snippet or a stack frame does not change it. `404` and `409` count only as HTTP
  status tokens (`HTTP/1.1 409`, `status 404`), never inside an id, a hash or a line number.
  Step facts are `step-facts.v5`.
- A write that fails with no step facts or no error class (an older upload) does not count
  as a conflict: the reason is unknown, so the check errs towards missing.

## 0.3.3 - 2026-11-14

### Findings you can trust: local analysis works out step facts, and state conflict needs a real conflict

- Local analysis now works out step facts, so the open source verification failure check
  can fire on a real unconfirmed outside step, and state conflict fires only on a real
  conflicting write. The verification failure check now gives the same answer on your
  machine as it does for an upload.
- The matching rules version is now `phase-3g-deterministic-rules-v3`. Every upload says
  which version made it (`metadata.analyser.matching_rules_version`), so findings from the
  earlier rules can be told apart from these.

### Checks joined by `;` or a newline, quiet redirects, `sleep`, and help calls

- A check before a merge or deploy is no longer thrown away because of shell punctuation.
  Parts joined by `;` or a newline are read like parts joined by `&&`: each part is still
  classified on its own, a write kind in any part still wins (`ls; rm -rf x` is `delete`,
  `git status; git push origin main` is `git_push` on `main_branch`), and the step is a check
  only when every part is an allowlisted check. So `cd x; git status` is `read_only`.
- Redirects that write no file are ignored: `2>&1`, `1>&2`, `>/dev/null`, `2>/dev/null` and
  `&>/dev/null`. A redirect to a real file still makes the step `unknown`.
- `sleep N` is skipped in a chain like `cd`. Still refused: `python`, `node`, `awk`, `xargs`,
  `bash -c`, `sh -c`, `eval`, `tee`, loops, heredocs, `export PATH=`, `$(...)` and backticks.
- Asking a deploy tool for help is `unknown`, no longer `deploy`: `--help`, `-h`, `-help` or
  `help` as the first argument, or a help flag right after the subcommand (`terraform apply
  -help`), for a fixed list of deploy tools. `git` and `gh` are never downgraded, and a help
  word that is an option value, a remote, a name or a body (`git -C help push origin main`,
  `gh pr comment 3 --body -h`, `docker push help`) keeps its kind.
- Opening a pull request through `gh api` (a write to `.../pulls`) is `unknown`, like
  `gh pr create`.
- The step facts version is now `step-facts.v4` (it was `v3`). The matching rules version
  stays `phase-3g-deterministic-rules-v3`: no rule's firing logic changed, only which steps
  count as checks.

### jq and yq count as checks only when they are plain filters

- A `jq` stage inside a chain of checks (`gh pr view 1 --json comments | jq
  '.comments[].body'`, `cat f.json | jq .x`) and single `gh` reads with their own filter
  (`gh pr view N --json comments -q '...'`, `--jq '...'`, `gh api <path> --jq '...'` as a GET
  with no `-X` write verb and no `-f` or `-F` fields) already counted as checks, and still do.
- 0.3.3 narrows `jq` and `yq` to plain filters. A `jq` call with a flag that reads another
  file (`--rawfile`, `--slurpfile`, `--argfile`, `-f`, `--from-file`) or loads modules (`-L`,
  `--library-path`, an `import` or `include` in the program) is now `unknown`, and so is
  `yq` with `-s`, `--split-exp` or `-f`, because they write or read other files. Before,
  those forms were wrongly counted as checks. A pipe into any other interpreter (`python`,
  `node`, `ruby`, `perl`, `sh`, `awk`) is still never a check.
- The step facts version is now `step-facts.v3` (it was `v2`). The matching rules version
  stays `phase-3g-deterministic-rules-v3`: no rule's firing logic changed, only which steps
  count as checks.

### Local analysis computes step facts like an upload

- Local analysis (`analyse_run`, `driftshield analyze` on a raw Claude Code, OpenClaw or
  Codex transcript) now computes step facts with the same fixed list classifier as an upload,
  so the verification failure check gives the same answer locally as it would for the upload.
  Before this, step facts were only computed while redacting, so a local analysis never
  reported a verification failure (0.3.1 and 0.3.2).
- What is uploaded does not change: the shared copy and the redacted copy are made exactly as
  before. A `step_facts` key already present in a transcript is never believed for a command
  that can be read.

### State conflict fires only on a rejected write

- The state conflict check used to fire on any failed read or write, including a failure
  that was only wording in the text (a "failed" or "error" word in a result that
  succeeded). A file that did not exist yet, read and then created, was reported as a
  state conflict. It now fires only on a write the tool reported as an error, after the
  run had already read something. A failed read alone, a write that succeeds and failure
  wording alone never fire.
- Redaction replaces every tool input, so the check cannot tell whether the read and the
  write touched the same file. A rejected write after any earlier read is the evidence.

### Verification failure counts a failed outside step

- A deploy, merge or push to main that was tried without a confirmation first now fires
  even when the command failed. The safeguard was skipped when the step was attempted.
  Before, a failed call was classed as an error and never checked.
- The unused `destructive_action_count` feature is gone. `confirmation_before_action`
  stays (a contradiction check reads it) and now means a confirmation came before the first
  outside step, not before the first tool call.

## 0.3.2 - 2026-11-13

### Uploads say which analyser made them

- Every upload now says which analyser made it, so DriftShield can count open source
  findings only from uploads checked by the current rules. Before this, a verdict made by
  0.3.1 could not be told from one made by 0.3.0, because none of the versions sent changed.
- The shared copy of each run carries `metadata.analyser`, with four fixed strings:
  `schema_version` (`analyser.v1`), `sdk_version` (the package version),
  `matching_rules_version` and `step_facts_version`. Nothing from the transcript or the
  machine goes in it, and there is no setting to leave it out. The README says exactly what
  is sent.
- The matching rules version now changes whenever a rule's behaviour changes. It had stayed
  at `phase-3g-deterministic-rules-v1` although 0.3.1 rewrote the verification failure rules.
  `phase-3g-deterministic-rules-v2` is the 0.3.1 rule set, and it is what 0.3.2 sends. A test
  pins the behaviour of every bundled fixture per version, so a change to a rule without a
  new version fails the build.
- The step facts version works the same way: `step-facts.v2` is the 0.3.1 classification
  (`step-facts.v1` was 0.3.0), and it changes whenever the classification changes.

## 0.3.1 - 2026-11-13

### Step facts: fewer false writes, and chains of checks count

- A chain of read only commands is now a check. When every part is a plain
  `read_only`, `test` or `build` command with no write flag, and the parts are
  joined only by `&&`, `||` or `|`, the step is labelled as that check, so
  `cd repo && git status` and `gh pr view 1 | head` are `read_only` and set
  `checked_before` for the steps after them. Any other shell syntax, any part
  that is not an allowlisted check, or a chain of only `cd` is still `unknown`,
  and a write kind is still found in any part of a chain. Only `cd` and `pushd`
  are skipped in a chain; `export`, `PATH` changes, `hash`, `alias`, `source`,
  `.` and environment assignments can change what a later part runs, so they
  make the step `unknown`. A `cd` out of the checkout makes the target `unknown`.
- An environment assignment before a check, such as `CI=1 npm test` or
  `PYTHONPATH=src pytest`, now makes the step `unknown` instead of a check,
  because an assignment such as `PATH` or `LD_PRELOAD` can change what the
  command runs. This is stricter than 0.3.0, so runs that used these forms will
  show fewer checked steps. A write kind is still found: `FOO=1 git push origin
  main` is still a `git_push`.
- A local `git merge` is no longer labelled `merge`. `merge` means a pull
  request merge: `gh pr merge`, or `gh api` with a merge endpoint and a write
  verb.
- `gh pr create` and every `aws ... invoke` (such as `aws lambda invoke`) are
  `unknown` and no longer `outside_write`. Opening a pull request for review and
  invoking a function or model are not writes to count.

### Verification failure fires only on a skipped safeguard

- The verification failure check (`R-VER-001`, `SEQ-VER-001`) used to fire on
  any run that used a shell, write or edit tool when some instruction mentioned
  confirming or approving, because no parser ever recorded a confirmation. It
  now fires only when a step that leaves the agent's own space has no
  confirmation before it: a `git_push` to a main branch, a `merge` (not into the
  own checkout), a `deploy`, a `delete` on an outside service or an
  `outside_write`, judged from the step facts. Reads, tests, builds, unknown
  steps, local file writes and edits never fire. A run with no step facts
  (older uploads, raw local transcripts) never fires. Because step facts only
  exist on redacted uploads, local analysis (`driftshield analyze` on a raw
  transcript) no longer reports a verification failure at all; the check applies
  to a run that has been redacted for upload.
- A confirmation counts when it comes before the outside step, or when the step
  facts say `checked_before` is true.
- The Claude Code parser records an `AskUserQuestion` call, and the Codex parser a
  `request_user_input` call, as a confirmation step instead of a plain tool call.
- The instruction keyword condition (confirm, approve, permission) stays as a
  gate. It no longer makes the check fire by itself.
- State conflict and policy divergence are unchanged. Policy divergence fires
  only on a force push against a loaded rule. State conflict follows failed
  reads and writes, which needs its own change.

## 0.3.0 - 2026-11-12

### Shell steps now carry four fixed list facts

- Every tool input is still replaced by a placeholder, so a shell step that ran
  `ls` looked the same as one that ran `git push`. The redacted transcript now
  keeps one extra key on each shell tool call, `step_facts`, with four values
  that can only come from a fixed list: `command_kind` (`read_only`, `test`,
  `build`, `git_push`, `merge`, `deploy`, `delete`, `outside_write`, `unknown`),
  `target_kind` (`own_checkout`, `main_branch`, `outside_service`, `unknown`),
  `exit_status` (`success`, `failure`, `unknown`) and `checked_before` (true or
  false: an earlier shell step in the run was `read_only`, `test` or `build`). (#272)
- The labels fail closed: `read_only`, `test` and `build` are given only to
  one plain command from a fixed allowlist, with no shell operator and no flag
  that writes files, so a formatter or a `--fix` run is never a check. A write
  kind is still found anywhere in a chain.
- A write hidden inside a command substitution is found too: `$(...)` and
  backticks are read, also inside double quotes, with a fixed limit on depth
  and size so a hostile command cannot slow analysis. Comment text and here
  document text is scanned like any other text, so it can only make a step look
  more like a write, never less. (#275)
- It covers Claude Code `Bash`, OpenClaw `exec` and `bash`, and Codex shell
  calls. The Claude Code, OpenClaw and Codex parsers carry the key through to
  `tool_activity.step_facts` on the normalised events.
- Never sent: command text, paths, arguments, prompts, code, or any hash of
  them. There is no setting to switch this off or to lower it. The README says
  exactly what is sent.
- Step facts never stop an analysis. A transcript with unusual JSON in its tool
  definitions or tool inputs, such as a schema with `"type": ["string", "null"]`,
  is analysed as before. If computing the facts ever fails, the redacted copy is
  made without them and one warning logs that facts were dropped and the error
  type, never any session content. (#277, #278)
- The redactor version is now `recursive-redactor.v3.1.0` and the ruleset
  `ruleset.v4`. Redacted output for transcripts with shell steps changes, so
  expect different hashes for the same input.

### Choose which local sessions may be sent: `driftshield capture`

- New `driftshield capture` commands: `init` writes a starting
  `~/.driftshield/capture.toml` with capture switched off, `status` shows the
  settings and `dry-run` lists which recent Claude Code and Codex sessions would
  be sent and why every other one is skipped. (#273)
- A session passes only when every working folder it recorded sits inside an
  allowed folder and outside every denied folder. Denied wins over allowed.
- Blocked terms are scrubbed from the redacted copy before it would be sent, and
  a session with more hits than `hold_over` is held. The dry run counts hits per
  session and never prints them. See `driftshield/docs/capture.md`.
- `driftshield capture watch` sends finished, allowed sessions to the workspace
  lane: quiet and finished only, once per version, scrubbed just before
  `submit`, held over the limit, retried with backoff. Its window starts at the
  first tick, so nothing older is sent unless `--since` asks. `capture submit`
  sends one session, `capture install` prints a launchd agent or systemd timer,
  and `capture status` lists held and failing sessions. (#274)
- Capture extensions: the `driftshield.capture.extensions` entry point group adds
  a scope rule (after the denied folders) and an after submit hook.

### ChatGPT conversation exports

- New source `chatgpt_export`: a ChatGPT export holding a single conversation is
  analysed along the branch ending at `current_node`. An export with several
  conversations is refused with a clear message; splitting is not supported yet. (#204)

## 0.2.2 - 2026-09-11

### Codex sessions can fail, and recovery needs matching evidence

- A Codex tool call whose output reports a non zero exit code (an `exit=N`
  line or a JSON `"exit_code": N`), or a flat record carrying `is_error` or a
  non empty `error`, is now a failed tool call, with the exit code and the tail
  of the output in `failure_context`. Before this release a Codex run could not
  fail. (#208)
- A failed tool call counts as recovered only when a later completed call of
  the same tool ran the same command or touched the same target. The
  recovering event is recorded on the failed one as `recovered_by`. An
  unrelated later success, such as reading a file after a failed test, no
  longer clears the failure. A failure that stays unrecovered mid run is a
  candidate break point with the strategy `unrecovered_tool_error`. (#209)
- The Codex rollout parser fills the structured tool inputs (command, file
  paths) from JSON string arguments, so the recovery rule and tool class
  policies apply to Codex sessions. (#218)
- A Codex shell call whose output reports only a `Process exited with code N`
  line, the header Codex writes above `Output:`, is now a failed tool call when
  N is non zero, with the same `exit_code` and `failure_context` fields. The
  `exit=N` and JSON shapes keep precedence. (#220)

Verdicts change for affected runs, so re-analyse anything you compare across
versions. Expect many more candidate break points on real sessions: the
stricter recovery rule reports failures the agent never retried against the
same target.

## 0.2.1 - 2026-09-05

### A tool error never recovered before the session ends is a failure

A run whose last tool call reported an error, with no later tool call
completing, now qualifies as a failure. Before this release such a run was
`unclassified` with `no_material_delta_detected` unless a risk detector also
fired, which on coding agent sessions such as Claude Code it rarely did, so a
session that died on a failed command looked the same as a successful one.

- `qualification_state` is `qualified_failure` with the reason
  `unrecovered_tool_error_at_session_end`, and the expected versus actual
  delta carries the same delta type.
- The candidate break point is that final failed tool call, so `analyze` and
  `report` point at the call that ended the run.
- A tool error a later completed tool call recovered is still not a failure.

Verdicts change for affected runs, so re-analyse anything you compare across
versions.

## 0.2.0 - 2026-08-27

First published release on PyPI, as `driftshield-sdk`. Earlier versions were
never published, so everything below is what you get when you install it for
the first time.

The distribution is `driftshield-sdk` rather than `driftshield` because PyPI
rejected the shorter name: it strips separators when checking for collisions,
and an unrelated project called `drift-shield` has held the name since 2024.
Nothing else changes. You install `driftshield-sdk`, you `import driftshield`
and the command is still `driftshield`.

```bash
pip install driftshield-sdk
```

### The public API is two calls

The `driftshield` package now has one door: `analyse_run` and `submit`.
Everything else in the package (parsers, format detection, redaction,
signature matching, transport) is internal and can change without notice.

```python
from driftshield import analyse_run, submit

run = analyse_run(open("session.jsonl", "rb").read(), source="session.jsonl")
receipt = submit(run)  # community lane, redacted, no key needed
```

- `analyse_run(content, *, source=None, format=None, run_id=None)` analyses one
  agent run and returns an `AnalysedRun`: the parsed events, the findings
  anchored to events, community signature hits, the qualification verdict,
  the redacted transcript and any warnings. It touches no network, database
  or filesystem.
- Supported inputs: Claude Code, Codex CLI, OpenClaw session and trajectory
  JSONL; Claude Desktop, Codex Desktop, CrewAI and LangChain single document
  JSON; and a wrapper object with the records under `"events"`. Detection is
  content first. A path is only a hint and the content wins when they
  disagree.
- Parsing is best effort. Lines that cannot be read are skipped and named in
  `run.warnings` (for example `line 12: not valid JSON, skipped`). Zero
  parseable events is an error, `NoParseableEventsError`, never an empty
  success. `.reason` tells you whether the content was empty, unrecognised,
  failed to parse or yielded no events.
- Redaction happens at the share boundary. `run.redacted_transcript` is
  exactly what a submission sends; nothing leaves the machine until you call
  `submit`.
- `submit(run, visibility="community", key=None, **options)` sends the
  redacted transcript. `"community"` (the default) needs no key and lands in
  the public community dataset. `"workspace"` needs your workspace API key and
  lands in your private workspace. The CLI's `--tier oss` and `--tier teams`
  are aliases for the two lanes.
- Every CLI command (`analyze`, `batch`, `submit`, `report`, `inspect`,
  `ingest`), the self hosted `/api/ingest` route and the connector watcher go
  through the same two calls, so they agree on formats, warnings and
  redaction.

Full reference: `docs/public-api.md`.

### CLI

- `driftshield batch <dir-or-archive>` analyses every transcript in a
  directory, `.zip` or `.tar.gz`, with per file outcomes and a stable `--json`
  summary. `--submit` submits each run; `--backfill` marks workspace
  submissions as post hoc imports so they index at their original time;
  `--workflow-reference` sets or derives the workflow per source.
- `driftshield submit` is the upload path for hosted analysis, with
  `--environment` (`production`, `staging`, `test`, `demo`), `--agent-id`,
  `--model-name`, `--model-version` and `--show-manifest` to print the
  redaction manifest before anything is sent.
- `driftshield --version` reports the installed version, and so does
  `GET /api/health` on a self hosted instance.

### Fixes

- Redaction is linear time on large transcripts. Email redaction previously
  backtracked quadratically, so big runs could take minutes or appear to hang.
- Batch mode detects the format from content before trusting a path hint.
  A `.jsonl` file that parsed to zero events under the hinted parser is now
  re-detected instead of being reported as empty.
- Self hosted ingest (`POST /api/ingest`) accepts `format=auto` and every
  supported transcript shape, including the OpenClaw trajectory wrapper, in
  line with the CLI.
- Redaction keeps message content analysable instead of dropping it
  wholesale, so submitted runs no longer degrade to zero tool calls. Nested
  structures are traversed rather than discarded.
- Signature matching covers the first wave of community failure families and
  surfaces genuine tool failures in agent trajectories.

### Breaking changes

The public surface was consolidated into `analyse_run` and `submit`. The
following importable names were removed. None of them had been published on
PyPI, but if you were installing from source they no longer exist.

| Removed | Use instead |
|---------|-------------|
| `driftshield.public.analyse` | `driftshield.analyse_run` (returns `AnalysedRun` instead of a dict) |
| `driftshield.public.detect_source` | `analyse_run(...).detected_format` |
| `driftshield.public.ANALYSE_SCHEMA_VERSION` | Removed; the return type is the contract |
| `driftshield.cli.parsers` (`detect_parser`, `get_parser`, `ParserNotFoundError`) | `analyse_run(content, format=...)`; unknown names raise `UnsupportedFormatError` |
| `driftshield.cli._session_payload.load_session_payload` | `analyse_run(open(path, "rb").read(), source=str(path))` |
| `driftshield.cli._signature_summary` (`build_signature_summary_from_match`, `build_signature_summary_from_session`) | `AnalysedRun.signature_hits` and `AnalysedRun.signature_summary` |
| `driftshield.cli._submit` (`submit_session_core`, `SubmitOutcome`, `SubmitCoreError`, `IncludeAnalysisError`) | `driftshield.submit` returning `SubmitReceipt`; errors are `SubmitError` |
| `driftshield.remote_submission` (`build_redacted_payload`, `redact_payload`, `redact_payload_with_manifest`, `detect_shape`, `derive_openclaw_provenance`, `UnknownTranscriptShapeError`) | `AnalysedRun.redacted_transcript`; `submit` reads agent and model from the run |
| `driftshield.api.ingest_workflow.resolve_format` | Internal to `/api/ingest`; use `analyse_run(..., format=...)` |
| `driftshield.db.persistence.IngestProvenance` | Internal; provenance is carried on `AnalysedRun` |
| `driftshield.parsers.openclaw_trajectory.unwrap_trajectory_wrapper` | `analyse_run` unwraps the trajectory wrapper itself |

Behaviour changes to be aware of:

- Zero parseable events now raises `NoParseableEventsError` everywhere (CLI,
  API and library). Previously some paths returned an empty result.
- `submit` never retries. A transport failure raises `SubmitError` with the
  HTTP status and body.
- A key on the community lane, or no key on the workspace lane, is an error
  rather than a silent fallback.
