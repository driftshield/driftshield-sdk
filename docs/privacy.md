# What leaves your machine

`driftshield submit` is the customer upload command. The client redacts the transcript
locally before upload. No raw transcript data leaves the machine unredacted.

See what the redactor would strip, without uploading:

```bash
driftshield submit --path <session.json> --dry-run-redaction
driftshield submit --path <session.json> --show-manifest
```

Only a small, fixed set of labels is kept for each step. This page lists them.

## What says which analyser made an upload

Every upload carries one more small block, `metadata.analyser`, next to the declared
environment in the shared copy of the run. It has four fixed strings and nothing else:

| Field | Value | Meaning |
|-------|-------|---------|
| `schema_version` | `analyser.v1` | The format of this block |
| `sdk_version` | for example `0.3.2` | The `driftshield` package version (`driftshield.__version__`). Sent as `unknown` if it is not a plain version number |
| `matching_rules_version` | for example `phase-3g-deterministic-rules-v2` | The version of the deterministic matching rules. It changes whenever a rule's firing behaviour changes |
| `step_facts_version` | for example `step-facts.v5` | The version of the step facts below: the labels of shell steps and the error class of a failed tool call. It changes whenever either changes |

They let a stored verdict or step fact be told apart from one made by an older SDK. They
come from the installed package, never from the transcript or the machine: a block already
present in a transcript is replaced. Nothing private is in them, and there is no setting to
leave them out.

## What is sent for each shell step

Redaction replaces every tool input with a placeholder, so by default nothing
tells `ls` and `git push` apart. For each shell step (Claude Code `Bash`,
OpenClaw `exec` and `bash`, and Codex shell calls) the redacted transcript
keeps one extra key, `step_facts`, with exactly the values below. Each value is
picked from a fixed list. This is always on. There is no option to turn it off
or to lower it.

| Field | Allowed values |
|-------|----------------|
| `command_kind` | `read_only`, `test`, `build`, `git_push`, `merge`, `deploy`, `delete`, `outside_write`, `send_outside`, `unknown` |
| `target_kind` | `own_checkout`, `main_branch`, `outside_service`, `unknown` |
| `exit_status` | `success`, `failure`, `unknown` |
| `checked_before` | `true` or `false` |
| `unread_own_merge` | `true` or `false` |
| `unread_start_label` | `true` or `false` |
| `unchecked_tool_step` | `true` or `false` |
| `error_class` | `none`, `precondition_failed`, `permission_denied`, `conflict`, `not_found`, `timeout`, `other` |
| `command_name` | the program and at most two subcommand words, from fixed lists (`gh pr merge`, `git push`, `pytest`, `npm run build`), or `other` |

`command_name` says what was run without saying what it was run on. It is worked out on
your machine from the same parse as `command_kind`: environment assignments, `sudo`, `env`
and runners (`uv run`, `npx`, `python -m`) are skipped, and a chain is named by the part that
gave the step its kind (`cd repo && gh pr merge 5` is `gh pr merge`). The program must be in a
fixed list of known programs and each subcommand word in a fixed list for that program, so an
argument, path, URL, branch, number, message, heredoc body, make target or script name nobody
listed never becomes part of the name. A script run by path (`./deploy.sh`) and any unlisted
program is `other`. The result must be at most three lowercase words of `a-z`, `0-9`, `.`,
`_` and `-`, each at most 32 characters, or it becomes `other`; a name carried by an already
redacted step is checked against the same shape again. A tool call that is not a shell step
and carries step facts (a tool a tool map names, or a failed call) gets its tool name,
lowercased, under the same shape rule.

`command_kind` and `target_kind` are decided on your machine by reading the
command, then only the label leaves. A command that does not match a known shape
is `unknown`. The rule is fail closed: `read_only`, `test` and `build` are only
given to a step where every part is a plain command from a fixed allowlist with
no flag that writes files, and the parts are joined only by `&&`, `||`, `|`, `;` or a newline.
`cd repo && git status` and `gh pr view 1 | head` are `read_only`. A `jq` stage is a plain filter and counts too (`gh pr view 1 --json comments | jq ...`), unless it reads another file or loads modules (`--rawfile`, `-f`, `-L`, `import`). Any other
shell syntax (brackets, `$(...)`, backticks, `&`, a comment, a heredoc, a loop), a
redirect to a file, any part that is not an allowlisted check, and a chain of only `cd`
make the step `unknown`. Redirects that write no file (`2>&1`, `>/dev/null`) are ignored.
The only things skipped in a chain are `cd`, `pushd` and `sleep N`:
`export`, `PATH` changes, `hash`, `alias`, `source`, `.` and environment
assignments such as `FOO=1 ls` can change what a later part runs, so they make
the step `unknown`. A `cd` to an absolute path, `~`, a variable or up out of the
checkout (`..`) makes the target `unknown`. A formatter, a `--fix` or `-w` run, or a
download that saves a file is never a check. A local `git merge` is `unknown`
(`merge` means a pull request merge, as in `gh pr merge`), and so are
`gh pr create`, every `aws ... invoke`, and housekeeping on pull requests and issues
(a comment, a body edit, closing, reopening, a draft toggle, creating an issue or a label,
a sub issue link, a branch update), which is low risk: it neither fires
the verification check nor ends the scope of an earlier check. A flag that deletes
(`gh pr close --delete-branch` or `-d`, `gh pr comment --delete-last`) makes the call a `delete`,
and taking a project, milestone, assignee or reviewer off (`--remove-project` and the like) is
`outside_write`. Adding a label (in any written
form), a workflow dispatch (it starts a run that can deploy), a review, a
merge, a release, a delete, a secret or variable change, and any repo, ruleset, ref or
collaborator change are not housekeeping and keep their kind. `aws s3 cp` from S3 to a local
path is a read, and `gh api -X GET` stays a read even with fields. A write
kind (`git_push`, `merge`, `deploy`, `delete`, `outside_write`) is still found
in any part of a chain, so `pytest && git push origin main` is a `git_push` on
`main_branch`. Comment and here document text is scanned like any other text and
can only make a step look more like a write, never less.
`exit_status` comes from the tool result's own error flag or exit code.
`checked_before` is true when a shell step that is `read_only`, `test` or `build` ran after
the previous outside step (a push to a main branch, a merge, a deploy, a delete on an outside
service or an outside write), or after the start of the run for the first one, or earlier in
the same command line (`cd x; git status; vercel --prod`). One early check does not excuse
every later outside step. A confirmation step before an outside step still counts.

A merge (`gh pr merge N`, `gh api .../pulls/N/merge`) is the exception: it is checked only by
a read of **that same pull request**, never by a local read, a test, a build or a read of
another pull request. The read is `gh pr view N`, `gh pr checks N`, or `gh api` on the pull
request, its reviews or its comments, and it counts if it came after the previous outside
step on that pull request, or earlier in the same command line, including inside `$(...)` or
a loop (`until gh pr checks 5 | grep -q pass; do sleep 10; done; gh pr merge 5`). Inside
`$(...)` or a loop, only reads and `sleep` count: another command, a redirect to a file, a
nested substitution or a write there makes the whole part unsafe and nothing before the
merge is trusted. A merge whose pull request number cannot be read from the command (a
variable, `$(...)`, the current branch) is not checked. The number is worked out on your
machine and never leaves: only `checked_before` is sent. Local changes such as `git commit` or `mkdir`
are `unknown`.

`unread_own_merge` and `unread_start_label` are what the verification failure check reads
for shell steps, and the only things it fires on there (for other tools, see the tool map
below). `unread_own_merge` is true for a step that merges pull request N when the run opened N (a
`gh pr create` whose result shows N's link) or pushed to N's branch, and no read of N came
between the last open or push and the merge. A read is generous: any statement naming N
(by number, link or branch) that runs `gh`, `curl`, a script or a shell function counts,
inside a loop or `$(...)` too, and so does a read earlier in the merge command itself. A
diff of N (`gh pr diff N`) is not a read: it shows the change, not whether the pull request
is ready. Deploys, pushes to main, deletes, other outside writes and merges of a pull request
the run did not open or push to never fire this check. The number, branch and link are
worked out on your machine; only the boolean leaves.

`unread_start_label` is true for a step that adds the label that starts an agent's work on
issue N (`agent:go`, by `gh issue edit N --add-label` or a `POST` to N's labels) with no
fresh read of N. A read is fresh when it is in the same command, before or after the add, or
in the previous ten shell steps and after the run's own last edit, comment or label change
on N in an earlier step. Other labels, removals and a number in a variable are not judged.
Only the boolean leaves.

## Why a failed step says why

`error_class` says why a step failed, and only a label leaves, never the error text.
It is read from the failed result on your machine before redaction hides it, by looking
for fixed phrases, in this order (the first class with a match wins). Phrases are looked
for only in the lead line (the first line, skipping an `Exit code N` header), in later
lines that start like an error (`Error:`, `fatal`, `ValueError:`, an `error` field) and in
the error fields of a JSON result. A stray word in a quoted snippet or a stack frame below
does not count. `404` and `409` count only as HTTP status tokens (`HTTP/1.1 409`,
`status 404`, `"code": "404"`, `404 Not Found`), never as a number inside an id, a hash or
a line number:

| Value | Meaning | Examples of what it matches |
|-------|---------|-----------------------------|
| `permission_denied` | The tool or the system refused the call | permission denied, `EACCES`, `EPERM`, a permission the user has not granted, a tool use the user rejected |
| `precondition_failed` | An edit was refused and nothing was written because the file was not as the edit expected | text to replace not found, more than one match, file not read yet, file changed since it was read, a patch that did not apply |
| `conflict` | Two writers disagreed | a merge conflict, already exists, `EEXIST`, HTTP 409, a version mismatch |
| `not_found` | The target is missing | `ENOENT`, no such file, command not found |
| `timeout` | The call ran out of time | timed out, `ETIMEDOUT` |
| `other` | The call failed for a reason none of the lists name | everything else that failed |
| `none` | The step did not fail, or its reason could not be read | |

Every shell step carries `error_class`. Any other tool call (an edit, a write, a read)
gets a `step_facts` block only when its result was an error, with `command_kind` and
`target_kind` set to `unknown` and the reason in `error_class`. A call that worked has no
`step_facts`. A value that is not in the list, or no value at all (an older upload), reads
as `none`. State conflict uses it: a write the tool rejected after an earlier read counts
only when the class is `conflict` or `other`, never for `precondition_failed`,
`permission_denied`, `not_found` or `timeout`, where nothing was written.

Never sent: the command text, any path or argument, prompts, code, file
contents, the error text, and any hash or fingerprint of them. The value of each field is
checked against its list before it is written, so a mistake in the classifier
can only produce `unknown`, never free text.

Why: a run that pushed to the main branch without any earlier check is a very
different run from one that listed a directory, and the placeholder hides the
difference. Four fixed list labels show it without revealing what you typed.
