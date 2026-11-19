# Agent guidance

DriftShield is an open source engine that reads an AI agent's transcript, classifies each step and finds where the run went wrong. The Python package lives in `driftshield/` (import `driftshield`, CLI `driftshield`). A FastAPI app and a React frontend (`driftshield/frontend/`) sit on top of the same engine.

## Working here

- Read the linked issue and the code paths it touches before changing anything, then carry the work through to a verified PR.
- Tests: `cd driftshield && uv run --extra dev pytest tests -q`. Frontend changes also need `npm run build` in `driftshield/frontend` and a real browser check.
- Commits and PR titles: Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`, `test:`), one line, no tool prefixes.
- Reviews come from the `driftshield-reviewer` GitHub App as a PR comment whose first line is `<!-- driftshield-agent-review:v1 ... verdict=approve|changes -->`. It skips draft PRs. A PR merges only on an `approve` verdict at its exact head commit.
- Keep the issue body, its checkboxes and any parent checklist in step with what actually shipped.

## Public repository

Everything tracked here is public. Every file must make sense without any private DriftShield repository, path or planning doc. `./scripts/check-public-scope.sh` enforces this in CI; run it for any change to docs, prompts, fixtures, templates or workflows.

## Engine door

- The public API is `driftshield.analyse_run` and `driftshield.submit` (`docs/public-api.md`). Every CLI command, the `/api/ingest` route and the connector watcher analyse through `analyse_run`. Add features behind that one path.
- Format detection lives only in `driftshield/src/driftshield/parsers/registry.py`: content decides, a path is a hint. A new parser comes with a fixture in `driftshield/tests/fixtures/transcripts/` and its hash in `golden/redaction_snapshot.json`.
- Zero parseable events raises `NoParseableEventsError`. Redaction of the bundled fixtures is pinned by `driftshield/tests/test_door.py`.
- The failure verdict (`qualification_state`) is decided in `core/canonical_analysis.py`, using the tool outcome rules in `core/analysis/tool_outcomes.py`. The section "What counts as a failure" in `docs/how-checks-work.md` states the same rules for users; change both together.

## Step facts and rules

- Step facts (`step_facts.py`, `step_facts_pr.py`, `step_facts_own_merge.py`, `step_facts_start_label.py`) classify each shell step, and each tool a tool map (`tool_map.py`) names. `STEP_FACTS_VERSION` in `step_facts.py` changes whenever any command's classification changes.
- The matching rules are in `core/deterministic_matching.py`. `RULESET_VERSION` changes whenever a rule's behaviour changes.
- Both versions are sent with every upload and pinned per version by `driftshield/tests/test_analyser_versions.py`, so a behaviour change without a version bump fails the build. Record each bump in `CHANGELOG.md`.

## Community upload

`driftshield submit --path <session.json>` sends only the redacted envelope of a finished run to the community pool. The intake URL is built in, the default tier is `oss` with no API key, and an API key picks the workspace on paid tiers. `telemetry remote-disable` opts out.

## Releases

- Process: `docs/release-runbook.md`. A `v<version>` tag on `main` runs `.github/workflows/release-publish.yml`; `scripts/release-build-check.sh` is the build check both release workflows share.
- The version lives in `driftshield/pyproject.toml` and `driftshield/src/driftshield/__init__.py`; keep them equal.
- The PyPI distribution is `driftshield-sdk`. The import package and console scripts stay `driftshield`, because PyPI refused that name as too close to `drift-shield`.

## Delivery agent files

`.claude/agents/`, `.claude/delivery/`, `.claude/hooks/` and `.claude/skills/issue-diagram` are synced from DriftShield's delivery tooling and overwritten on the next sync. Change them at the source.

## Keeping this file current

Add only what nearly every session needs and the code does not show. Point to the file or test that enforces a rule. Rewrite or prune before appending.
