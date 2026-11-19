# Run DriftShield from a clone

The local API, the investigation dashboard and the Docker images. For the CLI on its own, `pip install driftshield-sdk` is enough (see the [README](../README.md)).

## Prerequisites

- Python 3.12+
- Node.js 20+
- Docker (optional, but needed for the local API/dashboard Postgres path)

## 1. Setup from a clean clone

```bash
git clone https://github.com/driftshield/driftshield-sdk.git
cd driftshield-sdk
./scripts/dev-setup.sh
```

This creates local env files, installs backend and frontend dependencies, and starts local
Postgres if Docker is available. No private credentials or proprietary setup steps are
required for the OSS path.

## 2. Get a first useful result

```bash
cd driftshield
source .venv/bin/activate
driftshield report tests/fixtures/transcripts/sample_claude_code_session.jsonl --type summary
```

This generates a forensic report from the bundled sample transcript, which is the shortest
supported path from a clean clone to a meaningful DriftShield investigation artifact.

## 3. Verify the repo

```bash
cd ..
./scripts/dev-verify.sh
```

## 4. Run the full local stack

The local API and web dashboard expect a local Postgres instance. The supported dev path
is `docker-compose.dev.yml`; the production `docker-compose.yml` is not the primary quickstart.

Start the backend:

```bash
cd driftshield
source .venv/bin/activate
set -a
source .env
set +a
driftshield-api
```

The backend reads `API_KEY` and `DATABASE_URL` from process env, so source `driftshield/.env`
before starting it.

Start the frontend (in a separate terminal):

```bash
cd driftshield/frontend
npm run dev
```

Open http://localhost:5173 to view ingested sessions.

The dashboard reconstructs each run as a decision graph. Click a node to inspect
its risk flags, evidence, and inflection explanation, and open the generated
forensic report inline.

![DriftShield dashboard, session triage view](media/theme-shots/after/01-sessions-desktop.png)

![DriftShield dashboard, investigation graph view](media/theme-shots/after/02-investigation-desktop.png)

## 5. Feed the local dashboard (self-host path)

`driftshield ingest` uploads directly to a running local `/api/ingest` server. This is the
self-host and vetted-integration path, not the normal customer upload path.

```bash
cd driftshield
source .venv/bin/activate
set -a
source .env
set +a
DRIFTSHIELD_API_URL=http://localhost:8080 \
driftshield ingest --path tests/fixtures/transcripts/sample_claude_code_session.jsonl
```

Or ingest the latest Claude Code session for the current project:

```bash
set -a
source .env
set +a
source .venv/bin/activate
driftshield ingest --latest
```

## Generate a forensic report through the API

With the backend running and `API_KEY` exported from `driftshield/.env`, upload a
transcript directly to the API and get the persisted `forensic_report.v1` payload
back in one call:

```bash
cd driftshield
source .venv/bin/activate
set -a
source .env
set +a
curl -sS \
  -X POST http://localhost:8080/api/forensics/report \
  -H "X-API-Key: $API_KEY" \
  -F "file=@tests/fixtures/transcripts/sample_claude_code_session.jsonl" \
  -F "format=claude_code" \
  -F "report_type=summary"
```

This returns the ingested `session_id`, persisted forensic case metadata, and the
full JSON report contract that the CLI and dashboard surfaces share.

## Docker Deployment

```bash
cd driftshield

# Create .env with required values
cp .env.example .env
# Edit .env: set API_KEY and DB_PASSWORD

# Start the stack
docker compose up -d
```

The production compose file runs the app on port 8080 with PostgreSQL 16. Both `API_KEY` and `DB_PASSWORD` are required and will fail on startup if missing.

## CLI-only image

A separate `cli` build target packages just the `driftshield` CLI (no frontend, no web server), for running `batch`/`analyze`/`submit` standalone in CI or a customer environment:

```bash
cd driftshield
docker build --target cli -t driftshield-cli .

# Analyse every transcript under a mounted directory
docker run --rm -v $(pwd)/transcripts:/data driftshield-cli batch /data

# ...and submit the successfully analysed ones (opt-in; requires network egress)
docker run --rm -v $(pwd)/transcripts:/data driftshield-cli batch /data --submit
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.12, FastAPI, SQLAlchemy 2.0, Alembic, Pydantic |
| CLI | Typer + Rich |
| Frontend | React 19, TypeScript, Vite, Tailwind CSS 4, TanStack Query |
| Graph visualisation | @xyflow/react |
| Database | PostgreSQL 16 (production), SQLite in-memory (tests) |
| Testing | pytest (backend), Playwright (e2e), Vitest (frontend unit) |
| Infrastructure | Docker, docker-compose, GitHub Actions |

## Project Structure

```
driftshield/
├── src/driftshield/
│   ├── api/            # FastAPI routes (ingest, sessions, reports, connectors)
│   ├── cli/            # Typer commands and session discovery
│   ├── connectors/     # Auto-discovery of transcript sources
│   ├── core/
│   │   ├── analysis/   # Risk heuristics, inflection detection, session analysis
│   │   ├── graph/      # Decision graph builder and models
│   │   └── models.py   # Domain models (CanonicalEvent, RiskClassification)
│   ├── db/             # SQLAlchemy models, persistence, Alembic migrations
│   ├── parsers/        # Transcript format parsers (protocol + implementations)
│   └── reports/        # Jinja2 report templates
├── frontend/           # React investigation dashboard
├── tests/              # Backend test suite
└── docker-compose.yml  # Production deployment
```
