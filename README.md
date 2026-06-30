# AI Penetration Tester

A web app that runs a coordinated suite of free, open-source security scanners
against a target, explains every finding in plain language with a free LLM, and
produces a downloadable security report.

Point it at a live URL for dynamic testing (DAST) and/or upload source code for
static analysis (SAST). The system orchestrates proven engines, normalizes their
output into a single finding schema, and turns the results into a clear report.

> **Authorized testing only.** Active scanning probes a target for
> vulnerabilities. Only ever run it against systems you own or have explicit
> written permission to test. The app requires a consent acknowledgment before
> any active scan.

## Status

This repository is built in small, demoable increments. The latest commit adds
**scan submission with a consent gate and live progress**: a `POST /api/scans`
that refuses to run without an explicit authorization acknowledgment, an async
orchestrator stub that walks a scan through queued -> running -> done, live
updates over WebSocket (with a polling fallback), and a frontend form that
submits a target and shows progress in real time. Earlier increments delivered
the unified data layer (SQLModel/SQLite models + normalized finding schema) and
the project scaffold (FastAPI + React + Docker Compose).

## Planned capabilities

| Area | Engine(s) |
| --- | --- |
| SQL injection | sqlmap, ZAP active rules |
| XSS / SSRF / CSRF | OWASP ZAP, Nuclei |
| Authentication & session analysis | ZAP + custom checks (cookie flags, headers, CSRF tokens) |
| Server / config issues | Nikto |
| API fuzzing | schemathesis, ZAP API scan |
| Static analysis (uploaded code) | Semgrep |
| Plain-language explanations | Groq / Gemini with a template fallback |
| Reports | interactive HTML, PDF, JSON |

## Tech stack

- **Backend:** Python, FastAPI, SQLite, single-container async job runner (no Celery/Redis)
- **Frontend:** React + Vite
- **Tests:** pytest (backend), Vitest + Testing Library (frontend)
- **Packaging:** Docker + Docker Compose

## Project structure

```
.
├── backend/                 FastAPI service
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py          # health + root, app startup (table creation)
│   │   ├── database.py      # engine, session dependency, init_db
│   │   ├── models.py        # Scan / Finding / Report tables + enums
│   │   ├── schemas.py       # NormalizedFinding + API read/submit models
│   │   ├── events.py        # in-memory progress pub/sub broker
│   │   ├── orchestrator.py  # async job-runner stub (queued -> running -> done)
│   │   └── routers/
│   │       ├── scans.py     # POST/GET /scans + WebSocket progress
│   │       └── dev.py       # temporary seed/fetch routes
│   ├── tests/
│   │   ├── test_health.py
│   │   ├── test_models.py
│   │   ├── test_schemas.py
│   │   ├── test_scans_api.py
│   │   ├── test_orchestrator.py
│   │   ├── test_scan_ws.py
│   │   └── test_dev_routes.py
│   ├── Dockerfile
│   ├── pyproject.toml
│   ├── requirements.txt      # runtime deps
│   └── requirements-dev.txt  # test deps
├── frontend/                React + Vite app
│   ├── src/
│   │   ├── api.js           # health, createScan, getScan, live subscribe
│   │   ├── App.jsx          # submit form + live progress
│   │   ├── components/
│   │   │   ├── ScanForm.jsx       # target + consent gate
│   │   │   └── ScanProgress.jsx   # live status + progress bar
│   │   ├── index.css
│   │   └── main.jsx
│   ├── Dockerfile           # build -> nginx
│   ├── nginx.conf           # serves the app, proxies /health + /api (+ ws)
│   ├── index.html
│   └── vite.config.js
└── docker-compose.yml
```

## Quick start (Docker Compose)

The fastest way to see everything running:

```bash
docker compose up --build
```

Then open <http://localhost:8080>. The page shows **"backend healthy"** once the
API is up. Enter a target URL, confirm authorization, and start a scan to watch
it move through **queued -> running -> done** live. The API itself is on
<http://localhost:8000> (interactive docs at `/docs`).

### Try the data layer (temporary dev route)

While the real scan API is still being built, a temporary route lets you seed a
sample finding and read it back through the API:

```bash
# create a sample scan + finding
curl -X POST http://localhost:8000/api/dev/seed
# fetch a finding by id, or a scan together with its findings
curl http://localhost:8000/api/dev/findings/1
curl http://localhost:8000/api/dev/scans/1
```

These `/api/dev/*` routes exist only for the demo and will be removed once scan
submission and the orchestrator land.

## Local development

Run the two services in separate terminals.

**Backend** (from `backend/`):

```bash
python -m venv .venv
# Windows:  .venv\Scripts\activate
# macOS/Linux:  source .venv/bin/activate
pip install -r requirements-dev.txt
uvicorn app.main:app --reload --port 8000
```

**Frontend** (from `frontend/`):

```bash
npm install
npm run dev
```

Open the Vite dev server URL (defaults to <http://localhost:5173>). The dev
server proxies `/health` and `/api` to the backend on port 8000, so no extra
configuration is needed.

## Running the tests

**Backend** (from `backend/`):

```bash
pip install -r requirements-dev.txt
pytest
```

**Frontend** (from `frontend/`):

```bash
npm test
```

## Configuration

| Variable | Where | Default | Purpose |
| --- | --- | --- | --- |
| `ALLOWED_ORIGINS` | backend | `http://localhost:5173,http://localhost:8080` | Comma-separated CORS origins allowed to call the API directly. |
| `DATABASE_URL` | backend | `sqlite:///./data/app.db` | SQLModel/SQLAlchemy database URL. Defaults to a SQLite file on the mounted data volume. |
| `SCAN_STEP_DELAY` | backend | `0.6` | Seconds between simulated orchestrator progress steps (stub; lower it to speed up demos). |
| `VITE_API_BASE_URL` | frontend | _(empty)_ | Override the backend origin. Empty means same-origin requests through the dev/nginx proxy. |

## Roadmap

1. **Scaffold + health check + test harness** *(done)*
2. **Unified finding schema + data layer** *(done)*
3. **Consent gate + scan submission + live status** *(done)*
4. Engine adapter framework + Nuclei
5. OWASP ZAP integration (XSS, SSRF, CSRF, headers)
6. sqlmap integration (SQL injection)
7. Nikto + custom authentication analysis
8. API fuzzing (schemathesis + ZAP API scan)
9. Source-code upload + Semgrep SAST
10. AI explanation service (Groq/Gemini + fallback)
11. Report generation (HTML / PDF / JSON)
12. Full frontend integration
13. Safe demo mode + bundled vulnerable target + scope allowlist
14. Free deployment + docs
