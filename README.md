---
title: AI Penetration Tester
emoji: 🛡️
colorFrom: indigo
colorTo: purple
sdk: docker
app_port: 7860
pinned: false
---

# AI Penetration Tester

**▶ Live demo: https://hkfdihjebfvhdfbvgre-ai-pentester.hf.space**
(access-controlled — credentials provided on request; authorized users can run
live scans and download HTML / PDF / JSON reports)

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

This repository is built in small, demoable increments. The app now runs the
full flow end-to-end: submit a URL and/or upload a source zip, watch live
progress as seven engines (Nuclei, OWASP ZAP, sqlmap, Nikto, custom auth/header
checks, schemathesis API fuzzing, Semgrep SAST) run and merge into one findings
set, read **AI-generated explanations, impact, and remediation** for each finding
(Groq/Gemini when a key is set, built-in templates offline), explore a
**results dashboard** with severity summary and filtering, and download a
complete **HTML / PDF / JSON report**. Earlier increments delivered the engines,
the consent gate + live progress, the unified data layer, and the scaffold.

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
│   │   ├── orchestrator.py  # async runner: select adapters, run, persist findings
│   │   ├── adapters/
│   │   │   ├── base.py      # EngineAdapter interface (+ progress callback)
│   │   │   ├── owasp.py     # CWE -> OWASP Top 10 mapping
│   │   │   ├── nuclei.py    # Nuclei adapter
│   │   │   ├── zap.py       # OWASP ZAP adapter (spider/passive/active)
│   │   │   └── sqlmap.py    # sqlmap adapter (SQL injection)
│   │   └── routers/
│   │       ├── scans.py     # POST/GET /scans, /scans/{id}/findings, WS progress
│   │       └── dev.py       # temporary seed/fetch routes
│   ├── tests/
│   │   ├── test_health.py
│   │   ├── test_models.py
│   │   ├── test_schemas.py
│   │   ├── test_scans_api.py
│   │   ├── test_orchestrator.py
│   │   ├── test_nuclei_adapter.py
│   │   ├── test_zap_adapter.py
│   │   ├── test_sqlmap_adapter.py
│   │   ├── test_scan_ws.py
│   │   └── test_dev_routes.py
│   ├── Dockerfile           # python + nuclei + sqlmap
│   ├── pyproject.toml
│   ├── requirements.txt      # runtime deps
│   └── requirements-dev.txt  # test deps
├── frontend/                React + Vite app
│   ├── src/
│   │   ├── api.js           # health, createScan, getScan, getFindings, live subscribe
│   │   ├── App.jsx          # submit form + live progress + findings
│   │   ├── components/
│   │   │   ├── ScanForm.jsx       # target + consent gate
│   │   │   ├── ScanProgress.jsx   # live status + progress bar
│   │   │   └── FindingsList.jsx   # normalized findings for a completed scan
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
it move through **queued -> running -> done** live, then see the normalized
findings Nuclei reports. The API itself is on <http://localhost:8000>
(interactive docs at `/docs`).

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
| `SCAN_STEP_DELAY` | backend | `0.6` | Seconds between orchestrator progress steps (lower it to speed up demos). |
| `NUCLEI_TIMEOUT` | backend | `120` | Overall time-box (seconds) for a nuclei run (compose sets `90`). |
| `NUCLEI_TAGS` | backend | _(empty)_ | Comma-separated nuclei template tags to focus the scan (compose sets a fast default set; clear for a full scan). |
| `ZAP_API_URL` | backend | `http://zap:8090` | Base URL of the OWASP ZAP daemon's REST API. |
| `ZAP_TIMEOUT` | backend | `180` | Overall time-box (seconds) for a ZAP spider + active scan. |
| `SQLMAP_TIMEOUT` | backend | `180` | Overall time-box (seconds) for the sqlmap SQL-injection probe. |
| `GROQ_API_KEY` | backend | _(unset)_ | Optional. Enables AI explanations via Groq (primary). Read from env only. |
| `GEMINI_API_KEY` | backend | _(unset)_ | Optional. Enables AI explanations via Gemini (alternative). Used if no Groq key. |
| `MAX_UPLOAD_SIZE` | backend | `52428800` | Max source-zip upload size in bytes (50 MB). |
| `DEMO_MODE` | backend | `0` | Set to `1` to restrict scanning to the bundled Juice Shop and seed sample reports on startup. |
| `VITE_API_BASE_URL` | frontend | _(empty)_ | Override the backend origin. Empty means same-origin requests through the dev/nginx proxy. |

> **AI explanations are optional.** With no `GROQ_API_KEY` or `GEMINI_API_KEY`
> set, every finding still gets a clear explanation, impact, and remediation from
> built-in per-vulnerability templates, so the app is fully demoable offline.

## Roadmap

1. **Scaffold + health check + test harness** *(done)*
2. **Unified finding schema + data layer** *(done)*
3. **Consent gate + scan submission + live status** *(done)*
4. **Engine adapter framework + Nuclei** *(done)*
5. **OWASP ZAP integration (XSS, SSRF, CSRF, headers)** *(done)*
6. **sqlmap integration (SQL injection)** *(done)*
7. **Nikto + custom authentication analysis** *(done)*
8. **API fuzzing (schemathesis + ZAP API scan)** *(done)*
9. **Source-code upload + Semgrep SAST** *(done)*
10. **AI explanation service (Groq/Gemini + fallback)** *(done)*
11. **Report generation (HTML / PDF / JSON)** *(done)*
12. **Full frontend integration** *(done)*
13. **Safe demo mode + bundled vulnerable target** *(done)*
14. **Free deployment + docs** *(done)*

## Demo mode

Demo mode restricts the app so it can be safely exposed to the public internet
(e.g., for recruiters to try). When enabled:

- Scanning is limited to the bundled **OWASP Juice Shop** target only — external
  URLs are rejected with HTTP 403.
- A sample completed scan with findings and reports is seeded on first startup,
  so a visitor can immediately view a professional report without running a scan.
- The frontend shows a demo banner and pre-fills the Juice Shop URL.

**Enable demo mode:**

```bash
# Full stack with demo restrictions:
docker compose -f docker-compose.yml -f docker-compose.demo.yml up --build

# Or just set the env var on the backend:
DEMO_MODE=1
```

## Deployment

### Local (full power)

```bash
docker compose up --build
# open http://localhost:8080
```

All engines run with no restrictions. Add `GROQ_API_KEY` or `GEMINI_API_KEY` to
`docker-compose.yml` (or a `.env` file) for AI-powered explanations; without
them the built-in templates still produce clear findings.

### Free hosted demo (Hugging Face Spaces) — one container, one link

The root `Dockerfile` is an all-in-one image: it builds the React frontend and
serves it from the FastAPI backend (port 7860) with every engine installed, in
demo mode. A recruiter opens a single URL, views a pre-seeded sample report
instantly, and can run a real self-scan against the app — no external traffic,
no second service, fully free.

1. On <https://huggingface.co/new-space>, create a Space → **SDK: Docker** →
   template **Blank** → hardware **CPU basic (free)**.
2. Push this repository to the Space's git remote:

   ```bash
   git remote add space https://huggingface.co/spaces/<your-username>/<space-name>
   git push space main
   ```

   (Authenticate with your Hugging Face username and an access token from
   <https://huggingface.co/settings/tokens> as the password.)
3. The Space reads the `README.md` frontmatter (`sdk: docker`, `app_port: 7860`)
   and builds the root `Dockerfile`. First build takes ~10-20 min (it downloads
   the engines + nuclei templates).
4. Optional: add `GROQ_API_KEY` in the Space's **Settings → Secrets** for live
   AI explanations (the template fallback works without it).

The image ships with `DEMO_MODE=1` and `DEMO_TARGET=http://localhost:7860`, so
scanning is restricted to the app itself and a sample report is seeded on first
boot.

### Local single-container (mirrors the hosted demo)

```bash
docker build -t ai-pentester .
docker run -p 7860:7860 ai-pentester
# open http://localhost:7860
```

### Security notes for deployment

- The app performs **active scanning** which sends attack payloads to targets.
  Never expose it without `DEMO_MODE=1` unless you control the network.
- API keys are read from environment variables only and never logged or stored.
- The SQLite database is ephemeral on most free platforms; this is fine for demos.
