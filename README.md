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

This repository is built in small, demoable increments. **Task 1 (this commit)**
is the project scaffold: a FastAPI backend with a health check, a React
status page that reports backend health, a test harness for both, and a
Docker Compose setup that runs the whole thing.

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
│   │   └── main.py          # /health + root info endpoints
│   ├── tests/
│   │   └── test_health.py
│   ├── Dockerfile
│   ├── pyproject.toml
│   ├── requirements.txt      # runtime deps
│   └── requirements-dev.txt  # test deps
├── frontend/                React + Vite app
│   ├── src/
│   │   ├── api.js           # calls /health
│   │   ├── App.jsx          # status page
│   │   ├── App.test.jsx
│   │   ├── index.css
│   │   └── main.jsx
│   ├── Dockerfile           # build -> nginx
│   ├── nginx.conf           # serves the app, proxies /health + /api
│   ├── index.html
│   └── vite.config.js
└── docker-compose.yml
```

## Quick start (Docker Compose)

The fastest way to see everything running:

```bash
docker compose up --build
```

Then open <http://localhost:8080>. The page polls the backend and shows
**"backend healthy"** once the API is up. The API itself is on
<http://localhost:8000> (interactive docs at `/docs`).

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
| `VITE_API_BASE_URL` | frontend | _(empty)_ | Override the backend origin. Empty means same-origin requests through the dev/nginx proxy. |

## Roadmap

1. **Scaffold + health check + test harness** *(done)*
2. Unified finding schema + data layer
3. Consent gate + scan submission + live status
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
