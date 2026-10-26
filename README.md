# SecureScan AI

> **A full-stack passive website security configuration scanner built for learning, portfolios and responsible public assessment.**

SecureScan AI accepts a public URL, performs bounded passive HTTP/TLS checks without authentication or exploitation, and turns the evidence into a transparent, explainable report — complete with a weighted score, visual charts, finding cards and JSON/PDF export.

---

## Table of contents

- [Features](#features)
- [Architecture](#architecture)
- [Project structure](#project-structure)
- [Quick start (local)](#quick-start-local)
- [Docker](#docker)
- [Environment variables](#environment-variables)
- [Running tests](#running-tests)
- [API reference](#api-reference)
- [Scoring model](#scoring-model)
- [Safety controls](#safety-controls)
- [Limitations](#limitations)
- [License](#license)

---

## Features

| Category | What the scanner checks |
|---|---|
| **Transport** | HTTPS availability, TLS certificate validity and expiry, certificate protocol version, HTTP→HTTPS redirect behaviour |
| **Security headers** | `Strict-Transport-Security`, `Content-Security-Policy` (presence and unsafe directives), `X-Content-Type-Options`, `X-Frame-Options` / CSP `frame-ancestors`, `Referrer-Policy`, `Permissions-Policy` |
| **Cookie security** | `Secure`, `HttpOnly` and `SameSite` attributes on every visible `Set-Cookie` header |
| **Information exposure** | `Server`, `X-Powered-By`, `X-Generator`, debug/version headers, directory-listing patterns |
| **Mixed content** | Absolute `http://` references in an HTTPS page body |
| **Public metadata** | `robots.txt` and `sitemap.xml` accessibility |
| **Reporting** | Weighted configuration score (0–100), severity breakdown, Recharts visualisations, per-finding evidence + recommendation, JSON and PDF export |

**What SecureScan AI never does:** log in, exploit vulnerabilities, brute-force accounts, access private data or send denial-of-service traffic.

---

## Architecture

```
Browser (React + TypeScript + Tailwind)
        │  JSON over /api/*
        ▼
FastAPI (Python 3.12)
  ├── config.py      URL normalisation · DNS/IP SSRF guard
  ├── scanner.py     httpx async client · redirect revalidation · TLS probe
  ├── security_checks.py  Header · cookie · signal · redirect inspection
  ├── explanations.py     Local rule-based finding descriptions
  ├── scoring.py     Deduplicating weighted score
  ├── storage.py     SQLite scan history (optional)
  └── main.py        FastAPI routes · CORS · rate limit · PDF export
```

---

## Project structure

```
SecureScan-AI-Complete-Project/
├── backend/
│   ├── app/
│   │   ├── main.py              FastAPI routes, CORS, rate limiting, PDF/JSON export
│   │   ├── scanner.py           Bounded async HTTP orchestration, redirect + TLS checks
│   │   ├── config.py            URL normalisation, DNS/IP safety validation
│   │   ├── security_checks.py   Header, cookie, public signal, mixed-content inspection
│   │   ├── explanations.py      Local rule-based finding explanations (no AI key needed)
│   │   ├── scoring.py           Transparent weighted score and score bands
│   │   └── storage.py           SQLite report history
│   ├── tests/                   Mocked unit and API tests (pytest)
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── App.tsx              Dashboard flow and report composition
│   │   ├── api.ts               Backend API client
│   │   ├── types.ts             Shared TypeScript types
│   │   └── components/
│   │       ├── FindingCard.tsx  Expandable finding detail cards
│   │       ├── ScanCharts.tsx   Recharts donut + bar visualisations
│   │       └── ScoreRing.tsx    Animated conic-gradient score ring
│   ├── index.html
│   ├── vite.config.ts
│   └── vercel.json
├── docs/
│   ├── PROJECT_REPORT.md        Full academic project report
│   ├── CONCEPT_NOTE.md          Project concept note
│   └── PRESENTATION_OUTLINE.md  Slide outline
├── docker-compose.yml
├── plan.md
└── TODO.md
```

---

## Quick start (local)

**Prerequisites:** Node.js 22+, Python 3.12+, pnpm (via Corepack).

### 1 — Backend

```bash
# Create and activate a virtual environment
python -m venv .venv

# Windows PowerShell
.venv\Scripts\Activate.ps1
# macOS / Linux
source .venv/bin/activate

pip install -r backend/requirements.txt
```

Copy `.env.example` to `.env` if you want to change defaults, then start FastAPI:

```bash
# Windows PowerShell
$env:PYTHONPATH="backend"; .venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# macOS / Linux
PYTHONPATH=backend .venv/bin/python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### 2 — Frontend

```bash
corepack enable
pnpm install
pnpm --dir frontend dev
```

Open **http://localhost:3000**. Vite proxies `/api` and `/health` to FastAPI at `http://127.0.0.1:8000` — no browser-side CORS configuration needed during local development.

---

## Docker

Run both services with a single command:

```bash
docker compose up --build
```

- Dashboard → **http://localhost:3000**
- API → **http://localhost:8000**

SQLite data is kept in a named Docker volume so scan history survives container restarts.

---

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `FRONTEND_ORIGIN` | `http://localhost:3000` | Comma-separated allowed CORS origins for the FastAPI backend |
| `SECURESCAN_DB_PATH` | `./data/securescan.db` | SQLite database path (relative to project root or absolute) |
| `SCAN_TIMEOUT_SECONDS` | `8` | Per-request timeout in seconds |
| `SCAN_MAX_RESPONSE_BYTES` | `262144` | Maximum response body read per request (256 KB) |
| `SCAN_MAX_REDIRECTS` | `3` | Maximum redirect hops followed (hard cap: 5) |
| `SCAN_RATE_LIMIT` | `8` | Scans per minute per client IP (hard cap: 30) |
| `VITE_API_BASE_URL` | _(empty = relative)_ | Public HTTPS URL of the FastAPI backend (set in Vercel for production) |

---

## Running tests

**Backend** — fully mocked, no live network calls:

```bash
PYTHONPATH=backend .venv/bin/pytest -q
```

**Frontend** — TypeScript typecheck and production build:

```bash
pnpm --dir frontend typecheck
pnpm --dir frontend build
```

**API smoke test** (requires running backend):

```bash
curl http://localhost:8000/health
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target_url":"https://example.com"}'
```

---

## API reference

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Service health check |
| `POST` | `/api/scan` | Submit a URL for scanning. Body: `{"target_url": "https://…"}` |
| `GET` | `/api/scan/{scan_id}` | Retrieve a stored scan report |
| `GET` | `/api/scans?limit=12` | List recent scan history (max 50) |
| `GET` | `/api/scan/{scan_id}/report?format=json` | Download report as JSON |
| `GET` | `/api/scan/{scan_id}/report?format=pdf` | Download report as PDF |

A successful scan response includes: `scan_id`, `scanned_at`, `completed_at`, `hostname`, `reachable`, `status_code`, `response_time_ms`, `request_count`, `checks_completed`, `score`, `score_label`, `tls`, `headers`, `cookies`, `public_signals`, `findings`, `summary`, `errors` and `limitations`.

---

## Scoring model

The score starts at **100** and subtracts one fixed weight per unique finding ID (duplicate finding IDs are counted once):

| Severity | Weight |
|---|---|
| Critical | −30 |
| High | −15 |
| Medium | −8 |
| Low | −3 |
| Informational | 0 |

Score bands:

| Range | Label |
|---|---|
| 90–100 | Good configuration |
| 75–89 | Low apparent configuration risk |
| 50–74 | Moderate configuration risk |
| 25–49 | High configuration risk |
| 0–24 | Very high configuration risk |

If the primary response cannot be obtained the score shows **"Insufficient data"** rather than a misleading value.

---

## Safety controls

- Allows only `http://` and `https://` schemes; rejects credentials, fragments, non-standard ports, and `localhost`/internal hostnames.
- Resolves every hostname (including each redirect hop) and blocks private, loopback, link-local, reserved, multicast, unspecified and cloud-metadata addresses (SSRF protection).
- Limits: redirects, response bytes, request timeout, connection pool, per-client request rate.
- Never submits forms, reads authenticated content, probes arbitrary ports or attempts exploitation.
- Deploy behind a network egress policy as an additional control for shared or production environments.


---

## Limitations

- Only unauthenticated public HTTP responses are examined.
- Missing headers are configuration observations, not proof of exploitability.
- TLS certificate expiry is checked when the scanner can complete a normal handshake; some network environments block port 443.
- Robots.txt and sitemap.xml are informational signals and are never treated as vulnerabilities.
- The local explanation engine is deterministic; it describes rules, not dynamic AI-generated advice.
- A passing score cannot confirm that a website is secure or free from vulnerabilities.

---

## License

MIT. See [`LICENSE`](LICENSE).
