# SecureScan AI — Implementation Plan

## Product direction

SecureScan AI is a defensive, beginner-friendly website configuration scanner. It accepts a public HTTP(S) URL, applies bounded passive checks, stores an optional local scan history, and presents a transparent report that distinguishes observed configuration weaknesses from exploitable vulnerabilities.

## Architecture

- `backend/app/main.py`: FastAPI application, CORS, rate limiting, health and scan/report endpoints.
- `backend/app/schemas.py`: Pydantic request/response contracts.
- `backend/app/scanner.py`: orchestration, safe HTTP client, redirect/DNS validation, response limits, and scan metadata.
- `backend/app/security_checks.py`: evidence-based HTTPS/TLS, security headers, cookies, redirects, public metadata, robots/sitemap, and mixed-content checks.
- `backend/app/scoring.py`: deterministic weighted score with deduplication and insufficient-data handling.
- `backend/app/explanations.py`: local rule-based explanations with optional provider hook kept out of the critical path.
- `backend/app/storage.py`: SQLite scan history with bounded retention and JSON/report retrieval.
- `backend/tests/`: mocked unit/API coverage for validation, SSRF protection, redirect handling, headers, cookies, scoring, errors, and endpoint behavior.
- `frontend/src/`: React + TypeScript application with a dashboard-first layout, scanner flow, report state, charts, and responsive sections.
- `frontend/src/api.ts`: relative API client with error normalization.
- `frontend/src/types.ts`: shared frontend report types.
- `frontend/src/components/`: dashboard panels and reusable visual primitives.
- `frontend/public/manus-routes.json`: required route manifest.
- Root `README.md`, `docs/PROJECT_REPORT.md`, `docs/CONCEPT_NOTE.md`, `docs/PRESENTATION_OUTLINE.md`, `.env.example`, `LICENSE`, and deployment files.

The frontend is served by Vite on port 3000 for Preview. The FastAPI backend listens on port 8000 during local development and can be served behind a reverse proxy or as a separate Python service in production. Vite proxies `/api` to FastAPI locally; production deployment instructions document Vercel for the frontend and Render/Railway/Fly.io-style Python hosting for the backend.

## Security model

The server normalizes only `http` and `https` URLs, rejects credentials, localhost, special-use hostnames, private/reserved IPs, cloud metadata addresses, and unsafe ports. DNS answers are resolved before requests and each redirect is parsed and revalidated. The scanner uses a small request budget, short connect/read/write/pool timeouts, a response-size cap, redirect cap, and an in-process rate limiter. It never sends credentials, submits forms, performs authentication, brute force, exploitation, or internal network access.

## Report/scoring model

A scan starts at 100 and subtracts only for confirmed configuration findings, with a single weighted finding per control family where possible. Missing data is represented explicitly; a score is returned only when enough primary evidence was collected. Score bands follow the requested 90–100 / 75–89 / 50–74 / 25–49 / 0–24 labels. The UI explains that this is a configuration-check score, not a complete vulnerability assessment.

## Design system

### Alternative styles considered

- **Cybernetic Observatory** — 0.06 probability: a dark monitoring console with luminous telemetry and compact data bands.
- **Editorial Security Brief** — 0.07 probability: a light, report-oriented reading experience with restrained red-team accents.
- **Midnight Signal Grid** — 0.08 probability: an atmospheric navy control room with teal signal lines and crisp evidence cards.

### Chosen style: Midnight Signal Grid

- **Design movement:** enterprise SOC dashboard meets premium developer tooling.
- **Core principles:** evidence before decoration; high signal-to-noise; calm urgency; progressive disclosure for beginners.
- **Color philosophy:** deep navy creates a focused analysis surface; cyan and teal identify active telemetry; amber and red are reserved for actionable risk; muted slate keeps dense reports readable.
- **Layout paradigm:** a left-aligned hero rail introduces the scanner, while report content unfolds as stacked evidence bands with an offset score rail instead of a generic centered card grid.
- **Signature elements:** a segmented “signal pulse” status indicator, thin gridline overlays, and small monospace evidence labels paired with human explanations.
- **Interaction philosophy:** every action communicates state; scanning shows bounded progress, finding cards expose evidence first, and hover/focus states use restrained glow rather than movement-heavy effects.
- **Animation:** slow ambient grid drift, 1–2 second pulse on active scan indicators, 180ms panel transitions, and no animation that obscures content or runs indefinitely after completion.
- **Typography system:** `Space Grotesk` for display and UI headings, `Inter` for body copy, and `IBM Plex Mono` for URLs, evidence and metadata.
- **Brand essence:** “A clear, safe first look at how a public website is configured.” Personality: precise, reassuring, practical.
- **Brand voice:** headlines are direct (“See the signal before you ship.”); CTAs are explicit (“Scan a public URL”); explanations avoid fear language (“This is a configuration gap, not proof of exploitability.”).
- **Wordmark & logo:** a compact shield formed from three offset signal bars, paired with a two-line SecureScan AI wordmark.
- **Signature brand color:** Signal Teal `#1ED6C4`.

## Delivery workflow

1. Implement backend modules and mocked tests.
2. Implement frontend dashboard and report states.
3. Add README, project report, concept note, presentation outline, license, environment examples and deployment configuration.
4. Install dependencies, run backend tests, frontend typecheck/build, and verify health/route-manifest endpoints.
5. Fix confirmed issues, checkpoint the source, and leave publication as an explicit follow-up because auto-publish is disabled.

## Known boundaries

The scanner cannot prove absence of vulnerabilities, cannot inspect authenticated areas, and can only assess headers/cookies/body content visible to an unauthenticated passive request. SQLite history is appropriate for portfolio/local use; production deployments should use managed MySQL/Postgres or disable history if the platform filesystem is ephemeral. AI explanations use deterministic local rules so no paid AI key is required.
