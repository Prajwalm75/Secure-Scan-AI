# SecureScan AI — Presentation Outline

## Slide 1 — Title
SecureScan AI: Website Security Scanner and Risk Analyzer. Add the student name, department and academic year.

## Slide 2 — Problem
Website security settings are important but difficult for beginners to verify. Broad scanners can be expensive, noisy or unsafe for a student project.

## Slide 3 — Proposed solution
A public URL goes through bounded passive checks, then the application presents evidence, explanations, recommendations and a transparent configuration score.

## Slide 4 — Safety first
Show the validation path: normalize URL → resolve DNS → block non-public IPs → fetch with limits → revalidate redirects → store only the report. Emphasize permission and no intrusive testing.

## Slide 5 — Technology stack
React, TypeScript, Tailwind CSS, Recharts, FastAPI, httpx, Python standard libraries, ReportLab and SQLite.

## Slide 6 — Checks performed
HTTPS/TLS, HSTS, CSP, content-type sniffing, framing, Referrer-Policy, Permissions-Policy, cookies, server headers, robots/sitemap and mixed content.

## Slide 7 — Scoring and explainability
Start at 100, subtract weighted confirmed configuration weaknesses, deduplicate control families, and show “Insufficient data” when evidence is incomplete. Every finding includes evidence and a defensive fix.

## Slide 8 — User journey
Enter a permitted URL → watch bounded scan progress → read score and severity mix → inspect evidence → download JSON/PDF → scan again or review local history.

## Slide 9 — Testing
Mocked DNS, HTTP headers, cookies and redirects; API health/report checks; frontend typecheck and production build.

## Slide 10 — Deployment
Vercel hosts the frontend; Render/Railway/Fly.io-style Python hosting runs FastAPI. `VITE_API_BASE_URL` and `FRONTEND_ORIGIN` connect the two services.

## Slide 11 — Limitations
Passive unauthenticated checks cannot establish overall security, inspect private areas or prove exploitability. SQLite history is for portfolio/local usage unless replaced with managed persistence.

## Slide 12 — Demonstration and conclusion
Scan a permitted public URL, show the report and explain how evidence-first feedback can help a developer choose the next defensive improvement.
