# SecureScan AI — Concept Note

## Title

SecureScan AI: Passive Website Security Configuration Scanner and Risk Analyzer

## Overview

SecureScan AI is a safe, full-stack web application that helps website owners, junior developers and students understand the publicly observable security configuration of a website. A user enters a public URL and receives a structured report covering HTTPS/TLS, security headers, cookie attributes, redirect behaviour, information-exposure signals, mixed-content references and public metadata — without the tool ever logging in, exploiting anything or touching private data.

## Problem it solves

Most developers know that HTTPS, security headers and cookie attributes matter, but practical tooling to verify them is either too expensive, too broad, or too technical for a first look. SecureScan AI provides a focused, entry-level first assessment:

- **Free and self-hostable** — no paid API keys required; the explanation engine is entirely local and rule-based.
- **Evidence-first** — every finding shows the actual response header value, body extract or probe result that triggered it.
- **Honest about scope** — the tool states what it checked, what it could not see, and why a good score is not a security guarantee.

## Target users

| User | What they get |
|---|---|
| Final-year BCA / CS students | A portfolio project demonstrating full-stack design and responsible security tooling |
| Junior developers | A fast public-edge check before a site review or launch |
| Small-business website owners | A plain-language first look at basic configuration hygiene |
| Security instructors | A demonstrable, open-source tool with transparent scoring and modular code |

## Key innovation

The project combines three ideas rarely seen together in student projects:

1. **Real network-backed checks** — users scan actual URLs, not hardcoded demo data.
2. **Built-in SSRF protection** — the scanner defends its own execution environment using per-hop DNS resolution, IP block-listing and strict URL validation.
3. **Local explainable AI** — a rule-based engine turns raw HTTP observations into plain-language findings, risks and recommendations without an external AI key or service dependency.

## Scope

### In scope
- Passive public HTTP/TLS checks (headers, cookies, TLS certificate, redirects, public files, body signals)
- Transparent weighted score (0–100) with per-finding deduplication
- Exportable JSON and PDF reports
- SQLite scan history
- Full Docker + Vercel + Python-host deployment

### Out of scope
- Login testing, authentication bypass or credential checks
- Vulnerability exploitation, brute force or denial-of-service probing
- Private network access, internal API inspection or source-code analysis
- Any claim that a scanned site is secure or free from vulnerabilities

## Expected outcomes

The completed project is suitable for:

- Public GitHub repository with CI-ready mocked tests
- Live demo deployment (Vercel frontend + Render/Railway backend)
- Academic submission and viva demonstration
- Portfolio review by a hiring manager or technical interviewer

The codebase covers modular Python backend design, type-safe React frontend, secure input handling, passive cybersecurity analysis, data visualisation, PDF export, containerisation and deployment documentation — all in a single coherent application.

## Responsible use statement

SecureScan AI must only be used to scan websites you own or have explicit written permission to assess. The tool performs no intrusive actions and is designed to be a safe configuration aid, not an attack tool. This constraint is enforced both by policy and by the architecture of the scanner itself.
