from __future__ import annotations

import re
from http.cookies import SimpleCookie
from typing import Iterable
from urllib.parse import urljoin, urlsplit

from .explanations import finding
from .schemas import CookieCheck, Finding, HeaderCheck, Severity, TlsStatus

HEADER_DEFINITIONS: list[tuple[str, str, Severity]] = [
    ("Strict-Transport-Security", "HSTS tells browsers to prefer HTTPS after a secure visit.", "medium"),
    ("Content-Security-Policy", "CSP limits the sources a browser may load.", "medium"),
    ("X-Content-Type-Options", "nosniff reduces content-type guessing.", "low"),
    ("X-Frame-Options", "Frame protection helps reduce unexpected embedding.", "medium"),
    ("Referrer-Policy", "Referrer-Policy controls URL context shared with other origins.", "low"),
    ("Permissions-Policy", "Permissions-Policy constrains powerful browser features.", "low"),
]

# CSP directive values that significantly weaken protection
_CSP_UNSAFE_PATTERNS = re.compile(r"'unsafe-inline'|'unsafe-eval'|\*\s*(;|$)", re.I)


def header_value(headers, name: str) -> str | None:
    return headers.get(name) or headers.get(name.lower())


def inspect_headers(headers) -> tuple[list[HeaderCheck], list[Finding]]:
    checks: list[HeaderCheck] = []
    findings: list[Finding] = []
    for name, note, severity in HEADER_DEFINITIONS:
        value = header_value(headers, name)
        if name == "X-Frame-Options":
            csp = header_value(headers, "Content-Security-Policy") or ""
            present = bool(value or re.search(r"frame-ancestors\s+[^;]+", csp, flags=re.I))
            evidence = value or ("CSP frame-ancestors directive present" if present else "No X-Frame-Options or CSP frame-ancestors observed")
            checks.append(HeaderCheck(name=name, present=present, value=evidence, note=note, severity=severity))
            if not present:
                findings.append(finding("missing-framing-policy", evidence))
            continue
        present = bool(value)
        checks.append(HeaderCheck(name=name, present=present, value=value, note=note, severity=severity))
        code = {
            "Strict-Transport-Security": "missing-hsts",
            "Content-Security-Policy": "missing-csp",
            "X-Content-Type-Options": "missing-content-type",
            "Referrer-Policy": "missing-referrer-policy",
            "Permissions-Policy": "missing-permissions-policy",
        }.get(name)
        if not present and code:
            findings.append(finding(code, f"{name} was not present in the final response headers."))
        # Flag weak CSP: present but contains unsafe-inline / unsafe-eval / wildcard
        if name == "Content-Security-Policy" and present and value and _CSP_UNSAFE_PATTERNS.search(value):
            findings.append(finding("weak-csp", f"CSP contains a weakening directive: {value[:200]}"))
    return checks, findings


def inspect_cookies(headers) -> tuple[list[CookieCheck], list[Finding]]:
    cookies: list[CookieCheck] = []
    insecure_seen = False
    for raw in headers.get_list("set-cookie") if hasattr(headers, "get_list") else []:
        parsed = SimpleCookie()
        parsed.load(raw)
        if not parsed:
            continue
        for name, morsel in parsed.items():
            secure = bool(morsel["secure"])
            http_only = bool(morsel["httponly"])
            same_site = morsel["samesite"] or None
            missing = []
            if not secure:
                missing.append("Secure")
            if not http_only:
                missing.append("HttpOnly")
            if not same_site:
                missing.append("SameSite")
            if missing:
                insecure_seen = True
            cookies.append(CookieCheck(name=name, secure=secure, http_only=http_only, same_site=same_site, raw=raw, note="Missing: " + ", ".join(missing) if missing else "Secure, HttpOnly and SameSite are visible."))
    findings = [finding("insecure-cookie", "; ".join(f"{c.name}: {c.note}" for c in cookies if c.note.startswith("Missing")))] if insecure_seen else []
    return cookies, findings


def inspect_public_signals(headers, body: str, final_url: str) -> tuple[list[str], list[Finding]]:
    signals: list[str] = []
    findings: list[Finding] = []
    for header in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        value = header_value(headers, header)
        if value:
            signals.append(f"{header}: {value}")
    if any(header_value(headers, header) for header in ("server", "x-powered-by")):
        evidence = ", ".join(signals[:3])
        findings.append(finding("server-disclosure", evidence))
    debug_headers = [header for header in ("x-debug-token", "x-debug-exception", "x-aspnet-version", "x-generator") if header_value(headers, header)]
    if debug_headers:
        findings.append(finding("debug-header", ", ".join(debug_headers)))
    if re.search(r"<title>\s*(?:index of|directory listing)\s*<", body, flags=re.I) or re.search(r"Index of /", body, flags=re.I):
        signals.append("directory-listing pattern detected in public HTML")
        findings.append(finding("directory-listing", "The public HTML contains an Index of / or directory-listing title."))
    if final_url.startswith("https://"):
        mixed = re.findall(r"(?:src|href)\s*=\s*[\"'](http://[^\"']+)", body, flags=re.I)
        if mixed:
            signals.append(f"{len(mixed)} mixed-content reference(s) detected")
            findings.append(finding("mixed-content", f"Observed insecure references such as {mixed[0][:160]}"))
    return signals, findings


def inspect_redirects(start_url: str, final_url: str, statuses: Iterable[int]) -> list[Finding]:
    findings: list[Finding] = []
    if start_url.startswith("http://") and final_url.startswith("http://"):
        findings.append(finding("missing-hsts", "The scan began over HTTP and the final URL remained HTTP."))
    return findings


def inspect_public_file(path: str, response) -> str | None:
    if response is None:
        return None
    if response.status_code == 200:
        content_type = response.headers.get("content-type", "")
        if path.endswith("robots.txt") and "text" in content_type:
            return "robots.txt is publicly accessible."
        if path.endswith("sitemap.xml") and ("xml" in content_type or response.text.lstrip().startswith("<?xml")):
            return "sitemap.xml is publicly accessible."
    return None
