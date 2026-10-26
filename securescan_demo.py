"""
=============================================================
  SecureScan AI — Standalone Cybersecurity Demo Script
  Project  : Passive Website Security Configuration Scanner
  File     : securescan_demo.py
  Language : Python 3.12+
=============================================================

  This script is a self-contained demo of the core passive
  security checks performed by SecureScan AI.

  It covers:
    1. URL validation & SSRF protection
    2. TLS / HTTPS certificate inspection
    3. HTTP security header analysis
    4. Cookie security attribute inspection
    5. Server information disclosure detection
    6. Mixed-content & directory listing detection
    7. robots.txt / sitemap.xml public metadata check
    8. HTTP → HTTPS redirect chain inspection
    9. Risk scoring (weighted, deduplicating)
   10. Plain-text report output

  Usage:
    pip install httpx
    python securescan_demo.py https://example.com
    python securescan_demo.py https://example.com --json
=============================================================
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import re
import socket
import ssl
import sys
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from typing import Any
from urllib.parse import urljoin, urlsplit

try:
    import httpx
except ImportError:
    print("[ERROR] httpx is not installed. Run:  pip install httpx")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────
# 1. CONFIGURATION & CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

TIMEOUT_SECONDS: float = 8.0
MAX_RESPONSE_BYTES: int = 262_144   # 256 KB
MAX_REDIRECTS: int = 3
RATE_LIMIT: int = 8  # (not enforced in CLI — only for reference)

SECURITY_HEADERS: list[tuple[str, str, str]] = [
    ("Strict-Transport-Security", "medium",
     "HSTS instructs browsers to only connect over HTTPS after the first visit."),
    ("Content-Security-Policy", "medium",
     "CSP restricts the sources a browser is allowed to load."),
    ("X-Content-Type-Options", "low",
     "'nosniff' prevents MIME-type sniffing attacks."),
    ("X-Frame-Options", "medium",
     "Controls whether the page may be embedded in a frame (clickjacking defence)."),
    ("Referrer-Policy", "low",
     "Controls how much URL context is passed to other origins."),
    ("Permissions-Policy", "low",
     "Restricts access to powerful browser features (camera, microphone, …)."),
]

SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 30,
    "high":     15,
    "medium":    8,
    "low":       3,
    "info":      0,
}

CSP_UNSAFE = re.compile(r"'unsafe-inline'|'unsafe-eval'|\*\s*(;|$)", re.I)

# ─────────────────────────────────────────────────────────────────────────────
# 2. URL VALIDATION & SSRF PROTECTION
# ─────────────────────────────────────────────────────────────────────────────

class ScanInputError(ValueError):
    """Raised when the user-supplied URL is unsafe or malformed."""


def normalize_url(raw: str) -> str:
    """
    Normalise a user-supplied URL.
    Enforces: http/https only, no credentials, no fragment, no non-standard
    ports, no localhost / internal hostnames.
    """
    value = raw.strip()
    if not value:
        raise ScanInputError("Enter a website URL.")
    if "://" not in value:
        value = f"https://{value}"
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ScanInputError("Only HTTP and HTTPS URLs are supported.")
    if parsed.username or parsed.password:
        raise ScanInputError("URLs with embedded credentials are not allowed.")
    if parsed.fragment:
        raise ScanInputError("Remove the URL fragment (#…) and try again.")
    if not parsed.hostname:
        raise ScanInputError("Enter a valid public website hostname.")
    if len(value) > 2048:
        raise ScanInputError("The URL is too long (max 2048 characters).")
    if parsed.port and parsed.port not in {80, 443}:
        raise ScanInputError("Only standard HTTP (80) and HTTPS (443) ports are allowed.")
    host = parsed.hostname.rstrip(".").lower()
    internal = {"localhost", "localhost.localdomain", "metadata.google.internal",
                "host.docker.internal", "169.254.169.254"}
    if host in internal or host.endswith((".localhost", ".local", ".internal")):
        raise ScanInputError("Local and internal hostnames are not permitted (SSRF protection).")
    return value


def is_public_ip(addr: str) -> bool:
    """Return True only if the IP is a globally routable public address."""
    try:
        address = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
        or addr in {"169.254.169.254", "100.100.100.200"}  # cloud metadata
    )


def validate_public_url(url: str) -> tuple[str, list[str]]:
    """
    Validate and normalise the URL then resolve its hostname and verify
    every resolved IP is a public address (SSRF guard).
    Returns (normalised_url, [resolved_ips]).
    """
    normalized = normalize_url(url)
    parsed = urlsplit(normalized)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    hostname = parsed.hostname or ""
    if is_public_ip(hostname):
        return normalized, [hostname]
    try:
        answers = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ScanInputError("The hostname could not be resolved.") from exc
    ips = sorted({str(a[4][0]) for a in answers})
    if not ips or any(not is_public_ip(ip) for ip in ips):
        raise ScanInputError("The hostname resolves to a private or unsafe address.")
    return normalized, ips


# ─────────────────────────────────────────────────────────────────────────────
# 3. TLS / CERTIFICATE INSPECTION
# ─────────────────────────────────────────────────────────────────────────────

def check_tls(hostname: str) -> dict[str, Any]:
    """
    Open a TLS handshake to port 443 and return certificate metadata.
    This is a passive read — no exploitation is attempted.
    """
    ctx = ssl.create_default_context()
    result: dict[str, Any] = {"hostname": hostname, "available": False, "valid": False}
    try:
        with socket.create_connection((hostname, 443), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=hostname) as tls:
                cert = tls.getpeercert() or {}
                result["available"] = True
                result["valid"] = True
                result["protocol"] = tls.version()
                result["cipher"] = tls.cipher()
                not_after = cert.get("notAfter", "")
                if not_after:
                    expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    result["expires_at"] = expires.isoformat()
                    days_left = (expires - datetime.now(timezone.utc)).days
                    result["days_until_expiry"] = days_left
                    if days_left < 0:
                        result["expired"] = True
                    elif days_left < 30:
                        result["expiring_soon"] = True
                subject = dict(x[0] for x in cert.get("subject", []))
                result["common_name"] = subject.get("commonName", "")
                result["issuer"] = dict(x[0] for x in cert.get("issuer", []))
    except ssl.SSLCertVerificationError as exc:
        result["available"] = True
        result["valid"] = False
        result["error"] = f"Certificate verification failed: {exc}"
    except (ssl.SSLError, OSError, socket.timeout) as exc:
        result["error"] = f"TLS negotiation failed: {exc}"
    return result


# ─────────────────────────────────────────────────────────────────────────────
# 4–8. PASSIVE HTTP CHECKS
# ─────────────────────────────────────────────────────────────────────────────

def check_security_headers(headers: httpx.Headers) -> list[dict[str, Any]]:
    """
    Check for the presence and strength of each recommended security header.
    Returns a list of result dicts, one per header.
    """
    results = []
    for name, severity, note in SECURITY_HEADERS:
        value = headers.get(name) or headers.get(name.lower())
        if name == "X-Frame-Options":
            csp = headers.get("Content-Security-Policy") or headers.get("content-security-policy") or ""
            present = bool(value or re.search(r"frame-ancestors\s+[^;]+", csp, re.I))
        else:
            present = bool(value)
        entry: dict[str, Any] = {
            "header": name,
            "present": present,
            "value": value,
            "severity": severity,
            "note": note,
        }
        if name == "Content-Security-Policy" and present and value and CSP_UNSAFE.search(value):
            entry["weak_csp"] = True
            entry["weak_note"] = "CSP contains 'unsafe-inline', 'unsafe-eval', or a wildcard source."
        results.append(entry)
    return results


def check_cookies(headers: httpx.Headers) -> list[dict[str, Any]]:
    """
    Parse Set-Cookie headers and flag missing Secure, HttpOnly, SameSite attributes.
    """
    results = []
    raw_cookies: list[str] = []
    # httpx stores multiple Set-Cookie values as repeated header lines
    for key, val in headers.items():
        if key.lower() == "set-cookie":
            raw_cookies.append(val)
    for raw in raw_cookies:
        parsed = SimpleCookie()
        try:
            parsed.load(raw)
        except Exception:
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
            results.append({
                "name": name,
                "secure": secure,
                "http_only": http_only,
                "same_site": same_site,
                "missing_attributes": missing,
            })
    return results


def check_information_disclosure(headers: httpx.Headers) -> list[dict[str, Any]]:
    """
    Detect server/technology banners and debug headers that reveal stack info.
    """
    findings = []
    banner_headers = ["server", "x-powered-by", "x-aspnet-version", "x-generator"]
    for h in banner_headers:
        val = headers.get(h)
        if val:
            findings.append({
                "header": h,
                "value": val,
                "severity": "medium",
                "note": "Revealing server/technology information aids fingerprinting.",
            })
    debug_headers = ["x-debug-token", "x-debug-exception"]
    for h in debug_headers:
        val = headers.get(h)
        if val:
            findings.append({
                "header": h,
                "value": val,
                "severity": "high",
                "note": "Debug headers should never be exposed in production.",
            })
    return findings


def check_mixed_content(body: str, final_url: str) -> list[str]:
    """Find http:// references embedded in an https:// page (mixed content)."""
    if not final_url.startswith("https://"):
        return []
    mixed = re.findall(r'(?:src|href)\s*=\s*["\']( http://[^"\']+)', body, re.I)
    return mixed[:10]  # cap at 10 examples


def check_directory_listing(body: str) -> bool:
    """Detect a directory-listing page via its characteristic HTML title."""
    return bool(
        re.search(r"<title>\s*(?:index of|directory listing)\s*<", body, re.I)
        or re.search(r"Index of /", body, re.I)
    )


async def fetch_public_file(client: httpx.AsyncClient, base_url: str, path: str) -> tuple[str, int | None]:
    """Attempt to fetch a public metadata file (robots.txt, sitemap.xml)."""
    origin = "{scheme}://{netloc}".format(**urlsplit(base_url)._asdict())
    full_url = urljoin(origin + "/", path.lstrip("/"))
    try:
        validate_public_url(full_url)
        resp = await client.get(full_url, follow_redirects=False)
        return path, resp.status_code
    except Exception:
        return path, None


# ─────────────────────────────────────────────────────────────────────────────
# 9. SCORING ENGINE
# ─────────────────────────────────────────────────────────────────────────────

def compute_score(finding_ids_and_severities: list[tuple[str, str]]) -> tuple[int, str]:
    """
    Deduplicating weighted score: each unique finding ID is counted once.
    Score starts at 100 and subtracts per-severity weights.
    """
    unique: dict[str, str] = {}
    for fid, sev in finding_ids_and_severities:
        unique.setdefault(fid, sev)
    score = max(0, 100 - sum(SEVERITY_WEIGHTS.get(s, 0) for s in unique.values()))
    if score >= 90:
        label = "Good configuration"
    elif score >= 75:
        label = "Low apparent configuration risk"
    elif score >= 50:
        label = "Moderate configuration risk"
    elif score >= 25:
        label = "High configuration risk"
    else:
        label = "Very high configuration risk"
    return score, label


# ─────────────────────────────────────────────────────────────────────────────
# 10. MAIN SCAN ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

async def scan(url: str) -> dict[str, Any]:
    """
    Run a full passive security scan against the given URL.
    Returns a structured result dictionary.
    """
    scan_id = str(uuid.uuid4())
    started = time.perf_counter()
    scanned_at = datetime.now(timezone.utc).isoformat()

    # 1. Validate URL (raises ScanInputError if unsafe)
    normalized, resolved_ips = validate_public_url(url)
    parsed = urlsplit(normalized)
    hostname = parsed.hostname or ""

    result: dict[str, Any] = {
        "scan_id": scan_id,
        "target_url": url,
        "normalized_url": normalized,
        "hostname": hostname,
        "resolved_ips": resolved_ips,
        "scanned_at": scanned_at,
        "tls": {},
        "security_headers": [],
        "cookies": [],
        "information_disclosure": [],
        "public_files": {},
        "mixed_content": [],
        "directory_listing": False,
        "redirect_chain": [],
        "findings_summary": {},
        "score": None,
        "score_label": "Insufficient data",
        "errors": [],
    }

    # 2. TLS check
    if parsed.scheme == "https":
        result["tls"] = check_tls(hostname)

    # 3. HTTP scan
    timeout = httpx.Timeout(TIMEOUT_SECONDS)
    headers = {"User-Agent": "SecureScanAI-Demo/1.0 (+passive-configuration-checks)"}
    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=False,
        verify=True,
        headers=headers,
    ) as client:
        # Follow redirects manually to record the chain
        current = normalized
        visited: set[str] = set()
        response: httpx.Response | None = None
        body = ""

        for hop in range(MAX_REDIRECTS + 1):
            if current in visited:
                result["errors"].append("Redirect loop detected.")
                break
            visited.add(current)
            try:
                validate_public_url(current)
            except ScanInputError as exc:
                result["errors"].append(f"Redirect blocked: {exc}")
                break
            try:
                resp = await client.get(current)
                result["redirect_chain"].append({"url": current, "status": resp.status_code})
                if resp.status_code not in {301, 302, 303, 307, 308}:
                    response = resp
                    body = resp.text[:MAX_RESPONSE_BYTES]
                    break
                loc = resp.headers.get("location", "")
                if not loc:
                    response = resp
                    body = resp.text[:MAX_RESPONSE_BYTES]
                    break
                current = urljoin(current, loc)
            except httpx.TimeoutException:
                result["errors"].append("Request timed out.")
                break
            except httpx.HTTPError as exc:
                result["errors"].append(f"HTTP error: {type(exc).__name__}")
                break

        if response is not None:
            result["status_code"] = response.status_code
            result["final_url"] = str(response.url)

            # 4. Security headers
            result["security_headers"] = check_security_headers(response.headers)

            # 5. Cookie attributes
            result["cookies"] = check_cookies(response.headers)

            # 6. Information disclosure
            result["information_disclosure"] = check_information_disclosure(response.headers)

            # 7. Mixed content & directory listing
            result["mixed_content"] = check_mixed_content(body, str(response.url))
            result["directory_listing"] = check_directory_listing(body)

            # 8. Public metadata files
            for path in ("/robots.txt", "/sitemap.xml"):
                p, code = await fetch_public_file(client, normalized, path)
                result["public_files"][p] = code

    # 9. Scoring
    finding_ids: list[tuple[str, str]] = []
    for h in result["security_headers"]:
        if not h["present"]:
            finding_ids.append((f"missing-{h['header'].lower()}", h["severity"]))
        if h.get("weak_csp"):
            finding_ids.append(("weak-csp", "medium"))
    for c in result["cookies"]:
        if c["missing_attributes"]:
            finding_ids.append(("insecure-cookie", "medium"))
            break
    for d in result["information_disclosure"]:
        finding_ids.append((f"disclosure-{d['header']}", d["severity"]))
    if result["mixed_content"]:
        finding_ids.append(("mixed-content", "medium"))
    if result["directory_listing"]:
        finding_ids.append(("directory-listing", "high"))
    if result.get("tls") and not result["tls"].get("valid"):
        finding_ids.append(("invalid-tls", "critical"))

    if "status_code" in result:
        score, label = compute_score(finding_ids)
        result["score"] = score
        result["score_label"] = label

    counts = Counter(sev for _, sev in finding_ids)
    result["findings_summary"] = dict(counts)
    result["elapsed_ms"] = round((time.perf_counter() - started) * 1000)
    return result


# ─────────────────────────────────────────────────────────────────────────────
# 11. REPORT PRINTER
# ─────────────────────────────────────────────────────────────────────────────

def print_report(r: dict[str, Any]) -> None:
    sep = "=" * 68
    print(f"\n{sep}")
    print("  SecureScan AI - Passive Security Configuration Report")
    print(sep)
    print(f"  Target URL   : {r['target_url']}")
    print(f"  Normalized   : {r['normalized_url']}")
    print(f"  Hostname     : {r['hostname']}")
    print(f"  Resolved IPs : {', '.join(r.get('resolved_ips', []))}")
    print(f"  Scanned At   : {r['scanned_at']}")
    status = r.get("status_code", "unreachable")
    final = r.get("final_url", r["normalized_url"])
    print(f"  HTTP Status  : {status}  (final URL: {final})")
    print(f"  Elapsed      : {r.get('elapsed_ms', '?')} ms")
    print(f"  Score        : {r['score']} / 100 -- {r['score_label']}")
    print()

    # TLS
    tls = r.get("tls", {})
    print("-- TLS / Certificate " + "-" * 47)
    if not tls:
        print("  (HTTP - no TLS check performed)")
    elif tls.get("valid"):
        print("  [OK]  Valid certificate")
        print(f"      Protocol : {tls.get('protocol', 'unknown')}")
        print(f"      Expires  : {tls.get('expires_at', '?')}  ({tls.get('days_until_expiry', '?')} days)")
        print(f"      CN       : {tls.get('common_name', '?')}")
        issuer = tls.get("issuer", {})
        print(f"      Issued by: {issuer.get('organizationName', issuer.get('commonName', '?'))}")
        if tls.get("expired"):
            print("  [FAIL] CERTIFICATE IS EXPIRED")
        elif tls.get("expiring_soon"):
            print("  [WARN] Certificate expires within 30 days!")
    else:
        print(f"  [FAIL] TLS unavailable or invalid: {tls.get('error', 'unknown')}")
    print()

    # Security headers
    print("-- Security Headers " + "-" * 49)
    for h in r.get("security_headers", []):
        mark = "[OK]  " if h["present"] else "[MISS]"
        sev = f"[{h['severity'].upper()}]"
        val_preview = f" = {str(h['value'])[:55]}" if h["present"] and h["value"] else ""
        print(f"  {mark} {sev:<10} {h['header']}{val_preview}")
        if h.get("weak_csp"):
            print(f"     [WARN] Weak CSP: {h['weak_note']}")
    print()

    # Cookies
    cookies = r.get("cookies", [])
    print("-- Cookie Security " + "-" * 49)
    if not cookies:
        print("  No Set-Cookie headers observed.")
    else:
        for c in cookies:
            mark = "[OK]  " if not c["missing_attributes"] else "[WARN]"
            missing_str = ", ".join(c["missing_attributes"]) if c["missing_attributes"] else "none"
            print(f"  {mark} {c['name']}  |  Secure={c['secure']}  HttpOnly={c['http_only']}  SameSite={c['same_site']}  |  Missing: {missing_str}")
    print()

    # Information disclosure
    disclosures = r.get("information_disclosure", [])
    print("-- Information Disclosure " + "-" * 43)
    if not disclosures:
        print("  No server/technology banners detected.")
    else:
        for d in disclosures:
            print(f"  [WARN] [{d['severity'].upper()}] {d['header']}: {d['value']}")
    print()

    # Mixed content
    mixed = r.get("mixed_content", [])
    print("-- Mixed Content " + "-" * 51)
    if mixed:
        print(f"  [FAIL] {len(mixed)} insecure http:// reference(s) found on an HTTPS page:")
        for m in mixed[:3]:
            print(f"      {m}")
    else:
        print("  [OK]  No mixed-content references detected.")
    print()

    # Directory listing
    print("-- Directory Listing " + "-" * 47)
    if r.get("directory_listing"):
        print("  [FAIL] Directory listing pattern detected in public HTML.")
    else:
        print("  [OK]  No directory listing pattern detected.")
    print()

    # Public metadata files
    pf = r.get("public_files", {})
    print("-- Public Metadata Files " + "-" * 43)
    for path, code in pf.items():
        status_str = f"HTTP {code}" if code else "unreachable"
        mark = "[INFO]" if code == 200 else "[----]"
        print(f"  {mark}  {path}  ->  {status_str}")
    print()

    # Redirect chain
    chain = r.get("redirect_chain", [])
    print("-- Redirect Chain " + "-" * 50)
    if not chain:
        print("  No redirects followed.")
    else:
        for hop in chain:
            print(f"  [{hop['status']}]  {hop['url']}")
    print()

    # Score summary
    print("-- Findings Summary " + "-" * 49)
    fs = r.get("findings_summary", {})
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = fs.get(sev, 0)
        bar = "#" * count
        print(f"  {sev.capitalize():<12} {count:>2}  {bar}")
    print()

    # Errors
    if r.get("errors"):
        print("-- Scanner Notes " + "-" * 51)
        for err in r["errors"]:
            print(f"  [WARN] {err}")
        print()

    print("-- Scope & Limitations " + "-" * 45)
    print("  * Only unauthenticated public HTTP responses were examined.")
    print("  * Missing headers are observations, not proof of exploitability.")
    print("  * A passing score cannot confirm a website is fully secure.")
    print(sep)
    print()


# ---------------------------------------------------------------------------
# 12. CLI ENTRY POINT
# ---------------------------------------------------------------------------

async def main_async(url: str, output_json: bool) -> None:
    print(f"\n[*] Starting passive scan of: {url}")
    print("    This scanner only reads public HTTP responses. No exploitation.")
    try:
        result = await scan(url)
    except ScanInputError as exc:
        print(f"\n[ERROR] Invalid target: {exc}")
        sys.exit(1)
    except Exception as exc:
        print(f"\n[ERROR] Scan failed unexpectedly: {exc}")
        sys.exit(2)

    if output_json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print_report(result)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SecureScan AI - Passive Website Security Configuration Scanner"
    )
    parser.add_argument("url", help="Target URL (e.g. https://example.com)")
    parser.add_argument(
        "--json", action="store_true", dest="output_json",
        help="Output raw JSON instead of a formatted report"
    )
    args = parser.parse_args()
    asyncio.run(main_async(args.url, args.output_json))


if __name__ == "__main__":
    main()
