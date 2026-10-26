from __future__ import annotations

import asyncio
import ssl
import socket
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

import httpx

from .config import MAX_REDIRECTS, MAX_RESPONSE_BYTES, TIMEOUT_SECONDS, ScanInputError, validate_public_url
from .explanations import finding
from .security_checks import inspect_cookies, inspect_headers, inspect_public_file, inspect_public_signals, inspect_redirects
from .scoring import score_findings, summarize
from .schemas import ScanReport, TlsStatus


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


async def read_limited(response: httpx.Response) -> bytes:
    data = bytearray()
    async for chunk in response.aiter_bytes():
        data.extend(chunk)
        if len(data) >= MAX_RESPONSE_BYTES:
            break
    return bytes(data[:MAX_RESPONSE_BYTES])


def certificate_status(hostname: str) -> TlsStatus:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=min(TIMEOUT_SECONDS, 5)) as raw:
            with context.wrap_socket(raw, server_hostname=hostname) as secure_socket:
                certificate = secure_socket.getpeercert() or {}
                expires = certificate.get("notAfter")
                expires_at = None
                if isinstance(expires, str):
                    expires_at = datetime.strptime(expires, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc).isoformat()
                return TlsStatus(requested_https=True, available=True, valid_certificate=True, expires_at=expires_at, protocol=secure_socket.version())
    except ssl.SSLCertVerificationError as exc:
        return TlsStatus(requested_https=True, available=True, valid_certificate=False, error="TLS certificate verification failed.")
    except (ssl.SSLError, OSError, socket.timeout):
        return TlsStatus(requested_https=True, available=False, valid_certificate=False, error="TLS negotiation could not be completed from the scanner.")


async def fetch_with_redirects(client: httpx.AsyncClient, start_url: str) -> tuple[httpx.Response | None, str, str, int, list[str], list[int], str | None]:
    current = start_url
    visited: set[str] = set()
    body = ""
    statuses: list[int] = []
    errors: list[str] = []
    request_count = 0
    for _ in range(MAX_REDIRECTS + 1):
        if current in visited:
            return None, current, body, request_count, errors, statuses, "Redirect loop detected."
        visited.add(current)
        # Re-resolve the hostname before every hop to reduce DNS-rebinding and redirect bypass risk.
        validate_public_url(current)
        request_count += 1
        try:
            async with client.stream("GET", current, follow_redirects=False) as streamed:
                raw_body = await read_limited(streamed)
                response_headers = streamed.headers.copy()
                # httpx has already decoded content-encoding while streaming; remove
                # transfer metadata before creating the bounded in-memory response.
                response_headers.pop("content-encoding", None)
                response_headers.pop("transfer-encoding", None)
                response_headers.pop("content-length", None)
                response = httpx.Response(
                    status_code=streamed.status_code,
                    headers=response_headers,
                    content=raw_body,
                    request=streamed.request,
                )
                body = raw_body.decode(streamed.encoding or "utf-8", errors="replace")
            assert response is not None
            statuses.append(response.status_code)
        except httpx.TimeoutException:
            return None, current, body, request_count, errors, statuses, "The target timed out before the passive checks completed."
        except httpx.HTTPError as exc:
            return None, current, body, request_count, errors, statuses, f"The target could not be fetched safely: {type(exc).__name__}."
        if response.status_code not in {301, 302, 303, 307, 308} or not response.headers.get("location"):
            return response, current, body, request_count, errors, statuses, None
        next_url = urljoin(current, response.headers["location"])
        try:
            next_url, _ = validate_public_url(next_url)
        except ScanInputError as exc:
            return response, current, body, request_count, errors, statuses, f"A redirect was blocked: {exc}"
        current = next_url
    return None, current, body, request_count, errors, statuses, "The redirect limit was reached."


async def scan_target(raw_url: str) -> ScanReport:
    normalized, _ = validate_public_url(raw_url)
    parsed = urlsplit(normalized)
    started = time.perf_counter()
    scan_id = str(uuid.uuid4())
    scanned_at = utc_now()
    errors: list[str] = []
    public_signals: list[str] = []
    findings = []
    headers_checks = []
    cookies = []
    request_count = 0
    response: httpx.Response | None = None
    final_url = normalized
    body = ""
    statuses: list[int] = []
    tls = certificate_status(parsed.hostname or "") if parsed.scheme == "https" else TlsStatus(requested_https=False, available=None, valid_certificate=None, error=None)

    timeout = httpx.Timeout(TIMEOUT_SECONDS, connect=TIMEOUT_SECONDS, read=TIMEOUT_SECONDS, write=TIMEOUT_SECONDS, pool=TIMEOUT_SECONDS)
    limits = httpx.Limits(max_connections=4, max_keepalive_connections=2)
    headers = {"User-Agent": "SecureScanAI/1.0 (+passive-configuration-checks)"}
    async with httpx.AsyncClient(timeout=timeout, limits=limits, headers=headers, verify=True) as client:
        try:
            response, final_url, body, count, fetch_errors, statuses, fetch_error = await fetch_with_redirects(client, normalized)
            request_count += count
            errors.extend(fetch_errors)
            if fetch_error:
                errors.append(fetch_error)
            if response is not None:
                headers_checks, header_findings = inspect_headers(response.headers)
                cookies, cookie_findings = inspect_cookies(response.headers)
                public_signals, public_findings = inspect_public_signals(response.headers, body, final_url)
                findings.extend(header_findings + cookie_findings + public_findings)
                findings.extend(inspect_redirects(normalized, final_url, statuses))

                # A HEAD probe is non-invasive and avoids downloading a second page just to
                # verify whether the HTTP entry point upgrades to HTTPS.
                if parsed.scheme == "https" and request_count < 8:
                    http_url = normalized.replace("https://", "http://", 1)
                    try:
                        validate_public_url(http_url)
                        http_probe = await client.head(http_url, follow_redirects=False)
                        request_count += 1
                        location = http_probe.headers.get("location", "")
                        if 300 <= http_probe.status_code < 400 and location.lower().startswith("https://"):
                            public_signals.append("HTTP entry point redirects to HTTPS.")
                        elif http_probe.status_code not in {405, 501} and not location.lower().startswith("https://"):
                            findings.append(finding("http-not-upgraded", f"HTTP probe returned {http_probe.status_code} with no HTTPS redirect."))
                    except (httpx.HTTPError, ScanInputError):
                        public_signals.append("HTTP-to-HTTPS behavior could not be verified with a safe probe.")

                origin = f"{urlsplit(final_url).scheme}://{urlsplit(final_url).netloc}"
                for public_path in ("/robots.txt", "/sitemap.xml"):
                    if request_count >= 8:
                        break
                    try:
                        check_url = urljoin(origin + "/", public_path.lstrip("/"))
                        validate_public_url(check_url)
                        extra = await client.get(check_url, follow_redirects=False)
                        request_count += 1
                        signal = inspect_public_file(public_path, extra)
                        if signal:
                            public_signals.append(signal)
                    except (httpx.HTTPError, ScanInputError):
                        # Optional public metadata should not turn a valid primary scan into a failure.
                        continue
        except ScanInputError as exc:
            errors.append(str(exc))
        except Exception:
            errors.append("The scan stopped because a safe request could not be completed.")

    reachable = response is not None
    evidence_sufficient = bool(reachable and response is not None and response.status_code < 600 and request_count >= 1)
    score, score_label, score_note = score_findings(findings, evidence_sufficient)
    completed = utc_now()
    return ScanReport(
        scan_id=scan_id,
        target_url=raw_url.strip(),
        normalized_url=normalized,
        hostname=parsed.hostname or "unknown",
        scanned_at=scanned_at,
        completed_at=completed,
        reachable=reachable,
        status_code=response.status_code if response else None,
        final_url=final_url if reachable else None,
        response_time_ms=round((time.perf_counter() - started) * 1000),
        request_count=request_count,
        checks_completed=len(headers_checks) + len(cookies) + 4,
        evidence_sufficient=evidence_sufficient,
        score=score,
        score_label=score_label,
        score_note=score_note,
        summary=summarize(findings),
        tls=tls,
        headers=headers_checks,
        cookies=cookies,
        public_signals=public_signals,
        findings=findings,
        errors=errors,
        limitations=[
            "Only unauthenticated, passive HTTP responses were examined.",
            "Missing headers are configuration observations, not proof of an exploitable vulnerability.",
            "A successful scan cannot establish that a website is secure or free of vulnerabilities.",
        ],
    )
