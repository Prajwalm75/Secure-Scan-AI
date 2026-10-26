import httpx

from app.scoring import score_findings
from app.security_checks import inspect_cookies, inspect_headers, inspect_public_signals


def test_security_headers_detected_and_missing():
    headers = httpx.Headers({
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'self'",
        "X-Content-Type-Options": "nosniff",
        "Server": "example-edge/1.0",
    })
    checks, findings = inspect_headers(headers)
    assert any(check.name == "Content-Security-Policy" and check.present for check in checks)
    assert any(item.id == "missing-hsts" for item in findings)
    assert any(item.id == "missing-framing-policy" for item in findings) is False
    signals, public_findings = inspect_public_signals(headers, '<html><body><script src="http://cdn.example.com/a.js"></script></body></html>', "https://example.com")
    assert "server: example-edge/1.0" in signals
    assert any(item.id == "mixed-content" for item in public_findings)


def test_cookie_attributes_are_parsed():
    headers = httpx.Headers([
        ("set-cookie", "session=abc; Secure; HttpOnly; SameSite=Lax"),
        ("set-cookie", "legacy=value"),
    ])
    cookies, findings = inspect_cookies(headers)
    assert cookies[0].secure is True
    assert cookies[0].http_only is True
    assert cookies[0].same_site == "Lax"
    assert cookies[1].secure is False
    assert any(item.id == "insecure-cookie" for item in findings)


def test_score_is_transparent_and_deduplicated():
    _, findings = inspect_headers(httpx.Headers())
    score, label, note = score_findings(findings + findings, evidence_sufficient=True)
    assert score == 67
    assert label == "Moderate configuration risk"
    assert "not a complete vulnerability assessment" in note
    assert score_findings(findings, evidence_sufficient=False)[0] is None
