import httpx
import pytest

from app.scanner import fetch_with_redirects


@pytest.mark.asyncio
async def test_redirect_to_private_destination_is_blocked(monkeypatch):
    import app.scanner as scanner

    def fake_validate(url):
        if "127.0.0.1" in url:
            raise scanner.ScanInputError("private destination")
        return url, ["93.184.216.34"]

    monkeypatch.setattr(scanner, "validate_public_url", fake_validate)

    class FakeStream:
        def __init__(self, response):
            self.response = response

        async def __aenter__(self):
            return self.response

        async def __aexit__(self, *args):
            return None

    class FakeClient:
        def stream(self, method, url, follow_redirects=False):
            response = httpx.Response(302, headers={"location": "http://127.0.0.1/admin"}, request=httpx.Request(method, url))
            return FakeStream(response)

    response, final_url, body, count, errors, statuses, error = await fetch_with_redirects(FakeClient(), "https://example.com")
    assert response is not None
    assert count == 1
    assert statuses == [302]
    assert "blocked" in (error or "")
