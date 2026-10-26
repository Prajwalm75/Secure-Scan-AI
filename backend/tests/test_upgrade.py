import httpx
import pytest

from app.scanner import fetch_with_redirects


@pytest.mark.asyncio
async def test_redirect_chain_stops_at_final_response():
    class FakeStream:
        def __init__(self, response):
            self.response = response

        async def __aenter__(self):
            return self.response

        async def __aexit__(self, *args):
            return None

    class FakeClient:
        def stream(self, method, url, follow_redirects=False):
            if url == "https://example.com":
                response = httpx.Response(301, headers={"location": "https://www.example.com"}, request=httpx.Request(method, url))
            else:
                response = httpx.Response(200, headers={"content-type": "text/html"}, content=b"ok", request=httpx.Request(method, url))
            return FakeStream(response)

    # DNS is mocked so the test never contacts a live website.
    import app.scanner as scanner
    original = scanner.validate_public_url
    scanner.validate_public_url = lambda url: (url, ["93.184.216.34"])
    try:
        response, final_url, body, count, errors, statuses, error = await fetch_with_redirects(FakeClient(), "https://example.com")
    finally:
        scanner.validate_public_url = original
    assert response is not None
    assert final_url == "https://www.example.com"
    assert statuses == [301, 200]
    assert error is None
