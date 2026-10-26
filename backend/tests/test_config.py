import socket

import pytest

from app.config import ScanInputError, is_public_ip, normalize_url, resolve_host_ips, validate_public_url


def test_normalize_adds_https_and_rejects_credentials():
    assert normalize_url("example.com/path") == "https://example.com/path"
    with pytest.raises(ScanInputError, match="usernames"):
        normalize_url("https://user:pass@example.com")


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "fc00::1"])
def test_private_and_metadata_addresses_are_blocked(address):
    assert not is_public_ip(address)


def test_public_ip_and_dns_answers(monkeypatch):
    assert is_public_ip("93.184.216.34")
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))])
    assert resolve_host_ips("example.com", 443) == ["93.184.216.34"]
    with pytest.raises(ScanInputError):
        validate_public_url("http://localhost")


def test_private_dns_answer_is_blocked(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.10", 443))])
    with pytest.raises(ScanInputError, match="non-public"):
        validate_public_url("https://example.com")
