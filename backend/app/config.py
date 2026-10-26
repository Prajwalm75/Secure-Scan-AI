from __future__ import annotations

import ipaddress
import os
import socket
from typing import cast
from urllib.parse import urlsplit


class ScanInputError(ValueError):
    pass


def setting_float(name: str, default: float) -> float:
    try:
        return max(1.0, float(os.getenv(name, default)))
    except ValueError:
        return default


def setting_int(name: str, default: int) -> int:
    try:
        return max(1, int(os.getenv(name, default)))
    except ValueError:
        return default


TIMEOUT_SECONDS = setting_float("SCAN_TIMEOUT_SECONDS", 8)
MAX_RESPONSE_BYTES = setting_int("SCAN_MAX_RESPONSE_BYTES", 262_144)
MAX_REDIRECTS = min(setting_int("SCAN_MAX_REDIRECTS", 3), 5)
RATE_LIMIT = min(setting_int("SCAN_RATE_LIMIT", 8), 30)


def normalize_url(raw: str) -> str:
    value = raw.strip()
    if not value:
        raise ScanInputError("Enter a website URL.")
    if "://" not in value:
        value = f"https://{value}"
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ScanInputError("Only HTTP and HTTPS URLs are supported.")
    if parsed.username or parsed.password:
        raise ScanInputError("URLs with usernames or passwords are not allowed.")
    if parsed.fragment:
        raise ScanInputError("Remove the URL fragment and try again.")
    if not parsed.hostname:
        raise ScanInputError("Enter a valid public website hostname.")
    if len(value) > 2048:
        raise ScanInputError("The URL is too long.")
    if parsed.port and parsed.port not in {80, 443}:
        raise ScanInputError("Only standard HTTP and HTTPS ports are allowed.")
    host = parsed.hostname.rstrip(".").lower()
    if host in {"localhost", "localhost.localdomain", "metadata.google.internal", "host.docker.internal"} or host.endswith((".localhost", ".local", ".internal")):
        raise ScanInputError("Local and internal hostnames are not allowed.")
    return value


def is_public_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
        or value in {"169.254.169.254", "100.100.100.200"}
    )


def resolve_host_ips(hostname: str, port: int) -> list[str]:
    try:
        answers = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ScanInputError("The hostname could not be resolved to a public address.") from exc
    addresses = sorted({cast(str, answer[4][0]) for answer in answers})
    if not addresses or any(not is_public_ip(address) for address in addresses):
        raise ScanInputError("The hostname resolves to a non-public or unsafe address.")
    return addresses


def validate_public_url(url: str) -> tuple[str, list[str]]:
    normalized = normalize_url(url)
    parsed = urlsplit(normalized)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    hostname = parsed.hostname or ""
    ips: list[str] = [hostname] if is_public_ip(hostname) else resolve_host_ips(hostname, port)
    return normalized, ips
