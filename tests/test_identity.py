"""Identity functions — IP / user / API key / composite."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from hawkapi_ratelimit import api_key, composite_key, header_key, ip_key, user_key


@dataclass
class _Client:
    host: str


@dataclass
class _Request:
    headers: dict[str, str]
    client: _Client | None = None
    scope: dict[str, Any] | None = None


def test_ip_key_uses_peer_when_proxy_disabled() -> None:
    fn = ip_key(trusted_proxy=False)
    req = _Request(headers={"x-forwarded-for": "10.0.0.99"}, client=_Client(host="1.2.3.4"))
    assert fn(req) == "ip:1.2.3.4"


def test_ip_key_uses_xff_left_token_when_proxy_enabled() -> None:
    fn = ip_key(trusted_proxy=True)
    req = _Request(
        headers={"x-forwarded-for": "203.0.113.7, 10.0.0.1, 10.0.0.2"},
        client=_Client(host="10.0.0.2"),
    )
    assert fn(req) == "ip:203.0.113.7"


def test_ip_key_strips_port_from_xff() -> None:
    fn = ip_key(trusted_proxy=True)
    req = _Request(headers={"x-forwarded-for": "192.0.2.1:8080"}, client=_Client(host=""))
    assert fn(req) == "ip:192.0.2.1"


def test_ip_key_normalizes_ipv6() -> None:
    fn = ip_key(trusted_proxy=True)
    req = _Request(headers={"x-forwarded-for": "0:0:0:0:0:0:0:1"}, client=_Client(host=""))
    assert fn(req) == "ip:::1"


def test_ip_key_handles_bracketed_ipv6() -> None:
    fn = ip_key(trusted_proxy=True)
    req = _Request(headers={"x-forwarded-for": "[2001:db8::1]:8080"}, client=_Client(host=""))
    assert fn(req) == "ip:2001:db8::1"


def test_ip_key_falls_back_to_anon_when_no_client() -> None:
    fn = ip_key()
    req = _Request(headers={}, client=None, scope={})
    assert fn(req).startswith("ip:")


def test_user_key_anon_when_no_user() -> None:
    fn = user_key()
    req = _Request(headers={}, scope={})
    assert fn(req) == "user:anon"


def test_user_key_dict_user() -> None:
    fn = user_key(attribute="user_id")
    req = _Request(headers={}, scope={"user": {"user_id": "u-42"}})
    assert fn(req) == "user:u-42"


def test_user_key_object_user() -> None:
    fn = user_key(attribute="id")

    class _U:
        id = "alice"

    req = _Request(headers={}, scope={"user": _U()})
    assert fn(req) == "user:alice"


def test_header_key_reads_header() -> None:
    fn = header_key("x-api-key", prefix="api")
    req = _Request(headers={"x-api-key": "abc123"})
    assert fn(req) == "api:abc123"


def test_api_key_strips_bearer_prefix() -> None:
    fn = api_key()
    req = _Request(headers={"authorization": "Bearer my-token"})
    assert fn(req) == "apikey:my-token"


def test_api_key_passes_through_non_bearer() -> None:
    fn = api_key()
    req = _Request(headers={"authorization": "Basic dXNlcjpwYXNz"})
    assert fn(req) == "apikey:Basic dXNlcjpwYXNz"


def test_composite_key_combines() -> None:
    fn = composite_key(ip_key(), user_key())
    req = _Request(
        headers={},
        client=_Client(host="1.2.3.4"),
        scope={"user": {"user_id": "u-1"}},
    )
    assert fn(req) == "ip:1.2.3.4|user:u-1"
