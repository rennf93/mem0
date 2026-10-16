"""Tests for the optional fastapi-guard integration in server/security.py.

The guard is off by default. When enabled it adds per-IP auto bans, IP allow/deny
lists, trusted-proxy client-IP resolution and path/query/header screening, and
leaves rate limiting to slowapi.
"""

import asyncio
import os
import sys
from unittest.mock import patch

import pytest

pytest.importorskip("fastapi", reason="fastapi not installed")

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

# server/ modules use bare imports, so the server directory itself must be importable.
_SERVER_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "server")
if _SERVER_DIR not in sys.path:
    sys.path.insert(0, _SERVER_DIR)

from security import install_security  # noqa: E402

ATTACK = {"q": "<script>alert(1)</script>"}
LAN_IP = "192.168.1.50"
PUBLIC_IP = "203.0.113.7"


def _app() -> FastAPI:
    app = FastAPI()

    @app.get("/ping")
    def ping():
        return {"ok": True}

    @app.post("/memories")
    def memories(body: dict):
        return {"echo": body}

    return app


def _client(env: dict, peer: str = PUBLIC_IP) -> TestClient:
    app = _app()
    assert install_security(app, {"MEM0_SECURITY_ENABLED": "true", **env})
    return TestClient(app, client=(peer, 50000))


@pytest.fixture(autouse=True)
def _reset_guard_state():
    # The ban list is a process-wide singleton, so clear it between tests.
    pytest.importorskip("guard", reason="fastapi-guard not installed")
    from guard_core.handlers.ipban_handler import IPBanManager, reset_global_state

    asyncio.run(reset_global_state())
    yield
    IPBanManager().banned_ips.clear()


def test_disabled_adds_nothing_and_never_imports_guard():
    app = _app()
    # A None entry makes `import guard` raise ImportError, proving it is never attempted.
    with patch.dict(sys.modules, {"guard": None}):
        assert install_security(app, {}) is False
        assert install_security(app, {"MEM0_SECURITY_ENABLED": "false"}) is False
    assert app.user_middleware == []


def test_enabled_without_fastapi_guard_raises_clear_error():
    with patch.dict(sys.modules, {"guard": None}):
        with pytest.raises(RuntimeError, match="fastapi-guard is not installed"):
            install_security(_app(), {"MEM0_SECURITY_ENABLED": "true"})


def test_clean_request_passes():
    assert _client({}).get("/ping").status_code == 200


def test_attack_in_query_is_blocked():
    assert _client({}).get("/ping", params=ATTACK).status_code == 400


def test_ip_is_banned_after_repeated_attacks():
    client = _client({"MEM0_SECURITY_AUTO_BAN_THRESHOLD": "3"})
    for _ in range(5):
        client.get("/ping", params=ATTACK)
    assert client.get("/ping").status_code == 403


def test_other_ip_is_not_affected_by_a_ban():
    app = _app()
    install_security(app, {"MEM0_SECURITY_ENABLED": "true", "MEM0_SECURITY_AUTO_BAN_THRESHOLD": "2"})
    attacker = TestClient(app, client=(PUBLIC_IP, 50000))
    bystander = TestClient(app, client=("198.51.100.9", 50000))
    for _ in range(4):
        attacker.get("/ping", params=ATTACK)
    assert attacker.get("/ping").status_code == 403
    assert bystander.get("/ping").status_code == 200


def test_allowlist_rejects_other_ips_with_403():
    env = {"MEM0_SECURITY_ALLOWED_IPS": "10.0.0.0/8"}
    assert _client(env, peer=LAN_IP).get("/ping").status_code == 403
    assert _client(env, peer="10.1.2.3").get("/ping").status_code == 200


def test_blocklist_rejects_listed_ip():
    env = {"MEM0_SECURITY_BLOCKED_IPS": PUBLIC_IP}
    assert _client(env).get("/ping").status_code == 403


def test_spoofed_xff_from_untrusted_peer_is_ignored():
    # The peer is not a trusted proxy, so its claim to be 10.1.2.3 must not pass the allowlist.
    client = _client({"MEM0_SECURITY_ALLOWED_IPS": "10.0.0.0/8"})
    assert client.get("/ping", headers={"X-Forwarded-For": "10.1.2.3"}).status_code == 403


def test_xff_from_trusted_proxy_is_honoured():
    env = {"MEM0_SECURITY_ALLOWED_IPS": "10.0.0.0/8", "MEM0_SECURITY_TRUSTED_PROXIES": "172.16.0.0/12"}
    client = _client(env, peer="172.16.0.5")
    assert client.get("/ping", headers={"X-Forwarded-For": "10.1.2.3"}).status_code == 200


def test_trusted_proxies_default_to_loopback_only():
    client = _client({"MEM0_SECURITY_ALLOWED_IPS": "10.0.0.0/8"}, peer=LAN_IP)
    assert client.get("/ping", headers={"X-Forwarded-For": "10.1.2.3"}).status_code == 403
    loopback = _client({"MEM0_SECURITY_ALLOWED_IPS": "10.0.0.0/8"}, peer="127.0.0.1")
    assert loopback.get("/ping", headers={"X-Forwarded-For": "10.1.2.3"}).status_code == 200


def test_body_is_not_scanned_by_default():
    body = {"messages": [{"role": "user", "content": "<script>alert(1)</script> ' OR 1=1 --"}]}
    response = _client({}).post("/memories", json=body)
    assert response.status_code == 200
    assert response.json() == {"echo": body}


def test_body_scan_is_opt_in():
    body = {"messages": [{"role": "user", "content": "<script>alert(1)</script>"}]}
    assert _client({"MEM0_SECURITY_SCAN_BODY": "true"}).post("/memories", json=body).status_code == 400


def test_guard_does_not_rate_limit():
    client = _client({})
    assert all(client.get("/ping").status_code == 200 for _ in range(30))
