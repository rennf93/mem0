"""Optional fastapi-guard integration. Off unless MEM0_SECURITY_ENABLED is true.

Adds what slowapi (see rate_limit.py) does not: per-IP auto bans after repeated
attack attempts, IP allow/deny lists (IPs and CIDRs), trusted-proxy client-IP
resolution and path/query/header screening. It does not replace slowapi: the
guard's own rate limiter and security headers are off, so slowapi's 429s are
unchanged and requests are not counted twice.
"""

import os
from typing import Any, Mapping, Optional

_TRUE = {"1", "true", "yes", "on"}


def _csv(env: Mapping[str, str], name: str) -> list[str]:
    return [item.strip() for item in env.get(name, "").split(",") if item.strip()]


def build_config(env: Mapping[str, str]) -> Any:
    try:
        from guard import SecurityConfig
    except ImportError as exc:
        raise RuntimeError(
            "MEM0_SECURITY_ENABLED is true but fastapi-guard is not installed. "
            "Install it with `pip install fastapi-guard` or set MEM0_SECURITY_ENABLED=false."
        ) from exc

    return SecurityConfig(
        # Only these peers may set X-Forwarded-For; anyone else's header is ignored.
        trusted_proxies=_csv(env, "MEM0_SECURITY_TRUSTED_PROXIES") or ["127.0.0.1", "::1"],
        whitelist=_csv(env, "MEM0_SECURITY_ALLOWED_IPS") or None,
        blacklist=_csv(env, "MEM0_SECURITY_BLOCKED_IPS"),
        auto_ban_threshold=int(env.get("MEM0_SECURITY_AUTO_BAN_THRESHOLD", "5")),
        auto_ban_duration=int(env.get("MEM0_SECURITY_AUTO_BAN_DURATION", "3600")),
        # Memories, messages and prompts are free text, so bodies are not scanned by default.
        detection_scan_body=env.get("MEM0_SECURITY_SCAN_BODY", "").lower() in _TRUE,
        # slowapi owns rate limiting; keep the guard to bans, IP policy and screening.
        enable_rate_limiting=False,
        security_headers=None,
        enable_redis=False,
    )


def install_security(app: Any, env: Optional[Mapping[str, str]] = None) -> bool:
    """Mount the guard on `app` when enabled. Returns whether it was mounted.

    Call this before adding CORSMiddleware so CORS stays outermost and its headers
    are present on guard 403s.
    """
    env = os.environ if env is None else env
    if env.get("MEM0_SECURITY_ENABLED", "").lower() not in _TRUE:
        return False
    config = build_config(env)
    from guard import PureASGISecurityMiddleware

    app.add_middleware(PureASGISecurityMiddleware, config=config)
    return True
