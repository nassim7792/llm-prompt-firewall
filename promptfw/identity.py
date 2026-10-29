"""Signed identity and confirmation tokens for proxy mode.

The Chat Completions protocol has no field for "who is the user" or "the user approved
this action". In proxy mode, the application BACKEND passes both in the
X-PromptFW-Principal header, as a short-lived token signed with a key it shares with
the firewall (HMAC-SHA256). An end user who can reach the proxy cannot forge it.

    token   = base64url(payload_json) "." base64url(HMAC-SHA256(key, base64url(payload_json)))
    payload = {"sub": "alice", "roles": ["customer"], "exp": 1793312000, "jti": "<random>",
               "confirm": [{"tool": "refund", "args_sha256": "<hex>"}]}

* `exp` is mandatory and bounded (MAX_TTL_S): a stolen token is only useful briefly.
* `jti` makes the token single-use; it is mandatory when `confirm` is present, so an
  approval cannot be replayed for a second refund.
* a confirmation is bound to the tool AND to the exact arguments (SHA-256 of canonical JSON):
  if the model changes the amount, the approval no longer applies.

Limits: the replay cache is in memory (one process); with several proxy replicas, use a
shared store. HMAC means the backend and the firewall share a secret; asymmetric
signatures (JWT/EdDSA) would avoid that.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import secrets
import threading
import time
from typing import Any

MAX_TTL_S = 300


class TokenError(ValueError):
    pass


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def args_digest(args: dict[str, Any]) -> str:
    canonical = json.dumps(args, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


def sign(payload: dict[str, Any], key: bytes) -> str:
    body = _b64e(json.dumps(payload, separators=(",", ":")).encode())
    mac = hmac.new(key, body.encode(), hashlib.sha256).digest()
    return f"{body}.{_b64e(mac)}"


def mint(key: bytes, sub: str, roles: tuple[str, ...] = (), ttl_s: int = 120,
         confirm: list[tuple[str, dict[str, Any]]] | None = None) -> str:
    """Helper for backends and tests."""
    payload: dict[str, Any] = {"sub": sub, "roles": list(roles), "exp": int(time.time()) + ttl_s,
                               "jti": secrets.token_hex(12)}
    if confirm:
        payload["confirm"] = [{"tool": t, "args_sha256": args_digest(a)} for t, a in confirm]
    return sign(payload, key)


def verify(token: str, key: bytes, now: float | None = None) -> dict[str, Any]:
    now = time.time() if now is None else now
    try:
        body, mac = token.strip().split(".")
        expected = hmac.new(key, body.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _b64d(mac)):
            raise TokenError("bad signature")
        payload = json.loads(_b64d(body))
    except (ValueError, binascii.Error) as e:
        if isinstance(e, TokenError):
            raise
        raise TokenError("malformed token") from None

    if not isinstance(payload, dict):
        raise TokenError("malformed payload")
    sub, roles, exp = payload.get("sub"), payload.get("roles", []), payload.get("exp")
    if not isinstance(sub, str) or not sub.strip():
        raise TokenError("missing sub")
    if not isinstance(roles, list) or not all(isinstance(r, str) for r in roles):
        raise TokenError("roles must be a list of strings")
    if not isinstance(exp, (int, float)) or isinstance(exp, bool):
        raise TokenError("missing exp")
    if exp <= now:
        raise TokenError("expired")
    if exp - now > MAX_TTL_S:
        raise TokenError("lifetime too long")
    confirm = payload.get("confirm", [])
    if confirm:
        if not isinstance(payload.get("jti"), str):
            raise TokenError("confirmations require a jti (single use)")
        if not isinstance(confirm, list) or not all(
                isinstance(c, dict) and isinstance(c.get("tool"), str) and isinstance(c.get("args_sha256"), str)
                for c in confirm):
            raise TokenError("malformed confirm")
    return payload


class ReplayGuard:
    """Remembers token ids until they expire. In memory: one process only."""

    def __init__(self) -> None:
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def first_use(self, jti: str, exp: float, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        with self._lock:
            self._seen = {k: v for k, v in self._seen.items() if v > now}
            if jti in self._seen:
                return False
            self._seen[jti] = exp
            return True
