"""JSONL audit log that never stores attacker content.

`evidence` is derived from attacker-controlled text. Writing it raw would turn the audit
log into a second injection surface (think of a SIEM or an LLM summarising the logs later).
So only a keyed digest is written: equal payloads get equal digests, which is enough to
correlate, and nothing readable leaks.

Key management. Digests are only comparable if they were computed with the same key:
  1. explicit key (constructor), else
  2. PROMPTFW_AUDIT_KEY (environment), else
  3. PROMPTFW_AUDIT_KEY_FILE: read, or created with a random key and mode 0600 if missing, else
  4. a random key for this process only (a warning is logged: digests change at every restart).
Every record carries `key_id` (first 8 hex digits of SHA-256 of the key), so records written
under different keys, for instance after a rotation, are never compared by mistake. The key
itself is never written to the log.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
import time
from pathlib import Path

from promptfw.context import Context
from promptfw.verdict import Verdict

log = logging.getLogger("promptfw.audit")
MIN_KEY_BYTES = 16


def load_or_create_key(path: str | Path) -> bytes:
    """Read a persistent key file, or create it (random, 32 bytes, mode 0600) if it does not exist."""
    path = Path(path)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        key = path.read_bytes().strip()
    else:
        key = secrets.token_hex(32).encode()
        with os.fdopen(fd, "wb") as fh:
            fh.write(key)
    if len(key) < MIN_KEY_BYTES:
        raise ValueError(f"audit key in {path} is shorter than {MIN_KEY_BYTES} bytes")
    return key


def resolve_key(key: bytes | None = None) -> tuple[bytes, bool]:
    """Returns (key, persistent)."""
    if key:
        return key, True
    if os.getenv("PROMPTFW_AUDIT_KEY"):
        return os.environ["PROMPTFW_AUDIT_KEY"].encode(), True
    if os.getenv("PROMPTFW_AUDIT_KEY_FILE"):
        return load_or_create_key(os.environ["PROMPTFW_AUDIT_KEY_FILE"]), True
    return secrets.token_bytes(32), False


def key_id(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()[:8]


class AuditLog:
    def __init__(self, path: str | Path | None, key: bytes | None = None):
        self.path = Path(path) if path else None
        self._lock = threading.Lock()
        self._key, persistent = resolve_key(key)
        self.key_id = key_id(self._key)
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if not persistent:
                log.warning("no audit key configured (PROMPTFW_AUDIT_KEY or PROMPTFW_AUDIT_KEY_FILE): "
                            "digests will not be comparable across restarts")

    def digest(self, value: str) -> str:
        return hmac.new(self._key, value.encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:16]

    def record(self, stage: str, verdict: Verdict, ctx: Context | None = None, request_id: str = "") -> dict:
        rec = {
            "ts": round(time.time(), 3),
            "request_id": request_id,
            "key_id": self.key_id,
            "stage": stage,
            "policy_id": verdict.policy_id,
            "decision": verdict.decision.value,
            "score": round(verdict.score, 3),
            "elapsed_ms": round(verdict.elapsed_ms, 3),
            "spans": [{"trust": s.trust.value,
                       "origin": f"{s.origin.channel}:{self.digest(s.origin.ref)}" if s.origin else None,
                       "chars": len(s.text)} for s in (ctx.spans if ctx else ())],
            "findings": [{**f.to_dict(include_evidence=False), "evidence_digest": self.digest(f.evidence) if f.evidence else None}
                         for f in verdict.findings],
        }
        if self.path:
            line = json.dumps(rec, ensure_ascii=False)
            with self._lock, self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        return rec
