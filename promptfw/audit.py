"""JSONL audit log that never stores attacker content.

`evidence` is derived from attacker-controlled text. Writing it raw would turn the audit
log into a second injection surface (think of a SIEM or an LLM summarising the logs later).
So only a keyed digest is written: equal payloads get equal digests, which is enough to
correlate, and nothing readable leaks.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from pathlib import Path

from promptfw.context import Context
from promptfw.verdict import Verdict

_KEY = os.getenv("PROMPTFW_AUDIT_KEY", "").encode() or secrets.token_bytes(16)


def digest(value: str) -> str:
    return hmac.new(_KEY, value.encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:16]


class AuditLog:
    def __init__(self, path: str | Path | None):
        self.path = Path(path) if path else None
        self._lock = threading.Lock()
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, stage: str, verdict: Verdict, ctx: Context | None = None, request_id: str = "") -> dict:
        rec = {
            "ts": round(time.time(), 3),
            "request_id": request_id,
            "stage": stage,
            "policy_id": verdict.policy_id,
            "decision": verdict.decision.value,
            "score": round(verdict.score, 3),
            "elapsed_ms": round(verdict.elapsed_ms, 3),
            "spans": [{"trust": s.trust.value,
                       "origin": f"{s.origin.channel}:{digest(s.origin.ref)}" if s.origin else None,
                       "chars": len(s.text)} for s in (ctx.spans if ctx else ())],
            "findings": [{**f.to_dict(include_evidence=False), "evidence_digest": digest(f.evidence) if f.evidence else None}
                         for f in verdict.findings],
        }
        if self.path:
            line = json.dumps(rec, ensure_ascii=False)
            with self._lock, self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        return rec
