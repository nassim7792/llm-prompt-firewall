"""provenance: INVARIANT. Untrusted content can never be promoted to instruction.

Every DATA span is rendered between fences carrying a per-request nonce:

    <<<UNTRUSTED 3f9c1e0d47b28561 origin=ticket:8814>>>
    ...content, verbatim...
    <<<END 3f9c1e0d47b28561>>>

A static delimiter is forgeable by anyone who read the source (open source = everyone).
A 64-bit nonce drawn from a CSPRNG for each request is not. If the nonce appears inside
DATA, the attacker could only have learnt it from a leak: hard block, no threshold.
"""

from __future__ import annotations

import re

from promptfw.context import Context, Origin, Trust
from promptfw.normalize import readings
from promptfw.policy import Policy
from promptfw.verdict import Finding, Severity

NAME = "provenance"
_FENCE_SHAPE = re.compile(r"<<<\s*(untrusted|end)\b", re.IGNORECASE)


def fence_open(nonce: str, origin: Origin) -> str:
    return f"<<<UNTRUSTED {nonce} origin={origin}>>>"


def fence_close(nonce: str) -> str:
    return f"<<<END {nonce}>>>"


class ProvenanceLayer:
    name = NAME

    def inspect(self, ctx: Context, policy: Policy) -> list[Finding]:
        findings: list[Finding] = []
        nonce = ctx.nonce.casefold()
        for i, span in enumerate(ctx.spans):
            if span.trust is not Trust.DATA:
                continue
            texts = readings(span.text, "ingress")
            hit = next((r for r in texts if nonce in r.text.casefold()), None)
            if hit:
                findings.append(Finding(NAME, "nonce-forgery", Severity.CRITICAL, True, 1.0, i, hit.path,
                                        "<nonce>", "Fence nonce present inside DATA"))
                continue
            # Not the real nonce, but someone is trying to close or open a fence: scored.
            shape = next((r for r in texts if _FENCE_SHAPE.search(r.text)), None)
            if shape:
                findings.append(Finding(NAME, "fence-shape", Severity.HIGH, False, 0.7, i, shape.path,
                                        "<<<", "Fence-like delimiter inside DATA (guessing attempt)"))
        return findings
