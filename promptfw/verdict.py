"""Findings, decisions and verdicts.

The single most important field in this project is `Finding.invariant`:

* invariant=True  -> a structural rule was broken (nonce forged, tainted tool call,
                     canary leaked, URL to an unknown host). Always BLOCK, no threshold.
* invariant=False -> a scored guess (text "looks like" an injection). Compared to
                     `Policy.block_threshold`, and documented as incomplete.

Keeping the two apart is what lets the firewall say honestly which of its
decisions are guarantees and which are heuristics.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntEnum


class Severity(IntEnum):
    INFO = 0       # never blocks (e.g. "layer disabled")
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class Decision(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"


@dataclass(frozen=True)
class Finding:
    layer: str                 # normalize / ingress / provenance / toolauth / egress
    rule: str                  # e.g. "nonce-forgery", "PI-001"
    severity: Severity
    invariant: bool
    score: float = 0.0         # only meaningful for scored findings (0..1)
    span_index: int | None = None
    reading: str = "raw"       # which normalised reading matched (raw, canonical, base64...)
    evidence: str = ""         # attacker-derived: never written raw to the audit log
    message: str = ""

    @property
    def label(self) -> str:
        return f"{self.layer}/{self.rule}"

    def to_dict(self, include_evidence: bool = True) -> dict:
        d = {
            "layer": self.layer,
            "rule": self.rule,
            "severity": self.severity.name,
            "invariant": self.invariant,
            "score": round(self.score, 3),
            "span_index": self.span_index,
            "reading": self.reading,
            "message": self.message,
        }
        if include_evidence:
            d["evidence"] = self.evidence
        return d


@dataclass
class Verdict:
    decision: Decision
    findings: list[Finding] = field(default_factory=list)
    score: float = 0.0
    elapsed_ms: float = 0.0
    policy_id: str = "default"

    @property
    def blocked(self) -> bool:
        return self.decision is Decision.BLOCK

    @property
    def blocked_by(self) -> list[Finding]:
        """Findings that actually caused the BLOCK (invariants first)."""
        if not self.blocked:
            return []
        inv = [f for f in self.findings if f.invariant]
        return inv or [f for f in self.findings if f.severity > Severity.INFO and not f.invariant]

    def summary(self) -> str:
        head = f"{self.decision.value.upper()}  ({self.elapsed_ms:.2f} ms, policy {self.policy_id}, score {self.score:.2f})"
        lines = [head]
        for f in self.findings:
            mark = "!" if f.invariant else ("~" if f.severity > Severity.INFO else " ")
            via = f" via {f.reading}" if f.reading not in ("raw", "") else ""
            lines.append(f"  {mark} {f.label:<32} {f.severity.name:<8}{via}  {f.message}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "decision": self.decision.value,
            "score": round(self.score, 3),
            "elapsed_ms": round(self.elapsed_ms, 3),
            "policy_id": self.policy_id,
            "blocked_by": [f.label for f in self.blocked_by],
            "findings": [f.to_dict() for f in self.findings],
        }
