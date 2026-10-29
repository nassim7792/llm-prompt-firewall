"""ingress: best-effort text inspection. SCORED, never invariant by default.

Scope matters more than the regexes. The same sentence gets a different weight depending
on the span's trust level: a user writing "act as a translator" is giving an instruction
they are entitled to give; a support ticket saying it is trying to command the model.
"""

from __future__ import annotations

from promptfw.context import Context, Span, Trust
from promptfw.normalize import readings
from promptfw.policy import Policy
from promptfw.rules import CHAT_TEMPLATE_MARKERS, RULES
from promptfw.verdict import Finding, Severity

NAME = "ingress"
DECODING_STEPS = ("base64", "base32", "hex", "percent")


def _severity(score: float) -> Severity:
    if score >= 0.7:
        return Severity.HIGH
    if score >= 0.4:
        return Severity.MEDIUM
    return Severity.LOW


class IngressLayer:
    name = NAME

    def inspect(self, ctx: Context, policy: Policy) -> list[Finding]:
        findings: list[Finding] = []
        for i, span in enumerate(ctx.spans):
            if span.trust is Trust.SYSTEM:
                continue
            findings.extend(self._inspect_span(span, i, policy))
        return findings

    def _inspect_span(self, span: Span, idx: int, policy: Policy) -> list[Finding]:
        is_data = span.trust is Trust.DATA
        factor = 1.0 if is_data else policy.user_ingress_factor
        invariant = is_data and policy.strict_data
        texts = readings(span.text, "ingress")
        findings: list[Finding] = []

        # Chat-template markers: precision-first rule.
        for marker in CHAT_TEMPLATE_MARKERS:
            hit = next((r for r in texts if marker in r.text.casefold()), None)
            if hit:
                score = (0.85 if is_data else 0.6)
                findings.append(Finding(NAME, "chat-template-marker", _severity(score), invariant, score, idx,
                                        hit.path, marker, "Chat-template control token inside content"))
                break

        decoded_hit = False
        for rule in RULES:
            if rule.id in policy.disabled_rules:
                continue
            for reading in texts:
                m = rule.pattern.search(reading.text)
                if not m:
                    continue
                score = (rule.data_weight if is_data else rule.weight) * factor
                findings.append(Finding(NAME, rule.id, _severity(score), invariant, round(score, 3), idx,
                                        reading.path, m.group(0)[:80], f"{rule.description} [{rule.owasp}]"))
                if any(step in reading.path for step in DECODING_STEPS):
                    decoded_hit = True
                break

        # Instructions that only appear once decoded are an evasion attempt in themselves.
        if decoded_hit:
            findings.append(Finding(NAME, "decoded-payload", Severity.MEDIUM, invariant, 0.3, idx,
                                    message="Injection only visible after decoding an encoded blob"))
        return findings
