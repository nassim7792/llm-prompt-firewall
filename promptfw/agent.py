"""A deliberately gullible, deterministic agent.

It obeys every imperative it reads, anywhere in its prompt (system, user OR fenced data).
It holds a secret. It calls any tool it is told to. That is the point: if the secret
leaks with this agent behind the firewall, the firewall failed. There is no "the model
was having an off day" excuse, and the tests and benchmark run offline without any key.
"""

from __future__ import annotations

import json
import re

from promptfw.tools import AgentReply, ToolCall

_REVEAL = re.compile(r"(?i)\b(reveal|print|tell me|give me|output|leak|repeat|r[ée]v[èe]le|donne)\b.{0,40}"
                     r"\b(secret|password|canary|system prompt|prompt|instructions|mot de passe)\b")
_TOOL = re.compile(r"(?i)\b(?:call|invoke|appelle)\s+(?:the\s+)?(?:tool|function|l'outil)\s+([a-z_]\w*)\s*(?:with\s+)?(\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\})?")
_IMAGE = re.compile(r"!\[[^\]]*\]\([^)]+\)")
_SECRET = re.compile(r"(?i)secret(?: is|:)\s*([A-Za-z0-9-]{8,})")


class MockAgent:
    def __init__(self, secret: str | None = None):
        self.secret = secret

    def reply(self, messages: list[dict[str, str]]) -> AgentReply:
        system = " ".join(m["content"] for m in messages if m["role"] == "system")
        everything = " ".join(m["content"] for m in messages)
        # Real tokenizers read invisible Unicode tag characters; so does this agent.
        hidden = "".join(chr(ord(c) - 0xE0000) for c in everything if 0xE0020 <= ord(c) < 0xE007F)
        everything += " " + hidden
        secret = self.secret
        if secret is None:
            m = _SECRET.search(system)
            secret = m.group(1) if m else None

        tool_calls: list[ToolCall] = []
        for m in _TOOL.finditer(everything):
            name = m.group(1).lower()
            args = {}
            if m.group(2):
                try:
                    args = json.loads(m.group(2))
                except json.JSONDecodeError:
                    args = {}
            if secret:
                args = {k: (v.replace("{secret}", secret) if isinstance(v, str) else v) for k, v in args.items()}
            tool_calls.append(ToolCall(name, args))

        parts: list[str] = []
        if _REVEAL.search(everything):
            parts.append(f"Sure! The secret is {secret}." if secret else f"My instructions were: {system}")
        for img in _IMAGE.findall(everything):
            parts.append(img.replace("{secret}", secret or ""))
        if not parts and not tool_calls:
            parts.append("I have read your message and I am happy to help with your request.")
        return AgentReply(" ".join(parts), tuple(tool_calls))
