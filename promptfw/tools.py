"""Tool registry for agent mode: the model *requests* an action, the firewall *authorizes* it."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Effect(str, Enum):
    READ = "read"
    WRITE = "write"
    SEND = "send"        # e-mail, message, HTTP request: an exfiltration channel
    SPEND = "spend"      # payment, refund, purchase
    DELETE = "delete"


class Guard(str, Enum):
    NO_UNTRUSTED_INFLUENCE = "no_untrusted_influence"  # refused once any DATA span is in the context
    USER_CONFIRMED = "user_confirmed"                  # refused until the host app confirms
    ARGS_ALLOWLISTED = "args_allowlisted"              # argument values must be in an allowlist


@dataclass(frozen=True)
class Tool:
    name: str
    effects: frozenset[Effect] = frozenset()
    guards: frozenset[Guard] = frozenset()
    args: dict[str, type] = field(default_factory=dict)        # declared arguments and their type
    required: frozenset[str] = frozenset()
    allowlists: dict[str, frozenset[str]] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Tool":
        types = {"str": str, "int": int, "float": float, "bool": bool}
        return cls(
            name=raw["name"],
            effects=frozenset(Effect(e) for e in raw.get("effects", [])),
            guards=frozenset(Guard(g) for g in raw.get("guards", [])),
            args={k: types[v] for k, v in (raw.get("args") or {}).items()},
            required=frozenset(raw.get("required", [])),
            allowlists={k: frozenset(v) for k, v in (raw.get("allowlists") or {}).items()},
        )


@dataclass(frozen=True)
class ToolCall:
    name: str
    args: dict[str, Any] = field(default_factory=dict)
    user_confirmed: bool = False


@dataclass(frozen=True)
class AgentReply:
    text: str = ""
    tool_calls: tuple[ToolCall, ...] = ()
