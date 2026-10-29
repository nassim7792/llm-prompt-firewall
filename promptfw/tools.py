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
    ARGS_BOUND_TO_SESSION = "args_bound_to_session"    # target object must belong to the authenticated user


@dataclass(frozen=True)
class Tool:
    name: str
    effects: frozenset[Effect] = frozenset()
    guards: frozenset[Guard] = frozenset()
    args: dict[str, type] = field(default_factory=dict)        # declared arguments and their type
    required: frozenset[str] = frozenset()
    allowlists: dict[str, frozenset[str]] = field(default_factory=dict)
    bound_args: frozenset[str] = frozenset()   # args that must equal Context.principal

    def __post_init__(self) -> None:
        if Guard.ARGS_BOUND_TO_SESSION in self.guards and not self.bound_args:
            raise ValueError(f"tool {self.name!r}: args_bound_to_session needs at least one bound_args entry")
        unknown = self.bound_args - self.args.keys()
        if unknown:
            raise ValueError(f"tool {self.name!r}: bound_args not declared in args: {sorted(unknown)}")

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
            bound_args=frozenset(raw.get("bound_args", [])),
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
