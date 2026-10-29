"""Tool registry for agent mode: the model *requests* an action, the firewall *authorizes* it."""

from __future__ import annotations

import re
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
class ArgConstraint:
    """Value constraints on one argument (all optional)."""

    min: float | None = None
    max: float | None = None
    enum: frozenset[str] | None = None
    pattern: str | None = None        # full match, e.g. "^[0-9]{4}$"
    max_length: int | None = None

    def __post_init__(self) -> None:
        if self.pattern is not None:
            re.compile(self.pattern)  # fail at load time, not at the first call

    def violations(self, value: Any) -> list[str]:
        out = []
        numeric = isinstance(value, (int, float)) and not isinstance(value, bool)
        if self.min is not None and (not numeric or value < self.min):
            out.append(f"< min {self.min}")
        if self.max is not None and (not numeric or value > self.max):
            out.append(f"> max {self.max}")
        if self.enum is not None and str(value) not in self.enum:
            out.append("not in enum")
        if self.pattern is not None and not (isinstance(value, str) and re.fullmatch(self.pattern, value)):
            out.append("pattern mismatch")
        if self.max_length is not None and len(str(value)) > self.max_length:
            out.append(f"longer than {self.max_length}")
        return out

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ArgConstraint":
        unknown = set(raw) - {"min", "max", "enum", "pattern", "max_length"}
        if unknown:
            raise ValueError(f"unknown constraint(s): {sorted(unknown)}")
        return cls(min=raw.get("min"), max=raw.get("max"),
                   enum=frozenset(str(v) for v in raw["enum"]) if "enum" in raw else None,
                   pattern=raw.get("pattern"), max_length=raw.get("max_length"))


@dataclass(frozen=True)
class Tool:
    name: str
    effects: frozenset[Effect] = frozenset()
    guards: frozenset[Guard] = frozenset()
    args: dict[str, type] = field(default_factory=dict)        # declared arguments and their type
    required: frozenset[str] = frozenset()
    allowlists: dict[str, frozenset[str]] = field(default_factory=dict)
    bound_args: frozenset[str] = frozenset()   # args that must equal Context.principal.id
    permission: str | None = None              # required permission, granted through Policy.roles
    constraints: dict[str, ArgConstraint] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if Guard.ARGS_BOUND_TO_SESSION in self.guards and not self.bound_args:
            raise ValueError(f"tool {self.name!r}: args_bound_to_session needs at least one bound_args entry")
        unknown = self.bound_args - self.args.keys()
        if unknown:
            raise ValueError(f"tool {self.name!r}: bound_args not declared in args: {sorted(unknown)}")
        unknown = self.constraints.keys() - self.args.keys()
        if unknown:
            raise ValueError(f"tool {self.name!r}: constraints on undeclared args: {sorted(unknown)}")

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
            permission=raw.get("permission"),
            constraints={k: ArgConstraint.from_dict(v) for k, v in (raw.get("constraints") or {}).items()},
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
