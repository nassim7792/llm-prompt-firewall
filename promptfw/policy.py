"""Runtime policy, loadable from YAML (see config/policy.yaml)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from promptfw.tools import Effect, Tool

LAYERS = ("normalize", "ingress", "provenance", "toolauth", "egress")
NON_TEXT_MODES = ("block_untrusted", "block", "allow")
TRUST_LEVELS = ("trusted", "untrusted")
ASSISTANT_MODES = ("user", "data")
MIN_CANARY_ALNUM = 8  # a canary shorter than this after stripping would match by accident


class PolicyError(ValueError):
    pass


@dataclass
class Policy:
    id: str = "default"
    enabled_layers: frozenset[str] = frozenset(LAYERS)

    # Scored findings: block when the combined score reaches this value.
    block_threshold: float = 0.6
    # Ingress on USER spans. The original project skips them entirely; here they are
    # scanned with a reduced weight so that copy-pasted jailbreaks are still caught.
    user_ingress_factor: float = 0.7
    # When True, ingress findings on DATA spans become invariant (hard block).
    strict_data: bool = False
    disabled_rules: frozenset[str] = frozenset()

    # Egress
    canaries: tuple[str, ...] = ()
    allowed_hosts: tuple[str, ...] = ()        # suffix match: "example.com" covers "docs.example.com"
    enforce_url_allowlist: bool = True         # any URL to a non-allowlisted host is an invariant block
    detect_secrets: bool = True
    detect_pii: bool = True

    # Tools
    tools: dict[str, Tool] = field(default_factory=dict)
    forbidden_effects: frozenset[Effect] = frozenset()

    # Resource limits (anti-DoS): inspection cost grows linearly with input size, so oversized
    # inputs are refused up front (invariant, fail closed) instead of being partially inspected.
    max_span_chars: int = 50_000
    max_total_chars: int = 200_000
    max_output_chars: int = 50_000

    # Proxy: images / audio / files cannot be inspected by text rules.
    #   block_untrusted (default): refused inside tool results, recorded elsewhere
    #   block: refused everywhere      allow: recorded only (INFO)
    non_text_content: str = "block_untrusted"

    # Authorization: role -> permissions. A tool with `permission` is allowed only if one of
    # the principal's roles grants it.
    roles: dict[str, frozenset[str]] = field(default_factory=dict)
    # Trust per DATA channel ("kb": "trusted"). Unknown channels are untrusted. Only
    # no_untrusted_influence reads this: trusted DATA is still fenced and inspected.
    origin_trust: dict[str, str] = field(default_factory=dict)
    # Proxy: how to read an assistant turn that follows untrusted DATA in the history.
    #   user (default, known compromise) | data (stricter: the turn may carry the payload forward)
    assistant_after_data: str = "user"

    # Proxy rate limiting per client (None: disabled). Characters approximate the analysis cost.
    rate_limit_requests_per_minute: int | None = None
    rate_limit_chars_per_minute: int | None = None

    def __post_init__(self) -> None:
        unknown = set(self.enabled_layers) - set(LAYERS)
        if unknown:
            raise PolicyError(f"unknown layer(s): {sorted(unknown)}")
        if not 0 < self.block_threshold <= 1:
            raise PolicyError("block_threshold must be in (0, 1]")
        for name in ("max_span_chars", "max_total_chars", "max_output_chars"):
            if getattr(self, name) <= 0:
                raise PolicyError(f"{name} must be positive")
        if self.non_text_content not in NON_TEXT_MODES:
            raise PolicyError(f"non_text_content must be one of {NON_TEXT_MODES}")
        bad = {k: v for k, v in self.origin_trust.items() if v not in TRUST_LEVELS}
        if bad:
            raise PolicyError(f"origin_trust values must be one of {TRUST_LEVELS}: {bad}")
        for name in ("rate_limit_requests_per_minute", "rate_limit_chars_per_minute"):
            value = getattr(self, name)
            if value is not None and value <= 0:
                raise PolicyError(f"{name} must be positive or null")
        if self.assistant_after_data not in ASSISTANT_MODES:
            raise PolicyError(f"assistant_after_data must be one of {ASSISTANT_MODES}")
        for t in self.tools.values():
            if t.permission and not any(t.permission in perms for perms in self.roles.values()):
                raise PolicyError(f"tool {t.name!r} requires permission {t.permission!r} that no role grants")
        for c in self.canaries:
            if sum(ch.isalnum() for ch in c) < MIN_CANARY_ALNUM:
                raise PolicyError(f"canary too short once stripped to alphanumerics: {c!r}")

    def layer_enabled(self, name: str) -> bool:
        return name in self.enabled_layers

    def permissions_of(self, roles: frozenset[str]) -> frozenset[str]:
        return frozenset().union(*(self.roles.get(r, frozenset()) for r in roles))

    def is_trusted_channel(self, channel: str) -> bool:
        return self.origin_trust.get(channel) == "trusted"

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Policy":
        layers = raw.get("layers")
        return cls(
            id=raw.get("id", "default"),
            enabled_layers=frozenset(layers) if layers is not None else frozenset(LAYERS),
            block_threshold=float(raw.get("block_threshold", 0.6)),
            user_ingress_factor=float(raw.get("user_ingress_factor", 0.7)),
            strict_data=bool(raw.get("strict_data", False)),
            disabled_rules=frozenset(raw.get("disabled_rules", [])),
            canaries=tuple(raw.get("canaries", [])),
            allowed_hosts=tuple(h.lower().lstrip(".") for h in raw.get("allowed_hosts", [])),
            enforce_url_allowlist=bool(raw.get("enforce_url_allowlist", True)),
            detect_secrets=bool(raw.get("detect_secrets", True)),
            detect_pii=bool(raw.get("detect_pii", True)),
            tools={t["name"]: Tool.from_dict(t) for t in raw.get("tools", [])},
            forbidden_effects=frozenset(Effect(e) for e in raw.get("forbidden_effects", [])),
            max_span_chars=int(raw.get("max_span_chars", 50_000)),
            max_total_chars=int(raw.get("max_total_chars", 200_000)),
            max_output_chars=int(raw.get("max_output_chars", 50_000)),
            non_text_content=str(raw.get("non_text_content", "block_untrusted")),
            roles={r: frozenset(p) for r, p in (raw.get("roles") or {}).items()},
            origin_trust={str(k): str(v) for k, v in (raw.get("origin_trust") or {}).items()},
            assistant_after_data=str(raw.get("assistant_after_data", "user")),
            rate_limit_requests_per_minute=raw.get("rate_limit_requests_per_minute"),
            rate_limit_chars_per_minute=raw.get("rate_limit_chars_per_minute"),
        )

    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        with open(path, encoding="utf-8") as fh:
            return cls.from_dict(yaml.safe_load(fh) or {})
