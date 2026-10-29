"""Runtime policy, loadable from YAML (see config/policy.yaml)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from promptfw.tools import Effect, Tool

LAYERS = ("normalize", "ingress", "provenance", "toolauth", "egress")
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

    def __post_init__(self) -> None:
        unknown = set(self.enabled_layers) - set(LAYERS)
        if unknown:
            raise PolicyError(f"unknown layer(s): {sorted(unknown)}")
        if not 0 < self.block_threshold <= 1:
            raise PolicyError("block_threshold must be in (0, 1]")
        for c in self.canaries:
            if sum(ch.isalnum() for ch in c) < MIN_CANARY_ALNUM:
                raise PolicyError(f"canary too short once stripped to alphanumerics: {c!r}")

    def layer_enabled(self, name: str) -> bool:
        return name in self.enabled_layers

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
        )

    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        with open(path, encoding="utf-8") as fh:
            return cls.from_dict(yaml.safe_load(fh) or {})
