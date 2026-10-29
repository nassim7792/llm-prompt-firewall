"""The trust-tagged prompt.

The application declares *where* each piece of text comes from. The firewall then
decides based on provenance, not only on what the words look like:

    ctx = (Context()
           .system("You are a support agent.")
           .user("Where is my order?")
           .data(ticket_body, origin=Origin("ticket", "8814")))

"Ignore the previous instructions" typed by the user is a sentence about their own
conversation. The same sentence inside a support ticket is an attempt to command the model.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field, replace
from enum import Enum

NONCE_BYTES = 8  # 64 bits from a CSPRNG, fresh for every request


class Trust(str, Enum):
    SYSTEM = "system"  # written by the operator / developer
    USER = "user"      # typed by the human at the keyboard
    DATA = "data"      # written by "someone on the internet": RAG chunk, e-mail, web page, tool output


@dataclass(frozen=True)
class Origin:
    channel: str   # ticket, email, web, rag, tool...
    ref: str       # identifier inside that channel

    def __str__(self) -> str:
        return f"{self.channel}:{self.ref}"


@dataclass(frozen=True)
class Span:
    trust: Trust
    text: str
    origin: Origin | None = None

    def __post_init__(self) -> None:
        # Untrusted content without a declared source is not representable.
        if self.trust is Trust.DATA and self.origin is None:
            raise ValueError("a DATA span must declare its origin")
        if self.trust is not Trust.DATA and self.origin is not None:
            raise ValueError(f"a {self.trust.value} span cannot have an origin")


def new_nonce() -> str:
    return secrets.token_hex(NONCE_BYTES)


@dataclass(frozen=True)
class Context:
    """Immutable: every builder method returns a new Context."""

    spans: tuple[Span, ...] = ()
    nonce: str = field(default_factory=new_nonce)

    @property
    def tainted_by(self) -> tuple[Origin, ...]:
        """Untrusted origins that entered the context. Derived, never set: it cannot desync."""
        return tuple(s.origin for s in self.spans if s.trust is Trust.DATA and s.origin)

    @property
    def tainted(self) -> bool:
        return bool(self.tainted_by)

    def _extend(self, span: Span) -> "Context":
        return replace(self, spans=(*self.spans, span))

    def system(self, text: str) -> "Context":
        return self._extend(Span(Trust.SYSTEM, text))

    def user(self, text: str) -> "Context":
        return self._extend(Span(Trust.USER, text))

    def data(self, text: str, origin: Origin) -> "Context":
        return self._extend(Span(Trust.DATA, text, origin))

    def system_text(self) -> str:
        return "\n\n".join(s.text for s in self.spans if s.trust is Trust.SYSTEM)
