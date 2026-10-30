"""Reversible obfuscation primitives, shared by the benchmark, the property tests and the generator.

Each transform is a function str -> str that an attacker could ask the model to apply
(or apply themselves to a payload). They are composable: compose(text, ["hex", "reverse"]).
"""

from __future__ import annotations

import base64
import codecs
from collections.abc import Callable
from urllib.parse import quote


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


TRANSFORMS: dict[str, Callable[[str], str]] = {
    "base64": _b64,
    "base32": lambda s: base64.b32encode(s.encode()).decode(),
    "hex": lambda s: s.encode().hex(),
    "percent": lambda s: "".join(f"%{b:02X}" for b in s.encode()),
    "url_quote": quote,
    "rot13": lambda s: codecs.encode(s, "rot13"),
    "reverse": lambda s: s[::-1],
    "dashes": lambda s: "-".join(s),
    "spaces": lambda s: " ".join(s),
    "dots": lambda s: ".".join(s),
    "upper": str.upper,
    "lower": str.lower,
    "zero_width": lambda s: "​".join(s),
    "tags": lambda s: "".join(chr(0xE0000 + ord(c)) if 0x20 <= ord(c) < 0x7F else c for c in s),
    "fullwidth": lambda s: "".join(chr(ord(c) + 0xFEE0) if 0x21 <= ord(c) <= 0x7E else c for c in s),
    "embed": lambda s: f"Here is the reference you asked for: {s} (let me know if you need more).",
}

# Transforms a decoder can invert without knowing the payload (used for the nonce: the
# attacker must make the model READ it, so only encodings a tokenizer/model would decode).
DECODABLE = ("base64", "base32", "hex", "percent", "url_quote", "zero_width", "tags", "fullwidth", "embed")


def compose(text: str, names: list[str] | tuple[str, ...]) -> str:
    for name in names:
        text = TRANSFORMS[name](text)
    return text
