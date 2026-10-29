"""Anti-evasion normalisation: one input, a bounded set of *readings*.

Attackers rarely write "ignore previous instructions" in plain ASCII once a filter exists.
They use invisible characters, look-alike letters (Cyrillic "о"), leetspeak, s p a c e d
letters, base64 / hex / percent-encoding, or invisible Unicode "tag" characters.

A fixed pipeline (decode, then normalise, then match) loses to stacked obfuscation,
because the attacker chooses the order. So `readings()` applies every inverse transform
to every reading, breadth-first, until nothing new appears or a budget is hit.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata
from collections import deque
from dataclasses import dataclass
from urllib.parse import unquote

# Built from code points so that this file contains no invisible characters itself.
ZERO_WIDTH = frozenset(chr(c) for c in (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD, 0x180E))
BIDI = frozenset(chr(c) for c in (*range(0x202A, 0x202F), *range(0x2066, 0x206A)))
TAG_START, TAG_END = 0xE0000, 0xE007F  # "ASCII smuggling": invisible copies of ASCII
BLACK_FLAG = 0x1F3F4

# Confusables that NFKC does not fold: Cyrillic and Greek look-alikes of Latin letters.
_CONFUSABLE_PAIRS = {
    "a": (0x0430, 0x0410, 0x03B1, 0x0391), "b": (0x0432, 0x0412, 0x0392), "c": (0x0441, 0x0421),
    "d": (0x0501,), "e": (0x0435, 0x0415, 0x03B5, 0x0395), "h": (0x04BB, 0x041D, 0x043D, 0x0397),
    "i": (0x0456, 0x0406, 0x03B9, 0x0399), "j": (0x0458, 0x0408), "k": (0x043A, 0x041A, 0x03BA, 0x039A),
    "l": (0x04CF,), "m": (0x043C, 0x041C, 0x039C), "n": (0x039D,), "o": (0x043E, 0x041E, 0x03BF, 0x039F),
    "p": (0x0440, 0x0420, 0x03C1, 0x03A1), "q": (0x051B,), "s": (0x0455, 0x0405), "t": (0x0442, 0x0422, 0x03C4, 0x03A4),
    "u": (0x03C5,), "v": (0x03BD,), "w": (0x051D,), "x": (0x0445, 0x0425, 0x03A7), "y": (0x0443, 0x03A5),
    "z": (0x0396,),
}
CONFUSABLES = {chr(cp): latin for latin, cps in _CONFUSABLE_PAIRS.items() for cp in cps}
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})

_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}|[A-Za-z0-9_-]{24,}")
_B32 = re.compile(r"\b[A-Z2-7]{16,}={0,6}")
_HEX = re.compile(r"\b(?:[0-9a-fA-F]{2}){8,}\b")
_PCT = re.compile(r"(?:%[0-9a-fA-F]{2}){3,}")
# "i.g.n.o.r.e", "i g n o r e": 3+ letters joined by the SAME separator (back-reference),
# so that word boundaries ("i g n o r e  a l l") survive the collapse.
_SPACED = re.compile(r"\b[a-z0-9]([ .\-_*/])[a-z0-9](?:\1[a-z0-9])+\b")

INGRESS_BUDGET = 48
EGRESS_BUDGET = 96


@dataclass(frozen=True)
class Reading:
    path: str   # how this reading was obtained, e.g. "raw", "base64>canonical"
    text: str


@dataclass
class UnicodeReport:
    tags: int = 0
    zero_width: int = 0
    bidi: int = 0
    confusables: int = 0
    nfkc_changed: bool = False


# ---------------------------------------------------------------- single transforms

def canonical(text: str, report: UnicodeReport | None = None) -> str:
    """Decode tag chars, drop invisibles, fold confusables, NFKC, casefold, collapse spaces."""
    out: list[str] = []
    in_flag = False
    for ch in text:
        cp = ord(ch)
        if cp == BLACK_FLAG:
            in_flag = True
        elif not TAG_START <= cp <= TAG_END:
            in_flag = False
        if TAG_START <= cp <= TAG_END:
            if in_flag:  # subdivision flags (England, Scotland, Wales) use tag characters legitimately
                continue
            if report:
                report.tags += 1
            inner = cp - TAG_START
            if 0x20 <= inner < 0x7F:
                out.append(chr(inner))
            continue
        if ch in ZERO_WIDTH:
            if report:
                report.zero_width += 1
            continue
        if ch in BIDI:
            if report:
                report.bidi += 1
            continue
        if ch in CONFUSABLES:
            if report:
                report.confusables += 1
            ch = CONFUSABLES[ch]
        out.append(ch)
    joined = "".join(out)
    folded = unicodedata.normalize("NFKC", joined)
    if report and folded != joined:
        report.nfkc_changed = True
    return re.sub(r"\s+", " ", folded.casefold()).strip()


def _printable(s: str) -> bool:
    if len(s) < 4:
        return False
    ok = sum(ch.isprintable() or ch in "\r\n\t" for ch in s)
    return ok / len(s) >= 0.9 and sum(ch.isalpha() for ch in s) >= 3


def _try_b64(token: str) -> str | None:
    for alt in (False, True):
        try:
            padded = token + "=" * (-len(token) % 4)
            raw = base64.urlsafe_b64decode(padded) if alt else base64.b64decode(padded, validate=True)
            s = raw.decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if _printable(s):
            return s
    return None


def _try_b32(token: str) -> str | None:
    try:
        s = base64.b32decode(token + "=" * (-len(token) % 8)).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    return s if _printable(s) else None


def _try_hex(token: str) -> str | None:
    try:
        s = bytes.fromhex(token).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    return s if _printable(s) else None


def unwrap_embedded(text: str) -> dict[str, str]:
    """Decode encoded blobs, whole-span *and* embedded inside prose. Returns {kind: new_text}."""
    results: dict[str, str] = {}
    for kind, pattern, decoder in (("base64", _B64, _try_b64), ("base32", _B32, _try_b32), ("hex", _HEX, _try_hex)):
        changed = False

        def repl(m: re.Match, decoder=decoder) -> str:
            nonlocal changed
            decoded = decoder(m.group(0))
            if decoded is None:
                return m.group(0)
            changed = True
            return decoded

        new = pattern.sub(repl, text)
        if changed:
            results[kind] = new
    if _PCT.search(text):
        results["percent"] = unquote(text)
    return results


def despace(text: str) -> str:
    return _SPACED.sub(lambda m: re.sub(r"[^a-z0-9]", "", m.group(0)), text)


def strip_to_alnum(text: str) -> str:
    return "".join(ch for ch in text.casefold() if ch.isalnum())


def strip_separators(text: str) -> str:
    """Remove everything but letters/digits, keeping case (so a dashed base64 can still be decoded)."""
    return "".join(ch for ch in text if ch.isalnum() or ch in "+/=")


# ---------------------------------------------------------------- closure

def _step(text: str, mode: str) -> dict[str, str]:
    nxt: dict[str, str] = {"canonical": canonical(text)}
    nxt["leetspeak"] = nxt["canonical"].translate(LEET)
    nxt["despaced"] = despace(nxt["canonical"])
    # Before whitespace is collapsed, a double space still separates spaced-out words.
    nxt["despaced_raw"] = re.sub(r"\s+", " ", despace(text.casefold()))
    nxt.update(unwrap_embedded(text))
    if mode == "egress":
        nxt["rot13"] = codecs.decode(text, "rot13")
        nxt["reversed"] = text[::-1]
        nxt["stripped"] = strip_separators(text)
    return nxt


def readings(text: str, mode: str = "ingress", budget: int | None = None) -> list[Reading]:
    """Breadth-first closure of inverse transforms, bounded by `budget` readings."""
    budget = budget or (EGRESS_BUDGET if mode == "egress" else INGRESS_BUDGET)
    seen: dict[str, str] = {text: "raw"}
    queue: deque[tuple[str, str]] = deque([(text, "raw")])
    while queue and len(seen) < budget:
        current, path = queue.popleft()
        for name, new in _step(current, mode).items():
            if new and new not in seen and len(seen) < budget:
                new_path = name if path == "raw" else f"{path}>{name}"
                seen[new] = new_path
                queue.append((new, new_path))
    return [Reading(path, t) for t, path in seen.items()]


def unicode_report(text: str) -> UnicodeReport:
    rep = UnicodeReport()
    canonical(text, rep)
    return rep
