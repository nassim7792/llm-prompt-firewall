"""normalize: reports every transform it needed. It never decides alone.

A zero-width space in a ticket is not an attack. A sentence written in invisible Unicode
tag characters almost certainly is. Either way the transform is a signal worth recording.
"""

from __future__ import annotations

import re

from promptfw.context import Context, Trust
from promptfw.normalize import unicode_report, unwrap_embedded
from promptfw.policy import Policy
from promptfw.verdict import Finding, Severity

NAME = "normalize"


def _mixed_script_words(text: str) -> int:
    import unicodedata

    count = 0
    for word in re.findall(r"\w{3,}", text):
        scripts = {unicodedata.name(ch, "X").split(" ")[0] for ch in word if ch.isalpha()}
        if "LATIN" in scripts and scripts & {"CYRILLIC", "GREEK"}:
            count += 1
    return count


class NormalizeLayer:
    name = NAME

    def inspect(self, ctx: Context, policy: Policy) -> list[Finding]:
        findings: list[Finding] = []
        for i, span in enumerate(ctx.spans):
            if span.trust is Trust.SYSTEM:
                continue
            rep = unicode_report(span.text)
            if rep.tags:
                findings.append(self._f("unicode-tag-smuggling", Severity.HIGH, 0.65, i,
                                        f"{rep.tags} invisible Unicode tag characters decoded"))
            if rep.bidi:
                findings.append(self._f("bidi-control", Severity.LOW, 0.15, i,
                                        f"{rep.bidi} bidirectional control characters removed"))
            if rep.zero_width >= 3:
                findings.append(self._f("zero-width", Severity.LOW, 0.1, i,
                                        f"{rep.zero_width} zero-width characters removed"))
            mixed = _mixed_script_words(span.text)
            if mixed:
                findings.append(self._f("confusables", Severity.LOW, min(0.1 * mixed, 0.3), i,
                                        f"{mixed} word(s) mixing Latin and Cyrillic/Greek letters"))
            decoded = unwrap_embedded(span.text)
            if decoded:
                findings.append(self._f("encoded-blob", Severity.INFO, 0.0, i,
                                        f"decodable content: {', '.join(sorted(decoded))}"))
        return findings

    @staticmethod
    def _f(rule: str, sev: Severity, score: float, idx: int, msg: str) -> Finding:
        return Finding(NAME, rule, sev, invariant=False, score=score, span_index=idx, message=msg)
