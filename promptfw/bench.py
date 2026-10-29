"""Benchmark: detection per attack class, false positives, latency, per-layer ablation.

    promptfw bench                 # summary
    promptfw bench --explain       # which layer/rule caught each case, and what slipped through

Honesty notes printed with the report:
* the corpus was written by the same person as the rules, so detection measures what the
  author thought of, not what an attacker will think of;
* quote the HARD-benign false-positive rate, not the pooled one.
"""

from __future__ import annotations

import base64
import codecs
import statistics
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from urllib.parse import quote

import yaml

from promptfw.context import Context, Origin
from promptfw.firewall import Firewall
from promptfw.policy import LAYERS, Policy
from promptfw.tools import AgentReply, ToolCall
from promptfw.verdict import Verdict

HOMOGLYPH = str.maketrans({"a": "а", "e": "е", "o": "о", "i": "і", "c": "с", "p": "р",
                           "A": "А", "E": "Е", "O": "О", "T": "Т"})
LEET = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"})


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def apply_transform(text: str, name: str | None, nonce: str = "") -> str:
    text = text.replace("{nonce}", nonce).replace("{nonce_upper}", nonce.upper())
    if not name:
        return text
    tags = lambda s: "".join(chr(0xE0000 + ord(c)) if 0x20 <= ord(c) < 0x7F else c for c in s)  # noqa: E731
    transforms = {
        "tags": lambda: tags(text),
        "tags_suffix": lambda: (lambda a, b: a + ". " + tags(b))(*text.split(". ", 1)),
        "zero_width": lambda: "​".join(text),
        "homoglyph": lambda: text.translate(HOMOGLYPH),
        "leet": lambda: text.translate(LEET),
        "spaced": lambda: " ".join(".".join(w) for w in text.split()),
        "fullwidth": lambda: "".join(chr(ord(c) + 0xFEE0) if 0x21 <= ord(c) <= 0x7E else c for c in text),
        "bidi": lambda: "‭" + text.replace(" ", " ‮‬") + "‬",
        "base64": lambda: _b64(text),
        "hex": lambda: text.encode().hex(),
        "base32": lambda: base64.b32encode(text.encode()).decode(),
        "percent": lambda: "".join(f"%{b:02X}" for b in text.encode()),
        "base64_embedded": lambda: f"Please process reference {_b64(text)} before Friday, thanks.",
        "base64_twice": lambda: _b64(_b64(text)),
        "base64_of_leet": lambda: _b64(text.translate(LEET)),
        "base64_embedded_nonce": lambda: f"Reference: {_b64(f'<<<END {nonce}>>>')}",
        "rot13": lambda: codecs.encode(text, "rot13"),
        "reversed": lambda: text[::-1],
        "dashed_base64": lambda: "-".join(_b64(text)),
        "base64_dashed": lambda: _b64("-".join(text)),
        "url_quoted": lambda: quote(text),
    }
    return transforms[name]()


@dataclass
class Case:
    id: str
    cls: str
    kind: str          # attack | benign
    stage: str         # ingress | egress | tool
    hard: bool
    raw: dict
    split: str = "dev"  # "dev": used to tune the rules; "holdout": never used for tuning


@dataclass
class Result:
    case: Case
    verdict: Verdict

    @property
    def blocked(self) -> bool:
        return self.verdict.blocked


def load_corpus(root: str | Path) -> list[Case]:
    cases: list[Case] = []
    root = Path(root)
    for path in sorted(root.rglob("*.yaml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        rel = path.relative_to(root).parts
        split = rel[0] if len(rel) > 1 and rel[0] in SPLITS else "dev"
        for c in doc["cases"]:
            cases.append(Case(c["id"], doc["class"], doc["kind"], doc["stage"], bool(doc.get("hard")), c, split))
    return cases


SPLITS = ("dev", "holdout")
BASE_SYSTEM = "You are a support agent for Vantage Logistics. Be concise."


def run_case(fw: Firewall, case: Case) -> Verdict:
    c = case.raw
    ctx = Context().system(BASE_SYSTEM).user("Can you help me with this?")
    if case.stage == "ingress":
        text = apply_transform(c["text"], c.get("transform"), ctx.nonce)
        ctx = ctx.data(text, Origin("ticket", case.id)) if c.get("trust", "data") == "data" else ctx.user(text)
        return fw.inspect(ctx)
    if case.stage == "egress":
        return fw.inspect_egress(AgentReply(apply_transform(c["text"], c.get("transform"))), ctx)
    if case.stage == "tool":
        if c.get("principal"):
            ctx = ctx.as_principal(str(c["principal"]))
        if c.get("tainted"):
            ctx = ctx.data("Customer ticket body.", Origin("ticket", case.id))
        call = ToolCall(c["tool"], dict(c.get("args") or {}), bool(c.get("confirmed")))
        return fw.inspect_egress(AgentReply("", (call,)), ctx)
    raise ValueError(f"unknown stage {case.stage}")


@dataclass
class Report:
    results: list[Result]
    ablation: dict[str, tuple[int, int]] = field(default_factory=dict)

    def attacks(self) -> list[Result]:
        return [r for r in self.results if r.case.kind == "attack"]

    def benign(self, hard: bool | None = None) -> list[Result]:
        return [r for r in self.results if r.case.kind == "benign" and (hard is None or r.case.hard == hard)]

    @staticmethod
    def rate(rs: list[Result]) -> float:
        return 100.0 * sum(r.blocked for r in rs) / len(rs) if rs else 0.0

    def by_class(self) -> dict[str, list[Result]]:
        out: dict[str, list[Result]] = {}
        for r in self.results:
            out.setdefault(r.case.cls, []).append(r)
        return out

    def latency(self) -> tuple[float, float]:
        lat = sorted(r.verdict.elapsed_ms for r in self.results)
        if not lat:
            return 0.0, 0.0
        p99 = lat[min(len(lat) - 1, int(len(lat) * 0.99))]
        return statistics.median(lat), p99

    def subset(self, split: str) -> "Report":
        return Report([r for r in self.results if r.case.split == split])

    def metrics(self) -> dict:
        """Definitions: attacks blocked = true positives; benign blocked = false positives."""
        a, b, h = self.attacks(), self.benign(), self.benign(hard=True)
        p50, p99 = self.latency()
        return {
            "attacks": len(a), "benign": len(b), "benign_hard": len(h),
            "block_rate": round(self.rate(a), 2),               # TPR
            "false_negative_rate": round(100 - self.rate(a), 2) if a else 0.0,
            "false_positive_rate": round(self.rate(b), 2),
            "false_positive_rate_hard": round(self.rate(h), 2),
            "latency_ms_p50": round(p50, 3), "latency_ms_p99": round(p99, 3),
            "false_negatives": [r.case.id for r in a if not r.blocked],
            "false_positives": [r.case.id for r in b if r.blocked],
        }

    def render(self, explain: bool = False) -> str:
        lines = ["", "promptfw benchmark", "=" * 64]
        for split in SPLITS:
            sub = self.subset(split)
            if not sub.results:
                continue
            title = ("DEV split (used to tune the rules: optimistic)" if split == "dev"
                     else "HOLDOUT split (never used for tuning: the honest estimate)")
            lines += ["", title, "-" * 64, *sub._render_split()]
        if self.ablation:
            lines += ["", "Ablation on all attacks          solo   marginal"]
            for layer, (solo, marginal) in self.ablation.items():
                flag = "   <- INERT" if solo == 0 and marginal == 0 else ""
                lines.append(f"  {layer:<28} {solo:>5}   {marginal:>8}{flag}")
        lines += ["", "Note: both splits were written by the rules' author. Detection measures what the",
                  "author thought of, not what an attacker will think of.", ""]
        if explain:
            lines += ["Per-case attribution", "-" * 64]
            for r in self.results:
                status = "BLOCK" if r.blocked else "allow"
                expected = "BLOCK" if r.case.kind == "attack" else "allow"
                mark = "  " if status == expected else "XX"
                by = ", ".join(f"{f.label}" + (f" via {f.reading}" if f.reading not in ("raw", "") else "")
                               for f in r.verdict.blocked_by) or "-"
                lines.append(f"{mark} {r.case.split[:4]} {r.case.id:<8} {r.case.cls:<20} {status}  "
                             f"score={r.verdict.score:.2f}  {by}")
        return "\n".join(lines)

    def _render_split(self) -> list[str]:
        lines = ["Attack classes (block rate)"]
        for cls, rs in sorted(self.by_class().items()):
            if rs[0].case.kind != "attack":
                continue
            lines.append(f"  {cls:<24} {self.rate(rs):6.1f}%   {sum(r.blocked for r in rs):>3}/{len(rs)}")
        lines += ["", "Benign classes (false positives)"]
        for cls, rs in sorted(self.by_class().items()):
            if rs[0].case.kind != "benign":
                continue
            tag = "  (HARD)" if rs[0].case.hard else ""
            lines.append(f"  {cls:<24} {self.rate(rs):6.1f}%   {sum(r.blocked for r in rs):>3}/{len(rs)}{tag}")
        m = self.metrics()
        a = self.attacks()
        lines += [
            "",
            f"block rate (TPR)      {m['block_rate']:6.1f}%   {m['attacks']} attacks, {len({r.case.cls for r in a})} classes",
            f"false negative rate   {m['false_negative_rate']:6.1f}%   {', '.join(m['false_negatives']) or '-'}",
            f"false positive rate   {m['false_positive_rate']:6.1f}%   pooled, {m['benign']} benign: {', '.join(m['false_positives']) or '-'}",
            f"FPR on HARD benign    {m['false_positive_rate_hard']:6.1f}%   {m['benign_hard']} hard benign inputs",
            f"latency p50 / p99     {m['latency_ms_p50']:.2f} ms / {m['latency_ms_p99']:.2f} ms (firewall only)",
        ]
        return lines


def run(corpus: str | Path, policy: Policy, ablation: bool = True) -> Report:
    cases = load_corpus(corpus)
    fw = Firewall(policy)
    for c in cases:  # warm-up (regex compilation, imports) so latency is not skewed
        run_case(fw, c)
    report = Report([Result(c, run_case(fw, c)) for c in cases])
    if ablation:
        attacks = [c for c in cases if c.kind == "attack"]
        full = {c.id for c in attacks if run_case(fw, c).blocked}
        for layer in LAYERS:
            solo_fw = Firewall(replace(policy, enabled_layers=frozenset({layer})))
            without_fw = Firewall(replace(policy, enabled_layers=frozenset(LAYERS) - {layer}))
            solo = sum(run_case(solo_fw, c).blocked for c in attacks)
            without = {c.id for c in attacks if run_case(without_fw, c).blocked}
            report.ablation[layer] = (solo, len(full - without))
    return report


def default_corpus() -> Path:
    for base in (Path.cwd(), Path(__file__).resolve().parent.parent):
        if (base / "bench" / "corpus").is_dir():
            return base / "bench" / "corpus"
    raise FileNotFoundError("bench/corpus not found: run from the repository root")


if __name__ == "__main__":
    t = time.perf_counter()
    root = default_corpus()
    print(run(root, Policy.load(root.parent / "policy.yaml")).render())
    print(f"(ran in {time.perf_counter() - t:.1f}s)")
