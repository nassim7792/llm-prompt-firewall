"""Per-inspection cache of normalised readings."""

from promptfw import Context, Firewall, Origin, Policy, normalize
from promptfw.bench import default_corpus, load_corpus, run_case


def test_cache_does_not_change_any_verdict(monkeypatch):
    root = default_corpus()
    policy = Policy.load(root.parent / "policy.yaml")
    cases = [c for c in load_corpus(root) if c.stage == "ingress"]
    cached = [(c.id, run_case(Firewall(policy), c).to_dict()["blocked_by"]) for c in cases]
    monkeypatch.setattr("promptfw.firewall.reading_cache", lambda: __import__("contextlib").nullcontext())
    uncached = [(c.id, run_case(Firewall(policy), c).to_dict()["blocked_by"]) for c in cases]
    assert cached == uncached


def test_closure_is_computed_once_per_span_and_cache_does_not_outlive_the_call(monkeypatch):
    calls = []
    real = normalize._closure
    monkeypatch.setattr(normalize, "_closure", lambda *a: calls.append(a[1]) or real(*a))
    Firewall(Policy()).inspect(Context().user("hi").data("some ticket text", Origin("t", "1")))
    assert calls.count("ingress") == 2          # one per non-system span, shared by ingress and provenance
    assert normalize._CACHE.get() is None
