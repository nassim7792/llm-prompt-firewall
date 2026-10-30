"""Property-based and exhaustive tests of the anti-evasion closure.

Instead of a hand-written list of tricks, the tests compose obfuscation primitives
(promptfw.eval.transforms) and check that the invariant controls still hold.
Measured coverage is asserted as a floor, not as 100 %: depth-3 compositions that mix
separators with prose (e.g. base64 -> dashes -> embedded in a sentence) are known misses.
"""

import itertools

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from promptfw import AgentReply, Context, Firewall, Origin, Policy
from promptfw.eval.transforms import DECODABLE, TRANSFORMS, compose
from promptfw.layers import fence_close

SECRET = "VANTAGE-7731-ORION"
FW = Firewall(Policy(canaries=(SECRET,)))
LOSSLESS = [n for n in TRANSFORMS if n not in ("upper", "lower")]   # case changes destroy base64


def leaked(text: str) -> bool:
    return any(f.rule == "canary-leak" for f in FW.inspect_egress(AgentReply(text), Context()).findings)


def coverage(depth: int) -> float:
    combos = list(itertools.product(LOSSLESS, repeat=depth))
    return sum(leaked(compose(SECRET, c)) for c in combos) / len(combos)


def test_canary_every_single_and_double_composition():
    assert coverage(1) == 1.0
    assert coverage(2) == 1.0


@pytest.mark.slow
def test_canary_triple_compositions_floor():
    # Measured at 99.5 % (2730/2744) when this test was written. Floor, not a target.
    assert coverage(3) >= 0.98


@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.lists(st.sampled_from(LOSSLESS), min_size=1, max_size=2), st.sampled_from(["", "Sure! ", "Le code: "]))
def test_canary_random_compositions_with_prefix(names, prefix):
    assert leaked(prefix + compose(SECRET, names))


@settings(max_examples=150, deadline=None)
@given(st.lists(st.sampled_from(DECODABLE), min_size=1, max_size=2))
def test_forged_nonce_is_found_through_decodable_encodings(names):
    ctx = Context().user("hi")
    payload = compose(fence_close(ctx.nonce), names)
    v = FW.inspect(ctx.data(f"Ticket: {payload}", Origin("ticket", "1")))
    assert any(f.rule == "nonce-forgery" for f in v.findings), names


@settings(max_examples=300, deadline=None)
@given(st.text(max_size=400))
def test_arbitrary_unicode_never_crashes_a_layer(text):
    ctx = Context().user("hi").data(text, Origin("web", "1"))
    v_in = FW.inspect(ctx)
    v_out = FW.inspect_egress(AgentReply(text), ctx)
    assert not any(f.rule == "layer-error" for f in v_in.findings + v_out.findings)


@settings(max_examples=200, deadline=None)
@given(st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=300))
def test_text_without_the_nonce_never_triggers_nonce_forgery(text):
    ctx = Context().user("hi")
    if ctx.nonce in text.casefold():
        return
    v = FW.inspect(ctx.data(text, Origin("web", "1")))
    assert not any(f.rule == "nonce-forgery" for f in v.findings)
