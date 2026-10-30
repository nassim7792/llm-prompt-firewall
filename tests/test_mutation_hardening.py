"""Tests written after a mutmut run (mutation testing) revealed decisions that no test pinned down.

Each test targets a class of surviving mutants: boundaries (<= vs <), invariant flags that a
score of 1.0 would hide, malformed token fields, and canonical formats shared with backends.
"""

import time

import pytest
from fastapi.testclient import TestClient

from promptfw import AgentReply, Context, Firewall, Origin, Policy
from promptfw.firewall import combine, decide
from promptfw.identity import MAX_TTL_S, ReplayGuard, TokenError, args_digest, sign, verify
from promptfw.layers.toolauth import same_identity
from promptfw.proxy import create_app
from promptfw.verdict import Finding, Severity

KEY = b"k" * 16
NOW = 1_800_000_000.0


# ---------------------------------------------------------------- decision algebra
def test_score_exactly_at_threshold_blocks():
    d, _ = decide([Finding("x", "r", Severity.MEDIUM, False, 0.6)], Policy(block_threshold=0.6))
    assert d.value == "block"


def test_invariant_verdict_score_is_exactly_one():
    _, score = decide([Finding("x", "r", Severity.LOW, True, 0.0)], Policy())
    assert score == 1.0


def test_combine_clamps_scores_into_unit_interval():
    assert combine([1.7]) == 1.0 and combine([-0.5]) == 0.0


# ---------------------------------------------------------------- limits and fail-closed findings
def test_input_exactly_at_the_limit_is_accepted():
    fw = Firewall(Policy(max_span_chars=100, max_total_chars=1000))
    assert not any(f.rule == "input-too-large" for f in fw.inspect(Context().data("x" * 100, Origin("d", "1"))).findings)


@pytest.mark.parametrize("ctx", [
    Context().data("x" * 101, Origin("d", "1")),                                       # span limit
    Context().data("x" * 90, Origin("d", "1")).data("x" * 90, Origin("d", "2")),        # total limit
])
def test_size_findings_are_critical_invariants(ctx):
    v = Firewall(Policy(max_span_chars=100, max_total_chars=150)).inspect(ctx)
    f = v.blocked_by[0]
    assert (f.layer, f.rule, f.invariant, f.severity, f.score) == ("firewall", "input-too-large", True,
                                                                    Severity.CRITICAL, 1.0)


def test_output_size_finding_is_a_critical_invariant():
    f = Firewall(Policy(max_output_chars=10)).inspect_egress(AgentReply("y" * 11), Context()).blocked_by[0]
    assert (f.rule, f.invariant, f.severity) == ("output-too-large", True, Severity.CRITICAL)


def test_layer_error_finding_flags(monkeypatch):
    fw = Firewall(Policy())
    monkeypatch.setattr(fw.provenance, "inspect", lambda *a: 1 / 0)
    f = next(f for f in fw.inspect(Context().user("hi")).findings if f.rule == "layer-error")
    assert (f.layer, f.invariant, f.severity, f.score) == ("provenance", True, Severity.CRITICAL, 1.0)


def test_render_uses_lowercase_openai_roles():
    msgs = Firewall(Policy()).render(Context().system("s").user("u").data("d", Origin("w", "1")))
    assert [m["role"] for m in msgs] == ["system", "user", "user"]


# ---------------------------------------------------------------- identity tokens
@pytest.mark.parametrize("payload,reason", [
    ({"sub": 123, "exp": NOW + 60}, "sub"),
    ({"sub": " ", "exp": NOW + 60}, "sub"),
    ({"sub": "b", "roles": "admin", "exp": NOW + 60}, "roles"),
    ({"sub": "b", "roles": [1], "exp": NOW + 60}, "roles"),
    ({"sub": "b", "exp": True}, "exp"),
    ({"sub": "b", "exp": "tomorrow"}, "exp"),
    ({"sub": "b", "exp": NOW + 60, "jti": "j", "confirm": "refund"}, "confirm"),
    ({"sub": "b", "exp": NOW + 60, "jti": "j", "confirm": [{"tool": "refund"}]}, "confirm"),
    ({"sub": "b", "exp": NOW + 60, "jti": "j", "confirm": [{"args_sha256": "x"}]}, "confirm"),
])
def test_malformed_fields_raise_token_error_only(payload, reason):
    with pytest.raises(TokenError, match=reason):
        verify(sign(payload, KEY), KEY, now=NOW)


def test_expiry_and_lifetime_boundaries():
    with pytest.raises(TokenError, match="expired"):
        verify(sign({"sub": "b", "exp": NOW}, KEY), KEY, now=NOW)          # exp == now is expired
    verify(sign({"sub": "b", "exp": NOW + MAX_TTL_S}, KEY), KEY, now=NOW)  # exactly the max TTL is accepted
    with pytest.raises(TokenError, match="too long"):
        verify(sign({"sub": "b", "exp": NOW + MAX_TTL_S + 1}, KEY), KEY, now=NOW)


def test_error_messages_are_specific():
    with pytest.raises(TokenError, match="^bad signature$"):
        verify(sign({"sub": "b", "exp": time.time() + 60}, b"other-key-123456"), KEY)
    with pytest.raises(TokenError, match="^malformed token$"):
        verify("abc", KEY)
    with pytest.raises(TokenError, match="^malformed payload$"):
        verify(sign([1, 2], KEY), KEY)


def test_malformed_token_through_the_proxy_is_a_block_not_a_crash():
    c = TestClient(create_app(Policy(), principal_key=KEY))
    token = sign({"sub": 123, "exp": time.time() + 60}, KEY)
    r = c.post("/v1/chat/completions", headers={"x-promptfw-principal": token},
               json={"model": "m", "messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 200 and r.json()["promptfw"]["blocked_by"] == ["proxy/invalid-identity"]


def test_args_digest_canonical_vector():
    # Backends must compute the same digest: compact separators, sorted keys, UTF-8 kept as is.
    import hashlib
    assert args_digest({"b": "é", "a": 1}) == hashlib.sha256('{"a":1,"b":"é"}'.encode()).hexdigest()


def test_replay_guard_forgets_only_expired_ids():
    g = ReplayGuard()
    assert g.first_use("j", exp=NOW + 10, now=NOW)
    assert not g.first_use("j", exp=NOW + 10, now=NOW + 10 - 1e-6)
    assert g.first_use("j", exp=NOW + 30, now=NOW + 10)          # expired at exp == now, may be reused


# ---------------------------------------------------------------- identity comparison
def test_same_identity_normalises_both_sides():
    assert same_identity("alice", "@Alice")
    assert same_identity("@alice ", " alice")
    assert not same_identity("alice@", "alice")


# ---------------------------------------------------------------- second round (remaining logic survivors)
def test_required_attribute_alone_is_enforced():
    from promptfw import ToolCall
    from promptfw.tools import Tool
    pol = Policy(tools={"t": Tool("t", requires_attributes={"plan": "pro"})})
    ctx = Context().as_principal("bob", attributes={"plan": "free"})
    v = Firewall(pol).inspect_egress(AgentReply("", (ToolCall("t", {}),)), ctx)
    assert {f.rule for f in v.blocked_by} == {"attribute-mismatch"}


def test_provenance_inspects_every_data_span():
    from promptfw.layers import fence_close
    ctx = Context()
    ctx = ctx.data(f"x {fence_close(ctx.nonce)}", Origin("a", "1")).data("<<<END 0000>>>", Origin("b", "2"))
    rules = {f.rule for f in Firewall(Policy()).inspect(ctx).findings}
    assert {"nonce-forgery", "fence-shape"} <= rules


@pytest.mark.parametrize("n", range(1, 9))
def test_token_roundtrip_for_every_padding_length(n):
    token = sign({"sub": "b" * n, "exp": NOW + 60}, KEY)
    assert "=" not in token
    assert verify(token, KEY, now=NOW)["sub"] == "b" * n


def test_token_body_is_compact_json():
    import base64
    body = sign({"sub": "b", "exp": 1}, KEY).split(".")[0]
    assert base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)) == b'{"sub":"b","exp":1}'


def test_total_limit_boundary_and_tool_args_count_towards_output():
    from promptfw import ToolCall
    fw = Firewall(Policy(max_span_chars=100, max_total_chars=100, max_output_chars=20))
    assert not Firewall(Policy(max_span_chars=100, max_total_chars=100)).inspect(
        Context().data("x" * 100, Origin("d", "1"))).blocked
    assert fw.inspect(Context().data("x" * 50, Origin("d", "1")).data("x" * 51, Origin("d", "2"))).blocked
    big_args = AgentReply("hi", (ToolCall("t", {"a": "y" * 30}),))
    assert fw.inspect_egress(big_args, Context()).blocked_by[0].rule == "output-too-large"
    assert not any(f.rule == "output-too-large" for f in fw.inspect_egress(AgentReply("z" * 20), Context()).findings)


def test_verdict_metadata():
    v = Firewall(Policy(id="p-42")).inspect(Context().user("hello"))
    assert v.policy_id == "p-42" and 0 <= v.elapsed_ms < 5_000


def test_render_without_system_text_has_no_system_message():
    assert Firewall(Policy()).render(Context().user("u")) == [{"role": "user", "content": "u"}]
