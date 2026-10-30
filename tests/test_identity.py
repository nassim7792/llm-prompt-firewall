"""Signed identity and confirmation tokens (proxy mode)."""

import json
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from promptfw import ArgConstraint, Policy, Tool
from promptfw.identity import MAX_TTL_S, TokenError, args_digest, mint, sign, verify
from promptfw.proxy import create_app
from promptfw.tools import Effect, Guard
from tests.test_proxy_upstream import FakeUpstream, tool_call

KEY = b"test-key-0123456789"
POLICY = Policy(
    roles={"support_agent": frozenset({"refunds:create"})},
    tools={"refund": Tool("refund", frozenset({Effect.SPEND}), frozenset({Guard.USER_CONFIRMED}),
                          {"order_id": str, "amount": float}, frozenset({"order_id", "amount"}),
                          permission="refunds:create", constraints={"amount": ArgConstraint(max=100)})},
)
REFUND = {"order_id": "8814", "amount": 20.0}


def client(upstream, key=KEY):
    return TestClient(create_app(POLICY, upstream_url="http://up.test", principal_key=key,
                                 transport=httpx.MockTransport(upstream.handler)))


def ask(c, token=None):
    headers = {"x-promptfw-principal": token} if token else {}
    return c.post("/v1/chat/completions", headers=headers,
                  json={"model": "m", "messages": [{"role": "user", "content": "refund order 8814"}]}).json()


def refund_upstream(args=REFUND):
    return FakeUpstream(content=None, tool_calls=tool_call("refund", args))


# ---------------------------------------------------------------- token format
def test_roundtrip():
    payload = verify(mint(KEY, "bob", ("support_agent",)), KEY)
    assert payload["sub"] == "bob" and payload["roles"] == ["support_agent"]


@pytest.mark.parametrize("mutate", [
    lambda t: t[:-2] + ("AA" if not t.endswith("AA") else "BB"),   # signature tampered
    lambda t: sign({**json.loads(__import__("base64").urlsafe_b64decode(t.split(".")[0] + "==")),
                    "roles": ["admin"]}, b"other-key"),           # re-signed with another key
    lambda t: "not-a-token",
])
def test_forged_tokens_are_rejected(mutate):
    with pytest.raises(TokenError):
        verify(mutate(mint(KEY, "bob")), KEY)


def test_expired_and_overlong_tokens_are_rejected():
    with pytest.raises(TokenError, match="expired"):
        verify(sign({"sub": "bob", "exp": time.time() - 1}, KEY), KEY)
    with pytest.raises(TokenError, match="too long"):
        verify(sign({"sub": "bob", "exp": time.time() + MAX_TTL_S + 60}, KEY), KEY)


def test_confirmation_requires_jti():
    with pytest.raises(TokenError, match="jti"):
        verify(sign({"sub": "b", "exp": time.time() + 60,
                     "confirm": [{"tool": "refund", "args_sha256": args_digest(REFUND)}]}, KEY), KEY)


def test_args_digest_is_order_independent():
    assert args_digest({"a": 1, "b": 2}) == args_digest({"b": 2, "a": 1})


# ---------------------------------------------------------------- proxy behaviour
def test_signed_identity_with_role_and_confirmation_allows_the_refund():
    token = mint(KEY, "bob", ("support_agent",), confirm=[("refund", REFUND)])
    body = ask(client(refund_upstream()), token)
    assert "promptfw" not in body
    assert body["choices"][0]["message"]["tool_calls"][0]["function"]["name"] == "refund"


def test_confirmation_does_not_cover_different_arguments():
    token = mint(KEY, "bob", ("support_agent",), confirm=[("refund", REFUND)])
    body = ask(client(refund_upstream({"order_id": "8814", "amount": 90.0})), token)
    assert "toolauth/unconfirmed" in body["promptfw"]["blocked_by"]


def test_missing_role_is_denied():
    token = mint(KEY, "alice", ("customer",), confirm=[("refund", REFUND)])
    assert "toolauth/permission-denied" in ask(client(refund_upstream()), token)["promptfw"]["blocked_by"]


def test_forged_identity_blocks_the_request_before_the_model():
    up = refund_upstream()
    body = ask(client(up), mint(b"attacker-key", "bob", ("support_agent",)))
    assert body["promptfw"]["blocked_by"] == ["proxy/invalid-identity"]
    assert up.requests == []


def test_plain_user_id_is_rejected_when_signing_is_required():
    assert ask(client(refund_upstream()), "bob")["promptfw"]["blocked_by"] == ["proxy/invalid-identity"]


def test_token_replay_is_rejected():
    c = client(refund_upstream())
    token = mint(KEY, "bob", ("support_agent",), confirm=[("refund", REFUND)])
    assert "promptfw" not in ask(c, token)
    assert ask(c, token)["promptfw"]["blocked_by"] == ["proxy/identity-replayed"]


def test_unsigned_mode_keeps_plain_ids_but_grants_no_roles():
    body = ask(client(refund_upstream(), key=None), "bob")
    assert "toolauth/permission-denied" in body["promptfw"]["blocked_by"]


def test_signed_attributes_reach_the_principal():
    from promptfw.identity import verify
    assert verify(mint(KEY, "bob", attrs={"tenant": "acme"}), KEY)["attrs"] == {"tenant": "acme"}
    with pytest.raises(TokenError, match="attrs"):
        verify(sign({"sub": "b", "exp": time.time() + 60, "attrs": {"tenant": 1}}, KEY), KEY)
