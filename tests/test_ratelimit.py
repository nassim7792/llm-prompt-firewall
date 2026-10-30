"""Rate limiting by request count and by analysis cost."""

import pytest
from fastapi.testclient import TestClient

from promptfw import Policy, PolicyError
from promptfw.identity import mint
from promptfw.proxy import create_app
from promptfw.ratelimit import RateLimiter


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def test_request_bucket_refills_over_time():
    clock = Clock()
    rl = RateLimiter(requests_per_minute=2, clock=clock)
    assert rl.check("a", 10)[0] and rl.check("a", 10)[0]
    ok, reason, retry = rl.check("a", 10)
    assert not ok and reason == "requests" and retry == pytest.approx(30.0)
    clock.t = 30.0
    assert rl.check("a", 10)[0]


def test_clients_are_independent():
    rl = RateLimiter(requests_per_minute=1, clock=Clock())
    assert rl.check("a", 1)[0] and rl.check("b", 1)[0]
    assert not rl.check("a", 1)[0]


def test_cost_bucket_limits_large_inputs_and_refusal_consumes_nothing():
    clock = Clock()
    rl = RateLimiter(requests_per_minute=100, chars_per_minute=1000, clock=clock)
    assert rl.check("a", 800)[0]
    ok, reason, _ = rl.check("a", 800)
    assert not ok and reason == "analysis_cost"
    assert rl.check("a", 200)[0]             # the refused request did not eat the remaining tokens
    ok, _, retry = rl.check("a", 5000)
    assert not ok and retry == float("inf")  # larger than the bucket: never fits


def test_client_table_is_bounded():
    rl = RateLimiter(requests_per_minute=5, max_clients=3, clock=Clock())
    for i in range(10):
        rl.check(f"c{i}", 1)
    assert len(rl._buckets) <= 3


def test_disabled_by_default():
    assert RateLimiter().check("a", 10**9) == (True, None, 0.0)


def test_policy_validation():
    with pytest.raises(PolicyError):
        Policy(rate_limit_requests_per_minute=0)
    assert Policy.from_dict({"rate_limit_chars_per_minute": 5000}).rate_limit_chars_per_minute == 5000


def _post(c, headers=None):
    return c.post("/v1/chat/completions", headers=headers or {},
                  json={"model": "m", "messages": [{"role": "user", "content": "hello"}]})


def test_proxy_returns_429_with_retry_after_and_counts_it():
    c = TestClient(create_app(Policy(rate_limit_requests_per_minute=2)))
    assert _post(c).status_code == 200 and _post(c).status_code == 200
    r = _post(c)
    assert r.status_code == 429 and r.json()["error"]["code"] == "requests" and int(r.headers["retry-after"]) >= 1
    assert "promptfw_rate_limited_total 1" in c.get("/metrics").text


def test_proxy_keys_on_verified_identity():
    key = b"k" * 16
    c = TestClient(create_app(Policy(rate_limit_requests_per_minute=1), principal_key=key))
    assert _post(c, {"x-promptfw-principal": mint(key, "alice")}).status_code == 200
    assert _post(c, {"x-promptfw-principal": mint(key, "bob")}).status_code == 200   # separate bucket
    assert _post(c, {"x-promptfw-principal": mint(key, "alice")}).status_code == 429
