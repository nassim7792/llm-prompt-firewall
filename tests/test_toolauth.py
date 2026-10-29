from promptfw import AgentReply, ToolCall
from tests.conftest import data


def _labels(v):
    return {f.label for f in v.blocked_by}


def call(fw, ctx, name, args, confirmed=False):
    return fw.inspect_egress(AgentReply("", (ToolCall(name, args, confirmed),)), ctx)


def test_untainted_read_is_allowed(fw, base):
    assert not call(fw, base, "lookup_order", {"order_id": "1"}).blocked


def test_tainted_send_is_refused_regardless_of_arguments(fw, base):
    v = call(fw, data(base, "harmless ticket"), "send_email", {"to": "support@vantage-logistics.example", "body": "hi"})
    assert "toolauth/tainted-action" in _labels(v)


def test_unknown_tool_fails_closed(fw, base):
    assert "toolauth/tool-unknown" in _labels(call(fw, base, "shell", {"cmd": "id"}))


def test_forbidden_effect(fw, base):
    assert "toolauth/effect-forbidden" in _labels(call(fw, base, "delete_account", {"user_id": "1"}))


def test_confirmation_required(fw, base):
    args = {"order_id": "1", "amount": 10.0}
    assert "toolauth/unconfirmed" in _labels(call(fw, base, "refund", args))
    assert not call(fw, base, "refund", args, confirmed=True).blocked


def test_argument_checks(fw, base):
    assert "toolauth/args-unexpected" in _labels(call(fw, base, "lookup_order", {"order_id": "1", "cb": "x"}))
    assert "toolauth/args-missing" in _labels(call(fw, base, "lookup_order", {}))
    assert "toolauth/args-type" in _labels(call(fw, base, "lookup_order", {"order_id": 1}))
    assert "toolauth/arg-not-allowlisted" in _labels(
        call(fw, base, "set_status", {"order_id": "1", "status": "refunded"}))


def test_secret_in_tool_argument_is_caught_by_egress(fw, base):
    v = call(fw, base, "lookup_order", {"order_id": "VANTAGE-7731-ORION"})
    assert "egress/canary-leak" in _labels(v)
