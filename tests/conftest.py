import pytest

from promptfw import Context, Firewall, Origin, Policy
from promptfw.tools import Effect, Guard, Tool

SECRET = "VANTAGE-7731-ORION"


@pytest.fixture
def policy() -> Policy:
    return Policy(
        canaries=(SECRET,),
        allowed_hosts=("vantage-logistics.example",),
        forbidden_effects=frozenset({Effect.DELETE}),
        tools={
            "lookup_order": Tool("lookup_order", frozenset({Effect.READ}), args={"order_id": str},
                                 required=frozenset({"order_id"})),
            "send_email": Tool("send_email", frozenset({Effect.SEND}), frozenset({Guard.NO_UNTRUSTED_INFLUENCE}),
                               {"to": str, "body": str}, frozenset({"to", "body"})),
            "refund": Tool("refund", frozenset({Effect.SPEND}), frozenset({Guard.USER_CONFIRMED}),
                           {"order_id": str, "amount": float}, frozenset({"order_id", "amount"})),
            "set_status": Tool("set_status", frozenset({Effect.WRITE}), frozenset({Guard.ARGS_ALLOWLISTED}),
                               {"order_id": str, "status": str}, frozenset({"order_id", "status"}),
                               {"status": frozenset({"delivered", "delayed"})}),
            "delete_account": Tool("delete_account", frozenset({Effect.DELETE}), args={"user_id": str}),
        },
    )


@pytest.fixture
def fw(policy: Policy) -> Firewall:
    return Firewall(policy)


@pytest.fixture
def base() -> Context:
    return Context().system("You are a support agent.").user("Please help with this ticket.")


def data(ctx: Context, text: str, ref: str = "1") -> Context:
    return ctx.data(text, Origin("ticket", ref))
