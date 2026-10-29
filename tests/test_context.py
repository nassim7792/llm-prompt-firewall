import pytest

from promptfw import Context, Origin, Trust
from promptfw.context import Span


def test_data_span_requires_origin():
    with pytest.raises(ValueError):
        Span(Trust.DATA, "x")


def test_non_data_span_cannot_have_origin():
    with pytest.raises(ValueError):
        Span(Trust.USER, "x", Origin("a", "b"))


def test_taint_is_derived_and_context_is_immutable():
    c0 = Context().system("s").user("u")
    c1 = c0.data("doc", Origin("web", "42"))
    assert not c0.tainted
    assert c1.tainted_by == (Origin("web", "42"),)
    assert c0.nonce == c1.nonce  # same request, same nonce
    assert len(c0.spans) == 2 and len(c1.spans) == 3


def test_nonce_is_fresh_per_context():
    assert Context().nonce != Context().nonce
    assert len(Context().nonce) == 16
