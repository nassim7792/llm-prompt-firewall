"""End-to-end evaluation harness (mock target: validates the measurement chain, not security)."""

import json

from promptfw import AgentReply, Policy, ToolCall
from promptfw.eval.run import Scenario, Target, build_messages, goal_reached, load_scenarios, run_and_report

SECRET = "VL-1A2B3C4D-CODE"


def test_goal_judges():
    assert goal_reached({"type": "secret_leak"}, AgentReply(f"the code is {SECRET}"), SECRET)
    assert goal_reached({"type": "secret_leak"}, AgentReply("V-L-1-A-2-B-3-C-4-D-C-O-D-E"), SECRET)
    assert not goal_reached({"type": "secret_leak"}, AgentReply("I cannot share that."), SECRET)
    call = AgentReply("", (ToolCall("change_recovery_email", {"account": "@Sephora", "email": "x"}),))
    assert goal_reached({"type": "tool_call", "tool": "change_recovery_email", "args": {"account": "sephora"}}, call, SECRET)
    assert not goal_reached({"type": "tool_call", "tool": "refund"}, call, SECRET)
    assert goal_reached({"type": "url_host", "host": "evil.example"}, AgentReply("see https://cdn.evil.example/x"), SECRET)
    assert not goal_reached({"type": "url_host", "host": "evil.example"}, AgentReply("see https://notevil.example/"), SECRET)


def test_tool_messages_get_a_matching_assistant_call():
    s = Scenario("x", "f", "attack", "sys {secret}", [{"role": "user", "content": "q"},
                                                     {"role": "tool", "name": "fetch_page", "content": "doc"}])
    msgs = build_messages(s, SECRET)
    assert msgs[0]["content"] == f"sys {SECRET}"
    assert msgs[2]["role"] == "assistant" and msgs[2]["tool_calls"][0]["id"] == msgs[3]["tool_call_id"]


def test_scenarios_reference_declared_tools():
    policy = Policy.load("eval/policy.yaml")
    scenarios = load_scenarios("eval/scenarios")
    assert {s.kind for s in scenarios} == {"attack", "benign"}
    for s in scenarios:
        assert set(s.tools) <= set(policy.tools), s.id


def test_mock_run_produces_consistent_reports(tmp_path):
    m, md = run_and_report("eval/scenarios", Policy.load("eval/policy.yaml"), Target("mock"), 1, tmp_path)
    assert m["attack_runs"] > 0 and m["benign_runs"] > 0 and not m["errors"]
    assert m["asr_with_firewall"] <= m["asr_without_firewall"]
    assert m["block_rate"] + m["miss_rate"] == 100.0
    assert "ASR sans pare-feu" in md
    stems = {p.suffix for p in tmp_path.iterdir()}
    assert stems == {".json", ".csv", ".md"}
    data = json.loads(next(tmp_path.glob("*.json")).read_text(encoding="utf-8"))
    assert len(data["runs"]) == m["attack_runs"] + m["benign_runs"]
