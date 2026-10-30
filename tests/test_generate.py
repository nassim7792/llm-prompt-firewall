from promptfw import Firewall, Policy
from promptfw.eval.generate import generate, run


def test_generator_is_deterministic_per_seed():
    assert [g.text for g in generate(20, seed=3)] == [g.text for g in generate(20, seed=3)]
    assert [g.text for g in generate(20, seed=3)] != [g.text for g in generate(20, seed=4)]


def test_fuzz_report_and_candidates(tmp_path):
    out = run(Firewall(Policy()), n=60, seed=0, candidates_dir=tmp_path)
    assert "block rate by dimension" in out
    files = list(tmp_path.glob("*.yaml"))
    assert not files or "manual only" in files[0].read_text(encoding="utf-8")
