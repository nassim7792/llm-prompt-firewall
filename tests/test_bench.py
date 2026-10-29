from promptfw.bench import default_corpus, load_corpus, run
from promptfw.policy import Policy


def _report():
    root = default_corpus()
    return run(root, Policy.load(root.parent / "policy.yaml"))


def test_corpus_hard_benign_data_sits_in_data_spans():
    # Guard against a hard-benign case drifting into a USER span, where it would measure nothing.
    for c in load_corpus(default_corpus()):
        if c.cls == "data_hard":
            assert c.raw.get("trust", "data") == "data", c.id


def test_benchmark_floors_and_no_inert_layer():
    r = _report()
    assert r.rate(r.attacks()) >= 95.0
    assert r.rate(r.benign(hard=True)) <= 15.0
    for layer, (solo, marginal) in r.ablation.items():
        assert solo or marginal, f"layer {layer} is inert: delete it or give it a job"
