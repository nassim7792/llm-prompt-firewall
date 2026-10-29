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


def test_holdout_is_present_and_disjoint_from_dev():
    cases = load_corpus(default_corpus())
    dev = [c for c in cases if c.split == "dev"]
    hold = [c for c in cases if c.split == "holdout"]
    assert dev and hold
    assert not {c.id for c in dev} & {c.id for c in hold}
    # Same plain text under a different transform is a different test input.
    texts = lambda cs: {(str(c.raw.get("text", c.raw.get("args"))).casefold(), c.raw.get("transform"))  # noqa: E731
                        for c in cs}
    assert not texts(dev) & texts(hold), "a holdout case duplicates a dev case"


def test_dev_floors_and_no_inert_layer():
    # Floors apply to the DEV split only: putting a floor on the holdout would create an
    # incentive to tune the rules on it, which is exactly what the split exists to prevent.
    r = _report()
    dev = r.subset("dev")
    assert dev.rate(dev.attacks()) >= 95.0
    assert dev.rate(dev.benign(hard=True)) <= 15.0
    for layer, (solo, marginal) in r.ablation.items():
        assert solo or marginal, f"layer {layer} is inert: delete it or give it a job"


def test_metrics_are_consistent():
    m = _report().subset("holdout").metrics()
    assert m["block_rate"] + m["false_negative_rate"] == 100.0
    assert len(m["false_negatives"]) == round(m["attacks"] * m["false_negative_rate"] / 100)
