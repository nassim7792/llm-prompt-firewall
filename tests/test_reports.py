"""Machine-readable reports and CI gates."""

import csv
import json

from promptfw.cli import main


def test_bench_json_and_csv_exports(tmp_path, capsys):
    j, c = tmp_path / "b.json", tmp_path / "b.csv"
    assert main(["bench", "--no-ablation", "--json", str(j), "--csv", str(c)]) == 0
    data = json.loads(j.read_text(encoding="utf-8"))
    assert {"dev", "holdout"} <= set(data["splits"])
    dev = data["splits"]["dev"]
    assert {"block_rate", "false_negative_rate", "false_positive_rate_hard", "latency_ms_p95"} <= set(dev)
    rows = list(csv.DictReader(c.open(encoding="utf-8")))
    assert len(rows) == dev["attacks"] + dev["benign"] + data["splits"]["holdout"]["attacks"] + \
        data["splits"]["holdout"]["benign"]


def test_bench_gate_fails_on_regression(capsys):
    assert main(["bench", "--no-ablation", "--fail-dev-tpr-below", "101"]) == 1
    assert "REGRESSION" in capsys.readouterr().err


def test_eval_gate_passes_on_mock(tmp_path):
    assert main(["eval", "--target", "mock", "--out", str(tmp_path), "--quiet",
                 "--fail-asr-with-above", "0", "--fail-fpr-above", "0", "--fail-on-errors"]) == 0
