"""End-to-end test of the data pipeline on FAKE files in the real datasets' exact formats."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
PY = sys.executable


def run(args, cwd):
    r = subprocess.run([PY, *args], cwd=cwd, capture_output=True, text=True, timeout=300)
    assert r.returncode == 0, r.stdout + r.stderr
    return r.stdout


@pytest.fixture(scope="module")
def work(tmp_path_factory):
    d = tmp_path_factory.mktemp("pipeline")
    run([str(HERE / "data_tests/make_samples.py"), str(d)], cwd=d)
    return d


def test_tabformer_prepare_and_train(work):
    out = run([str(HERE / "prepare_data.py"), "tabformer", "--transactions", str(work / "credit_card_transactions-ibm_v2.csv"),
               "--users", str(work / "sd254_users.csv"), "--out", str(work / "prep.csv"), "--max-users", "30", "--user-fraction", "1"], cwd=work)
    assert "card holders" in out and "WARNING" not in out
    header = (work / "prep.csv").read_text().splitlines()[0].split(",")
    assert header[:6] == ["amount", "hour", "international", "new_payee", "velocity_10m", "is_fraud"]
    run([str(HERE / "train.py"), "--csv", str(work / "prep.csv"), "--model-out", str(work / "m.json"),
         "--eval-out", str(work / "e.json"), "--name", "tabformer-sample"], cwd=work)
    m = json.loads((work / "m.json").read_text()); e = json.loads((work / "e.json").read_text())
    assert m["trained_on"] == "tabformer-sample" and m["threshold"] > 0 and "chronological" in e["split"]
    assert "age" in e["fairness_at_review_threshold"] and "income" in e["fairness_at_review_threshold"]
    # the served model must load the new file
    sys.path.insert(0, str(HERE))
    from core import Model
    assert Model(work / "m.json").predict({"amount": 50, "hour": 3, "international": 0, "new_payee": 0, "velocity_10m": 0})


def test_velocity_uses_only_earlier_transactions(work):
    import csv
    rows = list(csv.DictReader(open(work / "prep.csv")))
    first_per_user = {}
    for r in rows:
        first_per_user.setdefault(r["user"], r)
    assert all(r["velocity_10m"] == "0" and r["new_payee"] == "1" for r in first_per_user.values())


@pytest.mark.parametrize("name,file", [("ulb", "creditcard.csv"), ("paysim", "PS_20174392719_1491204439457_log.csv"), ("baf", "Base.csv")])
def test_benchmarks(work, name, file):
    run([str(HERE / "benchmarks.py"), name, "--csv", str(work / file)], cwd=work)
    res = json.loads((work / "results" / f"{name}.json").read_text())
    assert res["test"]["roc_auc"] is not None and res["operating_points"]
    if name == "baf":
        f = res["fairness_at_first_operating_point"]
        assert set(f) == {"age", "income"} and "fpr_ratio_min_over_max" in f["age"]


def test_federated_matches_pooled(work):
    out = run([str(HERE / "federated.py"), "--csv", str(work / "prep.csv")], cwd=work)
    res = json.loads((work / "results" / "federated.json").read_text())
    assert res["shared_model_equals_pooled_max_weight_difference"] < 1e-6 and len(res["banks"]) >= 2
    assert res["numbers_shared_total"] < res["raw_values_that_stayed_private"]
    run([str(HERE / "federated.py"), "--csv", str(work / "prep.csv"), "--noise", "5"], cwd=work)
