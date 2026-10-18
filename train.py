"""Train the VaultSense fraud model that the API serves (logistic regression on 5 features).

  python train.py                                         # built-in synthetic data (demo)
  python train.py --csv data/tabformer_prepared.csv       # IBM TabFormer (after prepare_data.py)
  python train.py --csv ... --review-fpr 0.05             # smaller review queue, lower recall

What it does:
  * Newton / IRLS logistic regression trained to convergence (numpy, handles millions of rows).
  * Split: chronological 60/20/20 when the CSV has a `timestamp` column (train on the past, test on
    the future, like a real deployment); otherwise stratified random 60/20/20.
  * Two thresholds chosen on VALIDATION by false-positive budget: `threshold` (send to review) and
    `high_threshold` (high risk). All metrics are reported on the untouched TEST part.
  * Fairness: recall and false-positive rate by age group (and income, when present). Age and
    income are never model inputs.
  * Synthetic data only: also reports the ceiling (the formula that generated the data).
Writes model.json (served by the API on restart) and evaluation.json.
"""
import argparse
import csv
import json
import random
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from core import FEATURES, SCALES
from fraudlib import (at_threshold, fit_logistic, group_report, load_columns, ranking, sigmoid,
                      split_indices, threshold_for_fpr)

p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
p.add_argument("--csv", help="Prepared CSV with amount,hour,international,new_payee,velocity_10m,is_fraud (+ optional age, income, timestamp)")
p.add_argument("--review-fpr", type=float, default=0.10, help="Share of legitimate transactions you can afford to review (default 0.10)")
p.add_argument("--high-fpr", type=float, default=0.01, help="False-positive budget for 'high risk' (default 0.01)")
p.add_argument("--l2", type=float, default=0.01, help="L2 penalty (small: large amounts are rare, a strong penalty shrinks their weight)")
p.add_argument("--split", choices=["auto", "time", "random"], default="auto")
p.add_argument("--name", help="Dataset label stored in model.json (default: file name or 'synthetic')")
p.add_argument("--model-out", default="model.json")
p.add_argument("--eval-out", default="evaluation.json")
args = p.parse_args()
rng = random.Random(42)
SC = np.array(SCALES, dtype=float)


def true_risk_np(raw):
    return sigmoid(-6 + raw[:, 0] / 1800 + 1.7 * raw[:, 2] + 1.9 * raw[:, 3] + .13 * raw[:, 4])


# ------------------------------------------------------------------ data
synthetic = not args.csv
if synthetic:
    rows = []
    for i in range(7000):
        r = dict(amount=round(min(rng.expovariate(1/350), 10000), 2), hour=rng.randrange(24),
                 international=int(rng.random() < .12), new_payee=int(rng.random() < .2),
                 velocity_10m=rng.randrange(1, 21), age=rng.randrange(18, 91))
        risk = 1 / (1 + 2.718281828459045 ** -(-6 + r["amount"]/1800 + 1.7*r["international"] + 1.9*r["new_payee"] + .13*r["velocity_10m"]))
        r["is_fraud"] = int(rng.random() < risk)
        rows.append(r)
    with open("synthetic.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    data = {k: np.array([r[k] for r in rows], dtype=float) for k in rows[0]}
else:
    data = load_columns(args.csv, FEATURES + ["is_fraud"], optional=["age", "income", "timestamp"])

raw = np.column_stack([data[f] for f in FEATURES])
y = data["is_fraud"].astype(int)
X = np.clip(raw / SC, 0, 2)  # exactly what core.vector() does at serving time
n = len(y)
if n < 100 or y.sum() < 10:
    raise SystemExit(f"Need at least 100 rows and 10 fraud cases (got {n} rows, {int(y.sum())} fraud)")

ts = data.get("timestamp") if args.split in ("auto", "time") else None
if args.split == "time" and ts is None:
    raise SystemExit("--split time needs a timestamp column")
tr, va, te, split_desc = split_indices(n, y, ts, rng)

# ------------------------------------------------------------------ train + thresholds (validation)
bias, w = fit_logistic(X[tr], y[tr], l2=args.l2)
score = sigmoid(bias + X @ w)
review_t = threshold_for_fpr(score[va], y[va], args.review_fpr)
high_t = max(threshold_for_fpr(score[va], y[va], args.high_fpr), review_t)


# ------------------------------------------------------------------ test metrics
def block(idx):
    s, yy = score[idx], y[idx]
    return {"n": int(len(idx)), "fraud_count": int(yy.sum()), **ranking(s, yy),
            "review_operating_point": at_threshold(s, yy, review_t),
            "high_risk_operating_point": at_threshold(s, yy, high_t)}


report = {"model_version": "logistic-v2", "dataset": args.name or ("synthetic" if synthetic else Path(args.csv).name),
          "split": split_desc, "rows": {"train": int(len(tr)), "validation": int(len(va)), "test": int(len(te))},
          "test": block(te)}
groups = {}
age = data.get("age")
if age is not None and not np.all(np.isnan(age[te])):
    a = age[te]
    groups["age"] = group_report(score[te], y[te], {"under_60": a < 60, "60_plus": a >= 60}, review_t)
    report["under_60"] = block(te[a < 60]); report["age_60_plus"] = block(te[a >= 60])  # kept for older readers
inc = data.get("income")
if inc is not None and not np.all(np.isnan(inc[te])):
    m = np.nanmedian(inc[te]); i = inc[te]
    groups["income"] = group_report(score[te], y[te], {"below_median_income": i < m, "above_median_income": i >= m}, review_t)
if groups:
    report["fairness_at_review_threshold"] = groups
if synthetic:
    tr_true = true_risk_np(raw)
    report["ceiling_true_generating_formula_on_test"] = {**ranking(tr_true[te], y[te]),
        "at_same_false_positive_budget": at_threshold(tr_true[te], y[te], threshold_for_fpr(tr_true[va], y[va], args.review_fpr))}
report["note"] = ("Thresholds chosen on validation, metrics on test. Age and income are never model inputs; they are used "
                  "only to compare groups. Small fraud counts make group differences uncertain: read the 95% intervals.")

model = dict(weights=[float(x) for x in w], bias=bias, threshold=review_t, high_threshold=high_t,  # never rounded: tiny thresholds must not become 0
             version="logistic-v2", trained_on=report["dataset"], split=split_desc,
             trained_at=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
             test_summary={"recall": report["test"]["review_operating_point"]["recall"],
                           "false_positive_rate": report["test"]["review_operating_point"]["false_positive_rate"],
                           "roc_auc": report["test"]["roc_auc"], "test_fraud_cases": report["test"]["fraud_count"]},
             threshold_note=f"threshold = review line at <= {args.review_fpr:.0%} validation false-positive rate; "
                            f"high_threshold at <= {args.high_fpr:.0%}")
Path(args.model_out).write_text(json.dumps(model, indent=2))
Path(args.eval_out).write_text(json.dumps(report, indent=2))
print(json.dumps({"dataset": report["dataset"], "split": split_desc, "weights": [round(x, 3) for x in w],
                  "test": report["test"], "fairness": groups or None,
                  "ceiling": report.get("ceiling_true_generating_formula_on_test")}, indent=2))
