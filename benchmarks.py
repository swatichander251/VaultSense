"""Benchmarks on the other datasets in our datathon submission. These do NOT replace the live model
(that's TabFormer via train.py); each dataset has different columns, so each gets its own
logistic-regression model on its own features, with the same honest evaluation.

  python benchmarks.py ulb    --csv data/creditcard.csv
  python benchmarks.py paysim --csv data/PS_20174392719_1491204439457_log.csv --sample 0.3
  python benchmarks.py baf    --csv data/Base.csv

Results go to results/<dataset>.json and are printed.
  ulb    : rare-event detection (0.17% fraud). Chronological split on Time. Main metric PR-AUC.
  paysim : mobile-money transfer / cash-out scams. Chronological split on step (1 step = 1 hour).
  baf    : bank-account-opening fraud + FAIRNESS. Train months 0-4, validate 5, test 6-7 (as in the
           BAF paper). Threshold at 5% false-positive rate. Age and income are NOT model inputs; we
           compare false-positive rates across age (<50 vs 50+) and income groups (predictive equality).
"""
import argparse
import json
import math
import random
from pathlib import Path

import numpy as np

from fraudlib import (at_threshold, fit_logistic, group_report, load_columns, ranking, sigmoid,
                      standardize, threshold_for_fpr)


def onehot(values, categories):
    v = np.array(values)
    return np.column_stack([(v == c).astype(float) for c in categories]), [f"is_{c}" for c in categories]


def subsample(d, frac, seed=0):
    if frac >= 1:
        return d
    n = len(next(iter(v for v in d.values())))
    keep = np.random.RandomState(seed).random_sample(n) < frac
    return {k: (v[keep] if isinstance(v, np.ndarray) else [x for x, m in zip(v, keep) if m]) for k, v in d.items()}


def time_split(t, a=0.6, b=0.8):
    order = np.argsort(t, kind="stable"); n = len(t)
    return order[:int(a * n)], order[int(a * n):int(b * n)], order[int(b * n):]


def run(name, X, y, names, tr, va, te, fpr_budgets, extra_groups=None, note="", l2=1.0, split_desc=""):
    (Xtr, Xva, Xte), mu, sd = standardize(X[tr], X[va], X[te])
    bias, w = fit_logistic(Xtr, y[tr], l2=l2)
    s_va, s_te = sigmoid(bias + Xva @ w), sigmoid(bias + Xte @ w)
    res = {"dataset": name, "split": split_desc,
           "rows": {"train": int(len(tr)), "validation": int(len(va)), "test": int(len(te))},
           "fraud_rate_test": round(float(y[te].mean()), 5), "test": ranking(s_te, y[te]), "operating_points": {}}
    for b in fpr_budgets:
        t = threshold_for_fpr(s_va, y[va], b)
        res["operating_points"][f"fpr_budget_{b:g}"] = at_threshold(s_te, y[te], t)
    if extra_groups:
        t = threshold_for_fpr(s_va, y[va], fpr_budgets[0])
        res["fairness_at_first_operating_point"] = {g: group_report(s_te, y[te], masks, t) for g, masks in extra_groups(te).items()}
    top = sorted(zip(names, w), key=lambda kv: -abs(kv[1]))[:8]
    res["top_features_standardized_weight"] = [{"feature": k, "weight": round(float(v), 3)} for k, v in top]
    res["note"] = note
    Path("results").mkdir(exist_ok=True)
    Path(f"results/{name}.json").write_text(json.dumps(res, indent=2))
    print(json.dumps({k: res[k] for k in res if k != "top_features_standardized_weight"}, indent=2))
    print("Top features:", ", ".join(f"{d['feature']} ({d['weight']:+})" for d in res["top_features_standardized_weight"]))
    return res


def ulb(a):
    vs = [f"V{i}" for i in range(1, 29)]
    d = subsample(load_columns(a.csv, ["Time", "Amount", "Class"] + vs), a.sample)
    X = np.column_stack([d[v] for v in vs] + [np.log1p(np.maximum(d["Amount"], 0))])
    y = d["Class"].astype(int)
    tr, va, te = time_split(d["Time"])
    return run("ulb", X, y, vs + ["log_amount"], tr, va, te, [0.01, 0.001], l2=a.l2,
               split_desc="chronological 60/20/20 on Time",
               note="ULB features V1-V28 are anonymized PCA components, so they can't feed the live 5-feature model. "
                    "PR-AUC is the meaningful metric at 0.17% fraud; ROC-AUC looks high on rare events by default.")


def paysim(a):
    d = subsample(load_columns(a.csv, ["step", "amount", "oldbalanceOrg", "newbalanceOrig", "oldbalanceDest",
                                       "newbalanceDest", "isFraud"], text=["type"]), a.sample)
    types = [t.replace("-", "_").upper() for t in d["type"]]
    T, tnames = onehot(types, ["TRANSFER", "CASH_OUT", "PAYMENT", "CASH_IN", "DEBIT"])
    amt = d["amount"]
    err_orig = d["newbalanceOrig"] + amt - d["oldbalanceOrg"]   # money that "disappeared" from the sender
    err_dest = d["oldbalanceDest"] + amt - d["newbalanceDest"]  # money that never arrived
    X = np.column_stack([T, np.log1p(amt), np.log1p(d["oldbalanceOrg"]), np.log1p(d["newbalanceOrig"]),
                         np.log1p(d["oldbalanceDest"]), np.log1p(d["newbalanceDest"]),
                         np.sign(err_orig) * np.log1p(np.abs(err_orig)), np.sign(err_dest) * np.log1p(np.abs(err_dest)),
                         (d["step"] % 24)])
    names = tnames + ["log_amount", "log_old_bal_orig", "log_new_bal_orig", "log_old_bal_dest", "log_new_bal_dest",
                      "balance_error_orig", "balance_error_dest", "hour"]
    y = d["isFraud"].astype(int)
    tr, va, te = time_split(d["step"])
    return run("paysim", X, y, names, tr, va, te, [0.01, 0.001], l2=a.l2,
               split_desc="chronological 60/20/20 on step (hours)",
               note="isFlaggedFraud is excluded (it is the old rule system's output). PaySim's balance-error features are "
                    "known to make it unusually easy; treat very high scores as a property of the simulator, not of the model.")


BAF_CAT = ["payment_type", "employment_status", "housing_status", "source", "device_os"]
BAF_SKIP = {"fraud_bool", "customer_age", "income", "month"} | set(BAF_CAT)


def baf(a):
    import csv
    with open(a.csv, newline="", encoding="utf-8-sig") as f:
        header = next(csv.reader(f))
    num = [c for c in header if c not in BAF_SKIP]
    d = subsample(load_columns(a.csv, num + ["fraud_bool", "customer_age", "income", "month"], text=BAF_CAT), a.sample)
    parts, names = [np.column_stack([d[c] for c in num])], list(num)
    for c in BAF_CAT:
        cats = sorted(set(d[c]))
        m, nm = onehot(d[c], cats); parts.append(m); names += [f"{c}={x[3:]}" for x in nm]
    X = np.hstack(parts); y = d["fraud_bool"].astype(int); month = d["month"]
    tr, va, te = np.flatnonzero(month <= 4), np.flatnonzero(month == 5), np.flatnonzero(month >= 6)
    if len(te) == 0 or len(va) == 0:
        tr, va, te = time_split(month)
    age, inc = d["customer_age"], d["income"]

    def groups(idx):
        return {"age": {"under_50": age[idx] < 50, "50_plus": age[idx] >= 50},
                "income": {"low_income_<=0.3": inc[idx] <= 0.3, "middle_income": (inc[idx] > 0.3) & (inc[idx] < 0.7),
                           "high_income_>=0.7": inc[idx] >= 0.7}}
    return run("baf", X, y, names, tr, va, te, [0.05, 0.01], extra_groups=groups, l2=a.l2,
               split_desc="by month: train 0-4, validate 5, test 6-7",
               note="Age and income are not model inputs. fpr_ratio_min_over_max near 1.0 means groups get similar false-alarm "
                    "rates (predictive equality); the BAF paper uses 0.8 as a common fairness bar. Other features can still "
                    "carry age information indirectly, which is exactly what this check measures.")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("dataset", choices=["ulb", "paysim", "baf"])
    p.add_argument("--csv", required=True)
    p.add_argument("--sample", type=float, default=1.0, help="Random fraction of rows to use (e.g. 0.3 for PaySim's 6.3M rows)")
    p.add_argument("--l2", type=float, default=1.0)
    a = p.parse_args()
    {"ulb": ulb, "paysim": paysim, "baf": baf}[a.dataset](a)


if __name__ == "__main__":
    main()
