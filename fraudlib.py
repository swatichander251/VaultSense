"""Shared training + evaluation helpers (numpy). Used by train.py, benchmarks.py and federated.py.
The API itself never imports this, so the server doesn't need numpy to serve predictions."""
import csv
import math
from array import array

import numpy as np


def load_columns(path, numeric, optional=(), text=()):
    """Stream a CSV into numpy arrays (memory-light for millions of rows).
    Empty optional cells become NaN."""
    cols = {c: array("d") for c in list(numeric) + list(optional)}
    txt = {c: [] for c in text}
    with open(path, newline="", encoding="utf-8-sig") as f:
        rd = csv.DictReader(f)
        missing = set(numeric) - set(rd.fieldnames or [])
        if missing:
            raise SystemExit(f"{path} is missing columns {sorted(missing)}; found {rd.fieldnames}")
        opt = [c for c in optional if c in (rd.fieldnames or [])]
        for row in rd:
            for c in numeric:
                cols[c].append(float(row[c]))
            for c in opt:
                v = row[c]
                cols[c].append(float(v) if v not in ("", None) else math.nan)
            for c in text:
                txt[c].append(row[c])
    out = {c: np.frombuffer(a, dtype=np.float64) for c, a in cols.items() if len(a) or c in numeric}
    out.update(txt)
    return out


def sigmoid(z):
    return 1.0 / (1.0 + np.exp(-np.clip(z, -35, 35)))


def fit_logistic(X, y, l2=0.01, max_iter=50, sample_weight=None):
    """Newton / IRLS logistic regression with L2 on weights (not bias). Returns (bias, weights)."""
    n, k = X.shape
    Xb = np.hstack([np.ones((n, 1)), X])
    beta = np.zeros(k + 1)
    sw = np.ones(n) if sample_weight is None else sample_weight
    reg = np.full(k + 1, l2); reg[0] = 0.0
    for _ in range(max_iter):
        p = sigmoid(Xb @ beta)
        g = Xb.T @ (sw * (y - p)) - reg * beta
        H = (Xb * (sw * p * (1 - p))[:, None]).T @ Xb + np.diag(reg)
        step = np.linalg.solve(H + 1e-9 * np.eye(k + 1), g)
        beta += step
        if np.max(np.abs(step)) < 1e-8:
            break
    return float(beta[0]), beta[1:]


def stats_logistic(X, y, beta, l2=0.0):
    """Gradient and Hessian of the log-likelihood at beta: the ONLY things a simulated bank shares."""
    Xb = np.hstack([np.ones((len(y), 1)), X])
    p = sigmoid(Xb @ beta)
    return Xb.T @ (y - p), (Xb * (p * (1 - p))[:, None]).T @ Xb


def threshold_for_fpr(scores, y, budget):
    neg = np.sort(scores[y == 0])[::-1]
    k = int(budget * len(neg))
    return float(neg[k]) if k < len(neg) else 0.0


def wilson(k, n):
    if n == 0:
        return None
    z, p = 1.96, k / n
    d = 1 + z * z / n; c = (p + z * z / (2 * n)) / d; h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(c - h, 3), round(c + h, 3)]


def at_threshold(scores, y, t):
    pred = scores >= t
    tp = int(np.sum(pred & (y == 1))); fn = int(np.sum(~pred & (y == 1)))
    fp = int(np.sum(pred & (y == 0))); tn = int(np.sum(~pred & (y == 0)))
    return {"threshold": round(float(t), 4), "recall": round(tp / (tp + fn), 3) if tp + fn else None,
            "recall_95ci": wilson(tp, tp + fn), "precision": round(tp / (tp + fp), 3) if tp + fp else None,
            "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else None,
            "caught": tp, "missed": fn, "false_alarms": fp}


def ranking(scores, y):
    order = np.argsort(-scores, kind="stable")
    ys = y[order]
    P = int(ys.sum()); N = len(ys) - P
    if not P or not N:
        return {"roc_auc": None, "pr_auc": None}
    tp = np.cumsum(ys); fp = np.cumsum(1 - ys)
    ap = float(np.sum((tp / (tp + fp))[ys == 1]) / P)
    auc = float(np.sum(tp[ys == 0]) / (P * N))
    return {"roc_auc": round(auc, 3), "pr_auc": round(ap, 3)}


def split_indices(n, y, timestamps=None, seed_rng=None, fractions=(0.6, 0.8)):
    """Chronological split when timestamps exist (train on the past, test on the future),
    otherwise a stratified random split using the given python Random."""
    a, b = fractions
    if timestamps is not None and not np.all(np.isnan(timestamps)):
        order = np.argsort(timestamps, kind="stable")
        i, j = int(a * n), int(b * n)
        return order[:i], order[i:j], order[j:], "chronological 60/20/20 (train on the past, test on the future)"
    pos = [int(i) for i in np.flatnonzero(y == 1)]; neg = [int(i) for i in np.flatnonzero(y == 0)]
    seed_rng.shuffle(pos); seed_rng.shuffle(neg)

    def cut(xs):
        return xs[:int(a * len(xs))], xs[int(a * len(xs)):int(b * len(xs))], xs[int(b * len(xs)):]
    (p1, p2, p3), (n1, n2, n3) = cut(pos), cut(neg)
    return (np.array(p1 + n1, dtype=int), np.array(p2 + n2, dtype=int), np.array(p3 + n3, dtype=int),
            "stratified random 60/20/20")


def standardize(train_X, *others):
    mu = train_X.mean(axis=0); sd = train_X.std(axis=0); sd[sd == 0] = 1.0
    return [(m - mu) / sd for m in (train_X, *others)], mu, sd


def group_report(scores, y, groups, t):
    """Recall and false-positive rate per group at one threshold (fairness check)."""
    out = {}
    for name, mask in groups.items():
        if mask.sum() == 0:
            continue
        r = at_threshold(scores[mask], y[mask], t)
        out[name] = {"n": int(mask.sum()), "fraud": int(y[mask].sum()), "recall": r["recall"],
                     "recall_95ci": r["recall_95ci"], "false_positive_rate": r["false_positive_rate"]}
    fprs = [v["false_positive_rate"] for v in out.values() if v["false_positive_rate"]]
    if len(fprs) >= 2 and max(fprs) > 0:
        out["fpr_ratio_min_over_max"] = round(min(fprs) / max(fprs), 3)
    return out
