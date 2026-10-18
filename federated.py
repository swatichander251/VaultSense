"""Simulated banks: can banks learn fraud patterns together WITHOUT sharing customer data?

  python federated.py --csv data/tabformer_prepared.csv            # uses bank_id from prepare_data.py
  python federated.py --csv data/tabformer_prepared.csv --noise 5

Each Bank object keeps its transactions private. In every round it receives the current shared
model and returns only two aggregates: a gradient (6 numbers) and a Hessian (6x6 = 36 numbers).
The coordinator adds them up and takes one Newton step. No transaction, customer or card ever
leaves a bank.

Compares, on each bank's own future transactions (chronological split):
  * local only   - the bank trains on its own data alone
  * shared model - federated training across all banks (only aggregates shared)
  * pooled       - everyone's raw data in one place (the privacy-violating upper bound)
Federated Newton gives the same model as pooling (checked below), so sharing aggregates
loses no accuracy. --noise adds Gaussian noise (scaled to how much one transaction can change the
shared numbers) before anything leaves a bank, to show the privacy/accuracy trade-off. This is NOT a formal differential-privacy guarantee; aggregates
can still leak information, so production use needs secure aggregation and a DP analysis.
Writes results/federated.json.
"""
import argparse
import json
from pathlib import Path

import numpy as np

from core import FEATURES, SCALES
from fraudlib import at_threshold, fit_logistic, load_columns, ranking, sigmoid, stats_logistic, threshold_for_fpr

SC = np.array(SCALES, dtype=float)
MAX_ROW_GRAD_NORM = float(np.sqrt(1 + len(SCALES) * 2.0 ** 2))


class Bank:
    """Everything inside here is private to one bank."""

    def __init__(self, bank_id, X, y, ts):
        order = np.argsort(ts, kind="stable")
        n = len(y); i, j = int(.6 * n), int(.8 * n)
        self.id = bank_id
        self._tr, self._va, self._te = order[:i], order[i:j], order[j:]
        self._X, self._y = X, y
        self.size, self.fraud = int(n), int(y.sum())

    def share_stats(self, beta):
        """The ONLY thing that leaves the bank: aggregate gradient + Hessian on its training rows."""
        return stats_logistic(self._X[self._tr], self._y[self._tr], beta)

    def share_noisy_stats(self, beta, noise_multiplier, rng):
        """Noisy mode: gradient + Hessian with Gaussian noise added BEFORE they leave the bank.
        Features are clipped to [0, 2] and |y - p| <= 1, so one transaction changes the gradient by at most
        C = sqrt(1 + 5 * 2^2) and the Hessian by at most C^2 / 4; noise = noise_multiplier x that bound
        (the Gaussian mechanism, without a formal privacy accounting)."""
        g, H = stats_logistic(self._X[self._tr], self._y[self._tr], beta)
        g = g + rng.normal(0, noise_multiplier * MAX_ROW_GRAD_NORM, g.shape)
        E = rng.normal(0, noise_multiplier * MAX_ROW_GRAD_NORM ** 2 / 4, H.shape)
        return g, H + np.triu(E) + np.triu(E, 1).T

    def train_local(self, l2):
        b, w = fit_logistic(self._X[self._tr], self._y[self._tr], l2=l2)
        return np.concatenate([[b], w])

    def evaluate(self, beta, fpr_budget):
        """Bank picks its own threshold on its own validation data, then tests on its own future."""
        s = lambda idx: sigmoid(beta[0] + self._X[idx] @ beta[1:])
        t = threshold_for_fpr(s(self._va), self._y[self._va], fpr_budget)
        r = at_threshold(s(self._te), self._y[self._te], t)
        return {**ranking(s(self._te), self._y[self._te]), "recall": r["recall"], "recall_95ci": r["recall_95ci"],
                "false_positive_rate": r["false_positive_rate"], "test_fraud": r["caught"] + r["missed"]}


def federated_newton(banks, k, l2, rounds=30):
    """Exact: equals training on pooled data, while each bank shares only aggregates."""
    beta = np.zeros(k + 1)
    reg = np.full(k + 1, l2); reg[0] = 0
    shared_numbers = 0
    for r in range(rounds):
        G = -reg * beta; Hs = np.diag(reg).astype(float)
        for b in banks:
            g, H = b.share_stats(beta)
            G += g; Hs += H
            shared_numbers += g.size + H.size
        step = np.linalg.solve(Hs + 1e-9 * np.eye(k + 1), G)
        beta = beta + step
        if np.max(np.abs(step)) < 1e-8:
            return beta, r + 1, shared_numbers
    return beta, rounds, shared_numbers


def federated_noisy_newton(banks, k, l2, noise_multiplier, rounds=20, seed=0):
    """Privacy trade-off demo: Newton steps from noisy aggregates. The coordinator keeps the summed Hessian
    positive-definite (eigenvalue floor) so noise can't make a step blow up."""
    rng = np.random.RandomState(seed)
    beta = np.zeros(k + 1); reg = np.full(k + 1, l2); reg[0] = 0
    shared_numbers = 0
    for _ in range(rounds):
        G = -reg * beta; Hs = np.diag(reg).astype(float)
        for b in banks:
            g, H = b.share_noisy_stats(beta, noise_multiplier, rng)
            G += g; Hs += H; shared_numbers += g.size + H.size
        vals, vecs = np.linalg.eigh(Hs)
        floor = max(1e-6, 0.05 * vals.max())
        Hs = (vecs * np.maximum(vals, floor)) @ vecs.T
        beta = beta + np.linalg.solve(Hs, G)
    return beta, rounds, shared_numbers


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--csv", required=True, help="Output of prepare_data.py (needs bank_id and timestamp)")
    p.add_argument("--l2", type=float, default=0.01)
    p.add_argument("--fpr", type=float, default=0.10, help="False-positive budget each bank uses (default 0.10)")
    p.add_argument("--noise", type=float, default=0.0, help="Noise multiplier on shared gradients, e.g. 1, 5, 20 (privacy/accuracy trade-off demo)")
    a = p.parse_args()

    d = load_columns(a.csv, FEATURES + ["is_fraud", "bank_id", "timestamp"])
    X = np.clip(np.column_stack([d[f] for f in FEATURES]) / SC, 0, 2)
    y = d["is_fraud"].astype(int); bank = d["bank_id"].astype(int); ts = d["timestamp"]
    banks = [Bank(int(b), X[bank == b], y[bank == b], ts[bank == b]) for b in sorted(set(bank.tolist()))]
    k = X.shape[1]

    if a.noise:
        shared, rounds, n_shared = federated_noisy_newton(banks, k, a.l2, a.noise)
    else:
        shared, rounds, n_shared = federated_newton(banks, k, a.l2)
    # Pooled baseline: what you'd get if every bank handed over raw data (for comparison only).
    tr_all = [b for b in banks]
    Xp = np.vstack([b._X[b._tr] for b in tr_all]); yp = np.concatenate([b._y[b._tr] for b in tr_all])
    pb, pw = fit_logistic(Xp, yp, l2=a.l2); pooled = np.concatenate([[pb], pw])

    rows = []
    for b in banks:
        local = b.train_local(a.l2) if b._y[b._tr].sum() > 0 else None
        rows.append({"bank": b.id, "transactions": b.size, "fraud_cases": b.fraud,
                     "local_only": b.evaluate(local, a.fpr) if local is not None else "no fraud in training data",
                     "shared_model": b.evaluate(shared, a.fpr),
                     "pooled_raw_data": b.evaluate(pooled, a.fpr)})
    raw_values = int(sum(b.size for b in banks) * (k + 1))
    out = {"banks": rows,
           "shared_model_equals_pooled_max_weight_difference": float(np.max(np.abs(shared - pooled))) if not a.noise else None,
           "rounds": rounds, "numbers_shared_total": n_shared,
           "raw_values_that_stayed_private": raw_values,
           "noise": a.noise,
           "note": "Each bank shared only aggregate gradients and Hessians. Not a formal differential-privacy guarantee."}
    Path("results").mkdir(exist_ok=True)
    Path("results/federated.json").write_text(json.dumps(out, indent=2))

    print(f"{'bank':>4} {'transactions':>12} {'fraud':>6} | {'local-only recall':>17} {'shared recall':>13} {'pooled recall':>13} | FPR shared")
    for r in rows:
        lo = r["local_only"]["recall"] if isinstance(r["local_only"], dict) else None
        print(f"{r['bank']:>4} {r['transactions']:>12,} {r['fraud_cases']:>6} | {str(lo):>17} {str(r['shared_model']['recall']):>13} "
              f"{str(r['pooled_raw_data']['recall']):>13} | {r['shared_model']['false_positive_rate']}")
    if not a.noise:
        print(f"\nShared model vs pooled raw data: max weight difference {out['shared_model_equals_pooled_max_weight_difference']:.2e} (same model)")
    print(f"Numbers shared in total: {n_shared:,} over {rounds} rounds. Raw values kept private: {raw_values:,}.")


if __name__ == "__main__":
    main()
