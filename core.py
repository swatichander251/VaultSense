import math
import json
from pathlib import Path

FEATURES = ["amount", "hour", "international", "new_payee", "velocity_10m"]
SCALES = [5000, 23, 1, 1, 20]
BASE_DIR = Path(__file__).resolve().parent

def vector(t):
    return [min(max(float(t[k]) / s, 0), 2) for k, s in zip(FEATURES, SCALES)]

def sigmoid(z):
    return 1 / (1 + math.exp(-max(-35, min(35, z))))

class Model:
    def __init__(self, path=BASE_DIR / "model.json"):
        self.data = json.loads(Path(path).read_text())
        self.weights = self.data["weights"]
        self.bias = self.data["bias"]
        self.threshold = self.data["threshold"]                      # send to review
        self.high_threshold = self.data.get("high_threshold", self.threshold)  # high risk
        if len(self.weights) != len(FEATURES):
            raise ValueError(f"model.json has {len(self.weights)} weights but {len(FEATURES)} features are expected")

    def predict(self, t):
        x = vector(t)
        score = sigmoid(self.bias + sum(w*v for w, v in zip(self.weights, x)))
        contributions = sorted(zip(FEATURES, [w*v for w, v in zip(self.weights, x)]), key=lambda a: a[1], reverse=True)
        level = "high" if score >= self.high_threshold else "review" if score >= self.threshold else "low"
        return {"fraud_score": round(score, 6), "flagged": bool(score >= self.threshold), "risk_level": level,
                "threshold": self.threshold, "high_threshold": self.high_threshold,
                "explanations": [{"feature": k, "log_odds_contribution": round(v, 4)} for k, v in contributions if v > 0][:3],
                "explanation_note": "Exact additive model contributions relative to a zero-feature baseline; not causal explanations."}
