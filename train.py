import csv
import json
import random
import argparse
from pathlib import Path
from core import FEATURES, vector, sigmoid

parser = argparse.ArgumentParser()
parser.add_argument("--csv", help="Optional normalized labeled CSV; see README")
args = parser.parse_args()
rng = random.Random(42)
if args.csv:
    with open(args.csv, newline="") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        for k in FEATURES + ["is_fraud", "age"]:
            r[k] = float(r[k])
else:
    rows = []
    for i in range(7000):
        r = dict(amount=round(min(rng.expovariate(1/350), 10000), 2), hour=rng.randrange(24),
                 international=int(rng.random()<.12), new_payee=int(rng.random()<.2),
                 velocity_10m=rng.randrange(1, 21), age=rng.randrange(18, 91))
        risk = -6 + r["amount"]/1800 + 1.7*r["international"] + 1.9*r["new_payee"] + .13*r["velocity_10m"]
        r["is_fraud"] = int(rng.random() < sigmoid(risk))
        rows.append(r)
    with open("synthetic.csv", "w", newline="") as f:
        writer=csv.DictWriter(f, fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)
if len(rows) < 100:
    raise ValueError("Provide at least 100 labeled records")
rng.shuffle(rows)
train, test = rows[:int(.8*len(rows))], rows[int(.8*len(rows)):]
w = [0.0]*len(FEATURES); bias = -3.0
for epoch in range(35):
    rng.shuffle(train)
    lr = .06 / (1 + epoch*.08)
    for r in train:
        x = vector(r); error = sigmoid(bias+sum(a*b for a,b in zip(w,x))) - r["is_fraud"]
        bias -= lr*error
        w = [a-lr*(error*b+.0001*a) for a,b in zip(w,x)]
threshold = .25
Path("model.json").write_text(json.dumps(dict(weights=w,bias=bias,threshold=threshold,version="logistic-demo-v1"), indent=2))
def metrics(records):
    tp=fp=tn=fn=0
    for r in records:
        pred=sigmoid(bias+sum(a*b for a,b in zip(w,vector(r)))) >= threshold
        actual=bool(r["is_fraud"])
        tp += pred and actual; fp += pred and not actual
        tn += not pred and not actual; fn += not pred and actual
    return dict(n=len(records), fraud_count=tp+fn, precision=tp/(tp+fp) if tp+fp else None,
                recall=tp/(tp+fn) if tp+fn else None, false_positive_rate=fp/(fp+tn) if fp+tn else None)
report=dict(test=metrics(test), under_60=metrics([r for r in test if r["age"]<60]),
            age_60_plus=metrics([r for r in test if r["age"]>=60]),
            note="Synthetic random-split demonstration, not deployment validation. Age is excluded from scoring. Threshold is illustrative, not tuned.")
Path("evaluation.json").write_text(json.dumps(report, indent=2))
print(json.dumps(report, indent=2))
