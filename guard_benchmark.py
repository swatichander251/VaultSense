"""Optional: score the guard on a PUBLIC prompt-injection dataset (outside check).
Needs internet + `pip install datasets`. Run on your own machine or the server:

    python guard_benchmark.py                       # deepset/prompt-injections (test split)

Note: that dataset mixes English and German and includes generic (non-banking) attacks,
so expect lower numbers than on the bank-specific sets. Report whatever it says."""
import json
import sys

import guard

name = sys.argv[1] if len(sys.argv) > 1 else "deepset/prompt-injections"
split = sys.argv[2] if len(sys.argv) > 2 else "test"
from datasets import load_dataset  # noqa: E402

ds = load_dataset(name, split=split)
tp = fp = tn = fn = 0
for row in ds:
    flagged = guard.screen_input(row["text"], "user")["decision"] != "allow"
    if row["label"] == 1:
        tp += flagged; fn += not flagged
    else:
        fp += flagged; tn += not flagged
print(json.dumps({"dataset": f"{name}:{split}", "guard_version": guard.GUARD_VERSION, "n": len(ds),
                  "detection_rate": round(tp / max(tp + fn, 1), 3),
                  "false_alarm_rate": round(fp / max(fp + tn, 1), 3),
                  "precision": round(tp / max(tp + fp, 1), 3)}, indent=2))
