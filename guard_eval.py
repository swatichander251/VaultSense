"""Evaluate the chatbot guard on guard_eval_data.json.
Run:  python guard_eval.py          (writes guard_evaluation.json)
      python guard_eval.py --show   (also prints every miss and false alarm)"""
import json
import sys
from pathlib import Path

import guard

BASE = Path(__file__).resolve().parent


def evaluate(path, show=False):
    data = json.loads((BASE / path).read_text())
    groups = [("user", "user_attacks", True), ("user", "user_benign", False),
              ("retrieved", "retrieved_attacks", True), ("retrieved", "retrieved_benign", False)]
    report, misses = {}, []
    for source, key, is_attack in groups:
        decisions = [guard.screen_input(t, source)["decision"] for t in data[key]]
        n = len(decisions)
        blocked = sum(d == "block" for d in decisions)
        flagged = sum(d in ("block", "review") for d in decisions)
        report[key] = {"n": n, "blocked": blocked, "blocked_or_review": flagged,
                       "block_rate": round(blocked / n, 3), "flag_rate": round(flagged / n, 3)}
        for t, d in zip(data[key], decisions):
            if (is_attack and d == "allow") or (not is_attack and d != "allow"):
                misses.append({"set": key, "decision": d, "text": t})
    attacks = report["user_attacks"]["n"] + report["retrieved_attacks"]["n"]
    benign = report["user_benign"]["n"] + report["retrieved_benign"]["n"]
    summary = {
        "attack_detection_rate (block or review)": round(
            (report["user_attacks"]["blocked_or_review"] + report["retrieved_attacks"]["blocked_or_review"]) / attacks, 3),
        "attack_block_rate": round((report["user_attacks"]["blocked"] + report["retrieved_attacks"]["blocked"]) / attacks, 3),
        "false_alarm_rate (benign flagged)": round(
            (report["user_benign"]["blocked_or_review"] + report["retrieved_benign"]["blocked_or_review"]) / benign, 3),
        "benign_wrongly_blocked_rate": round((report["user_benign"]["blocked"] + report["retrieved_benign"]["blocked"]) / benign, 3),
    }
    if show:
        for m in misses:
            print(f"  [{m['set']}] {m['decision']:6} | {m['text']}")
    return {"summary": summary, "by_set": report, "missed_or_false_alarm": misses, "note": data["note"]}


def run(show=False):
    out = {"guard_version": guard.GUARD_VERSION,
           "dev_set (rules were tuned on this)": evaluate("guard_eval_data.json", show),
           "holdout_set (never used for tuning)": evaluate("guard_holdout_data.json", show)}
    (BASE / "guard_evaluation.json").write_text(json.dumps(out, indent=2))
    for k, v in out.items():
        if isinstance(v, dict):
            print(k, json.dumps(v["summary"], indent=2))
    return out


if __name__ == "__main__":
    run(show="--show" in sys.argv)
