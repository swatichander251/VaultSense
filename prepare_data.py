"""Turn IBM TabFormer card transactions into VaultSense's 5 model features.

Input  (Kaggle "ealtman2019/credit-card-transactions", or IBM/TabFormer on GitHub):
  credit_card_transactions-ibm_v2.csv  (or card_transaction.v1.csv)
    User,Card,Year,Month,Day,Time,Amount,Use Chip,Merchant Name,Merchant City,Merchant State,Zip,MCC,Errors?,Is Fraud?
  sd254_users.csv  (optional; row i = User i; gives birth year and income for the fairness check)

Output: one CSV with
  amount,hour,international,new_payee,velocity_10m,is_fraud,age,income,bank_id,user,timestamp

Leak-free features: "new payee" and "transactions in the last 10 minutes" are computed only
from that card holder's EARLIER transactions, never later ones. Streams the file, so 24M rows
need little memory; --max-users keeps a random subset of card holders (full histories).

Usage:
  python prepare_data.py tabformer --transactions data/credit_card_transactions-ibm_v2.csv \
      --users data/sd254_users.csv --out data/tabformer_prepared.csv --max-users 400 --banks 4
"""
import argparse
import csv
import random
import sys
from collections import deque
from datetime import datetime, timezone

US_STATES = set("""AL AK AZ AR CA CO CT DE FL GA HI ID IL IN IA KS KY LA ME MD MA MI MN MS MO MT NE NV NH NJ NM NY
NC ND OH OK OR PA RI SC SD TN TX UT VT VA WA WV WI WY DC PR GU VI AS MP AA AE AP""".split())
OUT_COLS = ["amount", "hour", "international", "new_payee", "velocity_10m", "is_fraud", "age", "income",
            "bank_id", "user", "timestamp"]
# Uneven bank sizes, like a real market: one large bank, one medium, two small.
BANK_SHARES = [0.45, 0.30, 0.15, 0.10]


def money(s):
    s = (s or "").strip().replace("$", "").replace(",", "")
    return float(s) if s else 0.0


def bank_for(user, n_banks, seed=7):
    """Stable assignment of a card holder to a simulated bank."""
    r = random.Random(f"{seed}:{user}").random()
    shares = BANK_SHARES[:n_banks] if n_banks <= len(BANK_SHARES) else [1 / n_banks] * n_banks
    total, acc = sum(shares), 0.0
    for i, s in enumerate(shares):
        acc += s / total
        if r < acc:
            return i
    return n_banks - 1


def load_users(path):
    """Returns {user_index: (birth_year, yearly_income)}. Column names matched loosely."""
    out = {}
    with open(path, newline="", encoding="utf-8-sig") as f:
        rd = csv.DictReader(f)
        cols = rd.fieldnames or []
        by = next((c for c in cols if c.lower().replace(" ", "") == "birthyear"), None)
        inc = next((c for c in cols if "yearly income" in c.lower()), None)
        if not by:
            sys.exit(f"users file: no 'Birth Year' column in {cols}")
        for i, row in enumerate(rd):
            out[i] = (int(float(row[by])), money(row[inc]) if inc else None)
    return out


def tabformer(args):
    users = load_users(args.users) if args.users else {}
    rng = random.Random(args.seed)
    keep, kept = {}, 0
    state = {}  # user -> {"times": deque, "merchants": set, "last": ts}
    written = frauds = out_of_order = skipped = 0

    with open(args.transactions, newline="", encoding="utf-8-sig") as f, open(args.out, "w", newline="") as g:
        rd = csv.DictReader(f)
        need = {"User", "Year", "Month", "Day", "Time", "Amount", "Merchant Name", "Merchant State", "Is Fraud?"}
        missing = need - set(rd.fieldnames or [])
        if missing:
            sys.exit(f"transactions file is missing columns: {sorted(missing)}. Found: {rd.fieldnames}")
        wr = csv.writer(g)
        wr.writerow(OUT_COLS)
        for n, row in enumerate(rd, 1):
            user = int(row["User"])
            if user not in keep:  # decide once per card holder, with a fixed seed: same users every run
                keep[user] = (args.max_users is None or kept < args.max_users) and rng.random() < args.user_fraction
                kept += keep[user]
            if not keep[user]:
                continue
            try:
                hh, mm = row["Time"].split(":")
                year = int(row["Year"])
                ts = int(datetime(year, int(row["Month"]), int(row["Day"]), int(hh), int(mm),
                                  tzinfo=timezone.utc).timestamp())
            except (ValueError, KeyError):
                skipped += 1
                continue
            if args.since_year and year < args.since_year:
                continue

            st = state.setdefault(user, {"times": deque(), "merchants": set(), "last": None})
            if st["last"] is not None and ts < st["last"]:
                out_of_order += 1
            st["last"] = ts if st["last"] is None else max(st["last"], ts)

            # Earlier transactions only:
            times = st["times"]
            while times and ts - times[0] > 600:
                times.popleft()
            velocity = len(times)
            merchant = row["Merchant Name"]
            new_payee = int(merchant not in st["merchants"])

            state_col = (row.get("Merchant State") or "").strip()
            international = int(bool(state_col) and state_col.upper() not in US_STATES)
            is_fraud = int(row["Is Fraud?"].strip().lower() in ("yes", "1", "true"))
            birth, income = users.get(user, (None, None))
            age = (year - birth) if birth else ""

            wr.writerow([money(row["Amount"]), int(hh), international, new_payee, velocity, is_fraud,
                         age, "" if income is None else income, bank_for(user, args.banks), user, ts])
            written += 1
            frauds += is_fraud
            times.append(ts)
            st["merchants"].add(merchant)
            if n % 1_000_000 == 0:
                print(f"  read {n:,} rows, kept {written:,} ...", flush=True)

    print(f"Wrote {written:,} transactions ({frauds:,} fraud, {frauds / max(written, 1):.3%}) "
          f"from {len(state):,} card holders to {args.out}")
    if skipped:
        print(f"Skipped {skipped:,} rows with unreadable dates/times")
    if out_of_order:
        print(f"WARNING: {out_of_order:,} rows were earlier than a previous row for the same user. Sort the file by "
              f"User, Year, Month, Day, Time first, or 'transactions in the last 10 minutes' will be off.")


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("tabformer", help="IBM TabFormer card transactions -> model features")
    t.add_argument("--transactions", required=True)
    t.add_argument("--users", help="sd254_users.csv (optional, adds age/income for fairness checks)")
    t.add_argument("--out", default="data/tabformer_prepared.csv")
    t.add_argument("--max-users", type=int, default=400,
                   help="Keep at most this many card holders (0 = all ~2,000; all = ~24M rows, needs lots of RAM to train)")
    t.add_argument("--user-fraction", type=float, default=0.25,
                   help="Chance each card holder is kept until --max-users is reached")
    t.add_argument("--since-year", type=int, default=0, help="Drop transactions before this year (e.g. 2010)")
    t.add_argument("--banks", type=int, default=4, help="Number of simulated banks to assign card holders to")
    t.add_argument("--seed", type=int, default=42)
    args = p.parse_args(argv)
    if args.cmd == "tabformer":
        if args.max_users == 0:
            args.max_users, args.user_fraction = None, 1.0
        tabformer(args)


if __name__ == "__main__":
    main()
