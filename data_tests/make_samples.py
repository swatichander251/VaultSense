"""Small FAKE files in the exact formats of the real datasets, used only to test the pipeline.
Numbers produced from these samples mean nothing; run the real data for real results.

python data_tests/make_samples.py data_tests/samples
"""
import csv
import math
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

out = Path(sys.argv[1] if len(sys.argv) > 1 else "data_tests/samples")
out.mkdir(parents=True, exist_ok=True)
rng = random.Random(1)

# ---------------------------------------------------------------- TabFormer (+ users)
users = 60
with open(out / "sd254_users.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["Person", "Current Age", "Retirement Age", "Birth Year", "Birth Month", "Gender", "Address", "Apartment",
                "City", "State", "Zipcode", "Latitude", "Longitude", "Per Capita Income - Zipcode",
                "Yearly Income - Person", "Total Debt", "FICO Score", "Num Credit Cards"])
    for u in range(users):
        by = rng.randint(1935, 2000)
        w.writerow([f"Person {u}", 2020 - by, 67, by, rng.randint(1, 12), rng.choice(["Male", "Female"]), "1 Main St", "",
                    "Dallas", "TX", 75080, 32.9, -96.7, "$29278", f"${rng.randint(15000, 150000)}", "$1000", 700, 3])

with open(out / "credit_card_transactions-ibm_v2.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["User", "Card", "Year", "Month", "Day", "Time", "Amount", "Use Chip", "Merchant Name", "Merchant City",
                "Merchant State", "Zip", "MCC", "Errors?", "Is Fraud?"])
    for u in range(users):
        t = datetime(2015, 1, 1) + timedelta(minutes=rng.randint(0, 10000))
        regulars = [str(rng.randint(-9 * 10**18, 9 * 10**18)) for _ in range(6)]
        for i in range(rng.randint(150, 400)):
            fraud_burst = rng.random() < 0.01
            for j in range(rng.randint(3, 6) if fraud_burst else 1):
                t += timedelta(minutes=rng.randint(1, 4)) if fraud_burst else timedelta(hours=rng.randint(2, 60))
                if fraud_burst:
                    amt, merch = rng.uniform(50, 2500), str(rng.randint(-9 * 10**18, 9 * 10**18))
                    st = rng.choice(["Italy", "Mexico", "CA", "NY", ""])
                else:
                    amt, merch, st = rng.expovariate(1 / 60), rng.choice(regulars), rng.choice(["TX", "TX", "OK", ""])
                if rng.random() < 0.03:
                    amt = -amt  # refund
                w.writerow([u, 0, t.year, t.month, t.day, t.strftime("%H:%M"), f"${amt:.2f}",
                            "Online Transaction" if st == "" else rng.choice(["Chip Transaction", "Swipe Transaction"]),
                            merch, "ONLINE" if st == "" else "Dallas", st, "" if st == "" else "75080.0",
                            5411, "", "Yes" if fraud_burst else "No"])

# ---------------------------------------------------------------- PaySim
with open(out / "PS_20174392719_1491204439457_log.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["step", "type", "amount", "nameOrig", "oldbalanceOrg", "newbalanceOrig", "nameDest", "oldbalanceDest",
                "newbalanceDest", "isFraud", "isFlaggedFraud"])
    for i in range(6000):
        step = rng.randint(1, 743)
        typ = rng.choice(["PAYMENT", "CASH_IN", "CASH_OUT", "TRANSFER", "DEBIT"])
        bal = rng.uniform(0, 50000)
        fraud = typ in ("TRANSFER", "CASH_OUT") and rng.random() < 0.03
        amt = bal if fraud else rng.uniform(1, min(bal, 5000) + 1)
        new = max(bal - amt, 0) if typ != "CASH_IN" else bal + amt
        dold = rng.uniform(0, 1e5)
        w.writerow([step, typ, f"{amt:.2f}", f"C{rng.randint(10**8, 10**9)}", f"{bal:.2f}", f"{new:.2f}",
                    ("M" if typ == "PAYMENT" else "C") + str(rng.randint(10**8, 10**9)), f"{dold:.2f}",
                    f"{dold if fraud else dold + amt:.2f}", int(fraud), 0])

# ---------------------------------------------------------------- ULB credit card
with open(out / "creditcard.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["Time"] + [f"V{i}" for i in range(1, 29)] + ["Amount", "Class"])
    for i in range(8000):
        fraud = rng.random() < 0.01
        vs = [rng.gauss(-2.5 if fraud and k in (3, 9, 13) else 0, 1) for k in range(1, 29)]
        w.writerow([i * 20, *[f"{v:.6f}" for v in vs], f"{rng.expovariate(1 / 80):.2f}", int(fraud)])

# ---------------------------------------------------------------- BAF (Base.csv)
cols = ["fraud_bool", "income", "name_email_similarity", "prev_address_months_count", "current_address_months_count",
        "customer_age", "days_since_request", "intended_balcon_amount", "payment_type", "zip_count_4w", "velocity_6h",
        "velocity_24h", "velocity_4w", "bank_branch_count_8w", "date_of_birth_distinct_emails_4w", "employment_status",
        "credit_risk_score", "email_is_free", "housing_status", "phone_home_valid", "phone_mobile_valid",
        "bank_months_count", "has_other_cards", "proposed_credit_limit", "foreign_request", "source",
        "session_length_in_minutes", "device_os", "keep_alive_session", "device_distinct_emails_8w",
        "device_fraud_count", "month"]
with open(out / "Base.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(cols)
    for i in range(10000):
        age = rng.choice([10, 20, 30, 40, 50, 60, 70, 80, 90])
        z = -4.5 + 0.02 * (age - 40) + rng.gauss(0, 1)
        fraud = int(rng.random() < 1 / (1 + math.exp(-z)))
        w.writerow([fraud, rng.choice([0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]),
                    round(rng.random() - 0.3 * fraud, 4), rng.choice([-1, rng.randint(1, 300)]), rng.randint(-1, 400),
                    age, round(rng.expovariate(1), 4), round(rng.gauss(10, 20), 3), rng.choice(["AA", "AB", "AC", "AD", "AE"]),
                    rng.randint(0, 6000), round(rng.uniform(0, 16000), 2), round(rng.uniform(1000, 9000), 2),
                    round(rng.uniform(2800, 7000), 2), rng.randint(0, 2400), rng.randint(0, 39) + 5 * fraud,
                    rng.choice(["CA", "CB", "CC", "CD", "CE", "CF", "CG"]), rng.randint(-150, 380) + 40 * fraud,
                    rng.randint(0, 1), rng.choice(["BA", "BB", "BC", "BD", "BE", "BF", "BG"]), rng.randint(0, 1),
                    rng.randint(0, 1), rng.randint(-1, 32), rng.randint(0, 1), rng.choice([200, 500, 1000, 1500, 2000]),
                    int(rng.random() < 0.03 + 0.1 * fraud), rng.choice(["INTERNET", "TELEAPP"]),
                    round(rng.expovariate(1 / 8), 3), rng.choice(["windows", "linux", "macintosh", "x11", "other"]),
                    rng.randint(0, 1), rng.randint(0, 2), 0, rng.randint(0, 7)])
print(f"Wrote sample files to {out}/")
