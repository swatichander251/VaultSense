# VaultSense data runbook: from the datathon datasets to a live model

Everything below runs **on the LinuxONE server** (`ssh` in, then `cd /srv/project`). Data never goes through
Lovable or anyone's laptop. Lovable only shows the results afterwards.

| Dataset (from our submission) | Script | What it proves | Output |
|---|---|---|---|
| IBM TabFormer (24M card transactions) | `prepare_data.py` then `train.py` | Trains the **live** model the API, chatbot and app use | `model.json`, `evaluation.json` |
| IBM TabFormer, split into 4 banks | `federated.py` | Banks learn together sharing only aggregates, never customer data | `results/federated.json` |
| Kaggle ULB (284K, 0.17% fraud) | `benchmarks.py ulb` | Rare-event detection | `results/ulb.json` |
| PaySim (6.3M mobile money) | `benchmarks.py paysim` | Transfer and cash-out scams | `results/paysim.json` |
| Feedzai BAF (1M account openings) | `benchmarks.py baf` | Fairness: false-alarm rates by age and income | `results/baf.json` |

Time needed: about 1 hour, mostly downloads.

---

## Step 0: Update the code and install training tools

```bash
cd /srv/project
git pull
source .venv/bin/activate          # if you use the venv from setup; skip if not
pip install -r requirements-dev.txt   # adds numpy + pytest (training only; the API doesn't need numpy)
python -m pytest -q test_app.py test_pipeline.py   # should say "42 passed"
df -h .                             # need ~6 GB free for all datasets
```

If `pip install numpy` tries to compile and fails on LinuxONE, install the system package instead:
`sudo dnf install python3-numpy` (RHEL) or `sudo apt install python3-numpy` (Ubuntu), then recreate the venv with
`python3 -m venv --system-site-packages .venv`.

## Step 1: Kaggle access (one time)

1. On kaggle.com: sign in → your profile picture → **Settings** → **API** → **Create New Token**. It downloads `kaggle.json`.
2. On the server:
```bash
pip install kaggle
mkdir -p ~/.kaggle && nano ~/.kaggle/kaggle.json   # paste the file's contents, save
chmod 600 ~/.kaggle/kaggle.json
```
Never commit `kaggle.json` to GitHub.

## Step 2: Download the four datasets

```bash
mkdir -p data && cd data
kaggle datasets download -d ealtman2019/credit-card-transactions --unzip     # IBM TabFormer (~2.3 GB)
kaggle datasets download -d mlg-ulb/creditcardfraud --unzip                  # ULB  -> creditcard.csv
kaggle datasets download -d ealaxi/paysim1 --unzip                           # PaySim -> PS_2017...log.csv
kaggle datasets download -d sgpjesus/bank-account-fraud-dataset-neurips-2022 -f Base.csv   # BAF (only the base file)
unzip -o Base.csv.zip 2>/dev/null; ls -lh
cd ..
```
If a dataset ID says "not found", search the dataset name on kaggle.com and copy the ID from its URL.
TabFormer is also on IBM's GitHub (`IBM/TabFormer`, file `card_transaction.v1.csv`); that copy has no users file,
so the age/income fairness check is skipped for it.

Add `data/` to `.gitignore` (it already ignores `.env`): `echo "data/" >> .gitignore`. Datasets don't go in the repo.

## Step 3: IBM TabFormer → the live model

```bash
# 3a. Turn transactions into the model's 5 features (~10 min for all 24M rows; streams, low memory)
python prepare_data.py tabformer \
  --transactions data/credit_card_transactions-ibm_v2.csv \
  --users data/sd254_users.csv \
  --out data/tabformer_prepared.csv --max-users 400 --banks 4

# 3b. Train (chronological split: trains on older years, tests on the newest)
cp model.json model.synthetic.json && cp evaluation.json evaluation.synthetic.json   # keep the demo model
python train.py --csv data/tabformer_prepared.csv --name "IBM TabFormer (400 card holders)"
```
`--max-users 400` keeps about 1 in 5 card holders with their full histories (roughly 5M transactions). If the server
runs out of memory, use `--max-users 200` or add `--since-year 2010`. Use `--max-users 0` for everyone if RAM allows.
Write down the printed recall, false-positive rate and fairness numbers.

## Step 4: Simulated banks (pattern sharing without data sharing)

```bash
python federated.py --csv data/tabformer_prepared.csv            # exact sharing (same model as pooling)
cp results/federated.json results/federated_exact.json
python federated.py --csv data/tabformer_prepared.csv --noise 5   # extra privacy noise: see the trade-off
python federated.py --csv data/tabformer_prepared.csv            # run exact again so the website shows it
```
What to say: "Each bank kept its transactions private and shared only a few dozen numbers per round, and the shared
model was identical to one trained on everyone's data. Smaller banks gained the most."
Only say that if your printed table shows it. It depends on the data.

## Step 5: The three benchmarks

```bash
python benchmarks.py ulb    --csv data/creditcard.csv
python benchmarks.py paysim --csv data/PS_20174392719_1491204439457_log.csv --sample 0.3
python benchmarks.py baf    --csv data/Base.csv
```
- ULB: quote **PR-AUC**, not ROC-AUC (ROC-AUC always looks high when fraud is rare).
- PaySim: very high scores are normal; its balance columns make fraud easy to spot. Say so if asked.
- BAF: look at `fpr_ratio_min_over_max` for age and income. 1.0 = equal false-alarm rates; the BAF paper uses 0.8 as
  a common fairness bar. Report what you get, even if it's below 0.8. That's the point of the check.

## Step 6: Restart the API so it serves the new model

```bash
tmux attach -t vaultsense        # or whatever your session is called
# Ctrl+C to stop the server, then start it again the same way you did before, e.g.:
set -a; source .env; set +a
uvicorn app:app --host 0.0.0.0 --port 8000 --no-access-log
# detach: Ctrl+B then D
curl -s localhost:8000/model -H "Authorization: Bearer $VAULTSENSE_API_KEY"   # should show trained_on: IBM TabFormer
```

## Step 7: Show it on the website (Lovable)

Paste prompt 5 ("Model & research page") from `LOVABLE_PROMPTS.md`. It reads `/model` and `/results` from the API.
No data is uploaded to Lovable.

## Step 8: Commit the results (not the data)

```bash
git add model.json evaluation.json results/*.json
git commit -m "Train live model on IBM TabFormer; add benchmark, fairness and simulated-bank results"
git push
```

## If something goes wrong

| Message | Fix |
|---|---|
| `missing columns [...]` | The file has different headers. Run `head -1 <file>` and send it to the team / Claude. |
| `WARNING: ... earlier than a previous row` | Sort the TabFormer file by user and time first: `(head -1 f.csv && tail -n +2 f.csv \| sort -t, -k1,1n -k3,3n -k4,4n -k5,5n -k6,6) > sorted.csv` |
| `Killed` during training | Out of memory: lower `--max-users`, or `--sample 0.2` for benchmarks. |
| `Need at least 100 rows and 10 fraud cases` | Too few users kept; raise `--max-users`. |
| Recall looks worse than on synthetic data | Expected and honest: real patterns are harder. Report it with the 95% interval. |
