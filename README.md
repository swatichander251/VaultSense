# VaultSense: runnable datathon starter

This is a synthetic-data prototype, not a certified banking security product.

## Model Architecture

     frontend ──login / save data──▶ Supabase (auth, profiles, cards, transactions)
           │
           └──POST /score + user's Supabase token──▶ this API on LinuxONE (fraud model)

- The frontend never holds `VAULTSENSE_API_KEY`. It sends the logged-in user's Supabase access token;
  the API checks it with Supabase Auth before scoring.
- `VAULTSENSE_API_KEY` is still accepted for curl, the built-in demo page at `/`, and the admin-only `/audit`.
  

## Chatbot guard (prompt injection + AI-assisted attacks)

`guard.py` + the `/guard/input`, `/guard/output`, `/guard/action` endpoints protect a bank chatbot.
See **CHATBOT_GUARD.md** for the threats covered, the integration flow, a system-prompt template and
honest evaluation results (`python guard_eval.py --show`).

## Website 

| Page | What it does |
|---|---|
| `/` | Public home page: live demo chatbot with protection on/off, live threat feed, 50-attack simulator, same-prompt comparison. Synthetic data only, rate-limited (`/demo/*` endpoints). |
| `/login` | Supabase sign up / log in |
| `/dashboard` | The user's accounts, cards and transactions (read with their own login, Row Level Security) |
| `/assistant` | Bank assistant behind the guard; transfers need the Confirm button |
| `/security` | Admin-only threat dashboard from `guard_events` |
| `/lab` | Old API-key demo page |

The browser only ever gets the Supabase **anon** key (`/config.js`); the service_role key stays on the server.
In Supabase → Authentication → URL Configuration, set the Site URL to your HTTPS address.

## Real datasets (IBM TabFormer, ULB, PaySim, BAF) and simulated banks


`prepare_data.py` (TabFormer -> model features, leak-free), `train.py --csv` (live model, chronological split, age/income
fairness), `benchmarks.py ulb|paysim|baf` (rare events, transfer scams, BAF fairness), `federated.py` (4 simulated banks
sharing only aggregates). `/model` and `/results` expose the outcomes to the website; data never leaves the server.
`test_pipeline.py` runs the whole pipeline on fake files in each dataset's exact format.

## Demo bank chatbot + security dashboard

- `POST /chat` runs a demo bank assistant where every message, document, tool call and reply goes through the guard.
  `POST /chat/confirm` is the app's Confirm button for transfers/new payees (the AI can't press it).
- Works with no AI key (`LLM_PROVIDER=mock`), or set `LLM_PROVIDER=openai|anthropic` + `LLM_API_KEY` + `LLM_MODEL`.
- The page at `/` has a chat panel with a "Guard on" switch: turn it off to show the poisoned-email attack stealing $480.
- Guard events are written to Supabase `guard_events` (metadata only) when `SUPABASE_SERVICE_ROLE_KEY` is set.

## Supabase

Run these in order in the Supabase SQL editor (all safe to re-run):
1. `supabase_migration_0_base.sql` (profiles, cards, transactions; skip if you already ran the first setup script)
2. `supabase_migration.sql` (model columns, profile trigger, guard_events)
3. `supabase_migration_2_chatbot.sql` (demo accounts and payees, locked-down transfer functions, server-only fraud
   fields, security admins, dashboard views)

`bash db_tests/run.sh` runs 25 security tests against a throwaway local Postgres (e.g. customer A can't see B's
data, customers can't edit balances or fraud scores, only the server can move money).

## Training and datasets

The included model (logistic-v2) is logistic regression trained to convergence with Newton's method (pure Python)
on 7,000 synthetic records, split 60/20/20 into train / validation / test. Thresholds are chosen on the validation set by
false-positive budget, then measured on the untouched test set. Run `python train.py` to reproduce
(`--review-fpr 0.05` for a smaller review queue).

| Test set (1,401 rows, 61 fraud) | v1 | v2 review line (`threshold`) | v2 high-risk line (`high_threshold`) |
|---|---|---|---|
| Recall | 0.15 | 0.48 (95% CI 0.36-0.60) | 0.11 |
| Precision | 0.50 | 0.19 | 0.32 |
| False-positive rate | 0.6% | 9.0% | 1.1% |

The model's ROC-AUC (0.79) matches the ceiling set by the formula that generated the data (0.80), so on these five
features more recall can only come from a lower threshold, at the cost of more false alarms. Real gains need more
signals (device, login location, the customer's usual amounts, payee age). v1 also under-weighted amount by about 15x;
a $9,000 transfer to a new payee now scores 0.44 (high) instead of 0.05. `/score` returns `risk_level`
(low / review / high).


Required numeric CSV columns: amount,hour,international,new_payee,velocity_10m,age,is_fraud
Use amount in consistent monetary units; hour 0-23; binary values 0/1; age for evaluation only. Define velocity_10m as a count calculated using only earlier events for the same pseudonymous account. Do NOT invent unavailable attributes or derive them using future transactions. This starter does not include adapters or download TabFormer, ULB, PaySim or BAF. ULB's anonymized features do not directly fit this schema: use a separate feature pipeline/model. Age and income are not accepted by /score. Income fairness evaluation is not implemented. Synthetic age groups do not validate fairness on real populations. Differences in subgroup rates require sample-size/uncertainty analysis and legal review.

## What the API does

GET / : demo form
GET /health : explicitly states hardware protection is not verified
POST /score : authenticated (API key or Supabase user token) score, threshold decision, exact additive log-odds contributions, inference-only elapsed milliseconds
POST /guard/input, /guard/output, /guard/action : chatbot guard layers (see CHATBOT_GUARD.md)
POST /chat, /chat/confirm : demo bank chatbot behind the guard
POST /transactions/{id}/score : score a saved Supabase transaction; server writes the result
POST /guard/unlock : admin API key only; unlock a session after human review
GET /audit : admin API key only; last 1,000 volatile HMAC-linked event records

No full transaction features are intentionally written by the app to disk or audit records. Validation errors list only the invalid field names, not the submitted values; still use only synthetic input and review ingress and platform logs. Response data and alert metadata remain sensitive. Python does not guarantee memory zeroization; no code-only claim of encrypted memory is made. No TLS or attestation is implemented by the app; use the cloud HTTPS endpoint for this demo.

The HMAC chain can detect some changes only when a verifier has a trusted prior checkpoint and the secret remains secure. A privileged holder of the audit key can rewrite it. It is NOT tamper-proof, immutable storage, hardware attestation or proof that data was never exposed. Do not use the single shared demo key across multiple banks.

## IBM Z / LinuxONE seperate deployment:

Use the same API application in an IBM Secure Execution-enabled guest on supported IBM Z/LinuxONE infrastructure, with IBM's supported confidential-container tooling. Build an s390x-compatible image and validate dependencies. Example build only:
docker buildx build --platform linux/s390x -t YOUR_REGISTRY/vaultsense:z-demo --push .

An s390x image alone does not enable confidential computing. Obtain the supported platform from your datathon organizer/IBM. Configure encrypted deployment contracts, workload integrity verification/attestation, protected keys, TLS termination inside the protected boundary, protected storage, disabled swap/core dumps as appropriate, and restricted ingress/egress. Keep training, feature engineering and inference within the approved boundary if they handle real bank data. The health endpoint deliberately remains false until an actual verification mechanism is implemented; never replace verification with an environment flag.

IBM Cloud Hyper Protect Virtual Servers for VPC is deprecated: no new instances after 28 February 2026; existing instances supported until 20 February 2027. Do not plan a new deployment around that service. IBM Confidential Computing Container Runtime / Platform on supported infrastructure is a separate deployment route to discuss with IBM.

No federated learning, secure aggregation, differential privacy, regulator access, customer notifications or real banking integration is implemented. Sharing model updates is not automatically private. Add these only with an explicit threat model and privacy controls. Alert explanations are predictive, not proof of fairness or causation; compliance needs jurisdiction-specific assessment.

## Official documentation

https://cloud.ibm.com/docs/codeengine?topic=codeengine-cli
https://cloud.ibm.com/docs/codeengine?topic=codeengine-secret
https://www.ibm.com/products/confidential-computing-container-runtime
https://www.ibm.com/docs/en/linux-on-systems?topic=execution-introduction
https://cloud.ibm.com/docs/vpc?topic=vpc-financial-transaction-confidential-computing-on-hyper-protect-virtual-server-for-vpc
