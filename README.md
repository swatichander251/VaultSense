# VaultSense: runnable datathon starter

This is a synthetic-data prototype, not a certified banking security product.

## Local quick start (Python 3.11+, Bash)

python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export VAULTSENSE_API_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')
export VAULTSENSE_AUDIT_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')
uvicorn app:app --host 127.0.0.1 --port 8080 --no-access-log

Open http://localhost:8080. In another shell with the same API key:

curl http://localhost:8080/score -H "Authorization: Bearer $VAULTSENSE_API_KEY" -H 'Content-Type: application/json' -d '{"amount":1800,"hour":2,"international":1,"new_payee":1,"velocity_10m":18}'

The browser token stays in the page input, not localStorage. Use synthetic data only. Never expose the local HTTP server to public traffic.

## IBM Cloud connection / deployment

Prerequisites: IBM Cloud account, CLI installed, permissions and a resource group, billing approval as applicable. Run from the extracted project directory. These commands create potentially billable resources; they have NOT been run by this project author.

ibmcloud login
ibmcloud target -r us-south -g YOUR_RESOURCE_GROUP
ibmcloud plugin install code-engine
ibmcloud ce project create --name vaultsense-demo
ibmcloud ce project select --name vaultsense-demo

Generate the two secrets as in local quick start, then:

ibmcloud ce secret create --name vaultsense-secrets --from-literal VAULTSENSE_API_KEY="$VAULTSENSE_API_KEY" --from-literal VAULTSENSE_AUDIT_KEY="$VAULTSENSE_AUDIT_KEY"
ibmcloud ce application create --name vaultsense --build-source . --build-strategy dockerfile --port 8080 --env-from-secret vaultsense-secrets --min-scale 1 --max-scale 1
ibmcloud ce application get --name vaultsense

Use the HTTPS application URL printed by IBM Cloud. The UI and /score endpoint are on this server. Do not place an IBM Cloud IAM key in the UI. The application bearer token is separate from the IBM Cloud login. Secret values passed on the command line may be visible to local privileged users; use a trusted workstation. For production use managed identity, per-bank authorization, rate limits and managed secret rotation.

Code Engine is the functional demo host, NOT evidence of IBM Z Secure Execution. A successful deployment does not verify confidential computing. Minimum scale one reduces cold starts but can incur continuous charges. Audit records are ephemeral and reset on restart; max scale one does not make them durable.

## Training and datasets

The included model is trained with pure-Python stochastic-gradient logistic regression on 7,000 generated synthetic records. Run python train.py to reproduce. The test split contains 1,400 records. Read evaluation.json: recall is low at the illustrative 0.25 threshold. This is an honest baseline, not a competitive fraud detector. Threshold selection should use a separate validation set, then evaluate on a held-out chronological test set. Report PR-AUC, recall at a fixed false-positive rate, cost-weighted errors and measured p50/p95/p99 end-to-end latency.

To bring your own dataset:
python train.py --csv normalized.csv

Required numeric CSV columns: amount,hour,international,new_payee,velocity_10m,age,is_fraud
Use amount in consistent monetary units; hour 0-23; binary values 0/1; age for evaluation only. Define velocity_10m as a count calculated using only earlier events for the same pseudonymous account. Do NOT invent unavailable attributes or derive them using future transactions. This starter does not include adapters or download TabFormer, ULB, PaySim or BAF. ULB's anonymized features do not directly fit this schema: use a separate feature pipeline/model. Age and income are not accepted by /score. Income fairness evaluation is not implemented. Synthetic age groups do not validate fairness on real populations. Differences in subgroup rates require sample-size/uncertainty analysis and legal review.

## What the API does

GET / : demo form
GET /health : explicitly states hardware protection is not verified
POST /score : authenticated score, threshold decision, exact additive log-odds contributions, inference-only elapsed milliseconds
GET /audit : authenticated last 1,000 volatile HMAC-linked event records

No full transaction features are intentionally written by the app to disk or audit records. Pydantic error responses can include invalid submitted values; use only synthetic input, suppress/transform validation detail before production, and review ingress and platform logs. Response data and alert metadata remain sensitive. Python does not guarantee memory zeroization; no code-only claim of encrypted memory is made. No TLS or attestation is implemented by the app; use the cloud HTTPS endpoint for this demo.

The HMAC chain can detect some changes only when a verifier has a trusted prior checkpoint and the secret remains secure. A privileged holder of the audit key can rewrite it. It is NOT tamper-proof, immutable storage, hardware attestation or proof that data was never exposed. Do not use the single shared demo key across multiple banks.

## IBM Z / LinuxONE confidential deployment: separate next stage

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
