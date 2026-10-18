# Lovable prompts for VaultSense

Replace `API_URL` with your HTTPS tunnel URL (e.g. `https://xxxx.trycloudflare.com`).
Send these one at a time and check each page works before sending the next.

---

## 1. Chat page (customer assistant)

```
Add a "Assistant" page (route /assistant, signed-in users only) with a chat UI for the VaultSense bank assistant.

Backend: our existing API at API_URL. Do NOT create a Supabase edge function or any other backend for this.
Put API_URL in one config constant.

Sending a message:
- POST {API_URL}/chat
- headers: Content-Type: application/json, Authorization: Bearer <the signed-in user's Supabase access token from supabase.auth.getSession()>
- body: { "session_id": <a random id generated when the chat opens, kept until "New chat">, "message": <text> }
- response: { reply: string, guard: Array<{layer, decision, doc?, action?, initiated_by?, rules?, reasons?}>, pending_actions: Array<{pending_id, summary, fraud_score}>, blocked_documents: string[] }

Show:
- Customer messages on the right, assistant replies on the left. Render replies as plain text (not HTML or markdown).
- Under each assistant reply, a row of small chips, one per item in `guard`:
  label = layer "input" -> "Message", "document" -> "Doc: {doc}", "action" -> "Action: {action}", "output" -> "Reply";
  then " → {decision}". Colors: allow = green; review, redact, require_confirmation, human_review = amber; block, deny = red.
  Tooltip on hover shows the rules and reasons joined by line breaks.
- For each item in `pending_actions`, a button "Confirm: {summary}". On click:
  POST {API_URL}/chat/confirm with the same headers and body { session_id, pending_id }.
  If response.status == "done" show a green success message and refresh balances; otherwise show the status and reasons in amber.
- A small shield badge in the header: "Protected by VaultSense Guard".
- Suggested prompts as clickable chips above the input: "What's my balance?", "Show my recent transactions",
  "Transfer $50 from checking to savings", "My card was stolen", "Summarize the latest rate change email".
- A "New chat" button that clears messages and makes a new session_id.
- Show a friendly error if the API is unreachable.
```

## 2. Security dashboard (admins only)

```
Add a "Security" page (route /security) for security admins.

Access: call supabase.rpc('is_security_admin'). If it returns false, show "You don't have access to this page"
and nothing else. Only show the "Security" link in the nav for admins.

Data comes straight from Supabase (no external API). Use these read-only views (RLS already restricts them to admins):
- guard_daily (day, layer, decision, events)
- guard_top_rules (rule, hits, last_seen)
- guard_recent_threats (created_at, layer, source, decision, risk_score, rules, session_hash, event_id)
and the table guard_events for totals.

Layout:
1. Four stat cards for the last 7 days: Total checks, Blocked (decision = block or deny), Needs review (review, human_review,
   require_confirmation), Redacted replies (redact).
2. Stacked bar chart of guard_daily for the last 14 days: x = day, stacked by decision (same colors as the chat chips).
3. Horizontal bar chart of the top 10 rows of guard_top_rules ordered by hits. Show rule names in plain English using this map:
   instruction_override / instruction_override_2 = "Tried to override instructions", role_hijack = "Jailbreak / role change",
   prompt_extraction = "Tried to steal system prompt", fake_delimiter = "Fake system message",
   other_customers_data / bulk_or_third_party_data = "Asked for other customers' data",
   exfil_markdown / exfil_send = "Data exfiltration attempt", hidden_unicode_tags / zero_width_chars / base64_payload /
   spaced_letters / unicode_lookalikes = "Hidden or obfuscated text", authority_claim = "Fake authority",
   credential_request = "Credential request", card_number / ssn / account_number = "Sensitive data in reply",
   canary_leak / prompt_fragment_leak = "System prompt leak", addressed_to_ai = "Document talking to the AI",
   bypass_verification = "Tried to skip verification", session_locked = "Locked session".
   Anything starting with "combo:" -> "Combined attack signals". Unknown -> show as-is.
4. Table of guard_recent_threats (newest first, 50 rows): time, layer, source, decision badge, risk score (0-1 as a bar),
   rules (as chips using the same plain-English map), session_hash.
5. Auto-refresh every 30 seconds, plus a Refresh button.
```

## 3. Make yourself a security admin

Run in Supabase SQL editor (use the email you sign in with):

```sql
insert into security_admins (user_id)
select id from auth.users where email = 'you@example.com'
on conflict do nothing;
```

## 4. (Optional) Add-transaction page uses server scoring

If you have an "Add transaction" page, change it so that after inserting the row it calls:

```
POST {API_URL}/transactions/{new_row_id}/score  with Authorization: Bearer <user access token>
```

and then re-fetches the row. Customers can no longer write fraud_score themselves (the database ignores it);
only this server call can set it.

---

## 5. Model & research page (shows the real-dataset results)

Run `DATA_RUNBOOK.md` on the server first; until then this page shows the synthetic demo model.

```
Add a "How VaultSense performs" page (route /research, signed-in users) that shows our model and dataset results.
Data comes from our API (API_URL), with the signed-in user's Supabase access token as Authorization: Bearer <token>:
- GET {API_URL}/model   -> { version, trained_on, trained_at, split, threshold, high_threshold, features[], test_summary: { recall, false_positive_rate, roc_auc, test_fraud_cases } }
- GET {API_URL}/results -> an object that may contain any of these keys (show a section only if its key exists):
    tabformer_live_model, ulb, paysim, baf_fairness, simulated_banks
Never upload or display raw transaction data on this page.

Sections:
1. "Live model" card: trained_on, trained_at, split, and three big numbers from test_summary:
   "Fraud caught" (recall as %), "Legit transactions flagged" (false_positive_rate as %), "Ranking score" (roc_auc).
   Under it, the 5 features as chips.
2. "Datasets" table, one row per available dataset:
   - IBM TabFormer (tabformer_live_model): test.roc_auc, test.pr_auc, test.review_operating_point.recall, .false_positive_rate
   - Kaggle ULB (ulb): test.roc_auc, test.pr_auc, and recall from the first entry of operating_points
   - PaySim (paysim): same as ULB
   Columns: Dataset, What it tests, ROC-AUC, PR-AUC, Recall, False-positive rate. Use "—" when missing.
   What it tests: TabFormer "Card transactions (live model)", ULB "Rare fraud (0.17%)", PaySim "Transfer & cash-out scams".
3. "Fairness" section:
   - From baf_fairness.fairness_at_first_operating_point.age and .income: grouped bar chart of false_positive_rate per group,
     plus a badge with fpr_ratio_min_over_max: green if >= 0.8 ("Within the 0.8 fairness bar"), amber otherwise ("Below the 0.8 bar").
   - From tabformer_live_model.fairness_at_review_threshold (age, income): the same chart, titled "Live model".
   - One line of text: "Age and income are never inputs to the model. We only use them to check that false alarms are spread fairly."
4. "Simulated banks" section from simulated_banks:
   - Table: one row per item in banks[]: Bank (bank), Transactions, Fraud cases, "Alone" (local_only.recall),
     "Sharing patterns" (shared_model.recall), "All data pooled" (pooled_raw_data.recall). Show recalls as %.
     If local_only is a string, show it as text.
   - Two stat cards: "Numbers shared" (numbers_shared_total) vs "Values kept private" (raw_values_that_stayed_private).
   - If shared_model_equals_pooled_max_weight_difference is below 0.000001, show a green note:
     "The shared model is identical to training on everyone's data, without any bank sharing a single transaction."
5. Footnote with each section's `note` field in small grey text.
Handle API errors with a friendly message.
```
