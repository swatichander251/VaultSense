\set ON_ERROR_STOP 1
insert into auth.users (id, email) values ('00000000-0000-0000-0000-00000000000a','a@x.com'),('00000000-0000-0000-0000-00000000000b','b@x.com');
insert into cards (user_id, brand, last4) values ('00000000-0000-0000-0000-00000000000a','Visa','4417'),('00000000-0000-0000-0000-00000000000b','Visa','9999');
insert into guard_events (layer, decision, rules) values ('input','block','{instruction_override}'),('output','redact','{card_number}');
select 'T1 signup created demo accounts: ' || count(*) from accounts;  -- expect 4

-- ---- act as customer A
set role authenticated; set request.jwt.claim.sub = '00000000-0000-0000-0000-00000000000a'; set request.jwt.claim.role = 'authenticated';
select 'T2 A sees only own accounts: ' || count(*) from accounts;           -- expect 2
with u as (update accounts set balance = 999999 returning 1) select 'T3 A balance edit rows changed (expect 0): ' || count(*) from u;
insert into transactions (user_id, amount, merchant, fraud_score, flagged) values ('00000000-0000-0000-0000-00000000000a', 50, 'Shop', 0.0, false);
update transactions set fraud_score = 0.01 where merchant = 'Shop';
select 'T4 A cannot set own fraud_score (expect null): ' || coalesce(fraud_score::text,'null') from transactions where merchant='Shop';
select 'T5 A sees guard events (expect 0): ' || count(*) from guard_events;
select 'T6 A sees dashboard view (expect 0): ' || count(*) from guard_recent_threats;
do $$ begin
  perform public.perform_transfer('00000000-0000-0000-0000-00000000000a','checking','savings',1);
  raise exception 'FAIL T7: customer could call perform_transfer';
exception when insufficient_privilege then raise notice 'T7 customer blocked from perform_transfer: OK'; end $$;
do $$ begin
  insert into security_admins values ('00000000-0000-0000-0000-00000000000a');
  raise exception 'FAIL T8: customer made self admin';
exception when insufficient_privilege then raise notice 'T8 customer cannot make self admin: OK'; end $$;
do $$ begin
  insert into accounts (user_id, kind, balance) values ('00000000-0000-0000-0000-00000000000a','checking',1e9);
  raise exception 'FAIL T9';
exception when insufficient_privilege or unique_violation then raise notice 'T9 customer cannot create money: OK'; end $$;
select 'T10 A cannot see B cards (expect 1 own): ' || count(*) from cards;
reset role;

-- ---- act as the server (service_role)
set role service_role; set request.jwt.claim.role = 'service_role'; set request.jwt.claim.sub = '';
select 'T11 transfer ok: ' || (public.perform_transfer('00000000-0000-0000-0000-00000000000a','checking','savings',100, 0.12, false, null, 'evt1', 'v1') is not null);
select 'T12 balances after (expect 2400/8100): ' || string_agg(kind||'='||balance, ' ' order by kind) from accounts where user_id='00000000-0000-0000-0000-00000000000a';
do $$ begin
  perform public.perform_transfer('00000000-0000-0000-0000-00000000000a','checking','savings',1000000);
  raise exception 'FAIL T13';
exception when others then if sqlerrm like '%insufficient funds%' then raise notice 'T13 overdraw blocked: OK'; else raise; end if; end $$;
do $$ begin
  perform public.perform_transfer('00000000-0000-0000-0000-00000000000a','checking','Rapid Pay LLC',50);
  raise exception 'FAIL T14';
exception when others then if sqlerrm like '%payee not found%' then raise notice 'T14 unknown payee blocked: OK'; else raise; end if; end $$;
select 'T15 add payee: ' || (public.add_payee_for('00000000-0000-0000-0000-00000000000a','Landlord LLC') is not null);
select 'T16 pay payee ok: ' || (public.perform_transfer('00000000-0000-0000-0000-00000000000a','checking','landlord llc',75) is not null);
select 'T17 new payee flagged on tx (expect true): ' || new_payee from transactions where merchant='landlord llc';
select 'T18 server CAN set fraud score: ' || fraud_score from transactions where event_id='evt1';
select 'T19 freeze A card: ' || public.freeze_card_for('00000000-0000-0000-0000-00000000000a', null);
do $$ begin
  perform public.freeze_card_for('00000000-0000-0000-0000-00000000000a', '9999');
  raise exception 'FAIL T20';
exception when others then if sqlerrm like '%card not found%' then raise notice 'T20 cannot freeze another users card: OK'; else raise; end if; end $$;
select 'T21 B balance untouched (expect 2500/8000): ' || string_agg(kind||'='||balance, ' ' order by kind) from accounts where user_id='00000000-0000-0000-0000-00000000000b';
reset role;

-- ---- make A a security admin (done by a human in the SQL editor)
insert into security_admins values ('00000000-0000-0000-0000-00000000000a');
set role authenticated; set request.jwt.claim.sub = '00000000-0000-0000-0000-00000000000a'; set request.jwt.claim.role = 'authenticated';
select 'T22 admin sees guard events (expect 2): ' || count(*) from guard_events;
select 'T23 admin top rules: ' || string_agg(rule||'='||hits, ', ') from guard_top_rules;
select 'T24 admin daily view rows: ' || count(*) from guard_daily;
set request.jwt.claim.sub = '00000000-0000-0000-0000-00000000000b';
select 'T25 non-admin B sees events (expect 0): ' || count(*) from guard_events;
reset role;
