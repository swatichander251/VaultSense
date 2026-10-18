-- VaultSense migration 2: demo chatbot + security dashboard.
-- Run AFTER supabase_migration.sql, in Supabase -> SQL Editor. Safe to re-run.
-- All balances and accounts are SYNTHETIC demo data.

-- ============================================================ accounts & payees
create table if not exists accounts (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users on delete cascade not null,
  kind text not null check (kind in ('checking', 'savings')),
  nickname text,
  balance numeric(14,2) not null default 0 check (balance >= 0),
  created_at timestamptz default now(),
  unique (user_id, kind)
);
alter table accounts enable row level security;
drop policy if exists "read own accounts" on accounts;
create policy "read own accounts" on accounts for select using (auth.uid() = user_id);
-- No insert/update/delete policies: customers can't edit balances. Only the functions below can.

create table if not exists payees (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users on delete cascade not null,
  name text not null check (char_length(name) between 1 and 80),
  created_at timestamptz default now(),
  unique (user_id, name)
);
alter table payees enable row level security;
drop policy if exists "read own payees" on payees;
create policy "read own payees" on payees for select using (auth.uid() = user_id);

alter table cards add column if not exists frozen boolean not null default false;
alter table transactions add column if not exists account_id uuid references accounts on delete set null;

-- ============================================================ fraud fields are server-only
-- Customers may still add transactions themselves, but only the server (service_role)
-- can set or change the fraud model's output.
create or replace function public.protect_fraud_fields()
returns trigger language plpgsql set search_path = '' as $$
begin
  if coalesce(auth.role(), '') <> 'service_role' then
    if tg_op = 'INSERT' then
      new.fraud_score := null; new.flagged := false; new.explanations := null;
      new.event_id := null; new.model_version := null;
    else
      new.fraud_score := old.fraud_score; new.flagged := old.flagged; new.explanations := old.explanations;
      new.event_id := old.event_id; new.model_version := old.model_version;
    end if;
  end if;
  return new;
end;
$$;
drop trigger if exists protect_fraud_fields on transactions;
create trigger protect_fraud_fields before insert or update on transactions
  for each row execute function public.protect_fraud_fields();

-- ============================================================ actions (server only)
-- These are SECURITY DEFINER and only service_role may call them. Each checks that the
-- account/card belongs to p_user, so the server can't be tricked into touching someone else's data.

create or replace function public.perform_transfer(
  p_user uuid, p_from_kind text, p_to text, p_amount numeric,
  p_fraud_score real default null, p_flagged boolean default false, p_explanations jsonb default null,
  p_event_id text default null, p_model_version text default null)
returns uuid language plpgsql security definer set search_path = '' as $$
declare
  v_from public.accounts%rowtype;
  v_to public.accounts%rowtype;
  v_tx uuid;
begin
  if p_amount is null or p_amount <= 0 then raise exception 'amount must be positive'; end if;
  select * into v_from from public.accounts where user_id = p_user and kind = p_from_kind for update;
  if not found then raise exception 'source account not found'; end if;
  if v_from.balance < p_amount then raise exception 'insufficient funds'; end if;

  if lower(p_to) in ('checking', 'savings') then
    if lower(p_to) = p_from_kind then raise exception 'cannot transfer to the same account'; end if;
    select * into v_to from public.accounts where user_id = p_user and kind = lower(p_to) for update;
    if not found then raise exception 'destination account not found'; end if;
    update public.accounts set balance = balance + p_amount where id = v_to.id;
  elsif not exists (select 1 from public.payees where user_id = p_user and lower(name) = lower(p_to)) then
    raise exception 'payee not found';
  end if;

  update public.accounts set balance = balance - p_amount where id = v_from.id;
  insert into public.transactions (user_id, account_id, amount, merchant, category, fraud_score, flagged,
                                   explanations, event_id, model_version, hour, international, new_payee)
  values (p_user, v_from.id, p_amount, p_to, 'transfer', p_fraud_score, coalesce(p_flagged, false),
          p_explanations, p_event_id, p_model_version,
          extract(hour from now() at time zone 'America/Chicago')::int, false,
          not exists (select 1 from public.payees where user_id = p_user and lower(name) = lower(p_to)
                      and created_at < now() - interval '1 day') and lower(p_to) not in ('checking', 'savings'))
  returning id into v_tx;
  return v_tx;
end;
$$;

create or replace function public.add_payee_for(p_user uuid, p_name text)
returns uuid language plpgsql security definer set search_path = '' as $$
declare v_id uuid;
begin
  insert into public.payees (user_id, name) values (p_user, trim(p_name))
  on conflict (user_id, name) do update set name = excluded.name
  returning id into v_id;
  return v_id;
end;
$$;

create or replace function public.freeze_card_for(p_user uuid, p_last4 text default null)
returns text language plpgsql security definer set search_path = '' as $$
declare v_last4 text;
begin
  update public.cards set frozen = true
   where id = (select id from public.cards
                where user_id = p_user and (p_last4 is null or last4 = p_last4)
                order by created_at limit 1)
  returning last4 into v_last4;
  if v_last4 is null then raise exception 'card not found'; end if;
  return v_last4;
end;
$$;

revoke all on function public.perform_transfer(uuid, text, text, numeric, real, boolean, jsonb, text, text) from public, anon, authenticated;
revoke all on function public.add_payee_for(uuid, text) from public, anon, authenticated;
revoke all on function public.freeze_card_for(uuid, text) from public, anon, authenticated;
grant execute on function public.perform_transfer(uuid, text, text, numeric, real, boolean, jsonb, text, text) to service_role;
grant execute on function public.add_payee_for(uuid, text) to service_role;
grant execute on function public.freeze_card_for(uuid, text) to service_role;

-- ============================================================ demo money for new users
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  insert into public.profiles (id, full_name)
  values (new.id, new.raw_user_meta_data ->> 'full_name')
  on conflict (id) do nothing;
  insert into public.accounts (user_id, kind, nickname, balance) values
    (new.id, 'checking', 'Everyday Checking', 2500.00),
    (new.id, 'savings', 'High-Yield Savings', 8000.00)
  on conflict (user_id, kind) do nothing;
  return new;
end;
$$;

-- Give demo accounts to users who signed up before this migration
insert into accounts (user_id, kind, nickname, balance)
select u.id, k.kind, k.nickname, k.balance
from auth.users u
cross join (values ('checking', 'Everyday Checking', 2500.00), ('savings', 'High-Yield Savings', 8000.00))
     as k(kind, nickname, balance)
on conflict (user_id, kind) do nothing;

-- ============================================================ security dashboard
-- Who may see guard events. Add people by hand in the SQL editor:
--   insert into security_admins (user_id) select id from auth.users where email = 'you@example.com';
create table if not exists security_admins (
  user_id uuid primary key references auth.users on delete cascade,
  added_at timestamptz default now()
);
alter table security_admins enable row level security;  -- no policies: invisible to the app

create or replace function public.is_security_admin()
returns boolean language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.security_admins where user_id = auth.uid());
$$;
revoke all on function public.is_security_admin() from public, anon;
grant execute on function public.is_security_admin() to authenticated;

drop policy if exists "security admins read guard events" on guard_events;
create policy "security admins read guard events" on guard_events
  for select to authenticated using (public.is_security_admin());

-- Views for the dashboard. security_invoker makes them respect the RLS above.
create or replace view guard_daily with (security_invoker = true) as
select date_trunc('day', created_at) as day, layer, decision, count(*) as events
from guard_events group by 1, 2, 3;

create or replace view guard_top_rules with (security_invoker = true) as
select rule, count(*) as hits, max(created_at) as last_seen
from guard_events, unnest(rules) as rule
where decision in ('block', 'review', 'redact', 'deny', 'human_review')
group by rule;

create or replace view guard_recent_threats with (security_invoker = true) as
select created_at, layer, source, decision, risk_score, rules, session_hash, event_id
from guard_events
where decision in ('block', 'review', 'redact', 'deny', 'human_review')
order by created_at desc limit 200;

grant select on guard_daily, guard_top_rules, guard_recent_threats to authenticated;
