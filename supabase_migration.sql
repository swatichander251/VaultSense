-- Run once in Supabase -> SQL Editor (after the tables you already created).
-- Adds the columns the VaultSense model needs, plus where to store its answer.

alter table transactions
  add column if not exists hour          int     check (hour between 0 and 23),
  add column if not exists international boolean default false,
  add column if not exists new_payee     boolean default false,
  add column if not exists velocity_10m  int     check (velocity_10m >= 0),
  add column if not exists explanations  jsonb,   -- top reasons returned by /score
  add column if not exists event_id      text,    -- links the row to the API audit log
  add column if not exists model_version text;

-- (fraud_score and flagged already exist from the first script)

-- Fast lookups for "how many transactions did this user make in the last 10 minutes"
create index if not exists transactions_user_time_idx on transactions (user_id, created_at desc);

-- Create a profile row automatically when someone signs up
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  insert into public.profiles (id, full_name)
  values (new.id, new.raw_user_meta_data ->> 'full_name');
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- Optional: chatbot guard events for a security dashboard.
-- RLS is on with NO policies, so only the server (service_role key) can read/write it.
-- Stores metadata only, never message text.
create table if not exists guard_events (
  id bigint generated always as identity primary key,
  created_at timestamptz default now(),
  user_id uuid references auth.users on delete set null,
  session_hash text,
  layer text check (layer in ('input', 'output', 'action')),
  source text,
  decision text,
  risk_score real,
  rules text[],
  event_id text
);
alter table guard_events enable row level security;
create index if not exists guard_events_time_idx on guard_events (created_at desc);
