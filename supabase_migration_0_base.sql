-- VaultSense base tables (the first script from setup). Safe to re-run.
create table if not exists profiles (
  id uuid primary key references auth.users on delete cascade,
  full_name text,
  created_at timestamptz default now()
);

create table if not exists cards (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users on delete cascade not null,
  brand text,
  last4 text check (char_length(last4) = 4),
  exp_month int,
  exp_year int,
  nickname text,
  created_at timestamptz default now()
);

create table if not exists transactions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users on delete cascade not null,
  card_id uuid references cards on delete set null,
  amount numeric(12,2) not null,
  merchant text,
  category text,
  location text,
  created_at timestamptz default now(),
  fraud_score real,
  flagged boolean default false
);

alter table profiles enable row level security;
alter table cards enable row level security;
alter table transactions enable row level security;

drop policy if exists "own profile" on profiles;
drop policy if exists "own cards" on cards;
drop policy if exists "own transactions" on transactions;
create policy "own profile" on profiles for all using (auth.uid() = id) with check (auth.uid() = id);
create policy "own cards" on cards for all using (auth.uid() = user_id) with check (auth.uid() = user_id);
create policy "own transactions" on transactions for all using (auth.uid() = user_id) with check (auth.uid() = user_id);
