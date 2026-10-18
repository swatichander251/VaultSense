#!/usr/bin/env bash
# Runs the migrations + security tests on a throwaway local Postgres 16 (NOT on your real Supabase).
# Usage: bash db_tests/run.sh      (needs postgresql-16 server binaries; run as a non-root user)
set -euo pipefail
cd "$(dirname "$0")/.."
BIN=${PG_BIN:-/usr/lib/postgresql/16/bin}
D=$(mktemp -d)
trap '"$BIN/pg_ctl" -D "$D/data" stop -m fast >/dev/null 2>&1 || true; rm -rf "$D"' EXIT
"$BIN/initdb" -D "$D/data" -A trust -U postgres >/dev/null
"$BIN/pg_ctl" -D "$D/data" -o "-p ${PG_PORT:-5499} -k $D" -l "$D/pg.log" -w start >/dev/null
P="psql -h $D -p ${PG_PORT:-5499} -U postgres -v ON_ERROR_STOP=1 -q"
for f in db_tests/supabase_stub.sql supabase_migration_0_base.sql supabase_migration.sql supabase_migration_2_chatbot.sql; do $P -f "$f" >/dev/null 2>&1; done
$P -t -A -f db_tests/security_tests.sql 2>&1 | grep -E '^T[0-9]|NOTICE:  T|FAIL|ERROR' | sed 's/^psql:.*NOTICE:  //'
