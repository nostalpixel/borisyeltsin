#!/usr/bin/env bash
# Restore drill: dump the running Compose database, restore the dump into a
# scratch database next to it, compare row counts table by table, then drop
# the scratch database. The live database is only read.
#
# Run from the directory that holds docker-compose.yml, with the same
# environment (POSTGRES_PASSWORD) you use for `docker compose up`. Run it at a
# quiet moment: a write between the count and the dump shows as a mismatch.
set -euo pipefail

compose=(docker compose)
live=boriseltsyn
scratch="boriseltsyn_drill_$(date +%s)"
dump="$(mktemp)"

sql() {
  "${compose[@]}" exec -T postgres psql -U boriseltsyn -v ON_ERROR_STOP=1 -At "$@"
}

cleanup() {
  rm -f "$dump"
  sql -d postgres -c "DROP DATABASE IF EXISTS $scratch" >/dev/null 2>&1 || true
}
trap cleanup EXIT

counts() {
  sql -d "$1" -c "
    SELECT table_name || ' ' || (xpath('/row/c/text()',
      query_to_xml(format('SELECT count(*) AS c FROM public.%I', table_name), false, true, '')))[1]::text
    FROM information_schema.tables
    WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
    ORDER BY table_name"
}

before="$(counts "$live")"
"${compose[@]}" exec -T postgres pg_dump -U boriseltsyn -d "$live" --format=custom >"$dump"
echo "dump: $(wc -c <"$dump" | tr -d ' ') bytes"

sql -d postgres -c "CREATE DATABASE $scratch" >/dev/null
"${compose[@]}" exec -T postgres pg_restore -U boriseltsyn -d "$scratch" --no-owner --exit-on-error <"$dump"
after="$(counts "$scratch")"

if [[ "$before" != "$after" ]]; then
  echo "restore drill FAILED: row counts differ (live, then restored)" >&2
  diff <(echo "$before") <(echo "$after") >&2 || true
  exit 1
fi
echo "$after" | sed 's/^/  /'
echo "restore drill OK: $(echo "$after" | wc -l | tr -d ' ') tables match"
