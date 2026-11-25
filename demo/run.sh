#!/bin/sh
# escrow demo: ticket OPS-142 ("add dana to the ops group, rotate the ops-svc
# API key, install jq") on a small NixOS config, end to end:
#   agent runs in the jail -> proposal -> self-approval refused -> reviewer
#   sees the file diff and the closure diff -> signer signs -> apply ->
#   verify-log -> a tampered log is caught.
# usage: demo/run.sh [--claude]     run from the repo root, in `nix develop`
#   --claude  use Claude Code as the agent: needs CLAUDE_CODE_OAUTH_TOKEN
#             (a Claude subscription: `claude setup-token`) or
#             ANTHROPIC_API_KEY (API credits), and Landlock ABI >= 10
set -eu

repo=$(cd "$(dirname "$0")/.." && pwd)
escrow=${ESCROW:-$repo/build/bin/escrow}
agent=scripted
[ "${1-}" = --claude ] && agent=claude
d=$(mktemp -d "${TMPDIR:-/tmp}/escrow-demo-XXXXXX")
export ESCROW_STATE=$d/state ESCROW_ROLES=$d/roles

step() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
run() { printf '\033[2m$ %s\033[0m\n' "$*"; "$@"; }
pub() { cut -d' ' -f1,2 "$d/$1.pub"; }

step "who may do what"
for u in alice bob carol; do
  ssh-keygen -q -t ed25519 -N '' -C "$u" -f "$d/$u"
done
cat >"$d/roles" <<EOF
alice requester $(pub alice)
bob reviewer $(pub bob)
carol signer $(pub carol)
EOF
cut -d' ' -f1,2 "$d/roles"

step "the workspace: a NixOS config (demo/ops)"
cp -r "$repo/demo/ops" "$d/ops"
run grep -n 'extraGroups' "$d/ops/configuration.nix"

step "the agent works on OPS-142, inside the jail"
if [ "$agent" = claude ]; then
  role=$(nix build --no-link --print-out-paths "path:$repo#role-claude")
  # Hand the agent exactly one credential; escrow passes nothing else in.
  cred=ANTHROPIC_API_KEY
  [ -n "${CLAUDE_CODE_OAUTH_TOKEN-}" ] && cred=CLAUDE_CODE_OAUTH_TOKEN
  run "$escrow" --role "$role" --key "$d/alice" --net --env "$cred" \
    --workspace "$d/ops" -- claude -p --dangerously-skip-permissions \
    "Ticket OPS-142: in this NixOS config, add user dana to the ops group and
rotate the ops-svc API key in keys/api.key to a new random demo value,
and add pkgs.jq to environment.systemPackages.
Edit the files only; don't build anything."
else
  role=$(nix build --no-link --print-out-paths "path:$repo#role-demo")
  run "$escrow" --role "$role" --key "$d/alice" --workspace "$d/ops" -- \
    ops-ticket
fi
id=$("$escrow" list | tail -n1 | cut -d' ' -f1)

step "the change is in escrow, not in the workspace"
run "$escrow" list
run grep -c '"ops"' "$d/ops/configuration.nix" || true

step "alice can't approve her own change"
run "$escrow" review "$id" --key "$d/alice" >/dev/null || true

step "bob reviews: file diff + what it changes in the system"
run "$escrow" review "$id" --key "$d/bob" --closures

step "carol signs and applies"
run "$escrow" sign "$id" --key "$d/carol" >/dev/null
run "$escrow" apply "$id" --key "$d/carol"
run grep -n 'extraGroups' "$d/ops/configuration.nix"

step "the audit trail, verifiable offline"
run "$escrow" verify-log
run cut -c1-100 "$d/state/log"

step "rewriting history is caught"
mkdir "$d/forged"
cp "$d/state/log" "$d/forged/log"
ln -s "$d/state/runs" "$d/forged/runs"
# Change one character of line 2 (its time): line 3's prev no longer matches.
sed -i '2s/T/X/' "$d/forged/log"
ESCROW_STATE=$d/forged run "$escrow" verify-log || true

printf '\nstate kept in %s\n' "$d"
