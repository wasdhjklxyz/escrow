# Scripted ops agent for the demo ticket OPS-142: "add dana to the ops group,
# rotate the ops-svc API key, install jq for the ops team". Runs in the
# jail with cwd /work (the config).
# Deterministic stand-in for an LLM agent, so the demo can't flake.

echo "OPS-142: add dana to ops"
sed -i '/users.users.dana = {/,/};/ s/extraGroups = \[ \];/extraGroups = [ "ops" ];/' \
  configuration.nix
# sed exits 0 on no match: check, so a reformatted config fails loudly.
grep -q 'extraGroups = \[ "ops" \];' configuration.nix

echo "OPS-142: rotate the ops-svc key"
printf 'demo-key-%s-rotated-not-a-secret\n' "$(date -u +%Y-%m-%d)" >keys/api.key

echo "OPS-142: install jq"
sed -i 's/environment.systemPackages = \[ \];/environment.systemPackages = [ pkgs.jq ];/' \
  configuration.nix
grep -q 'pkgs.jq' configuration.nix

echo "OPS-142: done"
