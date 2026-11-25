#ifndef ESCROW_CLOSURE_H
#define ESCROW_CLOSURE_H

struct changeset;

// Twist #4: what an approval changes in the *system*, not just the files.
// `escrow review/sign --closures` only (opt-in). If ws holds a flake with
// nixosConfigurations, builds every config's toplevel twice, from ws (the
// base) and from a temp copy with the change set applied, and prints
// `nix store diff-closures` between them, escaped. Host side, never in the
// jail, and it evaluates and builds Nix the agent wrote, so:
//   - no flake nixConfig, no import-from-derivation, no lock file updates;
//     no flake.lock, or a change set touching it: not built at all
//   - Nix's build sandbox must be on (sandbox = true)
//   - the proposal is evaluated with every proxy variable pointing at a
//     closed port, so eval-time fetches fail (ssh git URLs are not covered)
//   - nothing is built if a fixed-output derivation (the kind with network
//     in the sandbox) would be built rather than substituted
// Residual: `path:` copies the workspace into the world-readable store;
// derivation names in the output come from agent-written Nix (advisory,
// unsigned); diff-closures shows version and size changes, not every
// change. Prints why when it skips. Never exits on nix failures.
void closure_diff(const char *ws, const struct changeset *cs);

#endif
