#ifndef ESCROW_CLOSURE_H
#define ESCROW_CLOSURE_H

struct changeset;

// Twist #4: what an approval changes in the *system*, not just the files.
// If ws holds a flake with nixosConfigurations, builds every config's
// toplevel twice, from ws (the base) and from a temp copy of ws with the
// change set applied, and prints `nix store diff-closures` between them
// (escaped). Host side, at review time, never in the jail. It still
// evaluates and builds agent-written Nix, so: no flake-config prompts
// honoured, no import-from-derivation, no lock file updates, and a change
// set that touches flake.lock is not built at all (it could pull new
// inputs). Builds run in the Nix sandbox; `path:` copies the workspace
// into the store. Prints why when it skips. Never exits on build errors.
void closure_diff(const char *ws, const struct changeset *cs);

#endif
