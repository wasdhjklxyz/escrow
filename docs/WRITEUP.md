# escrow: agents propose, humans sign

## The problem

AI agents now edit real systems: configs, infrastructure, code. Every tool
that sandboxes them today answers one question, "can the agent hurt my
machine while it works?", for one person: the developer who runs the agent
and reviews its diff.

An organization needs different answers. Who asked for this change? Who
checked it? Who approved it, and can they prove it later? What exactly did
the approval change in the running system? An auditor wants to check all of
that offline, without trusting the tool that produced it.

## The twist

escrow is a sandbox whose output is a *proposal*, not a write. Four things
make it an organizational tool rather than a single-developer one:

1. **Separation of duties, enforced.** Requester, reviewer and signer are
   three different people (three distinct principals, so three distinct
   keys). A requester can never review or sign their own proposal, and a
   reviewer can't also sign it. The tool refuses; it isn't a convention.
2. **Signed decisions.** Every step is an SSH signature (`ssh-keygen -Y`)
   in its own namespace, over the exact bytes of the proposal record (apply
   signs a statement naming that record and the tree it produced). An
   auditor checks the chain, every signature and the record and change-set
   hashes offline with `ssh-keygen` and `sha256sum`; checking a tree
   against `base`/`post` needs the tree-hash serializer in FORMATS.md.
3. **Nix provenance.** The agent can only execute what is in its role's
   Nix closure; the record lists every store path. `/work` and `/tmp` are
   noexec and memfd exec is blocked, so store paths are the only
   executable files.
4. **Diff systems, not just repos.** When the workspace is a NixOS flake,
   `review --closures` (or `sign --closures`) adds `nix store diff-closures` to the file diff:
   the package-level changes the approval makes to the running system.
   It is advisory (names come from the evaluated Nix, and it is not
   signed); the file diff is what gets applied.

## Prior art

| | runs the agent | reviews | signed approval | SoD | system diff |
|---|---|---|---|---|---|
| Codex / Claude Code sandboxes | you | you | – | – | – |
| Dagger container-use, yoloAI, brood-box | you | you | – | – | – |
| Turso AgentFS, Tilde.run (agent filesystems) | you | you | – | – | – |
| **escrow** | requester | reviewer | SSH signatures, offline-verifiable | enforced | `nix store diff-closures` |

These are good sandboxes, built for one developer reviewing their own
agent's work (as described in their own materials, November 2026).
escrow's jail is deliberately conventional; the new part is everything
after the agent exits.

## How it works

```
escrow --role POLICY --key KEY --workspace W -- <agent ...>
  supervisor (host namespaces, never enters the jail)
    clone3(NEWUSER|NEWNS|NEWPID|NEWIPC|NEWUTS|NEWCGROUP[|NEWNET]) -> init (PID 1)
      identity uid map; max_user_namespaces=0
      root = tmpfs: role closure bound ro, overlay(lower=W) at /work,
             noexec /tmp, minimal /dev, fresh /proc; pivot_root
      agent: no caps, clean env, setsid, NO_NEW_PRIVS, Landlock, seccomp,
             stdin /dev/null, stdout+stderr to <run>/log, exec
  after the agent: the overlay upper dir is the change set
    diff walk -> frozen <run>/changes (payloads included)
    record (base tree hash, change-set hash, roles hash, closure, --net,
            --env names) -> requester signs
escrow review <id> --key BOB    # rendered from the change set; bob signs
escrow sign   <id> --key CAROL  # carol, a third principal, signs
escrow apply  <id> --key CAROL  # stage a copy, apply, sign, re-check base, swap atomically
escrow verify-log               # chain + every signature + SoD, offline
```

The formats an independent verifier needs are in
[`FORMATS.md`](FORMATS.md).

## Threat model

**Assets:** the real workspace (a config repo, a NixOS system), the host
the agent runs on, the review surface (what the humans read before
signing), and the audit trail.

**Adversaries and what holds:**

- *A malicious or prompt-injected agent* controls everything inside the
  jail. It can't write or read the host filesystem (pivot_root plus
  Landlock), reach the network (empty net ns; under `--net`, TCP port 443
  and UDP port 53 only, to any address), see host processes, IPC or
  keyrings (pid/ipc namespaces, seccomp), regain capabilities (identity
  map, no nested user ns), run binaries outside its closure (noexec, memfd
  blocked), or inject into the review (its output never shares the diff's
  stream; paths, link targets and file content are escaped, and record
  fields and log lines are refused unless printable ASCII).
- *A malicious requester* holds their own key and can hand-craft run
  directories, records, change sets, even append log lines. Separation of
  duties still holds because review and sign need other people's keys;
  apply re-verifies everything from signatures and writes only through an
  `openat2` resolver that refuses any symlink or mount crossing.
- *An auditor* trusts only `ssh-keygen`, `sha256sum` and the roles file.

**Not defended (limitations):**

- **Exfiltration through allowed channels.** With `--net`, anything the
  agent can read (the workspace) can leave through TCP 443 or UDP 53. No
  kernel jail can tell a legitimate API call from a leak.
- **Review-time Nix (`--closures`).** Building the closure diff evaluates
  and builds Nix the agent wrote, on the reviewer's host. escrow refuses
  fixed-output builds (the ones with network), points eval-time fetches at
  a dead proxy, and requires Nix's build sandbox, but an ssh git URL or
  its DNS lookup could still carry data out, and `path:` copies the
  workspace into the world-readable Nix store. That is why it is opt-in.
- **Kernel bugs.** escrow reduces attack surface (no nested user ns,
  seccomp, Landlock) but runs on the host kernel.
- **Interpreted code.** Store paths are the only executable *files*; an
  interpreter from the closure can still run any script the agent wrote.
- **The deployment model.** Separation of duties is only enforced if the
  requester can't write the workspace or the state dir directly. On one
  shared uid it is advisory.
- **Truncation.** The log is hash-chained, not witnessed. Edits and
  reordering are caught; cutting off the tail is only visible against a
  head hash kept elsewhere.
- **Roles rotation.** Each proposal and log line pins the roles file it
  was made under, and `verify-log` takes one roles file: a log that spans
  a roles change can't be verified in one pass today.
- **A write racing apply.** apply checks the workspace against `base`
  after the signer signs, then swaps. A write in the instant between is
  not lost (escrow keeps the old tree and says where) but the apply has
  already happened.
- **Review is a human.** escrow shows the reviewer exactly what will be
  applied, escaped, with a binary file's hash, xattr values as hashes and
  up to 200 entries of a recursive delete (then a count), but can't make
  them read it.

## Where this goes

- **An isolation ladder.** The same proposal pipeline over stronger jails:
  gVisor, a microVM per run, or a multikernel partition with its own
  kernel, chosen per role by risk.
- **Witnessed logs.** Independent witnesses cosign log heads so truncation
  and rewrites show up offline (the transparency-log model).
- **Roles from an SSH CA.** Short-lived role certificates and revocation
  lists instead of a static roles file; hardware keys for signers.
- **Warrants.** A signer pre-approves a scope (paths, closure deltas)
  before the agent runs; proposals outside it are rejected before review.
- **Escrowed side effects.** The same propose/sign/apply flow for what an
  agent does to the outside world (API calls, deploys), not just files.
- **Taint tracking.** Mark what the agent read and where it went: a
  flight recorder for blast-radius analysis.
- **Capabilities.** Per-tool, per-path grants instead of one closure per
  role.

## Prior and new work

The jail is built from standard Linux mechanisms (user, mount and pid
namespaces, overlayfs, pivot_root, Landlock, seccomp) in the same way
bubblewrap, container runtimes and the sandboxes above use them; escrow
implements them directly in C with no library beyond libc (it runs
coreutils, diffutils, `ssh-keygen` and, for `--closures`, `nix`). New here:
the frozen, signed change set; enforced separation of duties; the
offline-verifiable hash-chained log; the attested Nix closure; and
system-level review through the closure diff.

## AI usage

escrow was written with Claude Code. I wrote the spec (the twist, the
architecture, constraints, milestones and cut order) and defined the
workflow: the agent implemented each milestone, then independent reviewer
agents (correctness, offensive security with working proofs of concept,
minimalism, style, maintainability) attacked it, and every finding was
fixed with a regression test, over at least two rounds per milestone. For
the first two milestones I made the design calls (the supervisor never
enters the jail, clone3 into an init we control, the identity uid map,
the new mount API) and the agent wrote the code. From the third milestone
on I delegated design decisions to the agent as well; the judgment calls
it made were surfaced for me afterwards. I ran the end-to-end demo with a
real coding agent myself. All code is agent-written, and every
agent-written commit carries a `Co-Authored-By` trailer.
