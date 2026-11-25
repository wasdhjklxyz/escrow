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
   keys). A requester can never review or sign her own proposal, and a
   reviewer can't also sign it. The tool refuses; it isn't a convention.
2. **Signed decisions.** Every step is an SSH signature (`ssh-keygen -Y`)
   in its own namespace, over the exact bytes of the proposal record. An
   auditor verifies the whole history offline with `ssh-keygen` and
   `sha256sum`.
3. **Nix provenance.** The agent can only execute what is in its role's
   Nix closure; the record lists every store path. `/work` and `/tmp` are
   noexec and memfd exec is blocked, so store paths are the only
   executable files.
4. **Diff systems, not just repos.** When the workspace is a NixOS flake,
   review shows the file diff *and* `nix store diff-closures`: which
   packages and services the approval actually changes.

## Prior art

| | runs the agent | reviews | signed approval | SoD | system diff |
|---|---|---|---|---|---|
| Codex / Claude Code sandboxes | you | you | – | – | – |
| Dagger container-use, yoloAI, brood-box | you | you | – | – | – |
| Turso AgentFS, Tilde.run (agent filesystems) | you | you | – | – | – |
| **escrow** | requester | reviewer | SSH signatures, offline-verifiable | enforced | `nix store diff-closures` |

These are good sandboxes, built for one developer reviewing their own
agent's work (as described in their own materials at the time of writing).
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
      agent: no caps, clean env, setsid, stdin /dev/null, stdout+stderr
             to <run>/log, NO_NEW_PRIVS, Landlock, seccomp, exec
  after the agent: the overlay upper dir is the change set
    diff walk -> frozen <run>/changes (payloads included)
    record (base tree hash, change-set hash, roles hash, closure) -> requester signs
escrow review <id> --key BOB    # rendered from the change set; bob signs
escrow sign   <id> --key CAROL  # carol, a third principal, signs
escrow apply  <id> --key CAROL  # stage a copy, re-check base, apply, swap atomically
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
  Landlock), reach the network (empty net ns; under `--net`, TCP 443 and
  DNS only), see host processes, IPC or keyrings (pid/ipc namespaces,
  seccomp), regain capabilities (identity map, no nested user ns), run
  binaries outside its closure (noexec, memfd blocked), or inject into the
  review (its output never shares the diff's stream; every path, link
  target, record field and file content shown is escaped).
- *A malicious requester* holds her own key and can hand-craft run
  directories, records, change sets, even append log lines. Separation of
  duties still holds because review and sign need other people's keys;
  apply re-verifies everything from signatures and writes only through an
  `openat2` resolver that refuses any symlink or mount crossing.
- *An auditor* trusts only `ssh-keygen`, `sha256sum` and the roles file.

**Not defended (limitations):**

- **Exfiltration through allowed channels.** With `--net`, anything the
  agent can read (the workspace) can leave through TCP 443 or DNS. No
  kernel jail can tell a legitimate API call from a leak.
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
- **Roles rotation.** Each proposal pins the roles file it was made under;
  verifying old history needs the old roles file.
- **Review is a human.** escrow shows the reviewer exactly what will be
  applied, escaped and complete, including a binary file's hash, but
  can't make them read it.

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

## AI usage

escrow was written with Claude Code: the design decisions and reviews were
human, the implementation largely agent-written and then reviewed by
independent reviewer agents (correctness, offensive security, minimalism,
style, maintainability) in several rounds. Every agent-written commit
carries a `Co-Authored-By` trailer.
