# escrow

**Agents propose, humans sign.** escrow runs an AI agent (or any command)
in a throwaway, Nix-pinned Linux jail and turns what it changed into a
proposal. Nothing is written to the real workspace until three different
people request, review and sign it, and every step is an SSH signature in
a hash-chained log an auditor can verify offline.

Sandboxes for coding agents answer "can the agent hurt my machine?" for one
developer. escrow answers the organization's question: **who asked, who
checked, who approved, and can we prove it?**

- **Separation of duties, enforced.** Requester, reviewer and signer are
  different keys; a requester can never approve their own change (when the
  requester can't write the workspace directly; see the threat model).
- **Signed decisions.** Every proposal, review, signature and apply is an
  SSH signature. The log verifies offline with `ssh-keygen` and `sha256sum`
  (truncation shows only against a saved head hash).
- **Provenance.** The record lists the Nix store path of every binary the
  agent could exec, attested by the requester's signature.
- **Systems, not just repos.** When the workspace is a NixOS config,
  `review --closures` builds the base and proposed systems on the
  reviewer's host and shows `nix store diff-closures` (package and size
  changes, e.g. `jq: +90 KiB`).

## How it works

```
 escrow --role R --key alice --workspace W -- <agent>

   jail ───────────► proposal ──────► review ───────► sign ─────────► apply
   user/mount/pid/   change set,      bob signs off   carol signs     atomic swap,
   ipc/uts/cgroup,   record, and      on the exact    (never the      refused if W
   net unless --net, alice's SSH      diff            requester)      moved since
   Nix-closure root, signature
   Landlock, seccomp
        │                │                │              │               │
        └────────────────┴────────────────┴──────────────┴───────────────┘
                       hash-chained log  ──►  escrow verify-log
```

| Layer | What it stops |
|---|---|
| Mount namespace + a root built from the role's Nix closure | Seeing host files: only the closure, `/work`, and a scratch `/tmp`, `/dev`, `/proc` exist |
| Overlay on the workspace | Writing the real workspace: changes land in an upper dir that becomes the proposal |
| Read-only root, `noexec` on `/work` and `/tmp`, Landlock | Writing outside `/work` and `/tmp`; exec'ing any file outside the closure (an interpreter in the closure can still run scripts the agent wrote) |
| PID and IPC namespaces | Seeing or signalling host processes; host SysV IPC |
| Network namespace; with `--net`, none (the host network, held by Landlock) | Any network by default; with `--net`, everything but TCP connect to port 443 and UDP to port 53, on any address, host loopback included |
| seccomp | io_uring, memfd_create, keyrings, every socket but Unix, TCP and UDP, foreign-arch syscalls |

What a kernel jail cannot stop (exfiltration through an allowed channel,
kernel bugs) is in the [threat model](docs/WRITEUP.md#threat-model).
escrow also sets no CPU, memory or disk limits: run it under cgroups
(systemd, a container) if the agent might be hostile.

## Try it

Needs Linux ≥ 6.8 with unprivileged user namespaces and Nix with flakes.

```sh
nix develop
cmake -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build
demo/run.sh            # ticket OPS-142 on a small NixOS host, end to end
demo/run.sh --claude   # same, with Claude Code as the agent
```

The demo walks one ops ticket ("add dana to the ops group, rotate the
service key, install jq") through the whole flow: the agent works in the
jail, the requester can't approve their own change, the reviewer sees the
file diff and the closure diff, the signer signs and applies, `verify-log`
checks the chain, and a tampered log is caught.

## Use

```sh
# a role is a Nix closure: the only programs the agent can see or run
nix build .#role-demo -o role

# roles file: <principal> <roles> <ssh public key>
cat >roles <<EOT
alice requester $(cat alice.pub)
bob   reviewer  $(cat bob.pub)
carol signer    $(cat carol.pub)
EOT
export ESCROW_STATE=$PWD/state ESCROW_ROLES=$PWD/roles

escrow --role role --key alice --workspace ./config -- ops-ticket   # propose
escrow list
escrow review <id> --key bob      # what apply will write; bob signs
escrow review <id> --closures     # + nix store diff-closures (builds on this host)
escrow sign <id> --key carol      # a third person approves
escrow apply <id> --key carol     # atomic swap; refuses if the workspace moved
escrow verify-log                 # offline: chain, signatures, SoD
```

Without `--key`, a run just prints the diff and leaves the workspace alone
(the run dir is still kept under `<state>/runs/`). The agent's own output
goes to `<state>/runs/<id>/log`, never to escrow's stdout.

## Requirements

- Linux ≥ 6.8 with unprivileged user namespaces, run as a normal user
  (escrow refuses root). On Ubuntu:
  `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`.
- Landlock; without it escrow warns loudly and runs without it
  (namespaces, pivot_root, the read-only and noexec mounts and seccomp
  still apply). `--net` needs Landlock ABI ≥ 10.
- Nix with flakes and its build sandbox on (the default). The flake wraps
  the helpers escrow shells out to (coreutils, diffutils, openssh); escrow
  implements no crypto.
- The demo builds a small NixOS system (x86_64-linux) on first run: it
  needs network and a few minutes. `--claude` needs Landlock ABI ≥ 10 and
  `CLAUDE_CODE_OAUTH_TOKEN` (`claude setup-token`) or `ANTHROPIC_API_KEY`.

## Tests

```sh
nix build .#role-test -o build/role-test
tests/m1.sh     "$PWD/build/bin/escrow" "$PWD/build/role-test"   # overlay + diff
tests/escape.sh "$PWD/build/bin/escrow" "$PWD/build/role-test"   # hostile agent
tests/m3.sh     "$PWD/build/bin/escrow" "$PWD/build/role-test"   # proposals, SoD
```

CI runs all three under sanitizers.

## Docs

- [`docs/WRITEUP.md`](docs/WRITEUP.md): the problem, prior art, design,
  threat model, limitations, and where this goes.
- [`docs/FORMATS.md`](docs/FORMATS.md): every on-disk format, enough to
  write an independent verifier.
- A browser demo of the same flow (log in, play requester, reviewer and
  signer, run commands in the jail) lives on the
  [`web-ui`](https://github.com/wasdhjklxyz/escrow/tree/web-ui) branch.

## License

MIT
