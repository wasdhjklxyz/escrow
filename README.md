# escrow

**Agents propose, humans sign.** escrow runs a command (usually an AI agent)
in a throwaway, Nix-pinned Linux jail. Its file changes come out as a
proposal. A requester signs it, a different person reviews it, a third
signs it, and only then does it touch the real workspace. Every step is an
SSH signature in a hash-chained log that an auditor can verify offline.

Built for organizations: separation of duties is enforced, approvals are
signed artifacts, the record pins the Nix closure the agent ran with, and
when the workspace is a NixOS config, review shows what the approval
changes in the *system* (`nix store diff-closures`), not just the files.

The design, threat model and limitations: [`docs/WRITEUP.md`](docs/WRITEUP.md).
The on-disk formats: [`docs/FORMATS.md`](docs/FORMATS.md).

## Requirements

Linux ≥ 6.8 with unprivileged user namespaces and Landlock, run as a
normal user (escrow refuses root). `--net` needs Landlock ABI ≥ 10.
Nix with flakes. On Ubuntu 24.04:
`sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`.

## Try it

```sh
nix develop
cmake -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build
demo/run.sh            # ticket OPS-142 on a small NixOS host, end to end
demo/run.sh --claude   # same, with Claude Code as the agent
```

## Use

```sh
# a role is a Nix closure: the only programs the agent can see or run
nix build .#role-demo -o role

# roles file: <principal> <roles> <ssh public key>
cat >roles <<EOF
alice requester $(cat alice.pub)
bob   reviewer  $(cat bob.pub)
carol signer    $(cat carol.pub)
EOF
export ESCROW_STATE=$PWD/state ESCROW_ROLES=$PWD/roles

escrow --role role --key alice --workspace ./config -- ops-ticket   # propose
escrow list
escrow review <id> --key bob      # file diff + closure diff; bob signs
escrow sign <id> --key carol      # a third person approves
escrow apply <id> --key carol     # atomic, refuses if the workspace moved
escrow verify-log                 # offline: chain, signatures, SoD
```

Without `--key`, a run just prints the diff and changes nothing. The
agent's own output goes to `<state>/runs/<id>/log`, never to escrow's
stdout.

## Tests

```sh
nix build .#role-test -o build/role-test
tests/m1.sh     "$PWD/build/bin/escrow" "$PWD/build/role-test"   # overlay + diff
tests/escape.sh "$PWD/build/bin/escrow" "$PWD/build/role-test"   # hostile agent
tests/m3.sh     "$PWD/build/bin/escrow" "$PWD/build/role-test"   # proposals, SoD
```

## License

MIT
