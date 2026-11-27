# escrow-web

A login-protected web front end for the escrow CLI: pick a persona
(alice requester and reviewer, bob reviewer, carol signer), run an agent in the jail,
review the diff, sign, apply, verify the log, tamper with it.

It implements no policy. Every button runs the escrow binary, which does the
separation of duties, signatures and log; a refusal you see is escrow's.

**Demo signing only.** The personas' SSH keys live on the server, so anyone
who logs in can act as any of them. In production each signer's key stays
on their own machine. `server.py` logs which web user acted as which persona
on stderr; that mapping is not in the hash chain.

## Run locally

```sh
nix run .#web -- passwd --data ./web-data <user> # password >= 12 chars
nix run .#web -- serve --data ./web-data         # http://127.0.0.1:8080
```

The session cookie is `Secure`; browsers accept that on `localhost` without
TLS. Anywhere else, put it behind TLS.

To enable the Claude Code agent, start the server with
`CLAUDE_CODE_OAUTH_TOKEN` (`claude setup-token`) or `ANTHROPIC_API_KEY` set.
Each run costs tokens; use a key with a spend limit.

## Deploy (VPS)

Needs Linux >= 6.8 with unprivileged user namespaces, Landlock, and Nix.
The Claude agent needs Landlock ABI >= 10 (escrow refuses `--net` below it).
On Ubuntu, allow unprivileged user namespaces, and keep it across reboots:
`sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` plus the same
line in `/etc/sysctl.d/60-userns.conf`.

Run it as an unprivileged user, listening on loopback, with Caddy in front
for TLS (`/etc/caddy/Caddyfile`):

```caddyfile
escrow.example.com {
	reverse_proxy 127.0.0.1:8080
}
```

systemd unit (`/etc/systemd/system/escrow-web.service`):

```ini
[Unit]
Description=escrow web demo
After=network-online.target

[Service]
User=escrow
ExecStart=/home/escrow/.nix-profile/bin/escrow-web serve --data /home/escrow/web-data
EnvironmentFile=-/home/escrow/web.env
Restart=on-failure
# escrow sets no cgroup limits: cap the whole service, jails included, so a
# fork bomb or a memory hog in "Any command" can't take the box down.
TasksMax=512
MemoryMax=2G

[Install]
WantedBy=multi-user.target
```

escrow itself sets no rlimits or cgroups. The server caps each file a run
writes at 64 MiB (`prlimit --fsize`), and the unit caps memory and tasks, but
nothing caps total disk: a run can write many files, and each lands on the
host twice (overlay upper + change set). Put `--data` on its own size-capped
filesystem so a full disk stops escrow-web, not the box:

```sh
fallocate -l 4G /var/lib/escrow-web.img && mkfs.ext4 -q /var/lib/escrow-web.img
mkdir -p /home/escrow/web-data && mount -o loop /var/lib/escrow-web.img /home/escrow/web-data
chown escrow: /home/escrow/web-data   # and an fstab line to keep it mounted
```

Install it with `nix profile install .#web` as that user, and warm the store
once (run the ticket and a closure review) before anyone demos it.
`web.env` holds the Claude credential, mode 0600. The package brings its own
`nix` for `review --closures`; it talks to the host's nix daemon.

If an apply was interrupted (server killed mid-apply), later applies refuse
with "exists (left by a failed apply?)"; use "Reset the demo world" at the bottom of the page.
