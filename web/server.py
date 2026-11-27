#!/usr/bin/env python3
"""escrow-web: a login-protected web front end for the escrow CLI.

It implements no policy. Every action runs the escrow binary, which enforces
separation of duties, checks signatures and writes the hash-chained log; this
server only picks the arguments and shows the output, so a refusal in the UI
is escrow's refusal.

Not production signing: the demo personas' SSH keys (alice, bob, carol) live
on this server, so whoever logs in can act as any of them. In a real
deployment each signer's key stays on their own machine. Which web user
clicked as which persona goes to the access log on stderr, not the chain:
    <time> <ip> <user> as <persona>: <path> <id>

usage: escrow-web serve --data DIR [--listen HOST:PORT]
       escrow-web passwd --data DIR USER
env:   ESCROW, ESCROW_WEB_ROLE_DEMO, ESCROW_WEB_ROLE_CLAUDE,
       ESCROW_WEB_WORKSPACE (set by `nix run .#web`), and
       CLAUDE_CODE_OAUTH_TOKEN or ANTHROPIC_API_KEY to enable the Claude agent.

API (JSON; every POST needs `X-Escrow: 1`; all but login need the session):
    POST /api/login    {user, password}
    POST /api/logout
    GET  /api/state    personas, proposals, workspace files, log
    GET  /api/agentlog ?id=        the agent's own output (runs/<id>/log)
    POST /api/run      {persona, mode: ticket|command|claude, text}  proposes
    POST /api/view     {id, closures}           read-only, logs nothing
    POST /api/review   {id, persona, closures}  signs a review into the log
    POST /api/sign     {id, persona}
    POST /api/apply    {id, persona}
    POST /api/verify   {tamper}
    POST /api/reset
  Actions answer {ok, code, stdout, stderr, truncated} from World.escrow().

Coupled to escrow's human-readable output (change both sides together):
`escrow list` rows (src/cmd.c, cmd_list), the "proposed <id> as" line
(cmd_run), the review layout (render(), parsed in app.js renderDiff), and
the log line layout `<seq> <time> ...` (src/log.c), used by the tamper demo.
"""

import argparse
import getpass
import hashlib
import hmac
import ipaddress
import http.server
import json
import os
import re
import secrets
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.parse
from pathlib import Path

ESCROW = os.environ.get("ESCROW", "escrow")
ROLE_DEMO = os.environ.get("ESCROW_WEB_ROLE_DEMO", "")
ROLE_CLAUDE = os.environ.get("ESCROW_WEB_ROLE_CLAUDE", "")
WORKSPACE = os.environ.get("ESCROW_WEB_WORKSPACE", "")
# The credential handed to the Claude agent, if this server has one.
CRED = next((c for c in ("CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY") if os.environ.get(c)), None)
if not ROLE_CLAUDE:
    CRED = None
STATIC = Path(__file__).resolve().parent
PAGES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
}
# The demo world's roles file is written from this; escrow enforces it.
PERSONAS = {"alice": "requester,reviewer", "bob": "reviewer", "carol": "signer"}
# Same ticket as demo/run.sh; keep them in sync.
TICKET = (
    "Ticket OPS-142: in this NixOS config, add user dana to the ops group and\n"
    "rotate the ops-svc API key in keys/api.key to a new random demo value,\n"
    "and add pkgs.jq to environment.systemPackages.\n"
    "Edit the files only; don't build anything."
)
ID_RE = re.compile(r"[A-Za-z0-9]{6}")  # src/cmd.c check_id
# src/cmd.c cmd_run. Agent-chosen paths can appear raw in escrow's stderr
# ("not proposable: <path>"), so only the first line (printed before the
# agent runs) and the last line are trusted.
RUNDIR_RE = re.compile(r"escrow: run dir: .*/runs/([A-Za-z0-9]{6})")
PROPOSED_RE = re.compile(r"escrow: proposed ([A-Za-z0-9]{6}) as [a-z]+")
USER_RE = re.compile(r"[a-z][a-z0-9_-]{0,31}")
SESSION_TTL = 8 * 3600
MAX_BODY = 64 * 1024
MAX_TEXT = 4096  # also maxlength in index.html
MAX_PASSWORD = 1024
MIN_PASSWORD = 12
MAX_OUT = 4 * 1024 * 1024
MAX_FILE = 64 * 1024
MAX_WRITE = 64 * 1024 * 1024  # largest file a run may write (RLIMIT_FSIZE)
MAX_FILES = 50
MAX_FILES_BYTES = 256 * 1024  # all of /api/state's file text (NULs grow 6x in JSON)
MAX_DEPTH = 4
LOGIN_WINDOW = 600
LOGIN_FAILS = 5
# Timeouts in seconds. sign and apply have none: SIGKILL mid-apply skips its
# cleanup and leaves .<workspace>.escrow-<id> behind, which blocks every
# later apply until the world is reset.
RUN_TIMEOUT = 120
AGENT_TIMEOUT = 600
REVIEW_TIMEOUT = 900  # a cold NixOS closure build
LOCK_WAIT = 5  # how long a state read waits for a running action
# The users file has no params field: changing these locks everyone out.
SCRYPT = dict(n=2**14, r=8, p=1)


def log(msg):
    print(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), msg, file=sys.stderr, flush=True)


def scrypt(password, salt):
    return hashlib.scrypt(password.encode(), salt=salt, **SCRYPT)


def load_users(data):
    """users file: one `<name> <salt hex> <scrypt hex>` per line."""
    users = {}
    try:
        lines = (data / "users").read_text().splitlines()
    except FileNotFoundError:
        return users
    for n, line in enumerate(lines, 1):
        f = line.split()
        if len(f) != 3:
            sys.exit(f"escrow-web: {data / 'users'}:{n}: expected <name> <salt> <hash>")
        users[f[0]] = (bytes.fromhex(f[1]), bytes.fromhex(f[2]))
    return users


def read_capped(path, cap):
    """Read a regular file without following a final symlink; None if not one."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)  # no FIFO hang
    except OSError:
        return None
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            return None
        b = f.read(cap + 1)
    s = b[:cap].decode("utf-8", "replace")
    return s + "\n[truncated]" if len(b) > cap else s


def rmtree(path):
    """rm -rf that copes with the mode-000 dirs overlayfs leaves in runs/."""

    def fix(func, p, _exc):
        if func is os.open:  # a dir we couldn't open
            os.chmod(p, 0o700)
            return shutil.rmtree(p, onexc=fix)
        os.chmod(os.path.dirname(p), 0o700)
        func(p)

    if os.path.lexists(path):
        shutil.rmtree(path, onexc=fix)


def drain(p, timeout):
    """Read p's stdout and stderr, about MAX_OUT bytes each (one chunk over).

    Never communicate(): it buffers everything, and an agent controls how
    big the diff is (a 2 GB file is a 2 GB review). Past the cap or the
    timeout, kill the process group (the jail's init is in it).
    """
    bufs = {p.stdout: bytearray(), p.stderr: bytearray()}
    sel = selectors.DefaultSelector()
    for f in bufs:
        sel.register(f, selectors.EVENT_READ)
    deadline = None if timeout is None else time.monotonic() + timeout
    why = ""
    while sel.get_map() and not why:
        left = None if deadline is None else deadline - time.monotonic()
        if left is not None and left <= 0:
            why = f"killed after {timeout}s"
            break
        for k, _ in sel.select(left):
            chunk = os.read(k.fd, 65536)
            if not chunk:
                sel.unregister(k.fileobj)
                continue
            b = bufs[k.fileobj]
            b += chunk
            if len(b) > MAX_OUT:
                why = f"killed: output over {MAX_OUT} bytes"
                break
    sel.close()
    if why:
        os.killpg(p.pid, signal.SIGKILL)
    p.wait()
    out, err = bytes(bufs[p.stdout]), bytes(bufs[p.stderr])
    p.stdout.close()
    p.stderr.close()
    if why:
        err += f"\nescrow-web: {why}\n".encode()
    return out, err


def capped(b):
    """Decode output, saying so loudly if it had to be cut."""
    if len(b) <= MAX_OUT:
        return b.decode("utf-8", "replace"), False
    s = b[:MAX_OUT].decode("utf-8", "replace")
    return s + f"\n[escrow-web: output cut at {MAX_OUT} bytes: review it on the CLI]\n", True


class World:
    """The one shared demo world: keys, roles, workspace, escrow state."""

    def __init__(self, data):
        self.root = data / "world"
        self.lock = threading.Lock()
        self.busy = ""

    @property
    def keys(self):
        return self.root / "keys"

    @property
    def roles(self):
        return self.root / "roles"

    @property
    def workspace(self):
        return self.root / "ops"

    @property
    def state(self):
        return self.root / "state"

    @property
    def tmp(self):
        return self.root / "tmp"

    def reset(self):
        new = self.root.with_name("world.new")
        rmtree(new)
        (new / "keys").mkdir(parents=True, mode=0o700)
        lines = []
        for p, roles in PERSONAS.items():
            subprocess.run(
                ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", p, "-f", str(new / "keys" / p)],
                check=True,
            )
            pub = (new / "keys" / f"{p}.pub").read_text().split()[:2]
            lines.append(f"{p} {roles} {' '.join(pub)}\n")
        (new / "roles").write_text("".join(lines))
        # Copy contents only: the store copy's read-only modes stay behind.
        shutil.copytree(WORKSPACE, new / "ops", symlinks=True, copy_function=shutil.copyfile)
        for d, _, _ in os.walk(new / "ops"):
            os.chmod(d, 0o755)
        (new / "tmp").mkdir(mode=0o700)
        rmtree(self.root)
        new.rename(self.root)

    def escrow(self, args, timeout=RUN_TIMEOUT, state=None, cred=None):
        """Run escrow; {ok, code, stdout, stderr, truncated}.

        code is escrow's exit status, negative if killed by a signal (-9
        after a timeout). The Claude credential is stripped from every child
        unless asked for: escrow already scrubs the jail's env, this keeps it
        out of the host-side escrow process too.
        """
        env = {k: v for k, v in os.environ.items() if k not in ("CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY")}
        env["ESCROW_STATE"] = str(state or self.state)
        env["ESCROW_ROLES"] = str(self.roles)
        env["TMPDIR"] = str(self.tmp)  # review --closures' copies; wiped below
        if cred:
            env[cred] = os.environ[cred]
        # Own process group: the jail's init is in it, so a timeout kills all.
        p = subprocess.Popen(
            # escrow sets no rlimits or cgroups; cap each file the agent (and
            # escrow) can write. Total disk needs a capped filesystem for
            # --data (web/README.md); memory and PIDs, the systemd unit.
            ["prlimit", f"--fsize={MAX_WRITE}", ESCROW, *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            start_new_session=True,
        )
        out, err = drain(p, timeout)
        if p.returncode == -signal.SIGXFSZ:
            err += f"\nescrow-web: a file hit the {MAX_WRITE >> 20} MiB write cap; nothing was proposed\n".encode()
        for e in os.scandir(self.tmp):
            rmtree(e.path)
        stdout, t1 = capped(out)
        stderr, t2 = capped(err)
        truncated = t1 or t2
        return {"ok": p.returncode == 0 and not truncated, "code": p.returncode,
                "stdout": stdout, "stderr": stderr, "truncated": truncated}

    def run(self, args, timeout=RUN_TIMEOUT, cred=None):
        """A proposing run: ok means escrow proposed, whatever the agent exited."""
        r = self.escrow(args, timeout=timeout, cred=cred)
        lines = r["stderr"].splitlines() or [""]
        first, last = RUNDIR_RE.fullmatch(lines[0]), PROPOSED_RE.fullmatch(lines[-1])
        ok = bool(first and last and first.group(1) == last.group(1)) and not r["truncated"]
        r["id"] = last.group(1) if ok else None
        r["ok"] = ok
        return r

    def verify_tampered(self):
        """verify-log on a copy of the log with one character of line 1 changed.

        Line 2's prev field hashes line 1, so the chain breaks at line 2.
        """
        try:
            lines = (self.state / "log").read_text().splitlines(keepends=True)
        except FileNotFoundError:
            lines = []
        if len(lines) < 2:
            return {"ok": False, "code": -1, "stdout": "", "stderr": "escrow-web: the log needs 2 lines first\n",
                    "truncated": False}
        lines[0] = lines[0].replace("T", "X", 1)  # its time field (src/log.c)
        with tempfile.TemporaryDirectory(dir=self.root) as d:
            forged = Path(d)
            (forged / "log").write_text("".join(lines))
            (forged / "runs").symlink_to(self.state / "runs")
            r = self.escrow(["verify-log"], state=forged)
        note = "escrow-web: changed one character of line 1 in a copy of the log\n"
        if r["ok"]:
            note += "escrow-web: verify-log ACCEPTED the forged copy: the demo is broken\n"
        r["stderr"] = note + r["stderr"]
        r["ok"] = not r["ok"]  # ok: the forgery was caught
        return r

    def proposals(self):
        """`escrow list` rows: id, time, status, requester, cmd (src/cmd.c cmd_list).

        cmd is last and one line (record_quoted), principals have no spaces.
        """
        if not (self.state / "log").exists():  # nothing proposed yet
            return [], ""
        r = self.escrow(["list"])
        if not r["ok"]:
            return [], r["stderr"]
        rows = []
        for line in r["stdout"].splitlines():
            f = line.split(None, 4)
            f += [""] * (5 - len(f))
            rows.append(dict(zip(("id", "time", "status", "requester", "cmd"), f)))
        return rows, ""

    def files(self):
        files = []
        size = 0

        def walk(d, rel, depth):
            nonlocal size
            if depth > MAX_DEPTH:
                return
            for e in sorted(os.scandir(d), key=lambda e: e.name):
                if len(files) >= MAX_FILES or size >= MAX_FILES_BYTES:
                    files.append({"path": "…", "text": f"[more files: showing the first {len(files)}]"})
                    raise StopIteration
                r = f"{rel}{e.name}"
                if e.is_symlink():
                    files.append({"path": r, "text": f"-> {os.readlink(e.path)}"})
                elif e.is_dir(follow_symlinks=False):
                    walk(e.path, r + "/", depth + 1)
                elif e.name != "flake.lock":  # demo workspace: noise
                    t = read_capped(e.path, MAX_FILE)
                    t = "[not a regular file]" if t is None else t
                    size += len(t)
                    files.append({"path": r, "text": t})

        if self.workspace.exists():
            try:
                walk(self.workspace, "", 0)
            except StopIteration:
                pass
        return files


class App:
    def __init__(self, data):
        self.data = data
        self.world = World(data)
        self.sessions = {}
        self.fails = {}
        self.lock = threading.Lock()

    def login(self, ip, user, password):
        # Count the attempt before the slow scrypt, so concurrent guesses
        # can't all pass the limit check; a success takes it back.
        if ":" in ip:  # one IPv6 client owns a /64
            ip = str(ipaddress.ip_network(f"{ip}/64", strict=False))
        with self.lock:
            now = time.time()
            if len(self.fails) > 10000:
                self.fails = {k: v for k, v in self.fails.items() if v and now - v[-1] < LOGIN_WINDOW}
            recent = [t for t in self.fails.get(ip, []) if now - t < LOGIN_WINDOW]
            if len(recent) >= LOGIN_FAILS:
                self.fails[ip] = recent
                return None, 429
            recent.append(now)
            self.fails[ip] = recent
        users = load_users(self.data)
        # Unknown users still cost one scrypt: no timing oracle for names.
        salt, want = users.get(user, (b"\0" * 16, b"\0" * 64))
        good = hmac.compare_digest(scrypt(password, salt), want) and user in users
        with self.lock:
            if not good:
                return None, 401
            if now in self.fails.get(ip, []):
                self.fails[ip].remove(now)
            tok = secrets.token_urlsafe(32)
            self.sessions[tok] = (user, time.time() + SESSION_TTL)
            return tok, 200

    def session(self, tok):
        with self.lock:
            s = self.sessions.get(tok)
            if s and s[1] > time.time():
                return s[0]
            self.sessions.pop(tok, None)
            return None


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "escrow-web"
    sys_version = ""
    timeout = 30  # per-connection socket timeout
    app: App
    user = "-"

    # ---- plumbing

    def send(self, code, obj, cookie=None, ctype="application/json"):
        body = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
            "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        )
        if cookie is not None:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def client_ip(self):
        ip = self.client_address[0]
        fwd = self.headers.get("X-Forwarded-For")
        # Assumes exactly one local reverse proxy that appends the client
        # address (Caddy); anything else on loopback could spoof this.
        if fwd and ip == "127.0.0.1":
            ip = fwd.split(",")[-1].strip()
        return ip

    def cookie_token(self):
        # By hand: SimpleCookie drops the whole header on one bad cookie.
        for part in self.headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "sid":
                return v
        return ""

    def log_message(self, fmt, *args):
        log(f"{self.client_ip()} {self.user} {fmt % args}")

    def body(self):
        # A custom header + JSON content type: a cross-site form can't send
        # either without a CORS preflight, which this server never answers.
        if self.headers.get("X-Escrow") != "1":
            return None
        if not self.headers.get("Content-Type", "").startswith("application/json"):
            return None
        try:
            n = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return None
        if not 0 <= n <= MAX_BODY:
            return None
        try:
            obj = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return None
        return obj if isinstance(obj, dict) else None

    # ---- routes

    def do_GET(self):
        url = urllib.parse.urlsplit(self.path)
        if url.path in PAGES:
            name, ctype = PAGES[url.path]
            return self.send(200, (STATIC / name).read_bytes(), ctype=ctype)
        self.user = self.app.session(self.cookie_token()) or "-"
        if self.user == "-":
            return self.send(401, {"error": "not logged in"})
        w = self.app.world
        if url.path == "/api/state":
            return self.send_locked(self.state, wait=True)
        if url.path == "/api/agentlog":
            rid = urllib.parse.parse_qs(url.query).get("id", [""])[0]
            if not ID_RE.fullmatch(rid):
                return self.send(400, {"error": "bad id"})
            # The one place web/ reads escrow's state layout directly
            # (src/overlay.c: runs/<id>/log).
            t = read_capped(w.state / "runs" / rid / "log", MAX_OUT)
            return self.send(200, {"text": t if t is not None else ""})
        self.send(404, {"error": "not found"})

    def state(self):
        w = self.app.world
        proposals, error = w.proposals()
        return {
            "user": self.user,
            "personas": PERSONAS,
            "claude": CRED is not None,
            "ticket": TICKET,
            "proposals": proposals,
            "error": error,
            "files": w.files(),
            "log": read_capped(w.state / "log", MAX_OUT) or "",
        }

    def do_POST(self):
        path = urllib.parse.urlsplit(self.path).path
        req = self.body()
        if req is None:
            return self.send(400, {"error": "bad request"})
        if path == "/api/login":
            return self.login(req)

        tok = self.cookie_token()
        self.user = self.app.session(tok) or "-"
        if self.user == "-":
            return self.send(401, {"error": "not logged in"})
        if path == "/api/logout":
            with self.app.lock:
                self.app.sessions.pop(tok, None)
            return self.send(200, {}, cookie="sid=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0")

        w = self.app.world
        persona, rid = req.get("persona"), req.get("id")
        if persona is not None and not (isinstance(persona, str) and persona in PERSONAS):
            return self.send(400, {"error": "unknown persona"})
        if rid is not None and not (isinstance(rid, str) and ID_RE.fullmatch(rid)):
            return self.send(400, {"error": "bad id"})
        key = str(w.keys / persona) if persona else None
        log(f"{self.client_ip()} {self.user} as {persona or '-'}: {path} {rid or ''}")

        if path == "/api/reset":
            return self.send_locked(lambda: (w.reset(), {"ok": True, "stderr": "escrow-web: fresh world\n"})[1])
        if path == "/api/verify":
            if req.get("tamper") is True:
                return self.send_locked(w.verify_tampered)
            return self.send_locked(lambda: w.escrow(["verify-log"]))
        if path == "/api/run":
            return self.run(req, key)
        if rid is None:
            return self.send(400, {"error": "bad request"})
        closures = ["--closures"] if req.get("closures") is True else []
        if path == "/api/view":  # no --key: shows the diff, logs nothing
            return self.send_locked(lambda: w.escrow(["review", rid, *closures], timeout=REVIEW_TIMEOUT))
        if key is None:
            return self.send(400, {"error": "pick a persona"})
        if path == "/api/review":  # --key: signs a review into the log
            return self.send_locked(lambda: w.escrow(["review", rid, "--key", key, *closures], timeout=REVIEW_TIMEOUT))
        if path in ("/api/sign", "/api/apply"):
            cmd = {"/api/sign": "sign", "/api/apply": "apply"}[path]
            return self.send_locked(lambda: w.escrow([cmd, rid, "--key", key], timeout=None))
        self.send(400, {"error": "bad request"})

    def login(self, req):
        user, pw = req.get("user"), req.get("password")
        if not (isinstance(user, str) and USER_RE.fullmatch(user)
                and isinstance(pw, str) and len(pw) <= MAX_PASSWORD):
            return self.send(400, {"error": "bad request"})
        tok, code = self.app.login(self.client_ip(), user, pw)
        log(f"{self.client_ip()} {user} login {'ok' if tok else 'failed'}")
        if not tok:
            return self.send(code, {"error": "too many attempts" if code == 429 else "wrong user or password"})
        ck = f"sid={tok}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={SESSION_TTL}"
        self.send(200, {"user": user}, cookie=ck)

    def run(self, req, key):
        w = self.app.world
        mode, text = req.get("mode"), req.get("text", "")
        if key is None or not isinstance(text, str) or len(text) > MAX_TEXT:
            return self.send(400, {"error": "bad request"})
        base = ["--key", key, "--workspace", str(w.workspace)]
        if mode == "ticket":
            return self.send_locked(lambda: w.run(["--role", ROLE_DEMO, *base, "--", "ops-ticket"]))
        if mode == "command" and text.strip():
            return self.send_locked(lambda: w.run(["--role", ROLE_DEMO, *base, "--", "bash", "-c", text]))
        if mode == "claude" and text.strip():
            if CRED is None:
                return self.send(400, {"error": "no Claude credential on this server"})
            # Skipping Claude's permission prompts is fine: the jail is the
            # boundary (role-claude closure, Landlock, TCP 443 only). `--`
            # keeps a prompt like "--help" from being read as a flag.
            return self.send_locked(lambda: w.run(
                ["--role", ROLE_CLAUDE, *base, "--net", "--env", CRED, "--",
                 "claude", "-p", "--dangerously-skip-permissions", "--", text],
                timeout=AGENT_TIMEOUT, cred=CRED))
        self.send(400, {"error": "bad request"})

    def do_PUT(self):
        # Without this, http.server answers 501 with an HTML page and none
        # of our headers.
        self.send(405, {"error": "method not allowed"})

    do_DELETE = do_PATCH = do_PUT

    def send_locked(self, fn, wait=False):
        """Run fn with the world to ourselves and send its result."""
        w = self.app.world
        if not w.lock.acquire(timeout=LOCK_WAIT if wait else 0):
            return self.send(409, {"error": f"busy: {w.busy}"})
        try:
            w.busy = f"{self.user}: {urllib.parse.urlsplit(self.path).path}"
            if not w.root.exists():
                w.reset()
            res = fn()
        except Exception as e:
            log(f"escrow-web: {self.path} failed:\n{traceback.format_exc()}")
            return self.send(500, {"error": f"escrow-web: {self.path} failed: {e}"})
        finally:
            w.busy = ""
            w.lock.release()
        self.send(200, res)


def main():
    ap = argparse.ArgumentParser(prog="escrow-web")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--data", type=Path, required=True)
    s.add_argument("--listen", default="127.0.0.1:8080")
    pw = sub.add_parser("passwd")
    pw.add_argument("--data", type=Path, required=True)
    pw.add_argument("user")
    a = ap.parse_args()
    a.data.mkdir(parents=True, exist_ok=True, mode=0o700)

    if a.cmd == "passwd":
        if not USER_RE.fullmatch(a.user):
            sys.exit(f"escrow-web: bad user name {a.user!r}")
        p1 = getpass.getpass(f"password for {a.user}: ")
        if len(p1) < MIN_PASSWORD:
            sys.exit(f"escrow-web: password shorter than {MIN_PASSWORD} characters")
        if p1 != getpass.getpass("again: "):
            sys.exit("escrow-web: passwords differ")
        salt = secrets.token_bytes(16)
        users = {u: v for u, v in load_users(a.data).items() if u != a.user}
        users[a.user] = (salt, scrypt(p1, salt))
        tmp = a.data / "users.tmp"
        with os.fdopen(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
            f.writelines(f"{u} {s.hex()} {d.hex()}\n" for u, (s, d) in users.items())
        os.replace(tmp, a.data / "users")
        print(f"escrow-web: set password for {a.user}")
        return

    for name, v in (("ESCROW_WEB_ROLE_DEMO", ROLE_DEMO), ("ESCROW_WEB_WORKSPACE", WORKSPACE)):
        if not v:
            sys.exit(f"escrow-web: {name} not set (run it with `nix run .#web`)")
    if not load_users(a.data):
        sys.exit(f"escrow-web: no users; run `escrow-web passwd --data {a.data} <user>` first")
    host, _, port = a.listen.rpartition(":")
    Handler.app = App(a.data)
    srv = http.server.ThreadingHTTPServer((host, int(port)), Handler)
    log(f"escrow-web: listening on {a.listen}, data in {a.data}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
