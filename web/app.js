// escrow-web client. Everything from the server, including agent-written
// diffs and output, is rendered with textContent: never as HTML.
"use strict";

const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];
const TOAST_MS = 5000;
const TOAST_BAD_MS = 9000;
const POLL_MS = 15000;
// escrow's messages: err(3)/warnx(3) prefix them with the program name,
// which stays "escrow" because the Nix wrapper execs with `-a "$0"`.
const ESCROW_LINE = /^escrow(-web)?: /;
let state = null; // last /api/state
let persona = "alice";
let mode = "ticket";
let selected = null;
let inflight = false;

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

function toast(msg, kind) {
  const t = el("div", "toast " + kind, msg);
  $("#toasts").append(t);
  setTimeout(() => t.remove(), kind === "bad" ? TOAST_BAD_MS : TOAST_MS);
}

async function api(method, path, body) {
  const opt = { method, headers: { "X-Escrow": "1" } };
  if (body) {
    opt.headers["Content-Type"] = "application/json";
    opt.body = JSON.stringify(body);
  }
  const r = await fetch(path, opt);
  const j = await r.json().catch(() => ({ error: "bad response" }));
  if (r.status === 401 && path !== "/api/login") show(false);
  if (!r.ok) throw new Error(j.error || r.statusText);
  return j;
}

function show(app) {
  $("#app").hidden = !app;
  $("#login").hidden = app;
}

// ---- escrow output: its stderr lines become toasts

function report(res, out) {
  const lines = (res.stderr || "").split("\n").filter((l) => ESCROW_LINE.test(l));
  const last = lines[lines.length - 1] || (res.ok ? "done" : `exit ${res.code}`);
  toast(last.replace(ESCROW_LINE, ""), res.ok ? "good" : "bad");
  if (res.truncated) toast("output was cut: don't sign from here, review it on the CLI", "bad");
  if (out) {
    out.hidden = false;
    out.className = "out " + (res.ok ? "good" : "bad");
    out.textContent = (res.stdout || "") + (res.stderr || "");
  }
}

async function act(btn, fn) {
  if (inflight) return;
  inflight = true;
  document.body.classList.add("busy");
  const label = btn.textContent;
  const t0 = Date.now();
  const tick = setInterval(() => (btn.textContent = `${label} · ${Math.round((Date.now() - t0) / 1000)}s`), 1000);
  try {
    await fn();
  } catch (e) {
    toast(e.message, "bad");
  } finally {
    clearInterval(tick);
    btn.textContent = label;
    inflight = false;
    document.body.classList.remove("busy");
    refresh();
  }
}

// ---- rendering

function renderPersonas() {
  const box = $("#personas");
  box.replaceChildren();
  for (const [name, roles] of Object.entries(state.personas)) {
    const c = el("button", "persona" + (name === persona ? " on" : ""));
    c.append(el("span", "persona-name", name), el("span", "persona-roles", roles.split(",").join(" · ")));
    c.onclick = () => {
      persona = name;
      renderPersonas();
      markOffRole();
    };
    box.append(c);
  }
}

// Struck-through buttons are outside the persona's role. They still work, so
// you can watch escrow refuse. A hint only: escrow enforces the rules
// (src/cmd.c), including no self-review.
function markOffRole() {
  const prop = selected && state.proposals.find((x) => x.id === selected);
  for (const b of $$("[data-need]")) {
    let ok = state.personas[persona].split(",").includes(b.dataset.need);
    let why = `${persona} is not a ${b.dataset.need}`;
    if (ok && b.id === "review" && prop && prop.requester === persona) {
      ok = false;
      why = `${persona} requested this: no self-review`;
    }
    b.classList.toggle("off-role", !ok);
    b.title = ok ? "" : why + " (escrow will refuse)";
  }
}

function select(id) {
  selected = id;
  $("#diff").replaceChildren();
  $("#detail-out").hidden = true;
  renderProposals();
}

function renderProposals() {
  const tb = $("#proposals tbody");
  tb.replaceChildren();
  $("#no-proposals").hidden = state.proposals.length > 0;
  $("#proposals").hidden = state.proposals.length === 0;
  for (const p of [...state.proposals].reverse()) {
    const tr = el("tr", p.id === selected ? "on" : "");
    tr.append(el("td", "mono", p.id));
    const s = el("td");
    s.append(el("span", "badge " + p.status, p.status));
    tr.append(s, el("td", "", p.requester), el("td", "mono", p.cmd), el("td", "fine", p.time.replace("T", " ")));
    tr.onclick = () => act($("#view"), async () => (select(p.id), showDiff()));
    tb.append(tr);
  }
  $("#detail").hidden = !selected;
  markOffRole();
}

// The layout of `escrow review` (src/cmd.c render()): a header until the
// first "M|A|D path" line, unified diffs, then `nix store diff-closures`
// lines ("name: change").
function renderDiff(text) {
  const box = $("#diff");
  box.replaceChildren();
  let head = true;
  for (const line of text.split("\n")) {
    let cls = "ctx";
    if (/^[MAD] \S/.test(line)) {
      head = false;
      cls = "file";
    } else if (head) cls = "head";
    else if (line.startsWith("+++") || line.startsWith("---")) cls = "meta";
    else if (line.startsWith("@@")) cls = "hunk";
    else if (line.startsWith("+")) cls = "add";
    else if (line.startsWith("-")) cls = "del";
    else if (line.startsWith("closure diff")) cls = "file";
    else if (/^\S+: /.test(line)) cls = "closure";
    box.append(el("div", "diff-line " + cls, line || " "));
  }
}

function renderFiles() {
  const box = $("#files");
  const open = new Set($$("#files details[open] summary").map((s) => s.textContent));
  box.replaceChildren();
  for (const f of state.files) {
    const d = el("details");
    d.open = open.size ? open.has(f.path) : f.path === "configuration.nix";
    d.append(el("summary", "mono", f.path), el("pre", "file-body", f.text));
    box.append(d);
  }
}

async function refresh() {
  try {
    state = await api("GET", "/api/state");
  } catch (e) {
    if (e.message.startsWith("busy")) return;
    throw e;
  }
  $("#user").textContent = state.user;
  $("#ticket").textContent = state.ticket;
  if (!$("#prompt").value) $("#prompt").value = state.ticket;
  $("#no-claude").hidden = state.claude;
  if (state.error) toast("escrow list failed: " + state.error, "bad");
  if (selected && !state.proposals.some((p) => p.id === selected)) selected = null;
  renderPersonas();
  renderProposals();
  renderFiles();
  $("#log").textContent = state.log || "(empty: nothing has happened yet)";
}

// ---- actions

// Read-only: /api/view never signs. Renders only if the selection is still
// the one asked about.
async function showDiff() {
  const id = selected;
  const res = await api("POST", "/api/view", { id, closures: $("#closures").checked });
  if (selected !== id) return;
  renderDiff(res.stdout);
  if (!res.ok) report(res, $("#detail-out"));
}

$("#login-form").onsubmit = async (ev) => {
  ev.preventDefault();
  const f = new FormData(ev.target);
  try {
    await api("POST", "/api/login", { user: f.get("user"), password: f.get("password") });
    show(true);
    await refresh();
  } catch (e) {
    toast(e.message, "bad");
  }
};
$("#logout").onclick = async () => {
  await api("POST", "/api/logout", {}).catch(() => {});
  show(false);
};
for (const t of $$(".tab"))
  t.onclick = () => {
    mode = t.dataset.mode;
    for (const x of $$(".tab")) x.classList.toggle("on", x === t);
    for (const p of $$(".pane")) p.hidden = p.dataset.pane !== mode;
  };
$("#run").onclick = () =>
  act($("#run"), async () => {
    const text = mode === "claude" ? $("#prompt").value : mode === "command" ? $("#command").value : "";
    const res = await api("POST", "/api/run", { persona, mode, text });
    report(res, $("#run-out"));
    if (res.id) {
      select(res.id);
      await showDiff();
    }
  });
$("#view").onclick = () => act($("#view"), showDiff);
$("#review").onclick = () =>
  act($("#review"), async () => {
    const id = selected;
    const res = await api("POST", "/api/review", { id, persona, closures: $("#closures").checked });
    if (selected === id && res.stdout) renderDiff(res.stdout);
    report(res, $("#detail-out"));
  });
for (const id of ["sign", "apply"])
  $("#" + id).onclick = () =>
    act($("#" + id), async () => report(await api("POST", "/api/" + id, { id: selected, persona }), $("#detail-out")));
$("#agent-log").onclick = () =>
  act($("#agent-log"), async () => {
    const r = await api("GET", "/api/agentlog?id=" + encodeURIComponent(selected));
    const o = $("#detail-out");
    o.hidden = false;
    o.className = "out";
    o.textContent = r.text || "(the agent printed nothing)";
  });
$("#verify").onclick = () => act($("#verify"), async () => report(await api("POST", "/api/verify", {}), $("#verify-out")));
$("#tamper").onclick = () =>
  act($("#tamper"), async () => report(await api("POST", "/api/verify", { tamper: true }), $("#verify-out")));
$("#reset").onclick = () => {
  if (!confirm("Throw away all proposals, keys, the workspace and the log?")) return;
  act($("#reset"), async () => {
    select(null);
    for (const o of $$(".out")) o.hidden = true;
    report(await api("POST", "/api/reset", {}));
  });
};

// 401 shows the login page (api() does that); anything else, e.g. busy,
// shows the app and the poll fills it in.
refresh().then(
  () => show(true),
  (e) => e.message !== "not logged in" && (show(true), toast(e.message, "bad")),
);
setInterval(() => !inflight && !$("#app").hidden && refresh().catch(() => {}), POLL_MS);
