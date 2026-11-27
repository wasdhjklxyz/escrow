// escrow-web client. Everything from the server, including agent-written
// diffs and output, is rendered with textContent: never as HTML.
"use strict";

const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];
const TOAST_MS = 5000;
const TOAST_BAD_MS = 9000;
const POLL_MS = 15000;
const MAX_ACTIVITY = 50;
// escrow's messages: err(3)/warnx(3) prefix them with the program name,
// which stays "escrow" because the Nix wrapper execs with `-a "$0"`.
const ESCROW_LINE = /^escrow(-web)?: /;
const STEPS = [
  ["propose", "Proposed", "requester"],
  ["review", "Reviewed", "reviewer"],
  ["sign", "Signed", "signer"],
  ["apply", "Applied", "signer"],
];
const MODES = { ticket: "Ticket OPS-142", claude: "Claude Code", command: "a command" };
let state = null; // last /api/state
let persona = "alice";
let mode = "ticket";
let selected = null;
let inflight = false;
// Verify log passing for this exact log text is what makes the approval chain
// "checked"; anything appended or changed since makes it unchecked again.
let verifiedLog = null;
let pendingVerify = null; // event count verify-log reported, applied on refresh
let verdictLog = null; // the log text the verdict badge was shown for

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

const clock = () => new Date().toISOString().slice(11, 19); // UTC, like the log
const short = (h) => (h && h.length > 12 ? h.slice(0, 10) + "…" : h || "");

function toast(msg, kind) {
  const t = el("div", "toast " + kind, msg);
  $("#toasts").append(t);
  setTimeout(() => t.remove(), kind === "bad" ? TOAST_BAD_MS : TOAST_MS);
}

function activity(what, msg, ok) {
  const li = el("li", ok ? "good" : "bad");
  li.append(el("span", "t", clock()), el("span", "w", what), el("span", "m", msg));
  $("#activity").prepend(li);
  while ($("#activity").children.length > MAX_ACTIVITY) $("#activity").lastChild.remove();
  $("#no-activity").hidden = true;
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

// ---- escrow output: its last stderr line is the verdict

function verdict(res) {
  const lines = (res.stderr || "").split("\n").filter((l) => ESCROW_LINE.test(l));
  // verify-log reports success on stdout ("ok: N events, head ...").
  const fallback = (res.stdout || "").trim().split("\n")[0] || (res.ok ? "done" : `exit ${res.code}`);
  return (lines[lines.length - 1] || fallback).replace(ESCROW_LINE, "").replace(/\b([0-9a-f]{10})[0-9a-f]{54}\b/g, "$1…");
}

// out: where the full output goes; errOnly puts only stderr there (the diff
// pane already shows a review's stdout).
function report(what, res, out, errOnly = false, prefix = "") {
  const msg = prefix + verdict(res);
  toast(msg, res.ok ? "good" : "bad");
  activity(what, msg, res.ok);
  if (res.truncated) toast("output was cut: don't sign from here, review it on the CLI", "bad");
  if (out) {
    out.hidden = false;
    out.className = "out " + (res.ok ? "good" : "bad");
    out.textContent = (errOnly ? "" : res.stdout || "") + (res.stderr || "");
  }
  return msg;
}

async function act(btn, fn, what = btn.textContent) {
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
    activity(what, e.message, false);
  } finally {
    clearInterval(tick);
    btn.textContent = label;
    inflight = false;
    document.body.classList.remove("busy");
    refresh();
  }
}

// ---- the log: one line per event (docs/FORMATS.md, "Log")
// <seq> <time> <event> <id> <principal> <record-sha> <sig-sha> <extra> <roles-sha> <prev>

function logEvents() {
  return (state.log || "")
    .split("\n")
    .filter(Boolean)
    .map((l) => {
      const f = l.split(" ");
      return f.length === 10 ? { seq: f[0], time: f[1], event: f[2], id: f[3], who: f[4], sig: f[6], prev: f[9] } : null;
    })
    .filter(Boolean);
}

// ---- rendering

function renderPersonas() {
  const box = $("#personas");
  box.replaceChildren();
  for (const [name, p] of Object.entries(state.personas)) {
    const c = el("button", "persona" + (name === persona ? " on" : ""));
    c.append(
      el("span", "persona-name", name),
      el("span", "persona-roles", p.roles.split(",").join(" · ")),
      el("span", "persona-key", p.key),
    );
    c.title = `${name}'s SSH key: ${p.key}`;
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
    let ok = state.personas[persona].roles.split(",").includes(b.dataset.need);
    let why = `${persona} is not a ${b.dataset.need}`;
    if (ok && b.id === "review" && prop && prop.requester === persona) {
      ok = false;
      why = `${persona} requested it: no self-review`;
    }
    b.classList.toggle("off-role", !ok);
    b.title = ok ? "" : why + " (escrow will refuse)";
  }
}

function select(id) {
  selected = id;
  clearDiff();
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
    tr.append(s, el("td", "", p.requester), el("td", "mono cmd", p.cmd), el("td", "fine", p.time.replace("T", " ").replace("Z", "")));
    tr.onclick = () => act($("#view"), async () => (select(p.id), showDiff()));
    tb.append(tr);
  }
  $("#detail").hidden = !selected;
  renderChain();
  markOffRole();
}

// Who did each step of the selected proposal, straight from the log.
function renderChain() {
  const box = $("#chain");
  box.replaceChildren();
  if (!selected) return;
  const ev = logEvents().filter((e) => e.id === selected);
  const checked = verifiedLog !== null && verifiedLog === state.log;
  const note = $("#chain-note");
  note.textContent = checked
    ? "✓ Every signature above was checked by Verify log."
    : "Read from the audit log, signatures not checked yet: press Verify log in (04).";
  note.className = checked ? "fine good" : "fine";
  let next = true;
  for (const [event, label, role] of STEPS) {
    const e = ev.find((x) => x.event === event);
    const li = el("li", e ? "done" : next ? "next" : "");
    li.append(el("span", "step", label));
    if (e) {
      li.append(el("span", "by", e.who), el("span", "when", e.time.slice(11, 19) + " · log line " + e.seq));
    } else {
      li.append(el("span", "by", next ? `waiting for a ${role}` : ""), el("span", "when", ""));
      next = false;
    }
    box.append(li);
  }
}

// The layout of `escrow review` (src/cmd.c render()): a header, then per
// file an "M|A|D path ..." line, "--- a" / "+++ b" and unified-diff hunks;
// with --closures, a "closure diff: ..." line and nix's own output.
// Hunks are walked by their @@ line counts, so an added line that starts
// with "++" is still an addition. Everything after "closure diff" is nix
// output (an agent's Nix code can print there) and is never styled as diff.
function renderDiff(text) {
  const box = $("#diff");
  box.replaceChildren();
  let mode = "head"; // head | file | hunk | closure
  let oldLeft = 0,
    newLeft = 0;
  const n = { M: 0, A: 0, D: 0, add: 0, del: 0 };
  for (const line of text.split("\n")) {
    let cls = null;
    if (mode === "hunk") {
      const c = line[0];
      if (c === "+") (cls = "add"), n.add++, newLeft--;
      else if (c === "-") (cls = "del"), n.del++, oldLeft--;
      else if (c === " ") (cls = "ctx"), oldLeft--, newLeft--;
      else if (c === "\\") cls = "meta";
      if (!cls || (oldLeft <= 0 && newLeft <= 0)) mode = "file";
    }
    if (!cls) {
      if (mode === "closure") cls = "closure";
      else if (line.startsWith("closure diff")) (mode = "closure"), (cls = "file");
      else if (/^[MAD] \S/.test(line)) (mode = "file"), (cls = "file"), n[line[0]]++;
      else if (mode === "head") cls = "head";
      else if (line.startsWith("@@")) {
        const m = /^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@/.exec(line);
        cls = "hunk";
        if (m) {
          oldLeft = m[1] === undefined ? 1 : +m[1];
          newLeft = m[2] === undefined ? 1 : +m[2];
          if (oldLeft || newLeft) mode = "hunk";
        }
      } else if (line.startsWith("--- ") || line.startsWith("+++ ")) cls = "meta";
      else cls = "ctx";
    }
    box.append(el("div", "diff-line " + cls, line || " "));
  }
  const files = n.M + n.A + n.D;
  const kinds = [n.M && `${n.M} modified`, n.A && `${n.A} added`, n.D && `${n.D} deleted`].filter(Boolean);
  $("#diff-stat").replaceChildren(
    el("span", "", `${files} file${files === 1 ? "" : "s"}${kinds.length ? " (" + kinds.join(", ") + ")" : ""} · lines `),
    el("span", "plus", `+${n.add}`),
    el("span", "", " "),
    el("span", "minus", `−${n.del}`),
  );
  $("#diff-stat").hidden = false;
}

function clearDiff() {
  $("#diff").replaceChildren();
  $("#diff-stat").hidden = true;
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

function renderLog() {
  const tb = $("#log tbody");
  tb.replaceChildren();
  const ev = logEvents();
  $("#no-log").hidden = ev.length > 0;
  $("#log").hidden = ev.length === 0;
  for (const e of ev) {
    const tr = el("tr", e.id === selected ? "on" : "");
    const ev_ = el("td");
    ev_.append(el("span", "badge " + e.event, (STEPS.find((s) => s[0] === e.event) || [, e.event])[1].toLowerCase()));
    tr.append(
      el("td", "mono", e.seq),
      el("td", "fine", e.time.replace("T", " ").replace("Z", "")),
      ev_,
      el("td", "mono", e.id),
      el("td", "", e.who),
      el("td", "mono fine", short(e.sig)),
      el("td", "mono fine", short(e.prev)),
    );
    tb.append(tr);
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
  if (pendingVerify !== null) verifiedLog = logEvents().length === pendingVerify ? state.log : null;
  pendingVerify = null;
  if (verdictLog !== null && verdictLog !== state.log) $("#verdict").hidden = true;
  renderPersonas();
  renderProposals();
  renderFiles();
  renderLog();
}

// ---- actions

// Read-only: /api/view never signs. Renders only if the selection is still
// the one asked about.
async function showDiff() {
  const id = selected;
  const res = await api("POST", "/api/view", { id, closures: $("#closures").checked });
  if (selected !== id) return;
  if (res.ok) return renderDiff(res.stdout);
  clearDiff();
  report(`View diff ${id}`, res, $("#detail-out"), true);
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
$("#clear-activity").onclick = () => {
  $("#activity").replaceChildren();
  $("#no-activity").hidden = false;
};
for (const t of $$(".tab"))
  t.onclick = () => {
    mode = t.dataset.mode;
    for (const x of $$(".tab")) x.classList.toggle("on", x === t);
    for (const p of $$(".pane")) p.hidden = p.dataset.pane !== mode;
  };
$("#run").onclick = () =>
  act($("#run"), async () => {
    const who = persona,
      how = mode;
    const text = how === "claude" ? $("#prompt").value : how === "command" ? $("#command").value : "";
    const res = await api("POST", "/api/run", { persona: who, mode: how, text });
    const msg = report(`${who}: run ${MODES[how]}`, res, $("#run-out"));
    $("#run-details").hidden = false;
    $("#run-summary").textContent = (res.ok ? "✓ " : "✕ ") + msg + (res.ok && res.code ? ` (agent exited ${res.code})` : "");
    $("#run-summary").className = res.ok ? "good" : "bad";
    if (res.id) {
      select(res.id);
      await showDiff();
    }
  });
$("#view").onclick = () => act($("#view"), showDiff);
$("#review").onclick = () =>
  act($("#review"), async () => {
    const id = selected,
      who = persona;
    const res = await api("POST", "/api/review", { id, persona: who, closures: $("#closures").checked });
    if (selected === id && res.ok) renderDiff(res.stdout);
    $("#detail-out").hidden = true;
    report(`${who}: review ${id}`, res, res.ok ? null : $("#detail-out"), true);
  });
for (const id of ["sign", "apply"])
  $("#" + id).onclick = () =>
    act($("#" + id), async () => {
      const prop = selected,
        who = persona;
      const res = await api("POST", "/api/" + id, { id: prop, persona: who });
      $("#detail-out").hidden = true;
      report(`${who}: ${id} ${prop}`, res, res.ok ? null : $("#detail-out"), true);
    });
$("#agent-log").onclick = () =>
  act($("#agent-log"), async () => {
    const r = await api("GET", "/api/agentlog?id=" + encodeURIComponent(selected));
    const o = $("#detail-out");
    o.hidden = false;
    o.className = "out";
    o.textContent = r.text || "(the agent printed nothing)";
  });

function showVerdict(res, tampered) {
  const v = $("#verdict");
  v.hidden = false;
  v.className = "verdict " + (res.ok ? "good" : "bad");
  const last = verdict(res);
  v.textContent = (res.ok ? "✓ " : "✕ ") + (tampered && res.ok ? "forgery caught · " : "") + last;
  verdictLog = state.log;
}
$("#verify").onclick = () =>
  act($("#verify"), async () => {
    const res = await api("POST", "/api/verify", {});
    const m = /^ok: (\d+) events/.exec(res.stdout || "");
    pendingVerify = res.ok && m ? +m[1] : null;
    if (!res.ok) verifiedLog = null;
    if (res.ok) res.stdout = "log intact · " + res.stdout.replace(/^ok: /, "");
    report("Verify log", res, res.ok ? null : $("#verify-out"));
    if (res.ok) $("#verify-out").hidden = true;
    showVerdict(res, false);
  });
$("#tamper").onclick = () =>
  act($("#tamper"), async () => {
    const res = await api("POST", "/api/verify", { tamper: true });
    report("Tamper with history, then verify", res, $("#verify-out"), false, res.ok ? "forgery caught · " : "");
    showVerdict(res, true);
  });
$("#reset").onclick = () => {
  if (!confirm("Throw away all proposals, keys, the workspace and the audit log?")) return;
  act($("#reset"), async () => {
    select(null);
    for (const o of $$(".out")) o.hidden = true;
    $("#run-details").hidden = true;
    $("#verdict").hidden = true;
    report("Reset the demo world", await api("POST", "/api/reset", {}));
  });
};

// 401 shows the login page (api() does that); anything else, e.g. busy,
// shows the app and the poll fills it in.
refresh().then(
  () => show(true),
  (e) => e.message !== "not logged in" && (show(true), toast(e.message, "bad")),
);
setInterval(() => !inflight && !$("#app").hidden && refresh().catch(() => {}), POLL_MS);
