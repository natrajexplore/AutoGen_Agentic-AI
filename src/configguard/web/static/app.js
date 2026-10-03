// ConfigGuard UI. All config- and agent-derived text is inserted with textContent (via el()),
// never innerHTML: config descriptions/banners are untrusted and may carry injection payloads.
"use strict";

const AGENTS = ["ConfigParser", "ComplianceChecker", "RemediationEngineer", "Critic", "HumanApprover"];
const AGENT_COLOR = {
  ConfigParser: "var(--a-parser)", ComplianceChecker: "var(--a-checker)",
  RemediationEngineer: "var(--a-remed)", Critic: "var(--a-critic)", HumanApprover: "var(--a-human)",
};
const $ = (sel, root = document) => root.querySelector(sel);

// --------------------------------------------------------------------------- helpers

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") node.className = v;
    else if (k === "style") node.style.cssText = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

const badge = (text, cls) => el("span", { class: `badge ${cls || text}` }, text);
const statusBadge = (s) => badge(s === "NOT_APPLICABLE" ? "N/A" : s, s);
const money = (v) => `$${(v || 0).toFixed(4)}`;
const secs = (v) => `${Math.round(v || 0)}s`;

function toast(message, ms = 4000) {
  const t = el("div", { class: "toast", role: "status" }, message);
  document.body.append(t);
  setTimeout(() => t.remove(), ms);
}

async function api(path, options) {
  const res = await fetch(path, options);
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail || detail; } catch { /* not json */ }
    throw new Error(detail);
  }
  return res.headers.get("content-type")?.includes("json") ? res.json() : res.text();
}

function pretty(text) {
  if (typeof text !== "string") return JSON.stringify(text, null, 2);
  try { return JSON.stringify(JSON.parse(text), null, 2); } catch { return text; }
}

function parseJSON(text) {
  try { return JSON.parse(text); } catch { return null; }
}

// --------------------------------------------------------------------------- tabs + header

for (const tab of document.querySelectorAll(".tab")) {
  tab.addEventListener("click", () => showView(tab.dataset.view));
}

function showView(name) {
  for (const t of document.querySelectorAll(".tab")) t.classList.toggle("active", t.dataset.view === name);
  for (const v of document.querySelectorAll(".view")) v.classList.toggle("hidden", v.id !== `view-${name}`);
  if (name === "history") loadHistory();
  if (name === "baseline") loadBaseline();
}

async function loadInfo() {
  const info = await api("/api/info");
  const meta = $("#meta");
  meta.replaceChildren(
    el("span", { class: "chip" }, `${info.provider} · ${info.model}`),
    el("span", { class: "chip" }, info.baseline),
  );
  $("#key-warning").classList.toggle("hidden", info.api_key_configured);
}

// --------------------------------------------------------------------------- config picker

let configs = [];

async function loadConfigs(selectId) {
  configs = await api("/api/configs");
  renderConfigs(selectId);
}

function renderConfigs(selectId) {
  const filter = $("#config-filter").value.toLowerCase();
  const checked = new Set(selectedConfigs());
  if (selectId) checked.add(selectId);
  const list = $("#config-list");
  list.replaceChildren(...configs
    .filter((c) => c.name.toLowerCase().includes(filter))
    .map((c) => el("li", {},
      el("label", {},
        el("input", { type: "checkbox", value: c.id, checked: checked.has(c.id), onchange: updateRunButton }),
        el("span", { class: "name", title: c.name }, c.name),
        el("span", { class: "src" }, c.source === "uploads" ? "uploaded" : ""),
      ))));
  updateRunButton();
}

function selectedConfigs() {
  return [...document.querySelectorAll("#config-list input:checked")].map((i) => i.value);
}

function updateRunButton() {
  const n = selectedConfigs().length;
  const btn = $("#run-btn");
  btn.disabled = n === 0 || running;
  btn.textContent = n > 1 ? `Run batch (${n} configs)` : "Run audit";
}

$("#config-filter").addEventListener("input", () => renderConfigs());
$("#select-all").addEventListener("click", () => {
  for (const i of document.querySelectorAll("#config-list input")) i.checked = true;
  updateRunButton();
});
$("#select-none").addEventListener("click", () => {
  for (const i of document.querySelectorAll("#config-list input")) i.checked = false;
  updateRunButton();
});
$("#upload").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const form = new FormData();
  form.append("file", file);
  try {
    const saved = await api("/api/configs", { method: "POST", body: form });
    toast(`Uploaded ${saved.name}`);
    await loadConfigs(saved.id);
  } catch (err) {
    toast(`Upload failed: ${err.message}`);
  }
  e.target.value = "";
});

// --------------------------------------------------------------------------- pipeline strip

function resetPipeline() {
  for (const node of document.querySelectorAll(".agent-node")) {
    node.classList.remove("active", "done");
    $(".count", node).textContent = "";
  }
}

const toolCounts = {};
function setActiveAgent(agent) {
  if (!AGENTS.includes(agent)) return;
  const idx = AGENTS.indexOf(agent);
  for (const node of document.querySelectorAll(".agent-node")) {
    const i = AGENTS.indexOf(node.dataset.agent);
    node.classList.toggle("active", i === idx);
    if (i < idx) node.classList.add("done");
  }
}
function bumpToolCount(agent, n) {
  toolCounts[agent] = (toolCounts[agent] || 0) + n;
  const node = $(`.agent-node[data-agent="${agent}"]`);
  if (node) $(".count", node).textContent = `${toolCounts[agent]} tool call${toolCounts[agent] === 1 ? "" : "s"}`;
}
function finishPipeline() {
  for (const node of document.querySelectorAll(".agent-node")) {
    node.classList.remove("active");
    if (node.dataset.agent !== "HumanApprover") node.classList.add("done");
  }
}

// --------------------------------------------------------------------------- timeline rendering
// Records have the JSONL log shape {type, data}; shared by the live view and history replay.

function toolSummaryBadge(name, content) {
  const data = parseJSON(content);
  if (!data) return null;
  if (data.ok === false) return badge("error", "error");
  if (name === "check_rule" && data.finding) return statusBadge(data.finding.status);
  if (name === "record_remediation") return badge(data.recorded ? "recorded" : "rejected", data.recorded ? "yes" : "no");
  if (name === "get_audit_record" && data.gaps) return badge(data.gaps.length ? `${data.gaps.length} gaps` : "complete", data.gaps.length ? "no" : "yes");
  return badge("ok", "yes");
}

function createTimeline(container, { live }) {
  const callCards = new Map(); // call_id -> {details, slot}
  return function render(record) {
    const { type, data } = record;
    const agent = data.source || "";
    const color = AGENT_COLOR[agent] || "var(--a-user)";
    if (live) setActiveAgent(agent);

    if (type === "ToolCallRequestEvent") {
      const msg = el("div", { class: "msg", style: `--c:${color}` },
        el("div", { class: "msg-head" }, el("span", { class: "who" }, agent), `requests ${data.content.length} tool call${data.content.length === 1 ? "" : "s"}`));
      for (const call of data.content) {
        const slot = el("span");
        const details = el("details", { class: "tool" },
          el("summary", {}, el("span", { class: "fn" }, call.name), el("span", { class: "args" }, call.arguments), slot),
          el("div", { class: "label" }, "arguments"), el("pre", { class: "code" }, pretty(call.arguments)));
        callCards.set(call.id, { details, slot, name: call.name });
        msg.append(details);
      }
      if (live) bumpToolCount(agent, data.content.length);
      container.append(msg);
    } else if (type === "ToolCallExecutionEvent") {
      for (const res of data.content) {
        const card = callCards.get(res.call_id);
        if (!card) continue;
        const b = res.is_error ? badge("error", "error") : toolSummaryBadge(card.name, res.content);
        if (b) card.slot.replaceChildren(b);
        card.details.append(el("div", { class: "label" }, "result"), el("pre", { class: "code" }, pretty(res.content)));
      }
    } else if (type === "TextMessage" || type === "ToolCallSummaryMessage" || type === "StopMessage") {
      const usage = data.models_usage ? `${data.models_usage.prompt_tokens + data.models_usage.completion_tokens} tokens` : "";
      container.append(el("div", { class: "msg", style: `--c:${color}` },
        el("div", { class: "msg-head" }, el("span", { class: "who" }, agent || "system"), usage),
        el("div", { class: "msg-body" }, typeof data.content === "string" ? data.content : pretty(data.content))));
    }
    if (live) container.lastElementChild?.scrollIntoView({ block: "nearest", behavior: "smooth" });
  };
}

// --------------------------------------------------------------------------- results rendering

function renderStats(counts, extra = []) {
  return el("div", { class: "stats" },
    el("div", { class: "stat fail" }, el("b", {}, counts.FAIL), el("span", {}, "failed")),
    el("div", { class: "stat pass" }, el("b", {}, counts.PASS), el("span", {}, "passed")),
    el("div", { class: "stat" }, el("b", {}, counts.NOT_APPLICABLE), el("span", {}, "not applicable")),
    ...extra.map(([v, l]) => el("div", { class: "stat" }, el("b", {}, v), el("span", {}, l))));
}

function renderFindings(findings) {
  const order = (f) => f.rule_id;
  const rows = [...findings].sort((a, b) => order(a).localeCompare(order(b))).map((f) => {
    const ev = f.evidence.length
      ? f.evidence.slice(0, 4).map((e) => el("code", {}, `${e.line_number}: ${e.text.trim()}`))
      : [el("span", { class: "hint" }, (f.missing && f.missing[0]) || f.reason)];
    if (f.evidence.length > 4) ev.push(el("span", { class: "hint" }, `+${f.evidence.length - 4} more`));
    return el("tr", {},
      el("td", { class: "mono" }, f.rule_id),
      el("td", {}, f.title),
      el("td", {}, badge(f.severity)),
      el("td", {}, statusBadge(f.status)),
      el("td", { class: "evidence" }, ...ev));
  });
  return el("div", { class: "table-wrap" }, el("table", { class: "grid" },
    el("thead", {}, el("tr", {}, ...["Rule", "Title", "Severity", "Status", "Evidence (line: text)"].map((h) => el("th", {}, h)))),
    el("tbody", {}, ...rows)));
}

function renderRemediations(remediations, findings) {
  const byId = Object.fromEntries(findings.map((f) => [f.rule_id, f]));
  const ids = Object.keys(remediations).sort();
  if (!ids.length) return el("p", { class: "hint" }, "No remediation recorded.");
  return el("div", {}, ...ids.map((id) => {
    const r = remediations[id];
    const f = byId[id] || {};
    const lockouts = r.warnings.filter((w) => w.toUpperCase().includes("LOCKOUT"));
    return el("details", { class: "rem" },
      el("summary", {}, el("b", { class: "mono" }, id), f.title || "", f.severity ? badge(f.severity) : null,
        lockouts.length ? badge("lockout warning", "warn") : null),
      el("div", { class: "rem-body" },
        el("p", { class: "risk" }, r.risk_summary),
        ...r.warnings.map((w) => el("div", { class: w.toUpperCase().includes("LOCKOUT") ? "lockout" : "hint" }, w)),
        el("pre", { class: "code" }, r.commands.join("\n"))));
  }));
}

function renderResult(result) {
  const status = result.approved ? badge("approved", "approved") : badge("not approved", "not_approved");
  return el("div", { class: "result" },
    el("div", { class: "panel-head" }, el("h3", {}, `Result: ${result.device}`), status),
    renderStats(result.counts, [[secs(result.duration_s), "duration"], [result.tokens.toLocaleString(), "tokens"], [money(result.cost_usd), "cost"]]),
    result.gaps.length ? el("div", { class: "lockout" }, `Incomplete record: ${result.gaps.join("; ")}`) : null,
    el("h3", { style: "margin-top:12px" }, "Findings"), renderFindings(result.findings),
    el("h3", { style: "margin-top:12px" }, "Remediation (draft, review before applying)"),
    renderRemediations(result.remediations, result.findings));
}

// --------------------------------------------------------------------------- live run

let running = false;
let socket = null;
const sections = [];

function startRun(payload) {
  if (running) return;
  running = true;
  updateRunButton();
  resetPipeline();
  for (const k of Object.keys(toolCounts)) delete toolCounts[k];
  sections.length = 0;
  const area = $("#run-area");
  area.replaceChildren();
  showView("run");

  const proto = location.protocol === "https:" ? "wss" : "ws";
  socket = new WebSocket(`${proto}://${location.host}/ws/run`);
  let finished = false;
  socket.onopen = () => socket.send(JSON.stringify({ action: "start", ...payload }));
  socket.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.type === "run_end") finished = true;
    handle(msg, area);
  };
  socket.onclose = () => {
    if (!finished) {
      area.append(el("div", { class: "panel lockout" },
        "Connection closed before the run finished. An interrupted audit is saved as paused; resume it from History."));
    }
    running = false;
    socket = null;
    updateRunButton();
  };
}

function handle(msg, area) {
  switch (msg.type) {
    case "run_start":
      if (msg.total > 1) area.append(el("p", { class: "hint" }, `Batch of ${msg.total} configs. Audits run one after another.`));
      break;
    case "audit_start": {
      resetPipeline();
      for (const k of Object.keys(toolCounts)) delete toolCounts[k];
      const state = el("span", {}, badge("running", "running"));
      const timeline = el("div", { class: "timeline" });
      const body = el("div", { class: "audit-body" }, timeline);
      const details = el("details", { open: true },
        el("summary", { class: "audit-head" }, el("span", { class: "title" }, msg.label), state));
      details.append(body);
      const section = el("section", { class: "panel audit-section" }, details);
      // collapse the previous audit in a batch so the live one stays in view
      if (sections.length) $("details", sections[sections.length - 1].section).open = false;
      sections[msg.index] = { section, body, state, render: createTimeline(timeline, { live: true }) };
      area.append(section);
      break;
    }
    case "item":
      sections[msg.index]?.render(msg.record);
      break;
    case "audit_end": {
      const s = sections[msg.index];
      finishPipeline();
      const r = msg.result;
      s.state.replaceChildren(r.approved ? badge("approved", "approved") : badge("not approved", "not_approved"),
        " ", badge(`${r.counts.FAIL} FAIL`, r.counts.FAIL ? "FAIL" : "PASS"));
      const timeline = s.body.firstElementChild;
      const wrap = el("details", { class: "tool" }, el("summary", {}, el("span", { class: "fn" }, "Agent conversation"),
        el("span", { class: "args" }, `${timeline.children.length} steps`)));
      timeline.replaceWith(wrap);
      wrap.append(el("div", { style: "padding:0 10px 10px" }, timeline));
      s.body.append(renderResult(r));
      break;
    }
    case "audit_error":
      sections[msg.index]?.state.replaceChildren(badge("error", "error"));
      sections[msg.index]?.body.append(el("div", { class: "lockout" }, msg.error));
      break;
    case "question":
      setActiveAgent("HumanApprover");
      {
        const q = renderQuestion(msg);
        area.append(q);
        q.scrollIntoView({ behavior: "smooth", block: "center" });
      }
      break;
    case "run_end":
      renderRunEnd(msg, area);
      loadConfigs();
      break;
    case "error":
      area.append(el("div", { class: "panel lockout" }, msg.message));
      toast(msg.message);
      break;
  }
}

function answer(text, panel) {
  socket?.send(JSON.stringify({ action: "answer", text }));
  for (const b of panel.querySelectorAll("button, input")) b.disabled = true;
  panel.append(el("p", { class: "hint" }, `Answered: ${text}`));
}

function renderQuestion(msg) {
  const panel = el("section", { class: "panel question" });
  if (msg.kind === "overwrite") {
    panel.append(
      el("h3", {}, "HumanApprover: overwrite existing reports?"),
      el("p", {}, msg.text.trim().split("\n")[0]),
      el("div", { class: "actions" },
        el("button", { class: "btn danger", onclick: () => answer("overwrite", panel) }, "Overwrite"),
        el("button", { class: "btn primary", onclick: () => answer("keep", panel) }, "Keep old files (write new copy)")));
  } else if (msg.kind === "export") {
    const boxes = msg.eligible.map((d) => el("label", { class: "check" }, el("input", { type: "checkbox", value: d, checked: true }), d));
    panel.append(
      el("h3", {}, "HumanApprover: export remediation scripts?"),
      el("p", { class: "hint" }, "Scripts are written to remediation/ and marked REVIEW BEFORE APPLYING. Nothing is pushed to any device."),
      el("div", { class: "devices" }, ...boxes),
      el("div", { class: "actions" },
        el("button", { class: "btn primary", onclick: () => {
          const chosen = boxes.map((b) => $("input", b)).filter((i) => i.checked).map((i) => i.value);
          answer(chosen.length ? chosen.join(",") : "none", panel);
        } }, "Export selected"),
        el("button", { class: "btn", onclick: () => answer("none", panel) }, "Export none")));
  } else {
    const input = el("input", { type: "search", placeholder: "Your answer" });
    panel.append(el("h3", {}, "HumanApprover"), el("p", {}, msg.text), input,
      el("div", { class: "actions" }, el("button", { class: "btn primary", onclick: () => answer(input.value, panel) }, "Send")));
  }
  return panel;
}

function renderRunEnd(msg, area) {
  const panel = el("section", { class: "panel" },
    el("div", { class: "panel-head" }, el("h3", {}, "Run complete"),
      msg.all_approved ? badge("all approved", "approved") : badge("needs attention", "not_approved")));
  if (Object.keys(msg.errors).length) {
    panel.append(el("div", { class: "lockout" }, Object.entries(msg.errors).map(([k, v]) => `${k}: ${v}`).join("\n")));
  }
  panel.append(el("p", { class: "hint" }, "Files written:"),
    el("ul", { class: "files mono" }, ...msg.written.map((p) => el("li", {}, p))));
  area.append(panel);
  panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

$("#run-btn").addEventListener("click", () => {
  const ids = selectedConfigs();
  if (!ids.length) return;
  startRun({ mode: ids.length > 1 ? "batch" : "audit", configs: ids, export_allowed: $("#export-allowed").checked });
});

// --------------------------------------------------------------------------- history

async function loadHistory() {
  const audits = await api("/api/audits");
  const tbody = $("#history-table tbody");
  $("#history-empty").classList.toggle("hidden", audits.length > 0);
  tbody.replaceChildren(...audits.map((a) => el("tr", { class: "clickable", onclick: () => openAudit(a.audit_id) },
    el("td", {}, a.started ? new Date(a.started).toLocaleString() : "-"),
    el("td", {}, a.device || "-"),
    el("td", { class: "mono" }, a.config || "-"),
    el("td", {}, badge(a.status.replace("_", " "), a.status)),
    el("td", {}, a.counts.FAIL), el("td", {}, a.counts.PASS), el("td", {}, a.counts.NOT_APPLICABLE),
    el("td", {}, secs(a.duration_s)), el("td", {}, money(a.cost_usd)))));
}

async function openAudit(id) {
  const d = await api(`/api/audits/${encodeURIComponent(id)}`);
  const panel = $("#history-detail");
  const timeline = el("div", { class: "timeline" });
  const render = createTimeline(timeline, { live: false });
  for (const rec of d.timeline) render(rec);
  const fileLinks = d.outputs.map((kind) =>
    el("a", { class: "btn small", href: `/api/audits/${encodeURIComponent(id)}/${kind}`, target: "_blank", rel: "noopener" },
      kind === "report" ? "Open report (.md)" : "Open remediation script"));
  panel.replaceChildren(
    el("div", { class: "panel-head" },
      el("h2", {}, `${d.device || d.config || id}`),
      el("div", { class: "select-row" },
        ...fileLinks,
        d.resumable ? el("button", { class: "btn small primary", onclick: () => startRun({ mode: "resume", audit_id: id, export_allowed: true }) }, "Resume audit") : null,
        el("button", { class: "btn small ghost", onclick: () => panel.classList.add("hidden") }, "Close"))),
    el("p", { class: "hint" }, `Audit ${id} · ${d.config || ""} · ${d.model || ""} · ${d.runs} run(s) · status ${d.status}`),
    renderStats(d.counts, [[secs(d.duration_s), "duration"], [d.tokens.toLocaleString(), "tokens"], [money(d.cost_usd), "cost"]]),
    d.findings.length ? el("h3", { style: "margin-top:12px" }, "Findings") : null,
    d.findings.length ? renderFindings(d.findings) : el("p", { class: "hint" }, "No findings recorded (audit stopped early)."),
    el("h3", { style: "margin-top:12px" }, "Remediation"),
    renderRemediations(d.remediations, d.findings),
    el("details", { class: "tool", style: "margin-top:12px" },
      el("summary", {}, el("span", { class: "fn" }, "Agent conversation replay"), el("span", { class: "args" }, `${d.timeline.length} events`)),
      el("div", { style: "padding:0 10px 10px" }, timeline)));
  panel.classList.remove("hidden");
  panel.scrollIntoView({ behavior: "smooth" });
}

$("#history-refresh").addEventListener("click", loadHistory);

// --------------------------------------------------------------------------- baseline

let baselineLoaded = false;
async function loadBaseline() {
  if (baselineLoaded) return;
  const b = await api("/api/baseline");
  baselineLoaded = true;
  $("#baseline-title").textContent = `Baseline: ${b.file} (${b.rules.length} rules)`;
  $("#baseline-settings").textContent =
    `External interface pattern: ${b.settings.external_interface_pattern} · max exec-timeout: ${b.settings.max_exec_timeout_minutes} min · default SNMP communities: ${b.settings.default_snmp_communities.join(", ")}`;
  const tbody = $("#baseline-table tbody");
  tbody.replaceChildren();
  for (const r of b.rules) {
    const detail = el("tr", { class: "hidden" }, el("td", { colspan: "6" },
      el("p", {}, r.description),
      r.advisory ? el("p", { class: "hint" }, `Advisory: ${r.advisory}`) : null,
      el("div", { class: "label", style: "margin-left:0" }, "check"),
      el("pre", { class: "code", style: "margin:0 0 8px" }, JSON.stringify(r.check, null, 2)),
      el("div", { class: "label", style: "margin-left:0" }, "remediation hint"),
      el("pre", { class: "code", style: "margin:0" }, (r.remediation_hint || []).join("\n"))));
    const row = el("tr", { class: "clickable", onclick: () => detail.classList.toggle("hidden") },
      el("td", { class: "mono" }, r.id), el("td", {}, r.title), el("td", {}, badge(r.severity)),
      el("td", {}, r.category), el("td", { class: "mono" }, r.check.type),
      el("td", {}, r.lockout_risk ? badge("yes", "warn") : "-"));
    tbody.append(row, detail);
  }
}

// --------------------------------------------------------------------------- boot

loadInfo().catch((e) => toast(`Cannot reach backend: ${e.message}`));
loadConfigs().catch((e) => toast(`Cannot load configs: ${e.message}`));
