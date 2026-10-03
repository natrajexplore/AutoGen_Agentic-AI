// ConfigGuard UI. All config- and agent-derived text is inserted with textContent (via el()),
// never innerHTML: config descriptions/banners are untrusted and may carry injection payloads.
"use strict";

const AGENTS = ["ConfigParser", "ComplianceChecker", "RemediationEngineer", "Critic", "HumanApprover"];
const AGENT_COLOR = {
  ConfigParser: "var(--a-parser)", ComplianceChecker: "var(--a-checker)",
  RemediationEngineer: "var(--a-remed)", Critic: "var(--a-critic)", HumanApprover: "var(--a-human)",
};
const SEVERITIES = ["critical", "high", "medium", "low"];
const SEV_COLOR = { critical: "var(--sev-critical)", high: "var(--sev-high)", medium: "var(--sev-medium)", low: "var(--sev-low)" };
const RATING_COLOR = { Critical: "var(--sev-critical)", High: "var(--sev-high)", Medium: "var(--sev-medium)", Low: "var(--sev-low)", Compliant: "var(--pass)" };
const EFFECTIVE_LABEL = { PASS: "Pass", FAIL: "Open", RISK_ACCEPTED: "Risk accepted", FALSE_POSITIVE: "False positive", NOT_APPLICABLE: "N/A" };
const ACTIONS = [
  ["approve_fix", "Approve fix"], ["reject_fix", "Reject fix"], ["accept_risk", "Accept risk"],
  ["false_positive", "False positive"], ["", "Decide later"],
];
const $ = (sel, root = document) => root.querySelector(sel);
let INFO = { max_waiver_days: 365, reviewer_name: "" };

// --------------------------------------------------------------------------- helpers

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  setAttrs(node, attrs);
  append(node, children);
  return node;
}

function svg(tag, attrs = {}, ...children) {
  const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
  setAttrs(node, attrs);
  append(node, children);
  return node;
}

function setAttrs(node, attrs) {
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") node.setAttribute("class", v);
    else if (k === "style") node.style.cssText = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? "" : v);
  }
}

function append(node, children) {
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
}

const badge = (text, cls) => el("span", { class: `badge ${cls || text}` }, text);
const statusBadge = (s) => badge(EFFECTIVE_LABEL[s] || s, s);
const money = (v) => `$${(v || 0).toFixed(4)}`;
const secs = (v) => `${Math.round(v || 0)}s`;
const pct = (v) => (v === null || v === undefined ? "-" : `${Number(v).toFixed(1)}%`);
const when = (ts) => (ts ? new Date(ts).toLocaleString() : "-");
const scoreColor = (s) => (s >= 90 ? "var(--pass)" : s >= 70 ? "var(--sev-medium)" : s >= 50 ? "var(--sev-high)" : "var(--sev-critical)");

function toast(message, ms = 4000) {
  const t = el("div", { class: "toast", role: "status" }, message);
  document.body.append(t);
  setTimeout(() => t.remove(), ms);
}

async function api(path, options) {
  const res = await fetch(path, options);
  let body = null;
  const isJson = res.headers.get("content-type")?.includes("json");
  try { body = isJson ? await res.json() : await res.text(); } catch { /* empty */ }
  if (!res.ok) {
    const err = new Error((body && body.detail) || res.statusText);
    err.body = body;
    throw err;
  }
  return body;
}

function pretty(text) {
  if (typeof text !== "string") return JSON.stringify(text, null, 2);
  try { return JSON.stringify(JSON.parse(text), null, 2); } catch { return text; }
}
const parseJSON = (text) => { try { return JSON.parse(text); } catch { return null; } };

function store(key, value) {
  try {
    if (value === undefined) return localStorage.getItem(key) || "";
    localStorage.setItem(key, value);
  } catch { /* storage unavailable: per-session only */ }
  return value ?? "";
}

function frameworkChips(frameworks) {
  const chips = [];
  for (const [fw, ids] of Object.entries(frameworks || {})) {
    if (!ids || !ids.length) continue;
    const short = fw.startsWith("NIST") ? "NIST" : fw.startsWith("PCI") ? "PCI" : fw.startsWith("ISO") ? "ISO" : fw;
    chips.push(el("span", { class: "chip fw", title: fw }, `${short} ${ids.join(", ")}`));
  }
  return chips;
}

function isoPlus(days) {
  const d = new Date();
  d.setDate(d.getDate() + days);
  return d.toISOString().slice(0, 10);
}

// --------------------------------------------------------------------------- charts (inline SVG)

function gauge(score, size = 76) {
  const r = size / 2 - 7;
  const c = 2 * Math.PI * r;
  const value = score === null || score === undefined ? 0 : score;
  return svg("svg", { class: "chart", width: size, height: size, viewBox: `0 0 ${size} ${size}`, role: "img", "aria-label": `score ${pct(score)}` },
    svg("circle", { cx: size / 2, cy: size / 2, r, fill: "none", stroke: "var(--panel-2)", "stroke-width": 8 }),
    svg("circle", {
      cx: size / 2, cy: size / 2, r, fill: "none", stroke: scoreColor(value), "stroke-width": 8, "stroke-linecap": "round",
      "stroke-dasharray": `${(c * value) / 100} ${c}`, transform: `rotate(-90 ${size / 2} ${size / 2})`,
    }),
    svg("text", { x: "50%", y: "54%", "text-anchor": "middle", style: `font-size:${size / 5}px;font-weight:700;fill:var(--text)` },
      score === null || score === undefined ? "-" : `${Math.round(value)}%`));
}

function donut(segments, size = 120) {
  const total = segments.reduce((s, x) => s + x.value, 0) || 1;
  const r = size / 2 - 12;
  const c = 2 * Math.PI * r;
  let offset = 0;
  const node = svg("svg", { class: "chart", width: size, height: size, viewBox: `0 0 ${size} ${size}` },
    svg("circle", { cx: size / 2, cy: size / 2, r, fill: "none", stroke: "var(--panel-2)", "stroke-width": 16 }));
  for (const s of segments) {
    if (!s.value) continue;
    const len = (c * s.value) / total;
    node.append(svg("circle", {
      cx: size / 2, cy: size / 2, r, fill: "none", stroke: s.color, "stroke-width": 16,
      "stroke-dasharray": `${len} ${c - len}`, "stroke-dashoffset": -offset, transform: `rotate(-90 ${size / 2} ${size / 2})`,
    }, svg("title", {}, `${s.label}: ${s.value}`)));
    offset += len;
  }
  node.append(svg("text", { x: "50%", y: "54%", "text-anchor": "middle", style: "font-size:20px;font-weight:700;fill:var(--text)" },
    segments.reduce((s, x) => s + x.value, 0)));
  return node;
}

function lineChart(points, { width = 1100, height = 200 } = {}) {
  const pad = { l: 34, r: 10, t: 10, b: 22 };
  const w = width - pad.l - pad.r;
  const h = height - pad.t - pad.b;
  const x = (i) => pad.l + (points.length < 2 ? w / 2 : (i * w) / (points.length - 1));
  const y = (v) => pad.t + h - (v / 100) * h;
  const node = svg("svg", { class: "chart", viewBox: `0 0 ${width} ${height}`, style: "width:100%;height:auto;max-height:240px" });
  for (const v of [0, 50, 100]) {
    node.append(svg("line", { x1: pad.l, x2: width - pad.r, y1: y(v), y2: y(v), stroke: "var(--border)", "stroke-dasharray": "3 3" }),
      svg("text", { x: pad.l - 6, y: y(v) + 4, "text-anchor": "end" }, `${v}%`));
  }
  if (points.length) {
    const d = points.map((p, i) => `${i ? "L" : "M"}${x(i)},${y(p.fleet_score)}`).join(" ");
    node.append(svg("path", { d, fill: "none", stroke: "var(--accent)", "stroke-width": 2.5 }));
    points.forEach((p, i) => node.append(
      svg("circle", { cx: x(i), cy: y(p.score), r: 3.5, fill: scoreColor(p.score), stroke: "var(--panel)", "stroke-width": 1.5 },
        svg("title", {}, `${when(p.ts)} · ${p.device}: ${pct(p.score)} (fleet ${pct(p.fleet_score)})`))));
  }
  return node;
}

function sevBar(open) {
  const total = SEVERITIES.reduce((s, k) => s + (open[k] || 0), 0);
  const bar = el("div", { class: "sevbar", title: SEVERITIES.map((k) => `${k} ${open[k] || 0}`).join(" · ") });
  for (const k of SEVERITIES) {
    if (open[k]) bar.append(el("span", { style: `width:${(open[k] / total) * 100}%;background:${SEV_COLOR[k]}` }));
  }
  return bar;
}

function kpi(value, label, extra, { onclick, icon } = {}) {
  return el("div", { class: `kpi${onclick ? " clickable" : ""}`, onclick },
    icon || null,
    el("div", {}, el("div", { class: "val" }, value), el("div", { class: "lbl" }, label), extra || null));
}

// --------------------------------------------------------------------------- navigation

for (const tab of document.querySelectorAll(".tab")) tab.addEventListener("click", () => showView(tab.dataset.view));

function showView(name, { updateHash = true } = {}) {
  for (const t of document.querySelectorAll(".tab")) t.classList.toggle("active", t.dataset.view === name);
  for (const v of document.querySelectorAll(".view")) v.classList.toggle("hidden", v.id !== `view-${name}`);
  if (updateHash && name !== "audit") history.replaceState(null, "", `#${name}`);
  if (name === "dashboard") loadDashboard();
  if (name === "history") loadHistory();
  if (name === "risk") loadRisk();
  if (name === "baseline") loadBaseline();
}

async function loadInfo() {
  INFO = { ...INFO, ...(await api("/api/info")) };
  $("#meta").replaceChildren(
    el("span", { class: "chip" }, `${INFO.provider} · ${INFO.model}`),
    el("span", { class: "chip" }, INFO.baseline));
  $("#key-warning").classList.toggle("hidden", INFO.api_key_configured);
}

// --------------------------------------------------------------------------- dashboard

async function loadDashboard() {
  const body = $("#dash-body");
  let d;
  try { d = await api("/api/dashboard"); } catch (e) { body.replaceChildren(el("div", { class: "empty" }, `Cannot load dashboard: ${e.message}`)); return; }
  const f = d.fleet;
  $("#dash-sub").textContent = `Latest audit of each of ${f.devices} device(s) · ${f.audits} audit(s) on record`;
  if (!f.devices) {
    body.replaceChildren(el("div", { class: "empty" }, el("h3", {}, "No audits yet"),
      el("p", {}, "Run your first audit to populate the dashboard."),
      el("button", { class: "btn primary", onclick: () => showView("run") }, "Run an audit")));
    return;
  }
  const kpis = el("div", { class: "kpis" },
    kpi(pct(f.score), "Fleet compliance score", null, { icon: gauge(f.score, 58) }),
    kpi(f.devices, "Devices audited", el("div", { class: "hint" }, `${f.audits} audits total`)),
    kpi(f.open_total, "Open findings", sevBar(f.open_by_severity)),
    kpi(f.pending_reviews, "Devices awaiting review", el("div", { class: "hint" }, "open findings with no decision"),
      { onclick: () => showView("history") }),
    kpi(f.risk_accepted, "Risks accepted", el("div", { class: "hint" }, `${f.active_waivers} active waiver(s) · ${f.false_positives} false positive(s)`),
      { onclick: () => showView("risk") }),
    kpi(money(f.cost_usd), "AI spend", el("div", { class: "hint" }, `${f.tokens.toLocaleString()} tokens`)));

  const ratingSegs = Object.entries(d.ratings).map(([label, value]) => ({ label, value, color: RATING_COLOR[label] }));
  const ratings = el("section", { class: "panel" }, el("div", { class: "panel-head" }, el("h2", {}, "Device risk ratings")),
    el("div", { class: "select-row", style: "gap:22px" }, donut(ratingSegs),
      el("div", { class: "legend" }, ...ratingSegs.map((s) => el("div", { class: "row" },
        el("span", { class: "swatch", style: `background:${s.color}` }), `${s.label}`, el("b", { style: "margin-left:auto" }, s.value))))));

  const maxSev = Math.max(1, ...SEVERITIES.map((s) => f.open_by_severity[s]));
  const severity = el("section", { class: "panel" }, el("div", { class: "panel-head" }, el("h2", {}, "Open findings by severity")),
    ...SEVERITIES.map((s) => el("div", { class: "hbar" }, el("span", { class: "name" }, badge(s)),
      el("div", { class: "track" }, el("div", { class: "fill", style: `width:${(f.open_by_severity[s] / maxSev) * 100}%;background:${SEV_COLOR[s]}` })),
      el("b", {}, f.open_by_severity[s]))));

  const maxTop = Math.max(1, ...d.top_controls.map((t) => t.failing_devices));
  const top = el("section", { class: "panel" }, el("div", { class: "panel-head" }, el("h2", {}, "Most frequently failing controls")),
    d.top_controls.length ? null : el("p", { class: "hint" }, "No open failures across the fleet."),
    ...d.top_controls.slice(0, 8).map((t) => el("div", {},
      el("div", { class: "hbar" }, el("span", { class: "name", title: t.title }, `${t.id} ${t.title}`),
        el("div", { class: "track" }, el("div", { class: "fill", style: `width:${(t.failing_devices / maxTop) * 100}%;background:${SEV_COLOR[t.severity]}` })),
        el("b", {}, `${t.failing_devices}/${f.devices}`)))));

  const trend = el("section", { class: "panel" }, el("div", { class: "panel-head" }, el("h2", {}, "Compliance score over time"),
    el("span", { class: "hint" }, "line: fleet average · dots: individual audits")), lineChart(d.trend));

  body.replaceChildren(kpis,
    el("div", { class: "grid-3", style: "margin-bottom:14px" }, ratings, severity, top),
    el("div", { class: "stack" }, heatmap(d), trend, deviceTable(d)));
}

function heatmap(d) {
  const glyph = { PASS: "✓", FAIL: "✕", NOT_APPLICABLE: "·", RISK_ACCEPTED: "A", FALSE_POSITIVE: "FP" };
  const sevOf = Object.fromEntries(d.rules.map((r) => [r.id, r.severity]));
  const table = el("table", { class: "heat" },
    el("thead", {}, el("tr", {}, el("th", { class: "dev" }, "Device"),
      ...d.rules.map((r) => el("th", { title: `${r.id} ${r.title} (${r.severity})` }, r.id.slice(3))))),
    el("tbody", {}, ...d.devices.map((dev) => el("tr", {},
      el("td", { class: "dev", onclick: () => openAudit(dev.audit_id) },
        el("b", {}, dev.device), " ", el("span", { class: "hint" }, pct(dev.score)), " ", badge(dev.rating)),
      ...d.rules.map((r) => {
        const s = dev.statuses[r.id];
        return el("td", {
          class: `cell ${s || "none"} ${sevOf[r.id]}`,
          title: `${dev.device} · ${r.id} ${r.title}: ${EFFECTIVE_LABEL[s] || "not evaluated"}`,
          onclick: () => openAudit(dev.audit_id, "findings", r.id),
        }, glyph[s] || "");
      })))));
  const legend = el("div", { class: "select-row hint", style: "margin-top:8px;gap:14px" },
    ...[["PASS", "Pass"], ["FAIL critical", "Open (shade = severity)"], ["RISK_ACCEPTED", "Risk accepted"], ["FALSE_POSITIVE", "False positive"], ["NOT_APPLICABLE", "Not applicable"]]
      .map(([cls, label]) => el("span", { class: "select-row", style: "gap:5px" }, el("span", { class: `cell ${cls}`, style: "display:inline-block;width:14px;height:14px;border-radius:3px" }), label)));
  return el("section", { class: "panel" }, el("div", { class: "panel-head" }, el("h2", {}, "Compliance heatmap"),
    el("span", { class: "hint" }, "click a device or cell to open its audit")), el("div", { class: "table-wrap" }, table), legend);
}

function deviceTable(d) {
  return el("section", { class: "panel" }, el("div", { class: "panel-head" }, el("h2", {}, "Devices")),
    el("div", { class: "table-wrap" }, el("table", { class: "grid" },
      el("thead", {}, el("tr", {}, ...["Device", "Platform", "IOS-XE", "Score", "Rating", "Open crit/high", "Review", "Last audited"].map((h) => el("th", {}, h)))),
      el("tbody", {}, ...d.devices.map((dev) => el("tr", { class: "clickable", onclick: () => openAudit(dev.audit_id) },
        el("td", {}, el("b", {}, dev.device)), el("td", { class: "mono" }, dev.platform || "-"), el("td", {}, dev.software_version || "-"),
        el("td", {}, pct(dev.score)), el("td", {}, badge(dev.rating)),
        el("td", {}, `${dev.open_by_severity.critical} / ${dev.open_by_severity.high}`),
        el("td", {}, dev.needs_review ? badge(`${dev.undecided} awaiting decision`, "warn") : dev.reviewer ? badge(`reviewed: ${dev.reviewer}`, "reviewed") : badge("nothing open", "pending")),
        el("td", {}, when(dev.audited))))))));
}

$("#dash-refresh").addEventListener("click", loadDashboard);

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
  $("#config-list").replaceChildren(...configs
    .filter((c) => c.name.toLowerCase().includes(filter))
    .map((c) => el("li", {}, el("label", {},
      el("input", { type: "checkbox", value: c.id, checked: checked.has(c.id), onchange: updateRunButton }),
      el("span", { class: "name", title: c.name }, c.name),
      el("span", { class: "src" }, c.source === "uploads" ? "uploaded" : "")))));
  updateRunButton();
}

const selectedConfigs = () => [...document.querySelectorAll("#config-list input:checked")].map((i) => i.value);

function updateRunButton() {
  const n = selectedConfigs().length;
  const btn = $("#run-btn");
  btn.disabled = n === 0 || running;
  btn.textContent = n > 1 ? `Run batch (${n} configs)` : "Run audit";
}

$("#config-filter").addEventListener("input", () => renderConfigs());
$("#select-all").addEventListener("click", () => { for (const i of document.querySelectorAll("#config-list input")) i.checked = true; updateRunButton(); });
$("#select-none").addEventListener("click", () => { for (const i of document.querySelectorAll("#config-list input")) i.checked = false; updateRunButton(); });
$("#upload").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const form = new FormData();
  form.append("file", file);
  try {
    const saved = await api("/api/configs", { method: "POST", body: form });
    toast(`Uploaded ${saved.name}`);
    await loadConfigs(saved.id);
  } catch (err) { toast(`Upload failed: ${err.message}`); }
  e.target.value = "";
});

// --------------------------------------------------------------------------- pipeline strip

const toolCounts = {};
function resetPipeline() {
  for (const node of document.querySelectorAll(".agent-node")) { node.classList.remove("active", "done"); $(".count", node).textContent = ""; }
  for (const k of Object.keys(toolCounts)) delete toolCounts[k];
}
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

// --------------------------------------------------------------------------- agent timeline (live + replay)

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
  const callCards = new Map();
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
    } else if (["TextMessage", "ToolCallSummaryMessage", "StopMessage"].includes(type)) {
      const usage = data.models_usage ? `${data.models_usage.prompt_tokens + data.models_usage.completion_tokens} tokens` : "";
      container.append(el("div", { class: "msg", style: `--c:${color}` },
        el("div", { class: "msg-head" }, el("span", { class: "who" }, agent || "system"), usage),
        el("div", { class: "msg-body" }, typeof data.content === "string" ? data.content : pretty(data.content))));
    }
    if (live) container.lastElementChild?.scrollIntoView({ block: "nearest", behavior: "smooth" });
  };
}

// --------------------------------------------------------------------------- review form (live runs + History)

// payload: {devices:[{audit_id, device, approved, facts, assessment, items}], existing_reports, export_allowed,
//           reviewer, default_expiry, max_expiry, errors}; draft persists answers across re-asks.
function renderReviewForm(payload, { draft = {}, onSubmit, onSkip, title = "Human review: decide on each failed control" }) {
  const panel = el("section", { class: "panel review" });
  const reviewer = el("input", { type: "text", value: draft.reviewer ?? (payload.reviewer || store("cg.reviewer")), placeholder: "Your name (recorded with each decision)", maxlength: 80 });
  const ticket = el("input", { type: "text", value: draft.ticket ?? "", placeholder: "e.g. CHG0012345 (optional)", maxlength: 40 });
  const overwrite = el("input", { type: "checkbox", checked: draft.overwrite ?? false });
  const maxExpiry = payload.max_expiry || isoPlus(INFO.max_waiver_days || 365);
  const defaultExpiry = payload.default_expiry || isoPlus(90);
  const rows = [];

  panel.append(el("h3", {}, title),
    el("p", { class: "hint" }, "Only fixes you approve are exported (marked REVIEW BEFORE APPLYING). Accepted risks carry over to future audits until they expire. Undecided findings stay open."));
  if (payload.errors && payload.errors.length) {
    panel.append(el("div", { class: "errors" }, el("b", {}, "Not recorded. Please fix:"), el("ul", {}, ...payload.errors.map((e) => el("li", {}, e)))));
  }
  panel.append(el("div", { class: "who" },
    el("label", { class: "field" }, "Reviewer name *", reviewer),
    el("label", { class: "field" }, "Change ticket", ticket),
    payload.existing_reports && payload.existing_reports.length
      ? el("label", { class: "check", style: "align-self:end" }, overwrite, `Overwrite existing report(s): ${payload.existing_reports.join(", ")}`) : null));

  for (const dev of payload.devices) {
    const a = dev.assessment || {};
    const box = el("div", { class: "review-device" });
    const items = dev.items || [];
    const head = el("div", { class: "head" }, el("b", {}, dev.device),
      dev.facts && dev.facts.platform ? el("span", { class: "hint mono" }, `${dev.facts.platform} · IOS-XE ${dev.facts.software_version || "?"}`) : null,
      a.rating ? badge(a.rating) : null, a.score !== undefined ? el("span", { class: "hint" }, `score ${pct(a.score)}`) : null,
      dev.approved ? badge("AI review approved", "approved") : badge("AI review not approved: fixes can't be approved", "not_approved"));
    const approveAll = el("button", { class: "btn small", style: "margin-left:auto", onclick: () => {
      for (const r of rows) if (r.audit === dev.audit_id && r.eligible) r.set("approve_fix");
      updateCounts();
    } }, "Approve all eligible fixes");
    if (items.some((i) => i.fix_eligible)) head.append(approveAll);
    box.append(head);
    if (!items.length) box.append(el("div", { class: "review-item hint" }, "No failed controls on this device."));
    for (const item of items) box.append(reviewRow(dev, item));
    panel.append(box);
  }

  function reviewRow(dev, item) {
    const prev = (draft.decisions?.[dev.audit_id] || {})[item.rule_id] || (item.decision ? { action: item.decision.action, comment: item.decision.comment, expires: item.decision.expires } : {});
    const name = `d-${dev.audit_id}-${item.rule_id}`;
    const comment = el("input", { type: "text", value: prev.comment || "", placeholder: "Comment / justification", maxlength: 500 });
    const expires = el("input", { type: "date", value: prev.expires || defaultExpiry, min: isoPlus(1), max: maxExpiry, title: "Risk accepted until" });
    const expiresWrap = el("label", { class: "field" }, "Accepted until", expires);
    const seg = el("div", { class: "seg", role: "radiogroup" });
    const radios = {};
    for (const [value, label] of ACTIONS) {
      const disabled = value === "approve_fix" && !item.fix_eligible;
      const input = el("input", { type: "radio", name, value, checked: (prev.action || "") === value, disabled, onchange: () => { sync(); updateCounts(); } });
      radios[value] = input;
      seg.append(el("label", { class: disabled ? "disabled" : "", title: disabled ? (item.fix ? "AI review not approved or export disabled" : "no fix was drafted") : "" }, input, label));
    }
    const hint = el("span", { class: "hint" });
    function sync() {
      const action = current();
      expiresWrap.classList.toggle("hidden", action !== "accept_risk");
      comment.placeholder = action === "accept_risk" ? "Justification (required, 10+ characters)" : action === "false_positive" ? "Why is this a false positive? (required)" : "Comment (optional)";
      hint.textContent = action === "approve_fix" ? "This fix will be exported." : "";
    }
    const current = () => Object.entries(radios).find(([, r]) => r.checked)?.[0] ?? "";
    const row = el("div", { class: "review-item" });
    const top = el("div", { class: "top" }, badge(item.severity), el("b", { class: "mono" }, item.rule_id), el("span", {}, item.title), ...frameworkChips(item.frameworks));
    row.append(top);
    if (item.waiver) {
      row.append(el("div", { class: "hint" }, `Risk accepted until ${item.waiver.expires} by ${item.waiver.approver}: ${item.waiver.justification} (waiver; manage it in the Risk register)`));
      return row;
    }
    const ev = item.evidence.length ? item.evidence.map((e) => el("div", { class: "ev-line" }, el("span", { class: "hint mono" }, `line ${e.line_number}`), el("code", {}, e.text.trim())))
      : item.missing.map((m) => el("div", { class: "hint" }, `Missing: ${m}`));
    row.append(...ev);
    if (item.risk_summary) row.append(el("div", {}, item.risk_summary));
    if (item.fix) {
      row.append(el("details", { class: "tool" }, el("summary", {}, el("span", { class: "fn" }, "Proposed fix"),
        el("span", { class: "args" }, `${item.fix.commands.length} command(s)`), item.fix.lockout ? badge("lockout warning", "warn") : null),
        ...item.fix.warnings.map((w) => el("div", { class: w.toUpperCase().includes("LOCKOUT") ? "lockout" : "hint", style: "margin:0 10px" }, w)),
        el("pre", { class: "code" }, item.fix.commands.join("\n"))));
    }
    row.append(seg, el("div", { class: "extra" }, comment, expiresWrap), hint);
    sync();
    rows.push({
      audit: dev.audit_id, rule: item.rule_id, eligible: item.fix_eligible,
      set: (value) => { radios[value].checked = true; sync(); },
      value: () => ({ action: current(), comment: comment.value.trim(), expires: expires.value }),
    });
    return row;
  }

  const counts = el("span", { class: "hint" });
  function updateCounts() {
    const c = { approve_fix: 0, reject_fix: 0, accept_risk: 0, false_positive: 0, "": 0 };
    for (const r of rows) c[r.value().action] += 1;
    counts.textContent = `${c.approve_fix} fix(es) approved · ${c.reject_fix} rejected · ${c.accept_risk} risk(s) accepted · ${c.false_positive} false positive(s) · ${c[""]} undecided`;
  }
  updateCounts();

  function collect() {
    const out = { reviewer: reviewer.value.trim(), ticket: ticket.value.trim(), overwrite: overwrite.checked, decisions: {} };
    for (const r of rows) {
      const v = r.value();
      if (!v.action) continue;
      const entry = { action: v.action, comment: v.comment };
      if (v.action === "accept_risk") entry.expires = v.expires;
      (out.decisions[r.audit] = out.decisions[r.audit] || {})[r.rule] = entry;
    }
    return out;
  }

  const submit = el("button", { class: "btn primary", onclick: async () => {
    const data = collect();
    if (Object.keys(data.decisions).length && data.reviewer.length < 2) { toast("Enter your name to record decisions."); reviewer.focus(); return; }
    store("cg.reviewer", data.reviewer);
    for (const b of panel.querySelectorAll("button")) b.disabled = true;
    await onSubmit(data);
  } }, "Submit review");
  const skip = onSkip ? el("button", { class: "btn", onclick: () => { for (const b of panel.querySelectorAll("button")) b.disabled = true; onSkip({ overwrite: overwrite.checked }); } }, "Decide later") : null;
  panel.append(el("div", { class: "footer" }, submit, skip, counts));
  return panel;
}

// --------------------------------------------------------------------------- live run

let running = false;
let socket = null;
const sections = [];
let reviewDraft = {};

function startRun(payload) {
  if (running) return;
  running = true;
  updateRunButton();
  resetPipeline();
  sections.length = 0;
  reviewDraft = {};
  const area = $("#run-area");
  area.replaceChildren();
  showView("run");
  socket = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws/run`);
  let finished = false;
  socket.onopen = () => socket.send(JSON.stringify({ action: "start", ...payload }));
  socket.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.type === "run_end") finished = true;
    handle(msg, area);
  };
  socket.onclose = () => {
    if (!finished) area.append(el("div", { class: "panel lockout" }, "Connection closed before the run finished. An interrupted audit is saved as paused; resume it from History."));
    running = false;
    socket = null;
    updateRunButton();
  };
}

function resultCard(r) {
  const a = r.assessment;
  const facts = r.facts || {};
  return el("div", { class: "panel", style: "box-shadow:none" },
    el("div", { class: "detail-head" }, gauge(a.score, 64),
      el("div", { class: "title" }, el("h3", {}, r.device), el("div", { class: "hint mono" }, [facts.platform, facts.software_version && `IOS-XE ${facts.software_version}`, facts.serial_number].filter(Boolean).join(" · "))),
      badge(a.rating), r.approved ? badge("AI review approved", "approved") : badge("AI review not approved", "not_approved"),
      el("div", { class: "actions" }, el("button", { class: "btn small", onclick: () => openAudit(r.audit_id) }, "Open full audit"))),
    el("div", { class: "stats", style: "margin-top:10px" },
      ...SEVERITIES.map((s) => el("div", { class: "stat" }, el("b", { style: `color:${SEV_COLOR[s]}` }, a.open_by_severity[s]), el("span", {}, `open ${s}`))),
      el("div", { class: "stat" }, el("b", {}, r.counts.PASS), el("span", {}, "passed")),
      el("div", { class: "stat" }, el("b", {}, secs(r.duration_s)), el("span", {}, `${r.tokens.toLocaleString()} tokens · ${money(r.cost_usd)}`))));
}

function handle(msg, area) {
  switch (msg.type) {
    case "run_start":
      if (msg.total > 1) area.append(el("p", { class: "hint" }, `Batch of ${msg.total} configs. Audits run one after another; you review them together at the end.`));
      break;
    case "audit_start": {
      resetPipeline();
      const state = el("span", {}, badge("running", "running"));
      const timeline = el("div", { class: "timeline" });
      const body = el("div", { class: "audit-body" }, timeline);
      const details = el("details", { open: true }, el("summary", { class: "audit-head" }, el("span", { class: "title" }, msg.label), state));
      details.append(body);
      const section = el("section", { class: "panel audit-section" }, details);
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
      s.state.replaceChildren(badge(r.assessment.rating), " ", el("span", { class: "hint" }, pct(r.assessment.score)));
      const timeline = s.body.firstElementChild;
      const wrap = el("details", { class: "tool" }, el("summary", {}, el("span", { class: "fn" }, "Agent conversation"), el("span", { class: "args" }, `${timeline.children.length} steps`)));
      timeline.replaceWith(wrap);
      wrap.append(el("div", { style: "padding:0 10px 10px" }, timeline));
      s.body.prepend(resultCard(r));
      break;
    }
    case "audit_error":
      sections[msg.index]?.state.replaceChildren(badge("error", "error"));
      sections[msg.index]?.body.append(el("div", { class: "lockout" }, msg.error));
      break;
    case "question": {
      setActiveAgent("HumanApprover");
      area.querySelector(".review")?.remove();
      let panel;
      if (msg.kind === "review") {
        panel = renderReviewForm(msg.payload, {
          draft: reviewDraft,
          onSubmit: (data) => { reviewDraft = data; socket?.send(JSON.stringify({ action: "answer", text: JSON.stringify(data) })); panel.append(el("p", { class: "hint" }, "Submitted. Recording decisions...")); },
          onSkip: ({ overwrite }) => socket?.send(JSON.stringify({ action: "answer", text: JSON.stringify({ skip: true, overwrite }) })),
        });
      } else {  // generic fallback (e.g. future question kinds)
        const input = el("input", { type: "text", placeholder: "Your answer" });
        panel = el("section", { class: "panel review" }, el("h3", {}, "HumanApprover"), el("p", {}, msg.text), input,
          el("div", { class: "footer" }, el("button", { class: "btn primary", onclick: () => socket?.send(JSON.stringify({ action: "answer", text: input.value })) }, "Send")));
      }
      area.append(panel);
      panel.scrollIntoView({ behavior: "smooth", block: "start" });
      break;
    }
    case "run_end":
      area.querySelector(".review")?.remove();
      renderRunEnd(msg, area);
      loadConfigs();
      break;
    case "error":
      area.append(el("div", { class: "panel lockout" }, msg.message));
      toast(msg.message);
      break;
  }
}

function renderRunEnd(msg, area) {
  const panel = el("section", { class: "panel" },
    el("div", { class: "panel-head" }, el("h3", {}, "Run complete"),
      msg.all_approved ? badge("all audits AI-approved", "approved") : badge("needs attention", "not_approved")));
  if (Object.keys(msg.errors).length) panel.append(el("div", { class: "lockout" }, Object.entries(msg.errors).map(([k, v]) => `${k}: ${v}`).join("\n")));
  panel.append(el("div", { class: "select-row" }, ...msg.audit_ids.map((id) => {
    const a = msg.assessments[id];
    return el("button", { class: "btn small", onclick: () => openAudit(id) }, `Open ${id}`, a ? badge(a.rating) : null);
  }), el("button", { class: "btn small ghost", onclick: () => showView("dashboard") }, "View dashboard")));
  panel.append(el("p", { class: "hint", style: "margin-top:10px" }, "Files written:"), el("ul", { class: "files mono" }, ...msg.written.map((p) => el("li", {}, p))));
  area.append(panel);
  panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

$("#run-btn").addEventListener("click", () => {
  const ids = selectedConfigs();
  if (!ids.length) return;
  startRun({ mode: ids.length > 1 ? "batch" : "audit", configs: ids, export_allowed: $("#export-allowed").checked });
});

// --------------------------------------------------------------------------- audit detail

let AUDIT = null;
const viewCache = {};

async function openAudit(id, tab = "overview", focus = null) {
  showView("audit", { updateHash: false });
  const root = $("#view-audit");
  root.replaceChildren(el("p", { class: "hint" }, "Loading audit..."));
  try { AUDIT = await api(`/api/audits/${encodeURIComponent(id)}`); } catch (e) { root.replaceChildren(el("div", { class: "empty" }, `Cannot load audit: ${e.message}`)); return; }
  delete viewCache[id];
  renderAudit(tab, focus);
}

function renderAudit(tab, focus) {
  const d = AUDIT;
  history.replaceState(null, "", `#audit/${d.audit_id}/${tab}`);  // deep link to this audit and sub-tab
  const root = $("#view-audit");
  const a = d.assessment || { score: null, rating: "-", counts: {}, open_by_severity: {}, effective: {} };
  const f = d.facts || {};
  const open = Object.values(a.effective || {}).filter((s) => s === "FAIL").length;
  const undecided = (d.review_items || []).filter((i) => !i.waiver && !i.decision).length;
  const actions = el("div", { class: "actions" },
    ...d.outputs.map((kind) => el("a", { class: "btn small", href: `/api/audits/${encodeURIComponent(d.audit_id)}/${kind}`, target: "_blank", rel: "noopener" }, kind === "report" ? "Audit report (.md)" : "Remediation script")),
    d.resumable ? el("button", { class: "btn small primary", onclick: () => startRun({ mode: "resume", audit_id: d.audit_id, export_allowed: true }) }, "Resume audit") : null,
    el("button", { class: "btn small ghost", onclick: () => history.length > 1 ? history.back() : showView("history") }, "Back"));
  const head = el("section", { class: "panel" }, el("div", { class: "detail-head" }, gauge(a.score),
    el("div", { class: "title" }, el("h1", {}, d.device || d.config || d.audit_id),
      el("div", { class: "hint mono" }, [f.platform, f.software_version && `IOS-XE ${f.software_version}`, f.serial_number && `SN ${f.serial_number}`].filter(Boolean).join(" · ") || d.config),
      el("div", { class: "select-row", style: "margin-top:6px" }, a.rating ? badge(a.rating) : null,
        d.approved ? badge("AI review approved", "approved") : badge(d.status.replace("_", " "), d.status),
        d.reviewed ? badge(`reviewed by ${d.reviewer}`, "reviewed") : undecided ? badge(`${undecided} awaiting your decision`, "warn") : null,
        el("span", { class: "hint" }, `Report CG-${d.audit_id} · ${when(d.started)}`))),
    actions));
  const tabs = [["overview", "Overview"], ["findings", "Findings", open], ["config", "Configuration"], ["remediation", "Remediation", Object.keys(d.remediations).length],
    ["review", "Review", undecided || null], ["log", "Agent log", d.timeline.length]];
  const bar = el("div", { class: "subtabs" }, ...tabs.map(([key, label, n]) => el("button", { class: `subtab${key === tab ? " active" : ""}`, onclick: () => renderAudit(key) }, label, n ? el("span", { class: "n" }, n) : null)));
  const body = el("div");
  root.replaceChildren(head, bar, body);
  ({ overview: auditOverview, findings: auditFindings, config: auditConfig, remediation: auditRemediation, review: auditReview, log: auditLog })[tab](body, focus);
}

function auditOverview(body) {
  const d = AUDIT;
  const a = d.assessment;
  if (!a) { body.append(el("div", { class: "empty" }, "This audit stopped before any findings were recorded.")); return; }
  const f = d.facts || {};
  const intf = f.interfaces || {};
  const facts = [["Hostname", f.hostname || d.device], ["Platform (PID)", f.platform], ["Serial number", f.serial_number], ["Software version", f.software_version && `IOS-XE ${f.software_version}`],
    ["Boot image", f.boot_image], ["Configuration", f.config_lines && `${f.config_lines} lines · ${d.config}`],
    ["Interfaces", intf.physical !== undefined && `${intf.physical} physical · ${intf.virtual} virtual · ${intf.shutdown} shut down`],
    ["Management access", f.vty_lines !== undefined && `${f.vty_lines} vty lines · ${f.local_users} local user(s) · AAA ${f.aaa ? "on" : "off"}`],
    ["SNMP", f.snmp], ["ACLs / routing", f.acls !== undefined && `${f.acls} ACL(s) · ${(f.routing_protocols || []).join(", ") || "static only"}`]]
    .filter(([, v]) => v);
  const ids = d.finding_ids;
  const key = Object.keys(ids).filter((r) => a.effective[r] === "FAIL").map((r) => d.findings.find((x) => x.rule_id === r)).filter((x) => x && ["critical", "high"].includes(x.severity));
  const lastReview = d.reviews[d.reviews.length - 1];
  body.append(el("div", { class: "kpis" },
    kpi(pct(a.score), "Compliance score", el("div", { class: "hint" }, "weighted by severity")),
    kpi(a.counts.FAIL, "Open findings", sevBar(a.open_by_severity)),
    kpi(a.counts.PASS, "Controls passed"),
    kpi(a.counts.RISK_ACCEPTED, "Risks accepted"),
    kpi(a.counts.FALSE_POSITIVE, "False positives"),
    kpi(money(d.cost_usd), "AI cost", el("div", { class: "hint" }, `${d.tokens.toLocaleString()} tokens · ${secs(d.duration_s)}`))),
  el("div", { class: "grid-2" },
    el("section", { class: "panel" }, el("h2", {}, "Device information"), el("table", { class: "grid facts" }, el("tbody", {}, ...facts.map(([k, v]) => el("tr", {}, el("td", {}, k), el("td", {}, v)))))),
    el("div", { class: "stack" },
      el("section", { class: "panel" }, el("h2", {}, "Key risks"),
        key.length ? el("div", {}, ...key.map((x) => el("div", { class: "ev-line", style: "margin-top:8px" }, badge(x.severity),
          el("button", { class: "link", onclick: () => renderAudit("findings", x.rule_id) }, `${ids[x.rule_id]} ${x.rule_id} ${x.title}`))))
          : el("p", { class: "hint", style: "margin-top:8px" }, "No open critical or high findings.")),
      el("section", { class: "panel" }, el("h2", {}, "Review and sign-off"),
        el("table", { class: "grid facts" }, el("tbody", {},
          el("tr", {}, el("td", {}, "AI quality review"), el("td", {}, d.approved ? "Approved (Critic)" : "Not approved")),
          el("tr", {}, el("td", {}, "Human reviewer"), el("td", {}, lastReview ? lastReview.reviewer || "-" : "Pending")),
          el("tr", {}, el("td", {}, "Reviewed on"), el("td", {}, lastReview ? when(lastReview.ts) : "-")),
          el("tr", {}, el("td", {}, "Change ticket"), el("td", {}, lastReview?.ticket || "-")))),
        el("button", { class: "btn small", style: "margin-top:10px", onclick: () => renderAudit("review") }, d.reviewed ? "Update review" : "Review findings")))));
}

function auditFindings(body, focus) {
  const d = AUDIT;
  const a = d.assessment;
  if (!a) { body.append(el("div", { class: "empty" }, "No findings recorded.")); return; }
  let statusFilter = focus ? "all" : "open";
  let sevFilter = "";
  let text = "";
  const list = el("div");
  const chips = [["open", "Open"], ["accepted", "Risk accepted"], ["fp", "False positive"], ["pass", "Passed"], ["na", "N/A"], ["all", "All"]];
  const chipBar = el("div", { class: "filters" });
  const match = { open: "FAIL", accepted: "RISK_ACCEPTED", fp: "FALSE_POSITIVE", pass: "PASS", na: "NOT_APPLICABLE" };
  const sevSel = el("select", { onchange: (e) => { sevFilter = e.target.value; draw(); } }, el("option", { value: "" }, "All severities"), ...SEVERITIES.map((s) => el("option", { value: s }, s)));
  const search = el("input", { type: "search", placeholder: "Search rule, title, evidence", style: "max-width:260px", oninput: (e) => { text = e.target.value.toLowerCase(); draw(); } });
  function drawChips() {
    chipBar.replaceChildren(...chips.map(([k, label]) => el("button", { class: `chip-btn${k === statusFilter ? " active" : ""}`, onclick: () => { statusFilter = k; drawChips(); draw(); } }, label)), sevSel, search);
  }
  const order = (x) => [Object.keys(d.finding_ids).includes(x.rule_id) ? 0 : 1, SEVERITIES.indexOf(x.severity), x.rule_id];
  function draw() {
    const rows = d.findings
      .filter((x) => statusFilter === "all" || a.effective[x.rule_id] === match[statusFilter])
      .filter((x) => !sevFilter || x.severity === sevFilter)
      .filter((x) => !text || `${x.rule_id} ${x.title} ${x.evidence.map((e) => e.text).join(" ")}`.toLowerCase().includes(text))
      .sort((p, q) => { const a1 = order(p), b1 = order(q); return a1[0] - b1[0] || a1[1] - b1[1] || a1[2].localeCompare(b1[2]); });
    list.replaceChildren(...(rows.length ? rows.map(findingCard) : [el("p", { class: "hint" }, "No findings match the filter.")]));
    if (focus) {
      const target = list.querySelector(`[data-rule="${focus}"]`);
      if (target) { target.open = true; target.scrollIntoView({ block: "center" }); }
      focus = null;
    }
  }
  function findingCard(x) {
    const eff = a.effective[x.rule_id];
    const dec = d.decisions[x.rule_id];
    const rem = d.remediations[x.rule_id];
    const card = el("details", { class: "finding", "data-sev": x.severity, "data-rule": x.rule_id },
      el("summary", {}, d.finding_ids[x.rule_id] ? el("span", { class: "fid" }, d.finding_ids[x.rule_id]) : null,
        el("b", { class: "mono" }, x.rule_id), el("span", {}, x.title), badge(x.severity), statusBadge(eff),
        el("span", { class: "hint" }, d.status_labels[x.rule_id] || ""), ...frameworkChips(d.frameworks[x.rule_id])));
    const b = el("div", { class: "body" }, el("div", {}, x.reason));
    if (x.evidence.length) {
      b.append(el("div", { class: "label", style: "margin:0" }, "Evidence"),
        ...x.evidence.map((e) => el("div", { class: "ev-line" },
          el("button", { class: "link mono", title: "Show in configuration", onclick: () => renderAudit("config", e.line_number) }, `line ${e.line_number}`),
          el("code", {}, e.text.trim()))));
    }
    if (x.missing.length) b.append(el("div", { class: "label", style: "margin:0" }, "Missing configuration"), ...x.missing.map((m) => el("div", { class: "hint" }, m)));
    if (rem) b.append(el("div", { class: "label", style: "margin:0" }, "Risk"), el("div", {}, rem.risk_summary));
    if (x.advisory) b.append(el("div", { class: "hint" }, `Advisory: ${x.advisory}`));
    if (dec) b.append(el("div", { class: "hint" }, `Reviewer decision: ${dec.action.replace("_", " ")} by ${dec.reviewer} on ${when(dec.decided_at)}${dec.ticket ? ` · ticket ${dec.ticket}` : ""}${dec.comment ? ` · "${dec.comment}"` : ""}`));
    else if (a.waivers && a.waivers[x.rule_id]) { const w = a.waivers[x.rule_id]; b.append(el("div", { class: "hint" }, `Waiver: accepted by ${w.approver} until ${w.expires}: ${w.justification}`)); }
    card.append(b);
    return card;
  }
  drawChips();
  draw();
  body.append(el("section", { class: "panel" }, chipBar, list));
}

async function auditConfig(body, line) {
  const d = AUDIT;
  const panel = el("section", { class: "panel" }, el("p", { class: "hint" }, "Loading configuration..."));
  body.append(panel);
  const view = viewCache[d.audit_id]?.config || await api(`/api/audits/${encodeURIComponent(d.audit_id)}/view/config`).catch((e) => ({ available: false, reason: e.message }));
  (viewCache[d.audit_id] = viewCache[d.audit_id] || {}).config = view;
  if (!view.available) { panel.replaceChildren(el("div", { class: "empty" }, `Configuration unavailable: ${view.reason}`)); return; }
  const a = d.assessment || { effective: {} };
  const hlLines = Object.keys(view.highlights).map(Number).sort((x, y) => x - y);
  const cfg = el("div", { class: "cfg" });
  view.lines.forEach((text, i) => {
    const n = i + 1;
    const marks = view.highlights[String(n)] || [];
    const failing = marks.filter((m) => m.status === "FAIL");
    const accepted = marks.filter((m) => m.status === "RISK_ACCEPTED");
    let cls = "ln";
    if (failing.length) cls += " hl";
    else if (accepted.length) cls += " hl acc";
    else if (marks.length) cls += " hl ok";
    const worst = failing.sort((p, q) => SEVERITIES.indexOf(p.severity) - SEVERITIES.indexOf(q.severity))[0];
    cfg.append(el("div", { class: cls, id: `cfg-line-${n}`, style: worst ? `--sev:${SEV_COLOR[worst.severity]}` : "" },
      el("span", { class: "no" }, n), el("span", { class: "tx" }, text || " "),
      marks.length ? el("span", { class: "tags" }, ...marks.map((m) => el("span", { title: `${m.rule_id}: ${EFFECTIVE_LABEL[m.status] || m.status}` }, m.rule_id))) : null));
  });
  let cursor = -1;
  const jump = (dir) => {
    const fails = hlLines.filter((n) => (view.highlights[String(n)] || []).some((m) => a.effective[m.rule_id] === "FAIL" || m.status === "FAIL"));
    if (!fails.length) return;
    cursor = (cursor + dir + fails.length) % fails.length;
    focusLine(fails[cursor]);
  };
  function focusLine(n) {
    const node = cfg.querySelector(`#cfg-line-${n}`);
    if (!node) return;
    node.scrollIntoView({ block: "center" });
    node.classList.remove("flash");
    void node.offsetWidth;
    node.classList.add("flash");
  }
  panel.replaceChildren(
    el("div", { class: "panel-head" }, el("div", {}, el("h2", {}, view.file), el("p", { class: "hint" }, "Masked running-config: secrets are never shown. Highlighted lines are cited as evidence.")),
      el("div", { class: "select-row" }, el("button", { class: "btn small", onclick: () => jump(-1) }, "Previous open finding"), el("button", { class: "btn small", onclick: () => jump(1) }, "Next open finding"))),
    el("div", { class: "select-row hint", style: "margin-bottom:8px" },
      el("span", {}, el("span", { class: "swatch", style: "display:inline-block;background:var(--sev-critical)" }), " open finding"),
      el("span", {}, el("span", { class: "swatch", style: "display:inline-block;background:var(--accepted)" }), " risk accepted"),
      el("span", {}, el("span", { class: "swatch", style: "display:inline-block;background:var(--pass)" }), " evidence for a passing control")),
    cfg);
  if (line) setTimeout(() => focusLine(line), 50);
}

async function auditRemediation(body) {
  const d = AUDIT;
  const ids = Object.keys(d.remediations).sort((p, q) => (d.finding_ids[p] || "").localeCompare(d.finding_ids[q] || ""));
  if (!ids.length) { body.append(el("div", { class: "empty" }, "No remediation was drafted for this audit.")); return; }
  const byId = Object.fromEntries(d.findings.map((x) => [x.rule_id, x]));
  const cards = ids.map((id) => {
    const r = d.remediations[id];
    const x = byId[id] || {};
    const dec = d.decisions[id];
    const lockouts = r.warnings.filter((w) => w.toUpperCase().includes("LOCKOUT"));
    return el("details", { class: "finding", "data-sev": x.severity },
      el("summary", {}, el("span", { class: "fid" }, d.finding_ids[id] || ""), el("b", { class: "mono" }, id), x.title || "", x.severity ? badge(x.severity) : null,
        dec ? badge(dec.action.replace("_", " "), dec.action === "approve_fix" ? "approved" : dec.action === "reject_fix" ? "no" : "accepted") : badge("pending review", "pending"),
        lockouts.length ? badge("lockout warning", "warn") : null),
      el("div", { class: "body" }, el("div", {}, r.risk_summary),
        ...r.warnings.map((w) => el("div", { class: w.toUpperCase().includes("LOCKOUT") ? "lockout" : "hint" }, w)),
        el("pre", { class: "code", style: "margin:0" }, r.commands.join("\n"))));
  });
  const diffBox = el("div");
  let scope = "all";
  const scopeSel = el("select", { onchange: (e) => { scope = e.target.value; loadDiff(); } },
    el("option", { value: "all" }, "All drafted fixes"), el("option", { value: "approved" }, "Approved fixes only"));
  async function loadDiff() {
    diffBox.replaceChildren(el("p", { class: "hint" }, "Building preview..."));
    const p = await api(`/api/audits/${encodeURIComponent(d.audit_id)}/view/preview?scope=${scope}`).catch((e) => ({ available: false, reason: e.message }));
    if (!p.available) { diffBox.replaceChildren(el("div", { class: "empty" }, `Preview unavailable: ${p.reason}`)); return; }
    if (!p.diff.length) { diffBox.replaceChildren(el("p", { class: "hint" }, scope === "approved" ? "No approved fixes yet." : "No changes.")); return; }
    diffBox.replaceChildren(el("p", { class: "hint" }, `${p.rules.join(", ")} · +${p.added} / -${p.removed} lines (secrets, and placeholders in secret positions, are masked)`),
      el("div", { class: "diff" }, ...p.diff.map((line) => el("div", {
        class: line.startsWith("@@") ? "hunk" : line.startsWith("+") && !line.startsWith("+++") ? "add" : line.startsWith("-") && !line.startsWith("---") ? "del" : "",
      }, line || " "))));
  }
  body.append(el("div", { class: "grid-2" },
    el("section", { class: "panel" }, el("div", { class: "panel-head" }, el("h2", {}, "Drafted remediation"), el("span", { class: "hint" }, "syntax-checked and verified to resolve each finding")), ...cards),
    el("section", { class: "panel" }, el("div", { class: "panel-head" }, el("h2", {}, "Change preview"), scopeSel),
      el("p", { class: "hint", style: "margin-bottom:8px" }, "The running-config before and after applying the fixes, simulated by ConfigGuard. Nothing is sent to the device."), diffBox)));
  loadDiff();
}

function auditReview(body) {
  const d = AUDIT;
  const items = d.review_items || [];
  const history_ = el("section", { class: "panel" }, el("h2", {}, "Review history"),
    d.reviews.length ? el("table", { class: "grid" }, el("thead", {}, el("tr", {}, ...["When", "Reviewer", "Ticket", "Decisions"].map((h) => el("th", {}, h)))),
      el("tbody", {}, ...d.reviews.slice().reverse().map((r) => el("tr", {}, el("td", {}, when(r.ts)), el("td", {}, r.reviewer || "-"), el("td", {}, r.ticket || "-"),
        el("td", {}, (r.decisions || []).map((x) => `${x.rule_id}: ${x.action.replace("_", " ")}`).join(", ") || "none")))))
      : el("p", { class: "hint", style: "margin-top:8px" }, "No human review recorded yet."));
  if (!items.length) { body.append(el("div", { class: "empty" }, "No failed controls to review."), history_); return; }
  const payload = {
    devices: [{ audit_id: d.audit_id, device: d.device, approved: d.approved, facts: d.facts, assessment: d.assessment, items }],
    existing_reports: d.outputs.includes("report") ? [d.device] : [], export_allowed: true,
    reviewer: INFO.reviewer_name || (d.reviews.length ? d.reviews[d.reviews.length - 1].reviewer : "") || "",
    default_expiry: isoPlus(90), max_expiry: isoPlus(INFO.max_waiver_days || 365), errors: [],
  };
  let draft = {};
  const holder = el("div");
  const draw = (errors = []) => {
    holder.replaceChildren(renderReviewForm({ ...payload, errors }, {
      draft,
      title: d.reviewed ? "Update the review" : "Review the failed controls",
      onSubmit: async (data) => {
        draft = data;
        try {
          await api(`/api/audits/${encodeURIComponent(d.audit_id)}/review`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(data) });
          toast("Review recorded. Report and approved-fix script updated.");
          openAudit(d.audit_id, "overview");
        } catch (e) { draw(e.body?.errors || [e.message]); }
      },
    }));
  };
  draw();
  body.append(holder, history_);
}

function auditLog(body) {
  const timeline = el("div", { class: "timeline" });
  const render = createTimeline(timeline, { live: false });
  for (const rec of AUDIT.timeline) render(rec);
  body.append(el("section", { class: "panel" }, el("h2", {}, "Agent conversation replay"), el("p", { class: "hint", style: "margin-bottom:8px" }, "Every agent message and tool call, as logged in logs/<audit_id>.jsonl."), timeline));
}

// --------------------------------------------------------------------------- history

let HISTORY = [];
async function loadHistory() {
  HISTORY = await api("/api/audits");
  drawHistory();
}
function drawHistory() {
  const q = $("#history-filter").value.toLowerCase();
  const rows = HISTORY.filter((a) => !q || `${a.device} ${a.config} ${a.status} ${a.platform} ${a.rating} ${a.reviewer}`.toLowerCase().includes(q));
  $("#history-empty").classList.toggle("hidden", HISTORY.length > 0);
  $("#history-table tbody").replaceChildren(...rows.map((a) => el("tr", { class: "clickable", onclick: () => openAudit(a.audit_id) },
    el("td", {}, when(a.started)), el("td", {}, el("b", {}, a.device || "-"), el("div", { class: "hint mono" }, a.config || "")),
    el("td", { class: "mono" }, a.platform ? `${a.platform} · ${a.software_version || ""}` : "-"),
    el("td", {}, pct(a.score)), el("td", {}, a.rating ? badge(a.rating) : "-"),
    el("td", {}, badge(a.status.replace("_", " "), a.status)),
    el("td", {}, a.reviewed ? badge(`by ${a.reviewer}`, "reviewed") : (a.effective_counts?.FAIL ? badge("pending", "warn") : badge("-", "pending"))),
    el("td", {}, a.effective_counts ? a.effective_counts.FAIL : "-"), el("td", {}, money(a.cost_usd)))));
}
$("#history-refresh").addEventListener("click", loadHistory);
$("#history-filter").addEventListener("input", drawHistory);

// --------------------------------------------------------------------------- risk register

async function loadRisk() {
  const waivers = await api("/api/waivers");
  $("#risk-empty").classList.toggle("hidden", waivers.length > 0);
  $("#risk-table tbody").replaceChildren(...waivers.map((w) => {
    const cell = el("td");
    const revoke = el("button", { class: "btn small danger", onclick: () => {
      cell.replaceChildren(el("span", { class: "hint" }, "Revoke? "),
        el("button", { class: "btn small danger", onclick: async () => {
          try { await api(`/api/waivers/${encodeURIComponent(w.device)}/${encodeURIComponent(w.rule_id)}`, { method: "DELETE" }); toast("Waiver revoked: the finding is open again on the next audit."); loadRisk(); }
          catch (e) { toast(`Revoke failed: ${e.message}`); }
        } }, "Yes"), " ", el("button", { class: "btn small", onclick: () => cell.replaceChildren(revoke) }, "Cancel"));
    } }, "Revoke");
    cell.append(revoke);
    const soon = w.active && w.days_left <= 14;
    return el("tr", {},
      el("td", {}, w.active ? badge(soon ? `expires in ${w.days_left}d` : "active", soon ? "warn" : "accepted") : badge("expired", "no")),
      el("td", {}, el("b", {}, w.device)), el("td", { class: "mono" }, w.rule_id), el("td", {}, w.justification),
      el("td", {}, w.approver), el("td", {}, w.ticket || "-"), el("td", {}, w.created), el("td", {}, w.expires), cell);
  }));
}
$("#risk-refresh").addEventListener("click", loadRisk);

// --------------------------------------------------------------------------- baseline

let baselineLoaded = false;
async function loadBaseline() {
  if (baselineLoaded) return;
  const b = await api("/api/baseline");
  baselineLoaded = true;
  $("#baseline-title").textContent = `Baseline: ${b.file} (${b.rules.length} controls)`;
  $("#baseline-settings").textContent = `External interface pattern: ${b.settings.external_interface_pattern} · max exec-timeout: ${b.settings.max_exec_timeout_minutes} min · default SNMP communities: ${b.settings.default_snmp_communities.join(", ")}`;
  const tbody = $("#baseline-table tbody");
  tbody.replaceChildren();
  for (const r of b.rules) {
    const detail = el("tr", { class: "hidden" }, el("td", { colspan: "6" },
      el("p", {}, r.description), r.advisory ? el("p", { class: "hint" }, `Advisory: ${r.advisory}`) : null,
      el("div", { class: "label", style: "margin-left:0" }, "check"), el("pre", { class: "code", style: "margin:0 0 8px" }, JSON.stringify(r.check, null, 2)),
      el("div", { class: "label", style: "margin-left:0" }, "remediation hint"), el("pre", { class: "code", style: "margin:0" }, (r.remediation_hint || []).join("\n"))));
    tbody.append(el("tr", { class: "clickable", onclick: () => detail.classList.toggle("hidden") },
      el("td", { class: "mono" }, r.id), el("td", {}, r.title), el("td", {}, badge(r.severity)),
      el("td", {}, el("div", { class: "select-row", style: "gap:4px" }, ...frameworkChips(r.frameworks))),
      el("td", { class: "mono" }, r.check.type), el("td", {}, r.lockout_risk ? badge("yes", "warn") : "-")), detail);
  }
}

// --------------------------------------------------------------------------- boot

function route() {
  const hash = location.hash.slice(1);
  if (hash.startsWith("audit/")) {
    const [, id, tab] = hash.split("/");
    openAudit(id, ["overview", "findings", "config", "remediation", "review", "log"].includes(tab) ? tab : "overview");
  }
  else showView(["dashboard", "run", "history", "risk", "baseline"].includes(hash) ? hash : "dashboard", { updateHash: false });
}
loadInfo().catch((e) => toast(`Cannot reach backend: ${e.message}`));
loadConfigs().catch((e) => toast(`Cannot load configs: ${e.message}`));
route();
