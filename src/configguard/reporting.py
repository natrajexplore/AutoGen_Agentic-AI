"""Reports are rendered from the AuditContext record (tool output), never from agent chat text.

The Markdown report follows the structure of a professional audit deliverable: cover, executive
summary, scope and method, findings register, detailed findings, compliant / not-applicable
controls, risk-acceptance register, review sign-off and audit trail.

Config-derived text is untrusted, so it is placed in Markdown code spans (no HTML/link injection);
agent-written prose is HTML-escaped; CSV cells are guarded against spreadsheet formula injection.
"""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from configguard.context import AuditContext
from configguard.models import Finding, ReviewDecision
from configguard.scoring import Assessment, active_waivers, assess

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
REVIEW_BANNER = "REVIEW BEFORE APPLYING"
MAPPING_NOTE = "Framework mappings are best-effort control IDs; verify them with your compliance team."


@dataclass
class DeviceResult:
    """Everything reporting needs about one finished audit."""

    ctx: AuditContext
    device: str
    approved: bool
    critic_approved: bool
    gaps: list[str]
    duration_s: float
    prompt_tokens: int
    completion_tokens: int
    cost_usd: float
    model: str

    @property
    def counts(self) -> dict[str, int]:
        statuses = [f.status for f in self.ctx.findings.values()]
        return {s: statuses.count(s) for s in ("PASS", "FAIL", "NOT_APPLICABLE")}

    @property
    def assessment(self) -> Assessment:
        ctx = self.ctx
        return assess(list(ctx.findings.values()), ctx.decisions, active_waivers(ctx.waivers, ctx.hostname))


def device_name(ctx: AuditContext) -> str:
    """Safe file stem: hostname if parsed, else the config file stem."""
    return re.sub(r"[^A-Za-z0-9_.-]", "_", ctx.hostname)[:64]


def code(text: str) -> str:
    """Render untrusted text as an inline code span that cannot break out of itself."""
    text = text.replace("\n", " ").strip()
    fence = "``" if "`" in text else "`"
    return f"{fence} {text} {fence}" if fence == "``" else f"`{text}`"


def _cell(text: str) -> str:
    return text.replace("|", "\\|")


def prose(text: str) -> str:
    """Agent-written text in Markdown: escape HTML so it renders as text, never as markup."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _sorted_findings(ctx: AuditContext) -> list[Finding]:
    order = [r.id for r in ctx.baseline.rules] if ctx.baseline else sorted(ctx.findings)
    return [ctx.findings[r] for r in order if r in ctx.findings]


def finding_ids(ctx: AuditContext) -> dict[str, str]:
    """Stable report IDs (F-01, F-02, ...) for failed controls, worst severity first."""
    fails = sorted((f for f in ctx.findings.values() if f.status == "FAIL"),
                   key=lambda f: (SEVERITY_ORDER[f.severity], f.rule_id))
    return {f.rule_id: f"F-{i:02d}" for i, f in enumerate(fails, start=1)}


def status_label(effective: str, decision: ReviewDecision | None, expires: str | None = None) -> str:
    if effective == "PASS":
        return "Compliant"
    if effective == "NOT_APPLICABLE":
        return "Not applicable"
    if effective == "FALSE_POSITIVE":
        return "False positive"
    if effective == "RISK_ACCEPTED":
        return f"Risk accepted until {expires}" if expires else "Risk accepted"
    if decision and decision.action == "approve_fix":
        return "Open - fix approved"
    if decision and decision.action == "reject_fix":
        return "Open - fix rejected"
    return "Open - pending review"


def _frameworks(ctx: AuditContext, rule_id: str, short: bool = False) -> str:
    rule = ctx.baseline.rule(rule_id) if ctx.baseline else None
    if not rule:
        return "-"
    parts = []
    for fw, ids in rule.frameworks.items():
        if ids:
            label = fw.split(" ")[0] if short else fw
            parts.append(f"{label} {', '.join(ids)}")
    return "; ".join(parts) or "-"


def _expiry(result: DeviceResult, rule_id: str) -> str | None:
    ctx = result.ctx
    d = ctx.decisions.get(rule_id)
    if d and d.action == "accept_risk" and d.expires:
        return d.expires.isoformat()
    w = result.assessment.waivers.get(rule_id)
    return w.expires.isoformat() if w else None


def _reviewer(ctx: AuditContext) -> ReviewDecision | None:
    return max(ctx.decisions.values(), key=lambda d: d.decided_at, default=None)


def render_markdown(result: DeviceResult, generated: datetime) -> str:
    ctx = result.ctx
    a = result.assessment
    facts = ctx.facts or {}
    findings = _sorted_findings(ctx)
    ids = finding_ids(ctx)
    fails = [ctx.findings[r] for r in ids]
    passes = [f for f in findings if f.status == "PASS"]
    nas = [f for f in findings if f.status == "NOT_APPLICABLE"]
    last = _reviewer(ctx)
    reviewed = f"{last.reviewer}" + (f" · ticket {code(last.ticket)}" if last.ticket else "") if last else "_Not yet reviewed_"
    platform = " · ".join(x for x in (facts.get("platform"), f"IOS-XE {facts['software_version']}" if facts.get("software_version") else None) if x)

    lines = [
        "# Network Device Security Compliance Audit Report",
        "",
        "| | |",
        "|---|---|",
        f"| Device | **{result.device}**{(' · ' + platform) if platform else ''} |",
        f"| Report ID | {code('CG-' + ctx.audit_id)} |",
        f"| Report date | {generated.strftime('%Y-%m-%d %H:%M UTC')} |",
        f"| Baseline | {code(ctx.baseline_path.name)} ({len(findings)} controls) |",
        "| Classification | Confidential: contains masked configuration excerpts |",
        f"| Prepared by | ConfigGuard automated audit ({code(result.model)}) |",
        f"| Reviewed by | {reviewed} |",
        "",
        "## 1. Executive summary",
        "",
        f"**Compliance score: {a.score:.1f}%** · **Risk rating: {a.rating}** · "
        f"AI quality review: {'approved' if result.approved else '**not approved** - treat findings as provisional'}",
        "",
        f"{result.device} was assessed against {len(findings)} security controls. "
        f"{a.counts['PASS']} passed, {len(fails)} failed and {len(nas)} were not applicable. "
        f"Of the failed controls: {a.counts['FAIL']} open, {a.counts['RISK_ACCEPTED']} accepted as a risk, "
        f"{a.counts['FALSE_POSITIVE']} marked as a false positive by the reviewer.",
        "",
        "| Open findings | Critical | High | Medium | Low |",
        "|---|---|---|---|---|",
        "| Count | " + " | ".join(str(a.open_by_severity[s]) for s in ("critical", "high", "medium", "low")) + " |",
        "",
    ]
    if result.gaps:
        lines += ["> **Incomplete audit record:** " + "; ".join(result.gaps), ""]
    key = [f for f in fails if a.effective[f.rule_id] == "FAIL" and f.severity in ("critical", "high")]
    if key:
        lines += ["**Key risks**", ""]
        for f in key:
            rem = ctx.remediations.get(f.rule_id)
            lines.append(f"- **{ids[f.rule_id]} {f.title}** ({f.severity}): "
                         f"{prose(rem.risk_summary) if rem else prose(f.reason)}")
        lines.append("")

    lines += ["## 2. Scope and methodology", "", "**Device information**", "", "| | |", "|---|---|"]
    intf = facts.get("interfaces") or {}
    for label, value in (
        ("Hostname", facts.get("hostname") or result.device),
        ("Platform (PID)", facts.get("platform")),
        ("Serial number", facts.get("serial_number")),
        ("Software version", facts.get("software_version")),
        ("Configuration", f"{facts['config_lines']} lines, file {code(ctx.config_path.name)}, SHA-256 {code((ctx.config_sha256 or '')[:16])}" if facts.get("config_lines") else code(ctx.config_path.name)),
        ("Interfaces", f"{intf.get('physical', 0)} physical, {intf.get('virtual', 0)} virtual, {intf.get('shutdown', 0)} shut down" if intf else None),
        ("Management", f"{facts.get('vty_lines', 0)} vty lines, {facts.get('local_users', 0)} local user(s), AAA {'enabled' if facts.get('aaa') else 'disabled'}, SNMP {facts.get('snmp', '-')}" if facts else None),
        ("ACLs / routing", f"{facts.get('acls', 0)} ACL(s); routing: {', '.join(facts.get('routing_protocols') or []) or 'static only'}" if facts else None),
    ):
        if value:
            lines.append(f"| {label} | {value} |")
    lines += [
        "",
        "**Method**",
        "",
        "- Every control is evaluated by a deterministic rule engine against the configuration; each failure cites the exact configuration line or the required line that is missing.",
        "- Passwords, keys and SNMP communities are masked before any text is processed by the AI agents.",
        "- AI agents explain each risk and draft remediation; every draft is syntax-checked and verified to resolve its finding against a patched copy of the configuration.",
        "- An AI quality gate (Critic) reviews the recorded results, followed by human review of every failed control.",
        "- Compliance score: weighted share of applicable controls passing (critical 10, high 5, medium 3, low 1). Risk rating: severity of the worst open finding.",
        "",
        "## 3. Findings register",
        "",
    ]
    if fails:
        lines += ["| ID | Control | Title | Severity | Status | Frameworks |", "|---|---|---|---|---|---|"]
        for f in fails:
            label = status_label(a.effective[f.rule_id], ctx.decisions.get(f.rule_id), _expiry(result, f.rule_id))
            lines.append(f"| {ids[f.rule_id]} | {f.rule_id} | {_cell(f.title)} | {f.severity.capitalize()} | {label} | {_frameworks(ctx, f.rule_id, short=True)} |")
        lines += ["", f"_{MAPPING_NOTE}_", ""]
    else:
        lines += ["No control failures were found.", ""]

    if fails:
        lines += ["## 4. Detailed findings", ""]
    refs = ctx.baseline.settings.references if ctx.baseline else []
    for f in fails:
        d = ctx.decisions.get(f.rule_id)
        label = status_label(a.effective[f.rule_id], d, _expiry(result, f.rule_id))
        lines += [
            f"### {ids[f.rule_id]} · {f.rule_id} {f.title}",
            "",
            "| Severity | Status | Frameworks |",
            "|---|---|---|",
            f"| {f.severity.capitalize()} | {label} | {_frameworks(ctx, f.rule_id)} |",
            "",
            "**Description:** " + f.reason,
            "",
        ]
        if f.evidence:
            lines += ["**Evidence**", ""] + [f"- line {e.line_number}: {code(e.text)}" for e in f.evidence] + [""]
        if f.missing:
            lines += ["**Missing configuration**", ""] + [f"- {m}" for m in f.missing] + [""]
        rem = ctx.remediations.get(f.rule_id)
        if rem:
            lines += ["**Risk**", "", prose(rem.risk_summary), ""]
            lines += [f"**Recommendation ({REVIEW_BANNER})**", ""]
            if rem.warnings:
                lines += [f"> **{prose(w)}**" if "LOCKOUT" in w.upper() else f"> {prose(w)}" for w in rem.warnings] + [""]
            lines += ["```", *rem.commands, "```", ""]
        if d:
            note = f": {prose(d.comment)}" if d.comment else ""
            ticket = f", ticket {code(d.ticket)}" if d.ticket else ""
            lines += [f"**Reviewer decision:** {d.action.replace('_', ' ')} by {prose(d.reviewer)} on "
                      f"{d.decided_at.strftime('%Y-%m-%d')}{ticket}{note}", ""]
        elif f.rule_id in a.waivers:
            w = a.waivers[f.rule_id]
            lines += [f"**Risk acceptance (waiver):** approved by {prose(w.approver)}, expires {w.expires.isoformat()}: {prose(w.justification)}", ""]
        if f.advisory:
            lines += [f"_Advisory: {f.advisory}_", ""]
        if refs:
            lines += ["**References:** " + "; ".join(f"[{r.title}]({r.url})" for r in refs), ""]

    lines += ["## 5. Compliant controls", ""]
    if passes:
        lines += ["| Control | Title | Severity | Evidence |", "|---|---|---|---|"]
        for f in passes:
            ev = code(f.evidence[0].text) + f" (line {f.evidence[0].line_number})" if f.evidence else _cell(f.reason)
            lines.append(f"| {f.rule_id} | {_cell(f.title)} | {f.severity} | {_cell(ev)} |")
        lines.append("")
    else:
        lines += ["None.", ""]
    if nas:
        lines += ["## 6. Not applicable controls", "", "| Control | Title | Reason |", "|---|---|---|"]
        lines += [f"| {f.rule_id} | {_cell(f.title)} | {_cell(f.reason)} |" for f in nas] + [""]

    accepted = [f for f in fails if a.effective[f.rule_id] == "RISK_ACCEPTED"]
    fps = [f for f in fails if a.effective[f.rule_id] == "FALSE_POSITIVE"]
    lines += ["## 7. Risk acceptance register", ""]
    if accepted:
        lines += ["| ID | Control | Justification | Approved by | Ticket | Expires |", "|---|---|---|---|---|---|"]
        for f in accepted:
            d = ctx.decisions.get(f.rule_id)
            w = a.waivers.get(f.rule_id)
            just, who, tkt = (d.comment, d.reviewer, d.ticket) if d and d.action == "accept_risk" else (w.justification, w.approver, w.ticket) if w else ("", "", None)
            lines.append(f"| {ids[f.rule_id]} | {f.rule_id} | {_cell(prose(just))} | {_cell(prose(who))} | {tkt or '-'} | {_expiry(result, f.rule_id) or '-'} |")
        lines.append("")
    else:
        lines += ["No risks accepted.", ""]
    if fps:
        lines += ["**False positives**", ""]
        lines += [f"- {ids[f.rule_id]} {f.rule_id}: {prose(ctx.decisions[f.rule_id].comment)} ({prose(ctx.decisions[f.rule_id].reviewer)})" for f in fps] + [""]

    decided = {d.action for d in ctx.decisions.values()}
    counts = {act: sum(1 for d in ctx.decisions.values() if d.action == act) for act in ("approve_fix", "reject_fix", "accept_risk", "false_positive")}
    pending = sum(1 for f in fails if f.rule_id not in ctx.decisions and f.rule_id not in a.waivers)
    lines += [
        "## 8. Review and sign-off",
        "",
        "| | |",
        "|---|---|",
        f"| AI quality review | {'Approved (Critic)' if result.critic_approved else 'Not approved'}{' - record incomplete' if result.gaps else ''} |",
        f"| Human reviewer | {prose(last.reviewer) if last else '_pending_'} |",
        f"| Review date | {last.decided_at.strftime('%Y-%m-%d %H:%M UTC') if last else '-'} |",
        f"| Change ticket | {code(last.ticket) if last and last.ticket else '-'} |",
        f"| Decisions | {counts['approve_fix']} fix(es) approved · {counts['reject_fix']} rejected · "
        f"{counts['accept_risk']} risk(s) accepted · {counts['false_positive']} false positive(s) · {pending} pending |",
        "",
        "Remediation scripts contain only fixes approved above. ConfigGuard never applies changes to devices; "
        "apply approved changes through your change-management process."
        + ("" if decided else " _No human decisions recorded yet._"),
        "",
        "## Appendix A. Audit trail",
        "",
        "| | |",
        "|---|---|",
        f"| Audit ID | {code(ctx.audit_id)} |",
        f"| Model | {code(result.model)} |",
        f"| Tokens / cost | {result.prompt_tokens + result.completion_tokens:,} tokens · ${result.cost_usd:.4f} |",
        f"| Agent run time | {result.duration_s:.0f}s |",
        f"| Full log | {code('logs/' + ctx.audit_id + '.jsonl')} |",
        "",
        "---",
        "_Generated by ConfigGuard. Verdicts come from a deterministic rule engine; secrets are masked. "
        f"Remediation is a draft for human review and has not been applied to any device. {MAPPING_NOTE}_",
        "",
    ]
    return "\n".join(lines)


def render_remediation_script(result: DeviceResult, generated: datetime, rule_ids: list[str] | None = None) -> str:
    """Script for the given rules (default: every recorded remediation)."""
    ctx = result.ctx
    wanted = set(rule_ids) if rule_ids is not None else set(ctx.remediations)
    fails = [f for f in _sorted_findings(ctx) if f.status == "FAIL" and f.rule_id in ctx.remediations and f.rule_id in wanted]
    approvals = [ctx.decisions[f.rule_id] for f in fails if f.rule_id in ctx.decisions]
    last = max(approvals, key=lambda d: d.decided_at, default=None)
    bar = "!" + "=" * 72
    out = [
        bar,
        f"! {REVIEW_BANNER}",
        "! ConfigGuard draft remediation. NOT applied to any device.",
        f"! Device: {result.device}   Config: {ctx.config_path.name}   Audit: {ctx.audit_id}",
        f"! Generated: {generated.strftime('%Y-%m-%d %H:%M UTC')}",
    ]
    if last:
        out.append(f"! Fixes approved by: {last.reviewer} on {last.decided_at.strftime('%Y-%m-%d')}"
                   + (f"   Change ticket: {last.ticket}" if last.ticket else ""))
    out += [
        "! Apply in global configuration mode (configure terminal), in a maintenance window,",
        "! with console or out-of-band access available. Replace every <PLACEHOLDER> first.",
        bar,
    ]
    warnings = [(f.rule_id, w) for f in fails for w in ctx.remediations[f.rule_id].warnings if "LOCKOUT" in w.upper()]
    if warnings:
        out += ["!", "! LOCKOUT WARNINGS"] + [f"!   {rid}: {w}" for rid, w in warnings]
    placeholders = sorted({p for f in fails for c in ctx.remediations[f.rule_id].commands for p in re.findall(r"<[A-Z0-9_]+>", c)})
    if placeholders:
        out += ["!", "! Placeholders to replace: " + ", ".join(placeholders)]
    for f in fails:
        rem = ctx.remediations[f.rule_id]
        out += ["!", f"! --- {f.rule_id} {f.title} [{f.severity}]"]
        out += [f"! {w}" for w in rem.warnings]
        out += rem.commands
    out += ["!", f"! END - {REVIEW_BANNER}", ""]
    return "\n".join(out)


def _csv_safe(value: str) -> str:
    # Prevent spreadsheet formula injection from config-derived text.
    return "'" + value if value[:1] in ("=", "+", "-", "@", "\t", "\r") else value


def write_csv_summary(results: list[DeviceResult], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["device", "rule_id", "severity", "status", "evidence",
                         "review_status", "reviewer", "ticket", "frameworks"])
        for result in results:
            a = result.assessment
            ctx = result.ctx
            for f in _sorted_findings(ctx):
                evidence = "; ".join(f"L{e.line_number}: {e.text.strip()}" for e in f.evidence) or "; ".join(f.missing)
                d = ctx.decisions.get(f.rule_id)
                row = (result.device, f.rule_id, f.severity, f.status, evidence,
                       status_label(a.effective[f.rule_id], d, _expiry(result, f.rule_id)),
                       d.reviewer if d else "", (d.ticket or "") if d else "", _frameworks(ctx, f.rule_id, short=True))
                writer.writerow([_csv_safe(v) for v in row])
    return path


def render_batch_table(results: list[DeviceResult]) -> str:
    header = "| Device | Score | Rating | AI approved | PASS | FAIL | N/A | Open crit/high | Reviewed | Time | Tokens | Cost |"
    lines = [header, "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in results:
        c = r.counts
        a = r.assessment
        severe = a.open_by_severity["critical"] + a.open_by_severity["high"]
        reviewer = _reviewer(r.ctx)
        lines.append(
            f"| {r.device} | {a.score:.1f}% | {a.rating} | {'yes' if r.approved else 'NO'} | {c['PASS']} | {c['FAIL']} | "
            f"{c['NOT_APPLICABLE']} | {severe} | {reviewer.reviewer if reviewer else '-'} | {r.duration_s:.0f}s | "
            f"{r.prompt_tokens + r.completion_tokens:,} | ${r.cost_usd:.4f} |"
        )
    total_cost = sum(r.cost_usd for r in results)
    total_tokens = sum(r.prompt_tokens + r.completion_tokens for r in results)
    avg = sum(r.assessment.score for r in results) / len(results) if results else 0
    lines.append(f"| **Total ({len(results)})** | {avg:.1f}% avg | | | | | | | | | {total_tokens:,} | ${total_cost:.4f} |")
    return "\n".join(lines)


def now() -> datetime:
    return datetime.now(timezone.utc)
