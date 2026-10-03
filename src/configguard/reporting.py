"""Reports are rendered from the AuditContext record (tool output), never from agent chat text.

Config-derived text is untrusted, so it is placed in Markdown code spans (no HTML/link injection)
and CSV cells are guarded against spreadsheet formula injection.
"""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from configguard.context import AuditContext
from configguard.models import Finding

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
REVIEW_BANNER = "REVIEW BEFORE APPLYING"


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


def device_name(ctx: AuditContext) -> str:
    """Safe file stem: hostname if parsed, else the config file stem."""
    raw = (ctx.inventory or {}).get("hostname") or ctx.config_path.stem
    return re.sub(r"[^A-Za-z0-9_.-]", "_", raw)[:64]


def code(text: str) -> str:
    """Render untrusted text as an inline code span that cannot break out of itself."""
    text = text.replace("\n", " ").strip()
    fence = "``" if "`" in text else "`"
    return f"{fence} {text} {fence}" if fence == "``" else f"`{text}`"


def _cell(text: str) -> str:
    return text.replace("|", "\\|")


def _sorted_findings(ctx: AuditContext) -> list[Finding]:
    order = [r.id for r in ctx.baseline.rules] if ctx.baseline else sorted(ctx.findings)
    return [ctx.findings[r] for r in order if r in ctx.findings]


def render_markdown(result: DeviceResult, generated: datetime) -> str:
    ctx = result.ctx
    findings = _sorted_findings(ctx)
    fails = sorted((f for f in findings if f.status == "FAIL"), key=lambda f: SEVERITY_ORDER[f.severity])
    counts = result.counts
    status = "APPROVED" if result.approved else "NOT APPROVED - treat findings as provisional"

    lines = [
        f"# ConfigGuard audit: {result.device}",
        "",
        "| | |",
        "|---|---|",
        f"| Config file | {code(ctx.config_path.name)} |",
        f"| Audit ID | {code(ctx.audit_id)} |",
        f"| Generated | {generated.strftime('%Y-%m-%d %H:%M UTC')} |",
        f"| Baseline | {code(ctx.baseline_path.name)} |",
        f"| Review status | **{status}** |",
        f"| Model | {code(result.model)} · {result.prompt_tokens + result.completion_tokens:,} tokens · "
        f"${result.cost_usd:.4f} · {result.duration_s:.0f}s |",
        "",
        "## Summary for auditors",
        "",
        f"**{counts['FAIL']} of {len(findings)} controls failed**, {counts['PASS']} passed, "
        f"{counts['NOT_APPLICABLE']} not applicable.",
        "",
    ]
    if result.gaps:
        lines += ["> **Incomplete audit record:** " + "; ".join(result.gaps), ""]
    if fails:
        lines += ["| Severity | Control | What this means |", "|---|---|---|"]
        for f in fails:
            rem = ctx.remediations.get(f.rule_id)
            meaning = rem.risk_summary if rem else "(no risk summary recorded)"
            lines.append(f"| {f.severity.upper()} | {f.rule_id} {_cell(f.title)} | {_cell(meaning)} |")
        lines.append("")
    else:
        lines += ["No control failures were found.", ""]

    lines += ["## All findings", "", "| Rule | Severity | Status | Line(s) | Evidence |", "|---|---|---|---|---|"]
    for f in findings:
        ln = ", ".join(str(e.line_number) for e in f.evidence) or "-"
        ev = "<br>".join(code(e.text) for e in f.evidence[:3]) or (_cell(f.missing[0]) if f.missing else _cell(f.reason))
        if len(f.evidence) > 3:
            ev += f"<br>... +{len(f.evidence) - 3} more"
        lines.append(f"| {f.rule_id} | {f.severity} | **{f.status}** | {ln} | {_cell(ev)} |")
    lines.append("")

    if fails:
        lines += ["## Failed controls: detail and remediation", ""]
    for f in fails:
        lines += [f"### {f.rule_id} {f.title} ({f.severity})", "", f.reason, ""]
        if f.evidence:
            lines += ["**Evidence**", ""] + [f"- line {e.line_number}: {code(e.text)}" for e in f.evidence] + [""]
        if f.missing:
            lines += ["**Missing**", ""] + [f"- {m}" for m in f.missing] + [""]
        rem = ctx.remediations.get(f.rule_id)
        if rem:
            lines += ["**Risk**", "", rem.risk_summary, ""]
            if rem.warnings:
                lines += [f"> **{w}**" if "LOCKOUT" in w.upper() else f"> {w}" for w in rem.warnings] + [""]
            lines += [f"**Proposed remediation ({REVIEW_BANNER})**", "", "```", *rem.commands, "```", ""]
        if f.advisory:
            lines += [f"_Advisory: {f.advisory}_", ""]

    advisories = [f for f in findings if f.advisory and f.status != "FAIL"]
    if advisories:
        lines += ["## Advisories", ""] + [f"- {f.rule_id}: {f.advisory}" for f in advisories] + [""]
    lines += [
        "---",
        "_Generated by ConfigGuard. Verdicts come from a deterministic rule engine; secrets are masked. "
        "Remediation is a draft for human review and has not been applied to any device._",
        "",
    ]
    return "\n".join(lines)


def render_remediation_script(result: DeviceResult, generated: datetime) -> str:
    ctx = result.ctx
    fails = [f for f in _sorted_findings(ctx) if f.status == "FAIL" and f.rule_id in ctx.remediations]
    bar = "!" + "=" * 72
    out = [
        bar,
        f"! {REVIEW_BANNER}",
        "! ConfigGuard draft remediation. NOT applied to any device.",
        f"! Device: {result.device}   Config: {ctx.config_path.name}   Audit: {ctx.audit_id}",
        f"! Generated: {generated.strftime('%Y-%m-%d %H:%M UTC')}",
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
        writer.writerow(["device", "rule_id", "severity", "status", "evidence"])
        for result in results:
            for f in _sorted_findings(result.ctx):
                evidence = "; ".join(f"L{e.line_number}: {e.text.strip()}" for e in f.evidence) or "; ".join(f.missing)
                writer.writerow([_csv_safe(v) for v in (result.device, f.rule_id, f.severity, f.status, evidence)])
    return path


def render_batch_table(results: list[DeviceResult]) -> str:
    header = "| Device | Approved | PASS | FAIL | N/A | Critical/High FAIL | Time | Tokens | Cost |"
    lines = [header, "|---|---|---|---|---|---|---|---|---|"]
    for r in results:
        c = r.counts
        severe = sum(1 for f in r.ctx.findings.values() if f.status == "FAIL" and f.severity in ("critical", "high"))
        lines.append(
            f"| {r.device} | {'yes' if r.approved else 'NO'} | {c['PASS']} | {c['FAIL']} | {c['NOT_APPLICABLE']} | "
            f"{severe} | {r.duration_s:.0f}s | {r.prompt_tokens + r.completion_tokens:,} | ${r.cost_usd:.4f} |"
        )
    total_cost = sum(r.cost_usd for r in results)
    total_tokens = sum(r.prompt_tokens + r.completion_tokens for r in results)
    lines.append(f"| **Total ({len(results)})** | | | | | | | {total_tokens:,} | ${total_cost:.4f} |")
    return "\n".join(lines)


def now() -> datetime:
    return datetime.now(timezone.utc)
