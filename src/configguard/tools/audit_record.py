"""get_audit_record tool: read-only view of what the tools actually recorded.

Gives the Critic ground truth to review against, instead of other agents' chat claims.
"""

from __future__ import annotations

from typing import Any

from configguard.context import AuditContext
from configguard.scoring import active_waivers
from configguard.tools.ios_syntax import LOCKOUT_MARKER, lockout_risks
from configguard.tools.loader import error


def audit_gaps(ctx: AuditContext) -> list[str]:
    """Deterministic completeness problems. Empty list means the record is complete."""
    if ctx.baseline is None:
        return ["baseline not loaded"]
    gaps = [f"{r.id}: no finding recorded" for r in ctx.baseline.rules if r.id not in ctx.findings]
    waived = active_waivers(ctx.waivers, ctx.hostname)
    for rule_id, finding in ctx.findings.items():
        # a FAIL under an active risk acceptance needs no remediation
        if finding.status == "FAIL" and rule_id not in ctx.remediations and rule_id not in waived:
            gaps.append(f"{rule_id}: FAIL has no recorded remediation")
    for rule_id in ctx.remediations:
        if rule_id in ctx.findings and ctx.findings[rule_id].status != "FAIL":
            gaps.append(f"{rule_id}: remediation recorded for a non-FAIL finding")
    return gaps


def get_fail_findings(ctx: AuditContext) -> dict[str, Any]:
    """FAIL findings with the rule intent and remediation hint, for drafting fixes."""
    if ctx.baseline is None or not ctx.findings:
        return error("no findings recorded yet; the ComplianceChecker must run first")
    fails = []
    waived = active_waivers(ctx.waivers, ctx.hostname)
    for rule in ctx.baseline.rules:
        f = ctx.findings.get(rule.id)
        if f and f.status == "FAIL" and rule.id in waived:
            w = waived[rule.id]
            fails.append({"rule_id": rule.id, "risk_accepted": True, "skip": True,
                          "waiver": {"approver": w.approver, "expires": w.expires.isoformat()}})
        elif f and f.status == "FAIL":
            fails.append(
                {
                    "rule_id": rule.id,
                    "title": rule.title,
                    "intent": rule.description,
                    "remediation_hint": rule.remediation_hint,
                    "lockout_risk": rule.lockout_risk,
                    "evidence": [e.model_dump() for e in f.evidence],
                    "missing": f.missing,
                    "already_recorded": rule.id in ctx.remediations,
                }
            )
    return {"ok": True, "fail_count": len(fails), "fails": fails}  # entries with skip=true need no fix


def get_audit_record(ctx: AuditContext) -> dict[str, Any]:
    """Return every recorded finding and remediation, plus completeness gaps."""
    if ctx.baseline is None:
        return error("no baseline loaded yet")
    findings = []
    for rule in ctx.baseline.rules:
        f = ctx.findings.get(rule.id)
        rem = ctx.remediations.get(rule.id)
        if f is None or (f.status != "FAIL" and rem is None):
            # Non-FAIL findings need only their status for review; omitting evidence saves tokens.
            findings.append({"rule_id": rule.id, "status": f.status if f else None})
            continue
        findings.append(
            {
                "rule_id": rule.id,
                "status": f.status,
                "evidence": [e.model_dump() for e in f.evidence],
                "missing": f.missing,
                "remediation": None
                if rem is None
                else {
                    "rule_intent": rule.description,
                    "remediation_hint": rule.remediation_hint,
                    "risk_summary": rem.risk_summary,
                    "commands": rem.commands,
                    "warnings": rem.warnings,
                    "lockout_risks": lockout_risks(ctx, rem.commands),
                    "has_lockout_warning": any(LOCKOUT_MARKER in w.upper() for w in rem.warnings),
                },
            }
        )
    counts = {s: sum(1 for f in ctx.findings.values() if f.status == s) for s in ("PASS", "FAIL", "NOT_APPLICABLE")}
    return {"ok": True, "rule_count": len(ctx.baseline.rules), "counts": counts, "gaps": audit_gaps(ctx), "findings": findings}
