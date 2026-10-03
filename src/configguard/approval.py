# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Nataraj Angappan
"""HumanApprover: the final review gate, run after the agent team finishes.

The reviewer decides on EACH failed control, as in a real audit sign-off:
  approve_fix     the drafted remediation may be exported (only fixes approved here are exported)
  reject_fix      the drafted remediation is not acceptable; the finding stays open
  accept_risk     the risk is accepted until an expiry date (justification required); recorded
                  as a waiver so future audits show it as RISK_ACCEPTED instead of open
  false_positive  the verdict does not apply to this device (reason required)
Undecided findings stay pending. Every decision records reviewer, time, comment and change ticket.

All answers go through AutoGen's UserProxyAgent, and every rule lives in validate_review(), which
the CLI and the web UI share, so the server never trusts client-side checks.
"""

from __future__ import annotations

import json
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Any

from autogen_agentchat.agents import UserProxyAgent
from autogen_agentchat.messages import TextMessage
from autogen_core import CancellationToken

from configguard.models import ReviewDecision
from configguard.reporting import SEVERITY_ORDER, DeviceResult
from configguard.scoring import active_waivers

ACTIONS = ("approve_fix", "reject_fix", "accept_risk", "false_positive")
TICKET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,39}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]+")
MIN_JUSTIFICATION = 10
MAX_COMMENT = 500
MAX_REVIEWER = 80
DEFAULT_WAIVER_DAYS = 90
MAX_STRUCTURED_ATTEMPTS = 5


@dataclass
class ReviewOutcome:
    reviewer: str = ""
    ticket: str | None = None
    overwrite: bool = False
    decisions: dict[str, dict[str, ReviewDecision]] = field(default_factory=dict)  # audit_id -> rule_id -> decision

    def approved_fixes(self, audit_id: str) -> list[str]:
        return sorted(r for r, d in self.decisions.get(audit_id, {}).items() if d.action == "approve_fix")

    def counts(self) -> dict[str, int]:
        flat = [d.action for per in self.decisions.values() for d in per.values()]
        return {a: flat.count(a) for a in ACTIONS}


def clean(text: Any, limit: int) -> str:
    return _CONTROL.sub(" ", str(text or "")).strip()[:limit]


def safe_input(_prompt: str) -> str:
    # UserProxyAgent passes a generic "Enter your response:" prompt; our question is already printed.
    try:
        return input("> ")
    except EOFError:
        return ""


def fix_eligible(result: DeviceResult, rule_id: str, export_allowed: bool) -> bool:
    """A fix can be approved only for an AI-approved audit with a recorded, verified remediation."""
    f = result.ctx.findings.get(rule_id)
    return bool(export_allowed and result.approved and f and f.status == "FAIL" and rule_id in result.ctx.remediations)


def eligible_devices(results: list[DeviceResult]) -> list[str]:
    """Devices with at least one remediation that could be approved for export."""
    return [r.device for r in results if r.approved and r.counts["FAIL"] and r.ctx.remediations]


def review_items(result: DeviceResult, export_allowed: bool) -> list[dict[str, Any]]:
    """FAIL findings to review, worst first, with everything a reviewer needs to decide."""
    ctx = result.ctx
    waived = active_waivers(ctx.waivers, ctx.hostname)
    items = []
    fails = sorted((f for f in ctx.findings.values() if f.status == "FAIL"),
                   key=lambda f: (SEVERITY_ORDER[f.severity], f.rule_id))
    for f in fails:
        rule = ctx.baseline.rule(f.rule_id) if ctx.baseline else None
        rem = ctx.remediations.get(f.rule_id)
        w = waived.get(f.rule_id)
        items.append({
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "evidence": [e.model_dump() for e in f.evidence[:3]],
            "missing": f.missing[:2],
            "frameworks": rule.frameworks if rule else {},
            "risk_summary": rem.risk_summary if rem else None,
            "fix": None if rem is None else {
                "commands": rem.commands,
                "warnings": rem.warnings,
                "lockout": any("LOCKOUT" in x.upper() for x in rem.warnings),
            },
            "fix_eligible": fix_eligible(result, f.rule_id, export_allowed),
            "waiver": None if w is None else w.model_dump(mode="json"),
            "decision": ctx.decisions[f.rule_id].model_dump(mode="json") if f.rule_id in ctx.decisions else None,
        })
    return items


def validate_review(
    raw: Any,
    results: list[DeviceResult],
    *,
    export_allowed: bool,
    max_waiver_days: int,
    today: date | None = None,
) -> tuple[ReviewOutcome, list[str]]:
    """Validate a review submission. Returns the valid part plus a list of errors (empty = all valid)."""
    today = today or date.today()
    errors: list[str] = []
    if not isinstance(raw, dict):
        return ReviewOutcome(), ["review must be a JSON object"]
    reviewer = clean(raw.get("reviewer"), MAX_REVIEWER)
    ticket = clean(raw.get("ticket"), 40) or None
    outcome = ReviewOutcome(reviewer=reviewer, overwrite=raw.get("overwrite") is True)
    if ticket and not TICKET.match(ticket):
        errors.append("change ticket may contain only letters, digits, '.', '_' and '-' (max 40)")
        ticket = None
    outcome.ticket = ticket

    submitted = raw.get("decisions") or {}
    if not isinstance(submitted, dict):
        return outcome, errors + ["decisions must be an object keyed by audit id"]
    if any(submitted.values()) and len(reviewer) < 2:
        return outcome, errors + ["reviewer name is required to record decisions"]

    by_id = {r.ctx.audit_id: r for r in results}
    stamp = datetime.now(timezone.utc)
    for audit_id, per_rule in submitted.items():
        result = by_id.get(audit_id)
        if result is None or not isinstance(per_rule, dict):
            errors.append(f"unknown audit {audit_id!r}")
            continue
        for rule_id, entry in per_rule.items():
            where = f"{result.device} {rule_id}"
            finding = result.ctx.findings.get(rule_id)
            if finding is None or finding.status != "FAIL":
                errors.append(f"{where}: only FAIL findings can be reviewed")
                continue
            if not isinstance(entry, dict) or entry.get("action") not in ACTIONS:
                errors.append(f"{where}: action must be one of {', '.join(ACTIONS)}")
                continue
            action = entry["action"]
            comment = clean(entry.get("comment"), MAX_COMMENT)
            expires = None
            if action == "approve_fix" and not fix_eligible(result, rule_id, export_allowed):
                errors.append(f"{where}: no approvable fix (audit not approved, no remediation, or export disabled)")
                continue
            if action in ("accept_risk", "false_positive") and len(comment) < MIN_JUSTIFICATION:
                what = "justification" if action == "accept_risk" else "reason"
                errors.append(f"{where}: a {what} of at least {MIN_JUSTIFICATION} characters is required")
                continue
            if action == "accept_risk":
                try:
                    expires = date.fromisoformat(entry["expires"]) if entry.get("expires") else today + timedelta(days=DEFAULT_WAIVER_DAYS)
                except (TypeError, ValueError):
                    errors.append(f"{where}: expiry must be a date (YYYY-MM-DD)")
                    continue
                if not today < expires <= today + timedelta(days=max_waiver_days):
                    errors.append(f"{where}: expiry must be after today and within {max_waiver_days} days")
                    continue
            outcome.decisions.setdefault(audit_id, {})[rule_id] = ReviewDecision(
                rule_id=rule_id, action=action, reviewer=reviewer, comment=comment,
                ticket=ticket, expires=expires, decided_at=stamp,
            )
    return outcome, errors


class HumanApprover:
    """Console reviewer: asks per finding, one question at a time."""

    def __init__(
        self,
        input_func: Callable[[str], str] | Callable[[str, CancellationToken | None], Awaitable[str]] = safe_input,
        output: Callable[[str], None] = print,
        reviewer: str = "",
    ) -> None:
        self.agent = UserProxyAgent(name="HumanApprover", description="Human reviewer", input_func=input_func)
        self.output = output
        self.reviewer = reviewer
        self.transcript: list[tuple[str, str]] = []  # (question, answer) for the audit log
        # (kind, question, payload) while waiting; lets a UI render controls
        self.pending: tuple[str, str, dict[str, Any] | None] | None = None

    async def ask(self, question: str, kind: str = "text", payload: dict[str, Any] | None = None) -> str:
        self.pending = (kind, question, payload)
        self.output(question)
        response = await self.agent.on_messages(
            [TextMessage(content=question, source="ConfigGuard")], CancellationToken()
        )
        answer = str(response.chat_message.content).strip()
        self.pending = None
        self.transcript.append((question, answer if kind != "review" else "<structured review>"))
        return answer

    def _summary(self, results: list[DeviceResult]) -> None:
        lines = ["", "=" * 72, "HUMAN REVIEW", "=" * 72]
        for i, r in enumerate(results, start=1):
            a = r.assessment
            flag = "AI-approved" if r.approved else "NOT approved by AI review: fixes cannot be approved"
            lines.append(f"{i:>2}. {r.device:<20} score {a.score:>5.1f}%  rating {a.rating:<9} "
                         f"open FAIL {r.counts['FAIL']:>2}  [{flag}]")
        self.output("\n".join(lines))

    async def _ask_overwrite(self, existing_reports: list[str]) -> bool:
        if not existing_reports:
            return False
        answer = await self.ask(
            f"\nReports already exist for: {', '.join(existing_reports)}.\n"
            "Overwrite them? Type 'overwrite' to confirm, anything else keeps the old files: ",
            kind="overwrite",
        )
        return answer.lower() == "overwrite"

    async def review(
        self,
        results: list[DeviceResult],
        existing_reports: list[str],
        *,
        export_allowed: bool,
        max_waiver_days: int = 365,
        today: date | None = None,
    ) -> ReviewOutcome:
        today = today or date.today()
        self._summary(results)
        overwrite = await self._ask_overwrite(existing_reports)
        items = {r.ctx.audit_id: review_items(r, export_allowed) for r in results}
        if not any(i for per in items.values() for i in per if not i["waiver"]):
            self.output("\nNo open findings need a decision.")
            return ReviewOutcome(overwrite=overwrite)

        reviewer = self.reviewer or clean(await self.ask("\nReviewer name (required to record decisions): ", kind="text"), MAX_REVIEWER)
        if len(reviewer) < 2:
            self.output("No reviewer name given: findings stay pending and no fixes are exported.")
            return ReviewOutcome(overwrite=overwrite)
        ticket = clean(await self.ask("Change ticket (optional, Enter to skip): ", kind="text"), 40)

        raw: dict[str, Any] = {"reviewer": reviewer, "ticket": ticket, "overwrite": overwrite, "decisions": {}}
        keys = {"a": "approve_fix", "r": "reject_fix", "w": "accept_risk", "f": "false_positive"}
        for r in results:
            approve_rest = False
            for item in items[r.ctx.audit_id]:
                rid = item["rule_id"]
                if item["waiver"]:
                    self.output(f"  {rid}: risk accepted until {item['waiver']['expires']} by {item['waiver']['approver']} (waiver)")
                    continue
                if approve_rest and item["fix_eligible"]:
                    raw["decisions"].setdefault(r.ctx.audit_id, {})[rid] = {"action": "approve_fix"}
                    continue
                fix = item["fix"]
                fix_note = f"fix: {len(fix['commands'])} command(s){'  LOCKOUT WARNING' if fix['lockout'] else ''}" if fix else "no fix drafted"
                options = ("[a]pprove fix / " if item["fix_eligible"] else "") + "[r]eject fix / [w] accept risk / [f]alse positive / [s]kip"
                if item["fix_eligible"]:
                    options += " / [A]pprove all remaining fixes"
                answer = await self.ask(
                    f"\n{r.device}  {rid} [{item['severity']}] {item['title']}  ({fix_note})\n  {options}: ",
                    kind="decision",
                )
                if answer == "A" and item["fix_eligible"]:
                    approve_rest = True
                    answer = "a"
                action = keys.get(answer.lower())
                if action is None or (action == "approve_fix" and not item["fix_eligible"]):
                    continue  # skip / invalid -> pending (the safe default)
                entry: dict[str, Any] = {"action": action}
                if action == "accept_risk":
                    entry["comment"] = await self.ask("  Justification for accepting this risk: ", kind="text")
                    default = (today + timedelta(days=DEFAULT_WAIVER_DAYS)).isoformat()
                    entry["expires"] = (await self.ask(f"  Expires on (YYYY-MM-DD) [{default}]: ", kind="text")) or default
                elif action == "false_positive":
                    entry["comment"] = await self.ask("  Why is this a false positive? ", kind="text")
                elif action == "reject_fix":
                    entry["comment"] = await self.ask("  Reason for rejecting the fix (optional): ", kind="text")
                raw["decisions"].setdefault(r.ctx.audit_id, {})[rid] = entry

        outcome, errors = validate_review(raw, results, export_allowed=export_allowed,
                                          max_waiver_days=max_waiver_days, today=today)
        for e in errors:
            self.output(f"  not recorded: {e}")
        c = outcome.counts()
        self.output(f"\nRecorded: {c['approve_fix']} fix(es) approved, {c['reject_fix']} rejected, "
                    f"{c['accept_risk']} risk(s) accepted, {c['false_positive']} false positive(s).")
        return outcome


class StructuredApprover(HumanApprover):
    """UI reviewer: one structured question (JSON payload) answered with a JSON review form."""

    async def review(
        self,
        results: list[DeviceResult],
        existing_reports: list[str],
        *,
        export_allowed: bool,
        max_waiver_days: int = 365,
        today: date | None = None,
    ) -> ReviewOutcome:
        today = today or date.today()
        payload: dict[str, Any] = {
            "existing_reports": existing_reports,
            "export_allowed": export_allowed,
            "reviewer": self.reviewer,
            "today": today.isoformat(),
            "default_expiry": (today + timedelta(days=DEFAULT_WAIVER_DAYS)).isoformat(),
            "max_expiry": (today + timedelta(days=max_waiver_days)).isoformat(),
            "devices": [
                {
                    "audit_id": r.ctx.audit_id,
                    "device": r.device,
                    "approved": r.approved,
                    "facts": r.ctx.facts,
                    "assessment": r.assessment.to_dict(),
                    "items": review_items(r, export_allowed),
                }
                for r in results
            ],
            "errors": [],
        }
        for _ in range(MAX_STRUCTURED_ATTEMPTS):
            answer = await self.ask("Review the failed controls", kind="review", payload=payload)
            try:
                raw = json.loads(answer)
            except json.JSONDecodeError:
                raw = None
            if isinstance(raw, dict) and raw.get("skip") is True:
                return ReviewOutcome(overwrite=raw.get("overwrite") is True)
            outcome, errors = validate_review(raw, results, export_allowed=export_allowed,
                                              max_waiver_days=max_waiver_days, today=today)
            if not errors:
                return outcome
            payload = {**payload, "errors": errors}
        return ReviewOutcome()  # repeated invalid submissions: record nothing, approve nothing
