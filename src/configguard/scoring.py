"""Compliance score and risk rating, combining rule verdicts with human review and waivers.

- The rule engine's verdict never changes. Review and waivers only change a finding's *effective*
  status: a FALSE_POSITIVE counts as passing; a RISK_ACCEPTED finding still counts against the
  compliance score (it is non-compliant) but is no longer an open finding.
- Score = weighted share of applicable controls that pass (critical 10, high 5, medium 3, low 1).
- Rating = severity of the worst open finding, or "Compliant" when nothing is open.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date

from configguard.models import Finding, ReviewDecision, Waiver

WEIGHTS = {"critical": 10, "high": 5, "medium": 3, "low": 1}
SEVERITIES = ("critical", "high", "medium", "low")
RATINGS = ("Critical", "High", "Medium", "Low", "Compliant")
EFFECTIVE = ("PASS", "FAIL", "RISK_ACCEPTED", "FALSE_POSITIVE", "NOT_APPLICABLE")


@dataclass
class Assessment:
    effective: dict[str, str]  # rule_id -> effective status
    score: float  # 0-100, or 100.0 when nothing is applicable
    rating: str
    open_by_severity: dict[str, int] = field(default_factory=dict)
    counts: dict[str, int] = field(default_factory=dict)
    waivers: dict[str, Waiver] = field(default_factory=dict)  # active waivers applied, by rule

    def to_dict(self) -> dict:
        return {
            "effective": self.effective,
            "score": self.score,
            "rating": self.rating,
            "open_by_severity": self.open_by_severity,
            "counts": self.counts,
            "waivers": {k: v.model_dump(mode="json") for k, v in self.waivers.items()},
        }


def active_waivers(waivers: list[Waiver], device: str, today: date | None = None) -> dict[str, Waiver]:
    today = today or date.today()
    return {w.rule_id: w for w in waivers if w.device == device and w.active(today)}


def assess(
    findings: list[Finding],
    decisions: dict[str, ReviewDecision] | None = None,
    waivers: dict[str, Waiver] | None = None,
) -> Assessment:
    decisions = decisions or {}
    waivers = waivers or {}
    effective: dict[str, str] = {}
    applied: dict[str, Waiver] = {}
    for f in findings:
        status = f.status
        if status == "FAIL":
            decision = decisions.get(f.rule_id)
            if decision and decision.action == "false_positive":
                status = "FALSE_POSITIVE"
            elif (decision and decision.action == "accept_risk") or f.rule_id in waivers:
                status = "RISK_ACCEPTED"
                if f.rule_id in waivers:
                    applied[f.rule_id] = waivers[f.rule_id]
        effective[f.rule_id] = status

    by_rule = {f.rule_id: f for f in findings}
    applicable = [r for r, s in effective.items() if s != "NOT_APPLICABLE"]
    total = sum(WEIGHTS[by_rule[r].severity] for r in applicable)
    passing = sum(WEIGHTS[by_rule[r].severity] for r in applicable if effective[r] in ("PASS", "FALSE_POSITIVE"))
    score = round(100.0 * passing / total, 1) if total else 100.0

    open_by_severity = {s: 0 for s in SEVERITIES}
    for r, s in effective.items():
        if s == "FAIL":
            open_by_severity[by_rule[r].severity] += 1
    rating = next((sev.capitalize() for sev in SEVERITIES if open_by_severity[sev]), "Compliant")
    counts = {s: list(effective.values()).count(s) for s in EFFECTIVE}
    return Assessment(effective, score, rating, open_by_severity, counts, applied)
