# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Nataraj Angappan
"""Fleet dashboard: posture across the latest audit of every device, plus trends over time."""

from __future__ import annotations

from datetime import date
from typing import Any

from configguard.config.settings import Settings
from configguard.scoring import RATINGS, SEVERITIES
from configguard.tools.baseline import read_baseline
from configguard.waivers import WaiverStore
from configguard.web.history import _records, _state, load_result

MAX_AUDITS = 500


def build_dashboard(settings: Settings) -> dict[str, Any]:
    waivers = WaiverStore(settings.waivers_path).load()
    rows = []
    if settings.logs_dir.is_dir():
        logs = sorted(settings.logs_dir.glob("*.jsonl"), key=lambda p: p.stat().st_mtime)[-MAX_AUDITS:]
        for log in logs:
            try:
                if _state(settings, log.stem) is None:
                    continue
                result = load_result(settings, log.stem, waivers)
            except (ValueError, OSError, KeyError):
                continue
            if result is None or not result.ctx.findings:
                continue
            start = next((r for r in _records(log) if r.get("kind") == "audit_start"), {})
            rows.append((start.get("ts") or "", result))
    rows.sort(key=lambda r: r[0])

    latest: dict[str, tuple[str, Any]] = {}
    trend = []
    total_cost = total_tokens = 0.0
    for ts, result in rows:
        latest[result.device] = (ts, result)
        total_cost += result.cost_usd
        total_tokens += result.prompt_tokens + result.completion_tokens
        scores = [r.assessment.score for _, r in latest.values()]
        trend.append({"ts": ts, "device": result.device, "score": result.assessment.score,
                      "fleet_score": round(sum(scores) / len(scores), 1)})

    baseline = read_baseline(settings.baseline_path)
    rules = [{"id": r.id, "title": r.title, "severity": r.severity, "frameworks": r.frameworks} for r in baseline.rules]
    devices = []
    open_by_sev = {s: 0 for s in SEVERITIES}
    ratings = {r: 0 for r in RATINGS}
    control_fails: dict[str, int] = {r["id"]: 0 for r in rules}
    accepted = false_pos = pending_reviews = 0
    for device, (ts, result) in sorted(latest.items()):
        a = result.assessment
        ctx = result.ctx
        facts = ctx.facts or {}
        for s in SEVERITIES:
            open_by_sev[s] += a.open_by_severity[s]
        ratings[a.rating] += 1
        accepted += a.counts["RISK_ACCEPTED"]
        false_pos += a.counts["FALSE_POSITIVE"]
        undecided = [r for r, s in a.effective.items() if s == "FAIL" and r not in ctx.decisions]
        needs_review = bool(undecided)
        pending_reviews += needs_review
        for rule_id, status in a.effective.items():
            if status == "FAIL":
                control_fails[rule_id] = control_fails.get(rule_id, 0) + 1
        last = max(ctx.decisions.values(), key=lambda d: d.decided_at, default=None)
        devices.append({
            "device": device,
            "audit_id": ctx.audit_id,
            "audited": ts,
            "platform": facts.get("platform"),
            "software_version": facts.get("software_version"),
            "score": a.score,
            "rating": a.rating,
            "ai_approved": result.approved,
            "open_by_severity": a.open_by_severity,
            "counts": a.counts,
            "statuses": a.effective,
            "needs_review": needs_review,
            "undecided": len(undecided),
            "reviewer": last.reviewer if last else None,
        })

    scores = [d["score"] for d in devices]
    top = sorted(
        ({**r, "failing_devices": control_fails.get(r["id"], 0)} for r in rules if control_fails.get(r["id"], 0)),
        key=lambda r: (-r["failing_devices"], SEVERITIES.index(r["severity"]), r["id"]),
    )
    return {
        "fleet": {
            "devices": len(devices),
            "audits": len(rows),
            "score": round(sum(scores) / len(scores), 1) if scores else None,
            "open_by_severity": open_by_sev,
            "open_total": sum(open_by_sev.values()),
            "risk_accepted": accepted,
            "false_positives": false_pos,
            "pending_reviews": pending_reviews,
            "active_waivers": sum(1 for w in waivers if w.active(date.today())),
            "cost_usd": round(total_cost, 4),
            "tokens": int(total_tokens),
        },
        "ratings": ratings,
        "rules": rules,
        "devices": devices,
        "top_controls": top,
        "trend": trend,
    }
