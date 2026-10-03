"""Audit history for the UI, rebuilt from logs/<id>.jsonl and state/<id>.json.

Nothing here re-runs agents. A finished audit is reconstructed as a DeviceResult from its
checkpoint so the UI, dashboard and post-hoc review use the same scoring and reporting code.
"""

from __future__ import annotations

import difflib
import json
from pathlib import Path
from typing import Any

from configguard.approval import review_items
from configguard.config.settings import Settings
from configguard.context import AuditContext, sha256_text
from configguard.facts import device_facts
from configguard.persistence import checkpoint_path
from configguard.reporting import DeviceResult, device_name, finding_ids, status_label
from configguard.tools.audit_record import audit_gaps
from configguard.tools.baseline import read_baseline
from configguard.tools.masking import mask_line
from configguard.tools.simulate import apply_commands
from configguard.waivers import WaiverStore

MAX_VIEW_LINE = 300


def _records(log: Path) -> list[dict[str, Any]]:
    out = []
    for line in log.read_text(encoding="utf-8").splitlines():
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue  # tolerate a partially written last line
    return out


def _state(settings: Settings, audit_id: str) -> dict[str, Any] | None:
    path = checkpoint_path(settings.state_dir, audit_id)
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None


def _log(settings: Settings, audit_id: str) -> Path:
    return settings.logs_dir / f"{checkpoint_path(settings.state_dir, audit_id).stem}.jsonl"  # validates the id


def _config_text(ctx: AuditContext) -> tuple[str | None, str]:
    """Current config text if it still matches the audited file, else (None, reason)."""
    if not ctx.config_path.is_file():
        return None, "the audited config file is no longer available"
    text = ctx.config_path.read_text(encoding="utf-8", errors="replace")
    if ctx.config_sha256 and sha256_text(text) != ctx.config_sha256:
        return None, "the config file has changed since this audit"
    return text, ""


def load_result(settings: Settings, audit_id: str, waivers: list | None = None) -> DeviceResult | None:
    """Rebuild a finished audit as a DeviceResult (no agent run, no raw config kept)."""
    log = _log(settings, audit_id)
    state = _state(settings, audit_id)
    if state is None or not log.is_file():
        return None
    records = _records(log)
    ctx = AuditContext.from_dict(state["context"])
    if ctx.baseline_path.is_file():
        ctx.baseline = read_baseline(ctx.baseline_path)
    if ctx.facts is None:  # audits from before device facts existed
        text, _ = _config_text(ctx)
        if text is not None:
            ctx.facts = device_facts(text.splitlines())
    ctx.waivers = waivers if waivers is not None else WaiverStore(settings.waivers_path).load()
    ends = [r for r in records if r.get("kind") == "audit_end"]
    start = next((r for r in records if r.get("kind") == "audit_start"), {})
    device = (ends[-1].get("device") if ends else None) or device_name(ctx)
    return DeviceResult(
        ctx=ctx,
        device=device,
        approved=state.get("status") == "approved",
        critic_approved=state.get("status") == "approved",
        gaps=audit_gaps(ctx) if ctx.baseline else [],
        duration_s=sum(e.get("duration_s", 0) for e in ends),
        prompt_tokens=sum(e.get("prompt_tokens", 0) for e in ends),
        completion_tokens=sum(e.get("completion_tokens", 0) for e in ends),
        cost_usd=sum(e.get("cost_usd", 0) for e in ends),
        model=start.get("model") or "",
    )


def _summary(audit_id: str, records: list[dict[str, Any]], result: DeviceResult | None, state: dict | None) -> dict[str, Any]:
    starts = [r for r in records if r.get("kind") == "audit_start"]
    paused = any(r.get("kind") == "audit_paused" for r in records)
    base = {
        "audit_id": audit_id,
        "started": starts[0]["ts"] if starts else (records[0]["ts"] if records else None),
        "config": starts[0].get("config") if starts else None,
        "model": starts[0].get("model") if starts else None,
        "status": (state or {}).get("status") or ("paused" if paused else "incomplete"),
        "runs": len(starts),
    }
    if result is None:
        return {**base, "device": None, "counts": {"PASS": 0, "FAIL": 0, "NOT_APPLICABLE": 0},
                "score": None, "rating": None, "reviewed": False, "reviewer": None,
                "duration_s": 0, "tokens": 0, "cost_usd": 0}
    a = result.assessment
    last = max(result.ctx.decisions.values(), key=lambda d: d.decided_at, default=None)
    facts = result.ctx.facts or {}
    return {
        **base,
        "device": result.device,
        "platform": facts.get("platform"),
        "software_version": facts.get("software_version"),
        "counts": result.counts,
        "effective_counts": a.counts,
        "score": a.score if result.ctx.findings else None,
        "rating": a.rating if result.ctx.findings else None,
        "open_by_severity": a.open_by_severity,
        "reviewed": last is not None,
        "reviewer": last.reviewer if last else None,
        "duration_s": round(result.duration_s, 1),
        "tokens": result.prompt_tokens + result.completion_tokens,
        "cost_usd": round(result.cost_usd, 6),
    }


def list_audits(settings: Settings) -> list[dict[str, Any]]:
    if not settings.logs_dir.is_dir():
        return []
    waivers = WaiverStore(settings.waivers_path).load()
    audits = []
    for log in settings.logs_dir.glob("*.jsonl"):
        try:
            state = _state(settings, log.stem)
            result = load_result(settings, log.stem, waivers) if state else None
            audits.append(_summary(log.stem, _records(log), result, state))
        except (ValueError, OSError, KeyError):
            continue  # skip files that are not ConfigGuard audit logs
    return sorted(audits, key=lambda a: a["started"] or "", reverse=True)


def audit_detail(settings: Settings, audit_id: str) -> dict[str, Any] | None:
    log = _log(settings, audit_id)
    if not log.is_file():
        return None
    records = _records(log)
    state = _state(settings, audit_id)
    result = load_result(settings, audit_id) if state else None
    outputs: dict[str, str] = {}
    for r in records:
        if r.get("kind") == "outputs":
            outputs.update({k: v for k, v in r.items() if k in ("report", "remediation")})
    detail = {
        **_summary(audit_id, records, result, state),
        "timeline": [{"type": r["type"], "data": r["data"]} for r in records if r.get("kind") == "message"],
        "outputs": sorted(outputs),
        "resumable": (state or {}).get("status") in ("paused", "not_approved"),
        "findings": [], "remediations": {}, "decisions": {}, "facts": None, "assessment": None,
        "review_items": [], "frameworks": {}, "finding_ids": {}, "status_labels": {},
        "reviews": [r for r in records if r.get("kind") == "human_review"],
    }
    if result is not None:
        ctx = result.ctx
        a = result.assessment
        detail.update({
            "findings": [f.model_dump() for f in ctx.findings.values()],
            "remediations": {k: v.model_dump() for k, v in ctx.remediations.items()},
            "decisions": {k: v.model_dump(mode="json") for k, v in ctx.decisions.items()},
            "facts": ctx.facts,
            "assessment": a.to_dict(),
            "review_items": review_items(result, export_allowed=True) if ctx.baseline else [],
            "frameworks": {r.id: r.frameworks for r in ctx.baseline.rules} if ctx.baseline else {},
            "finding_ids": finding_ids(ctx),
            "status_labels": {
                rid: status_label(a.effective[rid], ctx.decisions.get(rid),
                                  (ctx.decisions[rid].expires.isoformat() if rid in ctx.decisions and ctx.decisions[rid].expires
                                   else a.waivers[rid].expires.isoformat() if rid in a.waivers else None))
                for rid in a.effective
            },
            "approved": result.approved,
        })
    return detail


def config_view(settings: Settings, audit_id: str) -> dict[str, Any] | None:
    """Masked config with evidence lines marked. Never returns unmasked text."""
    result = load_result(settings, audit_id)
    if result is None:
        return None
    text, reason = _config_text(result.ctx)
    if text is None:
        return {"available": False, "reason": reason}
    a = result.assessment
    highlights: dict[int, list[dict[str, str]]] = {}
    for f in result.ctx.findings.values():
        for e in f.evidence:
            highlights.setdefault(e.line_number, []).append(
                {"rule_id": f.rule_id, "severity": f.severity, "status": a.effective.get(f.rule_id, f.status)})
    lines = []
    for line in text.splitlines():
        masked = mask_line(line)
        lines.append(masked[:MAX_VIEW_LINE] + ("..." if len(masked) > MAX_VIEW_LINE else ""))
    return {"available": True, "file": result.ctx.config_path.name, "lines": lines, "highlights": highlights}


def remediation_preview(settings: Settings, audit_id: str, scope: str = "all") -> dict[str, Any] | None:
    """Unified diff (masked) of the config before/after applying the drafted (or approved) fixes."""
    result = load_result(settings, audit_id)
    if result is None:
        return None
    ctx = result.ctx
    text, reason = _config_text(ctx)
    if text is None:
        return {"available": False, "reason": reason}
    rules = [r for r in (finding_ids(ctx)) if r in ctx.remediations]
    if scope == "approved":
        rules = [r for r in rules if r in ctx.decisions and ctx.decisions[r].action == "approve_fix"]
    commands = [c for r in rules for c in ctx.remediations[r].commands]
    raw = text.splitlines()
    before = [mask_line(line) for line in apply_commands(raw, [])]  # normalised the same way as `after`
    after = [mask_line(line) for line in apply_commands(raw, commands)]
    diff = list(difflib.unified_diff(before, after, "running-config (current)", "running-config (after fixes)",
                                     lineterm="", n=2))
    return {
        "available": True,
        "scope": scope,
        "rules": rules,
        "diff": diff,
        "added": sum(1 for d in diff if d.startswith("+") and not d.startswith("+++")),
        "removed": sum(1 for d in diff if d.startswith("-") and not d.startswith("---")),
    }


def output_file(settings: Settings, audit_id: str, kind: str) -> Path | None:
    """Path of a report/remediation written for this audit, only if inside the output folders."""
    if kind not in ("report", "remediation"):
        return None
    log = _log(settings, audit_id)
    if not log.is_file():
        return None
    path = None
    for r in _records(log):
        if r.get("kind") == "outputs" and kind in r:
            path = Path(r[kind]).resolve()
    allowed = settings.reports_dir if kind == "report" else settings.remediation_dir
    if path is None or not path.is_file() or allowed.resolve() not in path.parents:
        return None
    return path
