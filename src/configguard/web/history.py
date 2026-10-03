"""Audit history for the UI, read from logs/<id>.jsonl (primary) and state/<id>.json (findings)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from configguard.config.settings import Settings
from configguard.persistence import checkpoint_path


def _records(log: Path) -> list[dict[str, Any]]:
    out = []
    for line in log.read_text(encoding="utf-8").splitlines():
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue  # tolerate a partially written last line
    return out


def _summary(audit_id: str, records: list[dict[str, Any]], state: dict[str, Any] | None) -> dict[str, Any]:
    starts = [r for r in records if r.get("kind") == "audit_start"]
    ends = [r for r in records if r.get("kind") == "audit_end"]
    paused = any(r.get("kind") == "audit_paused" for r in records)
    findings = (state or {}).get("context", {}).get("findings", {})
    statuses = [f["status"] for f in findings.values()]
    last_end = ends[-1] if ends else {}
    return {
        "audit_id": audit_id,
        "started": starts[0]["ts"] if starts else (records[0]["ts"] if records else None),
        "config": starts[0].get("config") if starts else None,
        "model": starts[0].get("model") if starts else None,
        "device": last_end.get("device"),
        "status": (state or {}).get("status") or ("paused" if paused else "incomplete"),
        "counts": {s: statuses.count(s) for s in ("PASS", "FAIL", "NOT_APPLICABLE")},
        "duration_s": round(sum(e.get("duration_s", 0) for e in ends), 1),
        "tokens": sum(e.get("prompt_tokens", 0) + e.get("completion_tokens", 0) for e in ends),
        "cost_usd": round(sum(e.get("cost_usd", 0) for e in ends), 6),
        "runs": len(starts),
    }


def _state(settings: Settings, audit_id: str) -> dict[str, Any] | None:
    path = checkpoint_path(settings.state_dir, audit_id)
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None


def list_audits(settings: Settings) -> list[dict[str, Any]]:
    if not settings.logs_dir.is_dir():
        return []
    audits = []
    for log in settings.logs_dir.glob("*.jsonl"):
        try:
            audits.append(_summary(log.stem, _records(log), _state(settings, log.stem)))
        except (ValueError, OSError):
            continue  # skip files that are not ConfigGuard audit logs
    return sorted(audits, key=lambda a: a["started"] or "", reverse=True)


def audit_detail(settings: Settings, audit_id: str) -> dict[str, Any] | None:
    log = settings.logs_dir / f"{checkpoint_path(settings.state_dir, audit_id).stem}.jsonl"  # validates the id
    if not log.is_file():
        return None
    records = _records(log)
    state = _state(settings, audit_id)
    context = (state or {}).get("context", {})
    outputs: dict[str, str] = {}
    for r in records:
        if r.get("kind") == "outputs":
            outputs.update({k: v for k, v in r.items() if k in ("report", "remediation")})
    return {
        **_summary(audit_id, records, state),
        "findings": list(context.get("findings", {}).values()),
        "remediations": context.get("remediations", {}),
        "timeline": [{"type": r["type"], "data": r["data"]} for r in records if r.get("kind") == "message"],
        "events": [r for r in records if r.get("kind") not in ("message",)],
        "outputs": sorted(outputs),
        "resumable": (state or {}).get("status") in ("paused", "not_approved"),
    }


def output_file(settings: Settings, audit_id: str, kind: str) -> Path | None:
    """Path of a report/remediation written for this audit, only if inside the output folders."""
    if kind not in ("report", "remediation"):
        return None
    log = settings.logs_dir / f"{checkpoint_path(settings.state_dir, audit_id).stem}.jsonl"
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
