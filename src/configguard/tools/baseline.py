"""Baseline tools: load_baseline, check_rule, find_config_lines."""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any

import regex
import yaml
from pydantic import ValidationError

from configguard.context import AuditContext
from configguard.models import Baseline
from configguard.tools.loader import error
from configguard.tools.parser import UNTRUSTED_NOTE
from configguard.tools.rule_checks import PYTHON_CHECKS, evaluate

MAX_PATTERN_LEN = 200
MAX_LINE_RESULTS = 50
MAX_LINE_CHARS = 200  # long lines (e.g. untrusted descriptions) are truncated in search results
SEARCH_BUDGET_S = 1.0


def read_baseline(path: Path) -> Baseline:
    """Parse and validate a baseline YAML file. Raises on any schema problem."""
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    baseline = Baseline(**data)
    for rule in baseline.rules:
        if rule.check.type == "python" and rule.check.function not in PYTHON_CHECKS:
            raise ValueError(f"{rule.id}: unknown python check function {rule.check.function!r}")
        c = rule.check
        singles = [c.pattern, c.parent, rule.applies_when.global_present if rule.applies_when else None]
        for pattern in [*c.all_of, *c.any_of, *c.require, *c.forbid, *(p for p in singles if p)]:
            re.compile(pattern)
    re.compile(baseline.settings.external_interface_pattern)
    return baseline


def load_baseline(ctx: AuditContext, path: str) -> dict[str, Any]:
    """Load the baseline assigned to this audit and list its rules."""
    try:
        requested = Path(path).resolve()
    except (OSError, ValueError) as exc:
        return error(f"invalid path: {exc}")
    if requested != ctx.baseline_path:
        return error(f"path {path!r} is not the baseline assigned to this audit")
    if not requested.is_file():
        return error(f"baseline file not found: {requested.name}")
    try:
        ctx.baseline = read_baseline(requested)
    except (yaml.YAMLError, ValidationError, ValueError, re.error) as exc:
        return error(f"invalid baseline: {exc}")
    return {
        "ok": True,
        "rule_count": len(ctx.baseline.rules),
        "rules": [{"id": r.id, "title": r.title, "severity": r.severity} for r in ctx.baseline.rules],
    }


def check_rule(ctx: AuditContext, rule_id: str) -> dict[str, Any]:
    """Evaluate one rule against the loaded config. The verdict is deterministic."""
    if not ctx.loaded:
        return error("no config loaded; call load_config first")
    if ctx.baseline is None:
        return error("no baseline loaded; call load_baseline first")
    rule = ctx.baseline.rule(rule_id.strip().upper())
    if rule is None:
        return error(f"unknown rule_id {rule_id!r}; valid ids: {[r.id for r in ctx.baseline.rules]}")
    try:
        finding = evaluate(ctx, rule, ctx.baseline.settings)
    except Exception as exc:  # surface rule-engine bugs as tool errors, not crashes
        return error(f"{rule.id} evaluation failed: {type(exc).__name__}: {exc}")
    ctx.findings[rule.id] = finding
    return {"ok": True, "finding": finding.model_dump(exclude_none=True)}


def find_config_lines(ctx: AuditContext, pattern: str) -> dict[str, Any]:
    """Regex search over the MASKED config, returning matching lines with line numbers.

    Searching masked text (not raw) stops the model from probing secret values with patterns.
    The `regex` engine's timeout bounds the whole search, so a pathological (ReDoS) pattern
    from the model cannot stall the audit.
    """
    if not ctx.loaded:
        return error("no config loaded; call load_config first")
    if len(pattern) > MAX_PATTERN_LEN:
        return error(f"pattern longer than {MAX_PATTERN_LEN} characters")
    try:
        rx = regex.compile(pattern, regex.I)
    except regex.error as exc:
        return error(f"invalid regex: {exc}")
    deadline = time.monotonic() + SEARCH_BUDGET_S
    hits = []
    try:
        for i, line in enumerate(ctx.masked_lines, start=1):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            if rx.search(line, timeout=remaining):
                text = line.rstrip()
                hits.append({"line_number": i, "text": text[:MAX_LINE_CHARS] + ("..." if len(text) > MAX_LINE_CHARS else "")})
    except TimeoutError:
        return error(f"pattern too expensive (exceeded {SEARCH_BUDGET_S}s); use a simpler regex")
    return {
        "ok": True,
        "note": UNTRUSTED_NOTE,
        "match_count": len(hits),
        "matches": hits[:MAX_LINE_RESULTS],
        "truncated": len(hits) > MAX_LINE_RESULTS,
    }
