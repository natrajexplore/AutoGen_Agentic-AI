# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Nataraj Angappan
"""Deterministic rule evaluation. This module, not the LLM, decides PASS/FAIL/NOT_APPLICABLE.

Matching runs on raw config lines (so e.g. default SNMP communities can be recognised),
but every line placed in evidence is masked.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from configguard.context import AuditContext
from configguard.models import BaselineSettings, EvidenceLine, Finding, Rule
from configguard.tools.masking import mask_line
from configguard.tools.parser import ensure_parsed, line_no, top_level


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.I)


def _ev(obj: Any) -> EvidenceLine:
    return EvidenceLine(line_number=line_no(obj), text=mask_line(obj.text.rstrip()))


def _children(obj: Any) -> list[Any]:
    return [c for c in obj.children if not c.is_comment and c.text.strip()]


def _matches(objs: list[Any], pattern: str) -> list[Any]:
    rx = _rx(pattern)
    return [o for o in objs if rx.search(o.text.strip())]


class Outcome:
    """Mutable result collected by a check, turned into a Finding at the end."""

    def __init__(self) -> None:
        self.fail_evidence: list[EvidenceLine] = []
        self.pass_evidence: list[EvidenceLine] = []
        self.missing: list[str] = []
        self.not_applicable: str | None = None
        self.pass_reason = ""
        self.advisory: str | None = None


# --------------------------------------------------------------------------- declarative checks


def _global_required(ctx: AuditContext, rule: Rule, _: BaselineSettings, out: Outcome) -> None:
    tops = top_level(ensure_parsed(ctx))
    for pattern in rule.check.all_of:
        hits = _matches(tops, pattern)
        if hits:
            out.pass_evidence.extend(_ev(h) for h in hits)
        else:
            out.missing.append(f"no config line matching /{pattern}/")
    if rule.check.any_of:
        hits = [h for p in rule.check.any_of for h in _matches(tops, p)]
        if hits:
            out.pass_evidence.extend(_ev(h) for h in hits)
        else:
            alternatives = " or ".join(f"/{p}/" for p in rule.check.any_of)
            out.missing.append(f"no config line matching {alternatives}")
    for pattern in rule.check.forbid:
        out.fail_evidence.extend(_ev(h) for h in _matches(tops, pattern))
    out.pass_reason = "all required lines present"


def _global_forbidden(ctx: AuditContext, rule: Rule, _: BaselineSettings, out: Outcome) -> None:
    assert rule.check.pattern
    tops = top_level(ensure_parsed(ctx))
    out.fail_evidence.extend(_ev(h) for h in _matches(tops, rule.check.pattern))
    out.pass_reason = f"no config line matches forbidden /{rule.check.pattern}/"


def _children_required(ctx: AuditContext, rule: Rule, _: BaselineSettings, out: Outcome) -> None:
    assert rule.check.parent
    parents = _matches(top_level(ensure_parsed(ctx)), rule.check.parent)
    if not parents:
        out.not_applicable = f"no sections matching /{rule.check.parent}/"
        return
    for parent in parents:
        kids = _children(parent)
        parent_failed = False
        for pattern in rule.check.require:
            hits = _matches(kids, pattern)
            if hits:
                out.pass_evidence.extend(_ev(h) for h in hits)
            else:
                out.missing.append(
                    f"'{parent.text.strip()}' (line {line_no(parent)}) has no line matching /{pattern}/"
                )
                parent_failed = True
        for pattern in rule.check.forbid:
            bad = _matches(kids, pattern)
            if bad:
                out.fail_evidence.extend(_ev(b) for b in bad)
                parent_failed = True
        if parent_failed:
            out.fail_evidence.append(_ev(parent))  # evidence is sorted by line number later
    out.pass_reason = f"all {len(parents)} matching section(s) compliant"


# --------------------------------------------------------------------------- python checks


def snmp_communities(ctx: AuditContext, rule: Rule, settings: BaselineSettings, out: Outcome) -> None:
    defaults = {c.lower() for c in settings.default_snmp_communities}
    community_rx = _rx(r"^snmp-server community (\S+)")
    host_rx = _rx(r"^snmp-server host \S+ (?:informs |traps )?(?:version (1|2c) )?(\S+)")
    tops = top_level(ensure_parsed(ctx))
    v2c_in_use = False
    for obj in tops:
        text = obj.text.strip()
        m = community_rx.match(text)
        if m:
            v2c_in_use = True
            if m.group(1).lower() in defaults:
                out.fail_evidence.append(_ev(obj))
            continue
        m = host_rx.match(text)
        if m and "version 3" not in text.lower():
            v2c_in_use = True
            if m.group(2).lower() in defaults:
                out.fail_evidence.append(_ev(obj))
    v3_groups = _matches(tops, r"^snmp-server group \S+ v3 (auth|priv)")
    out.pass_evidence.extend(_ev(g) for g in v3_groups)
    if v2c_in_use and not v3_groups:
        out.advisory = "SNMPv1/v2c communities in use; SNMPv3 (authPriv) is preferred."
    out.pass_reason = "no default SNMP community strings configured"


def exec_timeout(ctx: AuditContext, rule: Rule, settings: BaselineSettings, out: Outcome) -> None:
    parents = _matches(top_level(ensure_parsed(ctx)), r"^line (con|vty)\b")
    if not parents:
        out.not_applicable = "no line con/vty sections"
        return
    timeout_rx = _rx(r"^exec-timeout (\d+)(?: (\d+))?$")
    limit = settings.max_exec_timeout_minutes
    for parent in parents:
        lines = [c for c in _children(parent) if timeout_rx.match(c.text.strip())]
        if not lines:
            out.fail_evidence.append(_ev(parent))
            out.missing.append(f"'{parent.text.strip()}' (line {line_no(parent)}) has no exec-timeout")
            continue
        m = timeout_rx.match(lines[-1].text.strip())
        assert m
        minutes, seconds = int(m.group(1)), int(m.group(2) or 0)
        if minutes == 0 and seconds == 0:
            out.fail_evidence.extend([_ev(parent), _ev(lines[-1])])  # 0 0 disables the timeout
        elif minutes * 60 + seconds > limit * 60:
            out.fail_evidence.extend([_ev(parent), _ev(lines[-1])])
        else:
            out.pass_evidence.append(_ev(lines[-1]))
    out.pass_reason = f"all console/vty lines time out within {limit} minutes"


def cdp_external(ctx: AuditContext, rule: Rule, settings: BaselineSettings, out: Outcome) -> None:
    tops = top_level(ensure_parsed(ctx))
    ext_rx = _rx(settings.external_interface_pattern)
    external = []
    for intf in _matches(tops, r"^interface "):
        desc = next((c for c in _children(intf) if c.text.strip().startswith("description ")), None)
        if desc and ext_rx.search(desc.text):
            external.append(intf)
    if not external:
        out.not_applicable = "no interfaces with an external-facing description"
        return
    global_off = _matches(tops, r"^no cdp run$")
    if global_off:
        out.pass_evidence.extend(_ev(g) for g in global_off)
        out.pass_reason = "CDP disabled globally"
        return
    for intf in external:
        off = _matches(_children(intf), r"^no cdp enable$")
        if off:
            out.pass_evidence.append(_ev(off[0]))
        else:
            out.fail_evidence.append(_ev(intf))
            out.missing.append(f"'{intf.text.strip()}' (line {line_no(intf)}) has no 'no cdp enable'")
    out.pass_reason = f"CDP disabled on all {len(external)} external interface(s)"


def unused_interfaces(ctx: AuditContext, rule: Rule, settings: BaselineSettings, out: Outcome) -> None:
    interfaces = [
        i for i in _matches(top_level(ensure_parsed(ctx)), r"^interface ") if "null" not in i.text.lower()
    ]
    if not interfaces:
        out.not_applicable = "no interfaces"
        return
    in_use_rx = _rx(r"^(description |ip address \d|ipv6 address |ip unnumbered |switchport|channel-group )")
    for intf in interfaces:
        kids = [c.text.strip() for c in _children(intf)]
        if "shutdown" in kids or any(in_use_rx.match(k) for k in kids):
            continue
        out.fail_evidence.append(_ev(intf))
    out.pass_reason = "every interface is in use (IP, description or switchport) or shut down"


PYTHON_CHECKS: dict[str, Callable[[AuditContext, Rule, BaselineSettings, Outcome], None]] = {
    "snmp_communities": snmp_communities,
    "exec_timeout": exec_timeout,
    "cdp_external": cdp_external,
    "unused_interfaces": unused_interfaces,
}

_DECLARATIVE = {
    "global_required": _global_required,
    "global_forbidden": _global_forbidden,
    "children_required": _children_required,
}


# --------------------------------------------------------------------------- entry point


def evaluate(ctx: AuditContext, rule: Rule, settings: BaselineSettings) -> Finding:
    base: dict[str, Any] = {"rule_id": rule.id, "title": rule.title, "severity": rule.severity}

    if rule.applies_when and rule.applies_when.global_present:
        if not _matches(top_level(ensure_parsed(ctx)), rule.applies_when.global_present):
            return Finding(
                **base,
                status="NOT_APPLICABLE",
                reason=f"precondition not met: no line matching /{rule.applies_when.global_present}/",
            )

    out = Outcome()
    if rule.check.type == "python":
        assert rule.check.function
        func = PYTHON_CHECKS.get(rule.check.function)
        if func is None:
            raise ValueError(f"unknown python check function: {rule.check.function}")
        func(ctx, rule, settings, out)
    else:
        _DECLARATIVE[rule.check.type](ctx, rule, settings, out)

    advisory = out.advisory or rule.advisory
    if out.not_applicable:
        return Finding(**base, status="NOT_APPLICABLE", reason=out.not_applicable, advisory=advisory)
    if out.fail_evidence or out.missing:
        return Finding(
            **base,
            status="FAIL",
            evidence=_dedupe(out.fail_evidence),
            missing=out.missing,
            reason=rule.description,
            advisory=advisory,
        )
    return Finding(
        **base, status="PASS", evidence=_dedupe(out.pass_evidence), reason=out.pass_reason, advisory=advisory
    )


def _dedupe(lines: list[EvidenceLine]) -> list[EvidenceLine]:
    seen: dict[int, EvidenceLine] = {}
    for line in lines:
        seen.setdefault(line.line_number, line)
    return sorted(seen.values(), key=lambda e: e.line_number)
