"""Offline tests for reporting, human approval, persistence and telemetry (no LLM calls)."""

from __future__ import annotations

import asyncio
import csv
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from conftest import EXPECTED, FIXTURES, loaded_ctx
from configguard.approval import HumanApprover
from configguard.facts import device_facts
from configguard.persistence import checkpoint_path, load_checkpoint, save_checkpoint
from configguard.reporting import (
    DeviceResult,
    code,
    now,
    render_batch_table,
    render_markdown,
    render_remediation_script,
    write_csv_summary,
)
from configguard.telemetry import AuditLog, Usage
from configguard.tools.baseline import check_rule
from configguard.tools.ios_syntax import record_remediation
from configguard.tools.parser import parse_ios_config

WARN = ["LOCKOUT WARNING: keep a console session open."]


def audited(name: str, *, approved: bool = True) -> DeviceResult:
    """Deterministic stand-in for a finished agent audit: all rules checked, FAILs remediated."""
    ctx = loaded_ctx(FIXTURES / name)
    parse_ios_config(ctx)
    ctx.facts = device_facts(ctx.raw_lines)
    for rule in ctx.baseline.rules:
        check_rule(ctx, rule.id)
    fixes = {
        "CG-001": ["line vty 0 15", " transport input ssh", "exit"],
        "CG-007": ["no ip http server"],
        "CG-012": ["line con 0", " exec-timeout 10 0", "exit"],
    }
    for rule_id, cmds in fixes.items():
        if ctx.findings[rule_id].status == "FAIL":
            assert record_remediation(ctx, rule_id, f"Risk for {rule_id}.", cmds, WARN)["recorded"]
    return DeviceResult(ctx=ctx, device=ctx.inventory["hostname"], approved=approved, critic_approved=approved,
                        gaps=[], duration_s=12.3, prompt_tokens=1000, completion_tokens=100, cost_usd=0.0035,
                        model="gpt-4o")


def decide(result: DeviceResult, rule_id: str, action: str, **kw) -> None:
    from datetime import datetime, timezone

    from configguard.models import ReviewDecision

    result.ctx.decisions[rule_id] = ReviewDecision(rule_id=rule_id, action=action, reviewer="Jane Doe",
                                                   decided_at=datetime.now(timezone.utc), **kw)


# --------------------------------------------------------------------------- reporting


def test_professional_report_structure() -> None:
    md = render_markdown(audited("r03-mgmt-plane.cfg"), now())
    assert md.startswith("# Network Device Security Compliance Audit Report")
    for section in ("## 1. Executive summary", "## 2. Scope and methodology", "## 3. Findings register",
                    "## 4. Detailed findings", "## 5. Compliant controls", "## 7. Risk acceptance register",
                    "## 8. Review and sign-off", "## Appendix A. Audit trail"):
        assert section in md, section
    assert "**BR-R03** · C8200-1N-4T · IOS-XE 17.9" in md and "FGL2731L0QZ" in md
    assert "**Compliance score: 71.0%** · **Risk rating: Critical**" in md
    assert "| F-01 | CG-001 | Remote terminal access limited to SSH | Critical | Open - pending review | NIST AC-17(2), SC-8; PCI 2.2.7; ISO/IEC A.8.20, A.8.24 |" in md
    assert "REVIEW BEFORE APPLYING" in md and "> **LOCKOUT WARNING" in md and "Risk for CG-007." in md
    assert "Cisco Guide to Harden Cisco IOS Devices" in md and "_Not yet reviewed_" in md


def test_report_reflects_review_decisions() -> None:
    from datetime import date, timedelta

    result = audited("r03-mgmt-plane.cfg")
    decide(result, "CG-001", "approve_fix", ticket="CHG0012345")
    decide(result, "CG-007", "false_positive", comment="HTTP server is disabled by an upstream policy")
    decide(result, "CG-012", "accept_risk", comment="Console is in a locked room with CCTV",
           expires=date.today() + timedelta(days=30))
    md = render_markdown(result, now())
    assert "Open - fix approved" in md and "False positive" in md and "Risk accepted until" in md
    assert "Console is in a locked room with CCTV" in md and "Jane Doe" in md and "CHG0012345" in md
    assert "1 fix(es) approved · 0 rejected · 1 risk(s) accepted · 1 false positive(s) · 0 pending" in md
    assert "**Risk rating: Critical**" in md  # CG-001 is still open until the fix is applied


def test_report_marks_unapproved_and_neutralises_untrusted_text() -> None:
    md = render_markdown(audited("r09-injection-bait.cfg", approved=False), now())
    assert "**not approved**" in md
    assert code("<script>x</script>") == "`<script>x</script>`"
    assert code("a ` b") == "`` a ` b ``"


def test_remediation_script_contains_only_approved_fixes() -> None:
    result = audited("r03-mgmt-plane.cfg")
    decide(result, "CG-007", "approve_fix", ticket="CHG77")
    script = render_remediation_script(result, now(), ["CG-007"])
    lines = script.splitlines()
    assert lines[1] == "! REVIEW BEFORE APPLYING" and lines[-1] == "! END - REVIEW BEFORE APPLYING"
    assert "! Fixes approved by: Jane Doe" in script and "Change ticket: CHG77" in script
    assert [l for l in lines if l and not l.startswith("!")] == ["no ip http server"]


def test_remediation_script_default_includes_all_and_is_paste_safe() -> None:
    lines = render_remediation_script(audited("r03-mgmt-plane.cfg"), now()).splitlines()
    assert [l for l in lines if l and not l.startswith("!")] == [
        "line vty 0 15", " transport input ssh", "exit", "no ip http server", "line con 0", " exec-timeout 10 0", "exit"]


def test_csv_summary(tmp_path: Path) -> None:
    result = audited("r03-mgmt-plane.cfg")
    decide(result, "CG-001", "approve_fix", ticket="CHG1")
    rows = list(csv.reader(write_csv_summary([result, audited("r01-compliant.cfg")], tmp_path / "s.csv").open(encoding="utf-8")))
    assert rows[0] == ["device", "rule_id", "severity", "status", "evidence", "review_status", "reviewer", "ticket", "frameworks"]
    assert len(rows) == 1 + 28
    cg001 = next(r for r in rows if r[0] == "BR-R03" and r[1] == "CG-001")
    assert cg001[3] == "FAIL" and cg001[5] == "Open - fix approved" and cg001[6:8] == ["Jane Doe", "CHG1"]
    assert cg001[8].startswith("NIST AC-17(2)")


def test_csv_formula_injection_guard(tmp_path: Path) -> None:
    result = audited("r01-compliant.cfg")
    result.device = "=HYPERLINK(evil)"
    rows = list(csv.reader(write_csv_summary([result], tmp_path / "s.csv").open(encoding="utf-8")))
    assert rows[1][0].startswith("'=")


def test_batch_table_scores_and_totals() -> None:
    table = render_batch_table([audited("r03-mgmt-plane.cfg"), audited("r01-compliant.cfg", approved=False)])
    assert "| BR-R03 | 71.0% | Critical | yes | 11 | 3 | 0 | 2 | - |" in table
    assert "| EDGE-R01 | 100.0% | Compliant | NO |" in table
    assert "**Total (2)** | 85.5% avg" in table and "$0.0070" in table


# --------------------------------------------------------------------------- human approval (console)


def _approver(*answers: str, reviewer: str = "") -> HumanApprover:
    it = iter(answers)
    return HumanApprover(input_func=lambda _p: next(it, ""), output=lambda _s: None, reviewer=reviewer)


def test_console_review_per_finding() -> None:
    result = audited("r03-mgmt-plane.cfg")  # FAILs, worst first: CG-001, CG-007, CG-012
    approver = _approver("Jane Doe", "CHG0012345",
                         "a",                                            # CG-001 approve fix
                         "f", "HTTP blocked by upstream ACL on all paths",  # CG-007 false positive
                         "w", "Console sits in a locked cage", "")      # CG-012 accept risk, default expiry
    outcome = asyncio.run(approver.review([result], [], export_allowed=True))
    d = outcome.decisions[result.ctx.audit_id]
    assert {k: v.action for k, v in d.items()} == {"CG-001": "approve_fix", "CG-007": "false_positive", "CG-012": "accept_risk"}
    assert outcome.reviewer == "Jane Doe" and outcome.ticket == "CHG0012345" and d["CG-012"].expires is not None
    assert outcome.approved_fixes(result.ctx.audit_id) == ["CG-001"]


def test_console_approve_all_remaining() -> None:
    result = audited("r03-mgmt-plane.cfg")
    # "" answers the ticket question, then "A" approves every remaining fix
    outcome = asyncio.run(_approver("", "A", reviewer="Sam").review([result], [], export_allowed=True))
    assert outcome.approved_fixes(result.ctx.audit_id) == ["CG-001", "CG-007", "CG-012"]


def test_console_without_reviewer_or_on_eof_records_nothing() -> None:
    result = audited("r03-mgmt-plane.cfg")
    assert asyncio.run(_approver().review([result], [], export_allowed=True)).decisions == {}
    # reviewer given, then EOF on every decision -> all pending
    assert asyncio.run(_approver(reviewer="Sam").review([result], [], export_allowed=True)).decisions == {}


def test_console_cannot_approve_fix_for_unapproved_audit_or_disabled_export() -> None:
    blocked = audited("r03-mgmt-plane.cfg", approved=False)
    outcome = asyncio.run(_approver("", "a", "a", "a", reviewer="Sam").review([blocked], [], export_allowed=True))
    assert outcome.decisions == {}
    ok = audited("r03-mgmt-plane.cfg")
    outcome = asyncio.run(_approver("", "a", "a", "a", reviewer="Sam").review([ok], [], export_allowed=False))
    assert outcome.decisions == {}


def test_console_overwrite_needs_explicit_word() -> None:
    result = audited("r01-compliant.cfg")  # nothing to decide, only the overwrite question
    assert asyncio.run(_approver("yes").review([result], ["EDGE-R01"], export_allowed=True)).overwrite is False
    assert asyncio.run(_approver("overwrite").review([result], ["EDGE-R01"], export_allowed=True)).overwrite is True


# --------------------------------------------------------------------------- persistence


def test_checkpoint_round_trip(tmp_path: Path) -> None:
    result = audited("r03-mgmt-plane.cfg")
    path = save_checkpoint(tmp_path, result.ctx, {"team": "state"}, "paused")
    blob = path.read_text(encoding="utf-8")
    assert not [s for s in EXPECTED["secrets"] if s in blob]  # only masked evidence is persisted
    assert "raw_lines" not in blob and "masked_lines" not in blob
    ctx, team_state, status = load_checkpoint(tmp_path, result.ctx.audit_id)
    assert status == "paused" and team_state == {"team": "state"}
    assert ctx.findings == result.ctx.findings and ctx.remediations == result.ctx.remediations
    assert ctx.loaded and ctx.inventory["hostname"] == "BR-R03" and ctx.baseline is not None


def test_resume_refuses_changed_config(tmp_path: Path) -> None:
    cfg = tmp_path / "dev.cfg"
    cfg.write_text((FIXTURES / "r03-mgmt-plane.cfg").read_text())
    ctx = loaded_ctx(cfg)
    save_checkpoint(tmp_path, ctx, {}, "paused")
    cfg.write_text(cfg.read_text() + "\nhostname CHANGED\n")
    with pytest.raises(RuntimeError, match="changed on disk"):
        load_checkpoint(tmp_path, ctx.audit_id)


def test_checkpoint_path_rejects_traversal(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        checkpoint_path(tmp_path, "../../etc/passwd")


# --------------------------------------------------------------------------- telemetry


def test_usage_and_cost() -> None:
    usage = Usage()
    usage.add(SimpleNamespace(models_usage=SimpleNamespace(prompt_tokens=1_000_000, completion_tokens=100_000)))
    usage.add(SimpleNamespace(models_usage=None))
    assert (usage.prompt_tokens, usage.completion_tokens) == (1_000_000, 100_000)
    assert usage.cost_usd(2.5, 10.0) == pytest.approx(3.5)


def test_audit_log_writes_jsonl(tmp_path: Path) -> None:
    from autogen_agentchat.messages import TextMessage

    log = AuditLog(tmp_path / "logs" / "a.jsonl")
    log.event("audit_start", audit_id="abc")
    log.item(TextMessage(content="hello", source="Critic"))
    records = [json.loads(line) for line in log.path.read_text(encoding="utf-8").splitlines()]
    assert records[0]["kind"] == "audit_start" and records[0]["audit_id"] == "abc"
    assert records[1]["type"] == "TextMessage" and records[1]["data"]["source"] == "Critic"
    assert all("ts" in r for r in records)
