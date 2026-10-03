"""Offline tests for reporting, human approval, persistence and telemetry (no LLM calls)."""

from __future__ import annotations

import asyncio
import csv
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from conftest import EXPECTED, FIXTURES, loaded_ctx
from configguard.approval import HumanApprover, parse_selection
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


# --------------------------------------------------------------------------- reporting


def test_markdown_report_content() -> None:
    md = render_markdown(audited("r03-mgmt-plane.cfg"), now())
    assert md.startswith("# ConfigGuard audit: BR-R03")
    assert "**3 of 14 controls failed**" in md and "**APPROVED**" in md
    assert "| CG-001 | critical | **FAIL** |" in md
    assert "REVIEW BEFORE APPLYING" in md and "> **LOCKOUT WARNING" in md
    assert "transport input ssh" in md and "Risk for CG-007." in md


def test_markdown_marks_unapproved_and_neutralises_untrusted_text() -> None:
    result = audited("r09-injection-bait.cfg", approved=False)
    md = render_markdown(result, now())
    assert "NOT APPROVED" in md
    assert code("<script>x</script>") == "`<script>x</script>`"
    assert code("a ` b") == "`` a ` b ``"


def test_remediation_script_header_and_commands() -> None:
    script = render_remediation_script(audited("r03-mgmt-plane.cfg"), now())
    lines = script.splitlines()
    assert lines[1] == "! REVIEW BEFORE APPLYING" and lines[-1] == "! END - REVIEW BEFORE APPLYING"
    assert "! LOCKOUT WARNINGS" in script and " transport input ssh" in lines
    # every non-comment line is a remediation command, so the file is paste-safe once reviewed
    commands = [l for l in lines if l and not l.startswith("!")]
    assert commands == ["line vty 0 15", " transport input ssh", "exit", "no ip http server",
                        "line con 0", " exec-timeout 10 0", "exit"]


def test_csv_summary(tmp_path: Path) -> None:
    results = [audited("r03-mgmt-plane.cfg"), audited("r01-compliant.cfg")]
    rows = list(csv.reader(write_csv_summary(results, tmp_path / "s.csv").open(encoding="utf-8")))
    assert rows[0] == ["device", "rule_id", "severity", "status", "evidence"]
    assert len(rows) == 1 + 28
    cg001 = next(r for r in rows if r[0] == "BR-R03" and r[1] == "CG-001")
    assert cg001[3] == "FAIL" and "L" in cg001[4]


def test_csv_formula_injection_guard(tmp_path: Path) -> None:
    result = audited("r01-compliant.cfg")
    result.device = "=HYPERLINK(evil)"
    rows = list(csv.reader(write_csv_summary([result], tmp_path / "s.csv").open(encoding="utf-8")))
    assert rows[1][0].startswith("'=")


def test_batch_table_totals() -> None:
    table = render_batch_table([audited("r03-mgmt-plane.cfg"), audited("r01-compliant.cfg", approved=False)])
    assert "| BR-R03 | yes | 11 | 3 | 0 | 2 |" in table  # CG-001 critical + CG-007 high
    assert "| EDGE-R01 | NO |" in table and "**Total (2)**" in table and "$0.0070" in table


# --------------------------------------------------------------------------- human approval


@pytest.mark.parametrize(
    ("answer", "expected"),
    [("all", {"A", "B", "C"}), ("none", set()), ("1,3", {"A", "C"}), ("b", {"B"}), ("9, x", set()), ("", set())],
)
def test_parse_selection(answer: str, expected: set[str]) -> None:
    assert parse_selection(answer, ["A", "B", "C"]) == expected


def _approver(*answers: str) -> HumanApprover:
    it = iter(answers)
    return HumanApprover(input_func=lambda _p: next(it, ""), output=lambda _s: None)


def test_review_exports_only_approved_devices_with_fails() -> None:
    results = [audited("r03-mgmt-plane.cfg"), audited("r07-partial-vty.cfg", approved=False), audited("r01-compliant.cfg")]
    approver = _approver("all")
    decision = asyncio.run(approver.review(results, [], export_allowed=True))
    assert decision.export == {"BR-R03"}  # r07 not approved, r01 has nothing to fix
    assert decision.overwrite is False and len(approver.transcript) == 1


def test_review_overwrite_needs_explicit_word_and_eof_rejects() -> None:
    results = [audited("r03-mgmt-plane.cfg")]
    assert asyncio.run(_approver("yes", "1").review(results, ["BR-R03"], export_allowed=True)).overwrite is False
    decision = asyncio.run(_approver("overwrite", "").review(results, ["BR-R03"], export_allowed=True))
    assert decision.overwrite is True and decision.export == set()


def test_review_skips_export_question_when_disabled() -> None:
    approver = _approver("all")
    decision = asyncio.run(approver.review([audited("r03-mgmt-plane.cfg")], [], export_allowed=False))
    assert decision.export == set() and approver.transcript == []


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
