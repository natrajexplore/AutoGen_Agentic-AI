from __future__ import annotations

from conftest import BASELINE, FIXTURES
from configguard.context import AuditContext
from configguard.tools.audit_record import audit_gaps, get_audit_record, get_fail_findings
from configguard.tools.baseline import check_rule
from configguard.tools.ios_syntax import record_remediation

WARN = ["LOCKOUT WARNING: keep a console session open."]


def test_requires_baseline_and_findings(fixture_ctx) -> None:
    assert get_audit_record(AuditContext(FIXTURES / "r01-compliant.cfg", BASELINE))["ok"] is False
    assert "ComplianceChecker must run first" in get_fail_findings(fixture_ctx("r01-compliant.cfg"))["error"]


def test_gaps_track_missing_findings_and_remediations(fixture_ctx) -> None:
    ctx = fixture_ctx("r03-mgmt-plane.cfg")
    assert len(audit_gaps(ctx)) == 14
    for rule in ctx.baseline.rules:
        check_rule(ctx, rule.id)
    assert sorted(audit_gaps(ctx)) == [f"{r}: FAIL has no recorded remediation" for r in ("CG-001", "CG-007", "CG-012")]
    record_remediation(ctx, "CG-007", "HTTP is cleartext.", ["no ip http server"], [])
    record_remediation(ctx, "CG-012", "Idle sessions stay open.", ["line con 0", " exec-timeout 10 0", "exit"], [])
    record_remediation(ctx, "CG-001", "Telnet is cleartext.", ["line vty 0 4", " transport input ssh", "exit",
                                                                "line vty 5 15", " transport input ssh", "exit"], WARN)
    assert audit_gaps(ctx) == []


def test_fail_findings_carry_intent_and_hint(fixture_ctx) -> None:
    ctx = fixture_ctx("r05-credentials.cfg")
    for rule in ctx.baseline.rules:
        check_rule(ctx, rule.id)
    result = get_fail_findings(ctx)
    assert [f["rule_id"] for f in result["fails"]] == ["CG-003", "CG-004", "CG-014"]
    cg014 = result["fails"][2]
    assert "shutdown" in cg014["remediation_hint"] and cg014["intent"] and not cg014["already_recorded"]
    assert cg014["evidence"] == [{"line_number": 50, "text": "interface GigabitEthernet0/0/3"}]


def test_audit_record_reports_lockout_warning_state(fixture_ctx) -> None:
    ctx = fixture_ctx("r03-mgmt-plane.cfg")
    for rule in ctx.baseline.rules:
        check_rule(ctx, rule.id)
    record_remediation(ctx, "CG-001", "Telnet is cleartext.", ["line vty 0 15", " transport input ssh", "exit"], WARN)
    record = get_audit_record(ctx)
    assert record["counts"] == {"PASS": 11, "FAIL": 3, "NOT_APPLICABLE": 0}
    cg001 = next(f for f in record["findings"] if f["rule_id"] == "CG-001")
    assert cg001["remediation"]["lockout_risks"] and cg001["remediation"]["has_lockout_warning"]
    assert cg001["remediation"]["rule_intent"]
