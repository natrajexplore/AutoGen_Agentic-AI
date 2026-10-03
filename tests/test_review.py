"""Human review, scoring, waivers (risk acceptance) and device facts. No LLM calls."""

from __future__ import annotations

import asyncio
import dataclasses
import json
from datetime import date, timedelta
from pathlib import Path

import pytest
import yaml

from conftest import BASELINE, FIXTURES
from configguard.approval import StructuredApprover, validate_review
from configguard.config.settings import Settings
from configguard.facts import device_facts
from configguard.models import Finding, Waiver
from configguard.persistence import load_checkpoint, save_checkpoint
from configguard.runner import RunSummary, apply_review
from configguard.scoring import assess
from configguard.tools.audit_record import audit_gaps, get_fail_findings
from configguard.waivers import WaiverStore
from test_phase4 import audited

TODAY = date(2026, 10, 3)


def review(result, decisions: dict, **kw):
    raw = {"reviewer": kw.pop("reviewer", "Jane Doe"), "ticket": kw.pop("ticket", None),
           "decisions": {result.ctx.audit_id: decisions}}
    return validate_review(raw, [result], export_allowed=kw.pop("export_allowed", True), max_waiver_days=365, today=TODAY)


# --------------------------------------------------------------------------- validation


def test_valid_review_records_every_action() -> None:
    r = audited("r03-mgmt-plane.cfg")
    outcome, errors = review(r, {
        "CG-001": {"action": "approve_fix"},
        "CG-007": {"action": "false_positive", "comment": "HTTP disabled by upstream policy"},
        "CG-012": {"action": "accept_risk", "comment": "Console in locked room", "expires": "2026-12-31"},
    }, ticket="CHG0012345")
    assert errors == []
    d = outcome.decisions[r.ctx.audit_id]
    assert d["CG-012"].expires == date(2026, 12, 31) and d["CG-001"].ticket == "CHG0012345"
    assert outcome.counts() == {"approve_fix": 1, "reject_fix": 0, "accept_risk": 1, "false_positive": 1}


@pytest.mark.parametrize(
    ("decisions", "kw", "fragment"),
    [
        ({"CG-001": {"action": "approve_fix"}}, {"reviewer": " "}, "reviewer name is required"),
        ({"CG-003": {"action": "approve_fix"}}, {}, "only FAIL findings"),
        ({"CG-001": {"action": "delete_device"}}, {}, "action must be one of"),
        ({"CG-001": {"action": "approve_fix"}}, {"export_allowed": False}, "no approvable fix"),
        ({"CG-002": {"action": "approve_fix"}}, {}, "only FAIL findings"),
        ({"CG-012": {"action": "accept_risk", "comment": "short"}}, {}, "justification of at least"),
        ({"CG-007": {"action": "false_positive", "comment": ""}}, {}, "reason of at least"),
        ({"CG-012": {"action": "accept_risk", "comment": "a long enough reason", "expires": "2026-10-03"}}, {}, "after today"),
        ({"CG-012": {"action": "accept_risk", "comment": "a long enough reason", "expires": "2028-01-01"}}, {}, "within 365 days"),
        ({"CG-012": {"action": "accept_risk", "comment": "a long enough reason", "expires": "soon"}}, {}, "must be a date"),
        ({"CG-001": {"action": "approve_fix"}}, {"ticket": "CHG 1; rm -rf"}, "change ticket"),
    ],
)
def test_invalid_reviews_are_rejected(decisions, kw, fragment) -> None:
    _, errors = review(audited("r03-mgmt-plane.cfg"), decisions, **kw)
    assert any(fragment in e for e in errors), errors


def test_unapproved_audit_cannot_have_fix_approved_but_can_accept_risk() -> None:
    r = audited("r03-mgmt-plane.cfg", approved=False)
    outcome, errors = review(r, {"CG-001": {"action": "approve_fix"},
                                 "CG-012": {"action": "accept_risk", "comment": "Console in locked room"}})
    assert any("no approvable fix" in e for e in errors)
    assert list(outcome.decisions[r.ctx.audit_id]) == ["CG-012"]  # valid part kept
    assert outcome.decisions[r.ctx.audit_id]["CG-012"].expires == TODAY + timedelta(days=90)  # default expiry


def test_unknown_audit_and_garbage_input() -> None:
    r = audited("r03-mgmt-plane.cfg")
    _, errors = validate_review({"reviewer": "x y", "decisions": {"nope": {}}}, [r], export_allowed=True, max_waiver_days=365)
    assert any("unknown audit" in e for e in errors)
    assert validate_review("not a dict", [r], export_allowed=True, max_waiver_days=365)[1]


def test_reviewer_text_is_sanitised() -> None:
    r = audited("r03-mgmt-plane.cfg")
    outcome, _ = review(r, {"CG-001": {"action": "reject_fix", "comment": "bad\nreload"}}, reviewer="Jane\x00 Doe")
    d = outcome.decisions[r.ctx.audit_id]["CG-001"]
    assert d.reviewer == "Jane  Doe"  # control character collapsed to a space
    assert d.comment == "bad reload"  # newline collapsed: can't break report or script lines


# --------------------------------------------------------------------------- structured (web) approver


def _structured(*answers: str) -> StructuredApprover:
    it = iter(answers)
    return StructuredApprover(input_func=lambda _p: next(it, ""), output=lambda _s: None)


def test_structured_review_retries_until_valid() -> None:
    r = audited("r03-mgmt-plane.cfg")
    good = json.dumps({"reviewer": "Jane Doe", "decisions": {r.ctx.audit_id: {"CG-001": {"action": "approve_fix"}}}})
    approver = _structured("not json", json.dumps({"reviewer": "", "decisions": {r.ctx.audit_id: {"CG-001": {"action": "approve_fix"}}}}), good)
    outcome = asyncio.run(approver.review([r], [], export_allowed=True))
    assert outcome.approved_fixes(r.ctx.audit_id) == ["CG-001"]
    assert len(approver.transcript) == 3 and approver.transcript[0][1] == "<structured review>"


def test_structured_review_payload_and_skip() -> None:
    r = audited("r03-mgmt-plane.cfg")
    approver = _structured(json.dumps({"skip": True, "overwrite": True}))
    captured = {}
    original = approver.ask

    async def spy(question, kind="text", payload=None):
        captured.update(payload or {})
        return await original(question, kind, payload)

    approver.ask = spy
    outcome = asyncio.run(approver.review([r], ["BR-R03"], export_allowed=True))
    assert outcome.decisions == {} and outcome.overwrite is True
    device = captured["devices"][0]
    assert device["device"] == "BR-R03" and device["assessment"]["rating"] == "Critical"
    items = {i["rule_id"]: i for i in device["items"]}
    assert list(items) == ["CG-001", "CG-007", "CG-012"] and items["CG-001"]["fix_eligible"]
    assert items["CG-001"]["fix"]["lockout"] and items["CG-001"]["frameworks"]["PCI DSS v4.0"] == ["2.2.7"]
    assert captured["existing_reports"] == ["BR-R03"]


def test_structured_review_gives_up_after_repeated_invalid_answers() -> None:
    r = audited("r03-mgmt-plane.cfg")
    outcome = asyncio.run(_structured(*["{}x"] * 10).review([r], [], export_allowed=True))
    assert outcome.decisions == {}


# --------------------------------------------------------------------------- scoring


def _f(rule_id: str, severity: str, status: str) -> Finding:
    kw = {"missing": ["x"]} if status == "FAIL" else {}
    return Finding(rule_id=rule_id, title=rule_id, severity=severity, status=status, reason="r", **kw)


def test_score_weights_and_rating() -> None:
    findings = [_f("A", "critical", "FAIL"), _f("B", "low", "PASS"), _f("C", "high", "PASS"), _f("D", "medium", "NOT_APPLICABLE")]
    a = assess(findings)
    assert a.score == round(100 * 6 / 16, 1) and a.rating == "Critical"
    assert a.open_by_severity == {"critical": 1, "high": 0, "medium": 0, "low": 0}


def test_false_positive_passes_and_accepted_risk_still_counts_against_score() -> None:
    from datetime import datetime, timezone

    from configguard.models import ReviewDecision

    findings = [_f("A", "critical", "FAIL"), _f("B", "high", "FAIL"), _f("C", "low", "PASS")]
    stamp = datetime.now(timezone.utc)
    decisions = {"A": ReviewDecision(rule_id="A", action="false_positive", reviewer="j", decided_at=stamp)}
    waivers = {"B": Waiver(device="d", rule_id="B", justification="j", approver="a", expires=TODAY, created=TODAY)}
    a = assess(findings, decisions, waivers)
    assert a.effective == {"A": "FALSE_POSITIVE", "B": "RISK_ACCEPTED", "C": "PASS"}
    assert a.score == round(100 * 11 / 16, 1) and a.rating == "Compliant"  # nothing open


def test_all_not_applicable_scores_100() -> None:
    assert assess([_f("A", "high", "NOT_APPLICABLE")]).score == 100.0


# --------------------------------------------------------------------------- waivers


def _waiver(rule="CG-012", device="BR-R03", days=30) -> Waiver:
    return Waiver(device=device, rule_id=rule, justification="Console in locked room", approver="Jane",
                  expires=date.today() + timedelta(days=days), created=date.today())


def test_waiver_store_add_replace_revoke(tmp_path: Path) -> None:
    store = WaiverStore(tmp_path / "waivers.yaml")
    assert store.load() == []
    store.add([_waiver(), _waiver("CG-007")])
    store.add([_waiver(days=60)])  # replaces the CG-012 entry
    loaded = store.load()
    assert len(loaded) == 2 and next(w for w in loaded if w.rule_id == "CG-012").expires == date.today() + timedelta(days=60)
    assert store.path.read_text(encoding="utf-8").startswith("# ConfigGuard risk-acceptance register")
    assert store.revoke("BR-R03", "CG-007") is True and store.revoke("BR-R03", "CG-007") is False
    assert [w.rule_id for w in store.load()] == ["CG-012"]


def test_waiver_store_rejects_invalid_file(tmp_path: Path) -> None:
    path = tmp_path / "waivers.yaml"
    path.write_text(yaml.safe_dump({"waivers": [{"device": "x"}]}))
    with pytest.raises(ValueError, match="invalid waivers file"):
        WaiverStore(path).load()


def test_active_waiver_skips_remediation_and_closes_gap() -> None:
    r = audited("r03-mgmt-plane.cfg")
    del r.ctx.remediations["CG-012"]
    assert "CG-012: FAIL has no recorded remediation" in audit_gaps(r.ctx)
    r.ctx.waivers = [_waiver()]
    assert audit_gaps(r.ctx) == []
    skip = next(f for f in get_fail_findings(r.ctx)["fails"] if f["rule_id"] == "CG-012")
    assert skip["skip"] is True and "intent" not in skip  # nothing to draft, fewer tokens
    assert r.assessment.effective["CG-012"] == "RISK_ACCEPTED"


def test_expired_or_other_device_waiver_does_not_apply() -> None:
    r = audited("r03-mgmt-plane.cfg")
    r.ctx.waivers = [_waiver(days=-1), _waiver(device="OTHER")]
    assert r.assessment.effective["CG-012"] == "FAIL"


# --------------------------------------------------------------------------- apply_review end to end


def test_apply_review_writes_register_report_script_and_checkpoint(tmp_path: Path) -> None:
    settings = dataclasses.replace(
        Settings.from_env(), baseline_path=BASELINE, reports_dir=tmp_path / "reports",
        remediation_dir=tmp_path / "remediation", logs_dir=tmp_path / "logs", state_dir=tmp_path / "state",
        waivers_path=tmp_path / "waivers.yaml",
    )
    r = audited("r03-mgmt-plane.cfg")
    save_checkpoint(settings.state_dir, r.ctx, {}, "approved")
    outcome, errors = validate_review({"reviewer": "Jane Doe", "ticket": "CHG42", "decisions": {r.ctx.audit_id: {
        "CG-007": {"action": "approve_fix"},
        "CG-012": {"action": "accept_risk", "comment": "Console in locked room",
                   "expires": (date.today() + timedelta(days=30)).isoformat()},
    }}}, [r], export_allowed=True, max_waiver_days=365)
    assert errors == []
    summary = RunSummary(results=[r])
    apply_review(settings, summary, outcome)

    waivers = WaiverStore(settings.waivers_path).load()
    assert [(w.device, w.rule_id, w.approver, w.ticket) for w in waivers] == [("BR-R03", "CG-012", "Jane Doe", "CHG42")]
    script = next(p for p in summary.written if p.name.endswith("_remediation.txt")).read_text(encoding="utf-8")
    assert [l for l in script.splitlines() if l and not l.startswith("!")] == ["no ip http server"]  # approved only
    report = next(p for p in summary.written if p.suffix == ".md").read_text(encoding="utf-8")
    assert "Risk accepted until" in report and "Open - fix approved" in report and "Open - pending review" in report
    ctx, _, _ = load_checkpoint(settings.state_dir, r.ctx.audit_id)
    assert {k: d.action for k, d in ctx.decisions.items()} == {"CG-007": "approve_fix", "CG-012": "accept_risk"}
    log = [json.loads(l) for l in (settings.logs_dir / f"{r.ctx.audit_id}.jsonl").read_text(encoding="utf-8").splitlines()]
    review_event = next(e for e in log if e["kind"] == "human_review")
    assert review_event["reviewer"] == "Jane Doe" and len(review_event["decisions"]) == 2


def test_no_approved_fix_means_no_script(tmp_path: Path) -> None:
    settings = dataclasses.replace(
        Settings.from_env(), baseline_path=BASELINE, reports_dir=tmp_path / "r", remediation_dir=tmp_path / "m",
        logs_dir=tmp_path / "l", state_dir=tmp_path / "s", waivers_path=tmp_path / "w.yaml")
    summary = RunSummary(results=[audited("r03-mgmt-plane.cfg")])
    from configguard.approval import ReviewOutcome

    apply_review(settings, summary, ReviewOutcome())
    assert not any(p.name.endswith("_remediation.txt") for p in summary.written)


# --------------------------------------------------------------------------- device facts


def test_device_facts_from_fixture() -> None:
    facts = device_facts((FIXTURES / "r10-mixed.cfg").read_text().splitlines())
    assert facts["hostname"] == "EDGE-R10" and facts["software_version"] == "17.3"
    assert (facts["platform"], facts["serial_number"]) == ("ISR4431/K9", "FOC2129X0EF")
    assert facts["interfaces"] == {"physical": 4, "virtual": 1, "shutdown": 1}
    assert facts["vty_lines"] == 16 and facts["snmp"] == "v1/v2c" and facts["aaa"] is True


def test_device_facts_variants() -> None:
    facts = device_facts(["hostname X", "boot system flash:c8000be-universalk9.17.09.04a.SPA.bin",
                          "router ospf 1", "router bgp 65000", "snmp-server group G v3 priv", "line vty 0 4"])
    assert facts["boot_image"] == "c8000be-universalk9.17.09.04a.SPA.bin"
    assert facts["routing_protocols"] == ["bgp", "ospf"] and facts["snmp"] == "v3" and facts["vty_lines"] == 5
