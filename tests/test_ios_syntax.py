from __future__ import annotations

import pytest

from conftest import BASELINE
from configguard.tools.baseline import check_rule, read_baseline
from configguard.tools.ios_syntax import lockout_risks, record_remediation, validate_ios_syntax


def errors(commands: list[str]) -> list[str]:
    return validate_ios_syntax(commands)["errors"]


@pytest.mark.parametrize("rule", read_baseline(BASELINE).rules, ids=lambda r: r.id)
def test_every_baseline_remediation_hint_is_valid(rule) -> None:
    assert errors(rule.remediation_hint) == []


def test_valid_multi_mode_script() -> None:
    result = validate_ios_syntax(
        [
            "ip access-list standard <MGMT_ACL>",
            " 10 permit 10.1.1.0 0.0.0.255",
            " deny any log",
            "exit",
            "line vty 0 15",
            " access-class <MGMT_ACL> in",
            " transport input ssh",
            " exec-timeout 10 0",
            "exit",
            "interface GigabitEthernet0/0/3",
            " shutdown",
            "exit",
            "banner login ^C",
            "Authorized access only.",
            "^C",
        ]
    )
    assert result["valid"], result["errors"]
    assert result["placeholders"] == ["<MGMT_ACL>"]


@pytest.mark.parametrize(
    ("commands", "fragment"),
    [
        ([], "no commands"),
        (["transport input ssh"], "sub-mode command used at global level"),
        (["line vty 0 4", " transport input ssh"], "end inside 'line' mode"),
        (["line vty 0 4", " service password-encryption", "exit"], "add 'exit' first"),
        (["line vty 0 4", " frobnicate", "exit"], "unrecognised command 'frobnicate'"),
        (["exit"], "'exit' at global"),
        (["reload"], "not allowed"),
        (["write memory"], "not allowed"),
        (["do show run"], "not allowed"),
        (["configure terminal"], "not allowed"),
        (["frobnicate all"], "unrecognised global command"),
        (["enable secret Hunter2"], "must be placeholders"),
        (["username admin secret 0 Hunter2"], "must be placeholders"),
        (["no snmp-server host 10.1.1.60 version 2c <MASKED:weak-default>"], "masked values cannot"),
        (["ip ssh version 3"], "malformed"),
        (["line vty 0 4", " exec-timeout ten", "exit"], "malformed"),
        (["line vty 0 4", " transport input sssh", "exit"], "malformed"),
        (["logging trap verbose"], "malformed"),
        (["line vty 0 4", " access-class MGMT", "exit"], "malformed"),
        (["line vty zero", "exit"], "expected 'line con 0'"),
        (["interface Bogus9", "exit"], "unrecognised interface name"),
        (["banner login ^C", "text"], "not closed"),
        (["hostname R1\nreload"], "control"),
    ],
)
def test_invalid_scripts(commands: list[str], fragment: str) -> None:
    result = validate_ios_syntax(commands)
    assert not result["valid"]
    assert any(fragment in e for e in result["errors"]), result["errors"]


# --------------------------------------------------------------------------- lockout + record


VTY_FIX = ["line vty 0 15", " transport input ssh", "exit"]
WARNING = ["LOCKOUT WARNING: verify SSH works from a second session first; recover via console."]


def test_lockout_risks_detected(fixture_ctx) -> None:
    ctx = fixture_ctx("r10-mixed.cfg")
    assert lockout_risks(ctx, VTY_FIX)
    assert any("not defined" in r for r in lockout_risks(ctx, ["line vty 0 4", " access-class NOPE in", "exit"]))
    assert not any("not defined" in r for r in lockout_risks(ctx, ["line vty 0 4", " access-class MGMT-ACL in", "exit"]))
    assert lockout_risks(ctx, ["aaa authentication login default group TACACS-GRP"])
    assert not lockout_risks(ctx, ["aaa authentication login default group TACACS-GRP local"])
    assert lockout_risks(ctx, ["interface GigabitEthernet0/0/1", " shutdown", "exit"])  # has an IP
    assert not lockout_risks(ctx, ["interface GigabitEthernet0/0/3", " shutdown", "exit"])  # unused, no IP
    assert not lockout_risks(ctx, ["no ip http server"])


def test_aaa_new_model_without_users_is_a_risk(text_ctx) -> None:
    assert lockout_risks(text_ctx("hostname X"), ["aaa new-model"])
    assert not lockout_risks(text_ctx("username a secret 9 x"), ["aaa new-model"])


def test_record_remediation_requires_fail_finding(fixture_ctx) -> None:
    ctx = fixture_ctx("r10-mixed.cfg")
    assert "run check_rule first" in record_remediation(ctx, "CG-007", "risk", ["no ip http server"], [])["error"]
    check_rule(ctx, "CG-003")  # PASS on r10
    assert "only for FAIL" in record_remediation(ctx, "CG-003", "risk", ["service password-encryption"], [])["error"]


def test_record_remediation_validates_and_stores(fixture_ctx) -> None:
    ctx = fixture_ctx("r10-mixed.cfg")
    check_rule(ctx, "CG-007")
    bad = record_remediation(ctx, "CG-007", "HTTP is cleartext.", ["ip http server off"], [])
    assert bad["ok"] is False and bad["errors"]
    assert "CG-007" not in ctx.remediations
    good = record_remediation(ctx, "cg-007", "HTTP is cleartext.", ["no ip http server"], [])
    assert good == {"ok": True, "recorded": True, "lockout_risks": [], "placeholders": []}
    assert ctx.remediations["CG-007"].commands == ["no ip http server"]


def test_record_remediation_enforces_lockout_warning(fixture_ctx) -> None:
    ctx = fixture_ctx("r10-mixed.cfg")
    check_rule(ctx, "CG-001")
    missing = record_remediation(ctx, "CG-001", "Telnet is cleartext.", VTY_FIX, ["be careful"])
    assert missing["ok"] is False and "LOCKOUT WARNING" in missing["errors"][0]
    ok = record_remediation(ctx, "CG-001", "Telnet is cleartext.", VTY_FIX, WARNING)
    assert ok["recorded"] and ok["lockout_risks"]


def test_baseline_lockout_flag_forces_warning(fixture_ctx) -> None:
    # CG-005 is flagged lockout_risk in the baseline; r10 has local users, so the guard
    # itself finds nothing, but the warning is still required.
    ctx = fixture_ctx("r10-mixed.cfg")
    check_rule(ctx, "CG-005")
    fix = ["aaa authentication login default local"]
    assert record_remediation(ctx, "CG-005", "No login method.", fix, [])["ok"] is False
    assert record_remediation(ctx, "CG-005", "No login method.", fix, WARNING)["recorded"]
