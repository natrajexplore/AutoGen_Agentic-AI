# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Nataraj Angappan
from __future__ import annotations

import pytest

from configguard.tools.baseline import check_rule
from configguard.tools.ios_syntax import record_remediation, validate_ios_syntax
from configguard.tools.simulate import apply_commands, verify_fix

WARN = ["LOCKOUT WARNING: keep a console session open."]

# A complete, hand-written remediation for every violation seeded in r02.
R02_FIXES = {
    "CG-001": ["line vty 0 15", " transport input ssh", "exit"],
    "CG-002": ["ip ssh version 2"],
    "CG-003": ["service password-encryption"],
    "CG-004": ["no enable password", "enable algorithm-type scrypt secret <STRONG_SECRET>"],
    "CG-005": ["aaa new-model", "aaa authentication login default local"],
    "CG-006": ["no snmp-server community <CURRENT_RO_COMMUNITY>", "no snmp-server community private",
               "snmp-server group <SNMP_GROUP> v3 priv"],
    "CG-007": ["no ip http server"],
    "CG-008": ["banner login ^C", "Authorized access only.", "^C"],
    "CG-009": ["logging host <SYSLOG_SERVER_IP>", "logging trap informational"],
    "CG-010": ["ntp authentication-key 1 md5 <NTP_KEY>", "ntp trusted-key 1", "ntp authenticate",
               "ntp server <NTP_SERVER_IP> key 1"],
    "CG-011": ["line vty 0 15", " access-class MGMT-ACL in", "exit"],
    "CG-012": ["line con 0", " exec-timeout 10 0", "exit", "line vty 0 15", " exec-timeout 10 0", "exit"],
    "CG-013": ["interface Gi0/0/0", " no cdp enable", "exit"],
    "CG-014": ["interface GigabitEthernet0/0/3", " shutdown", "exit"],
}


@pytest.mark.parametrize("rule_id", sorted(R02_FIXES))
def test_each_r02_fix_resolves_its_rule(fixture_ctx, rule_id: str) -> None:
    ctx = fixture_ctx("r02-all-violations.cfg")
    assert validate_ios_syntax(R02_FIXES[rule_id])["valid"]
    assert verify_fix(ctx, rule_id, R02_FIXES[rule_id]) is None


def test_all_r02_fixes_together_make_device_compliant(fixture_ctx) -> None:
    ctx = fixture_ctx("r02-all-violations.cfg")
    commands = [c for fix in R02_FIXES.values() for c in fix]
    ctx.raw_lines = apply_commands(ctx.raw_lines, commands)
    ctx.parse = None
    assert {r.id: check_rule(ctx, r.id)["finding"]["status"] for r in ctx.baseline.rules} == {
        r: "PASS" for r in R02_FIXES
    }


@pytest.mark.parametrize(
    ("fixture", "rule_id", "commands"),
    [
        # r10's default community is on the host line; removing a community line does not fix it
        ("r10-mixed.cfg", "CG-006", ["no snmp-server community public"]),
        # covers only one of the two vty blocks
        ("r07-partial-vty.cfg", "CG-001", ["line vty 0 4", " transport input ssh", "exit"]),
        # new interface via placeholder leaves the real external interface untouched
        ("r04-snmp-ssh-cdp.cfg", "CG-013", ["interface <EXTERNAL_INTERFACE>", " no cdp enable", "exit"]),
        # adds a secret but leaves the forbidden enable password in place
        ("r05-credentials.cfg", "CG-004", ["enable secret <STRONG_SECRET>"]),
    ],
)
def test_incomplete_fixes_are_detected(fixture_ctx, fixture, rule_id, commands) -> None:
    assert verify_fix(fixture_ctx(fixture), rule_id, commands) is not None


def test_placeholder_in_no_command_matches_any_value(fixture_ctx) -> None:
    ctx = fixture_ctx("r10-mixed.cfg")
    assert verify_fix(ctx, "CG-006", ["no snmp-server host 10.1.1.60 version 2c <CURRENT_COMMUNITY>"]) is None


def test_submode_replacement_semantics() -> None:
    lines = ["line vty 0 4", " transport input telnet ssh", " exec-timeout 0 0", "interface Gi1", " cdp enable"]
    out = apply_commands(lines, ["line vty 0 4", " transport input ssh", " exec-timeout 5 0", "exit",
                                 "interface GigabitEthernet1", " no cdp enable", "exit"])
    assert out == ["line vty 0 4", " transport input ssh", " exec-timeout 5 0", "interface Gi1", " no cdp enable"]


def test_acl_entries_accumulate_and_banner_replaces() -> None:
    lines = ["banner motd ^C", "old", "^C"]
    out = apply_commands(lines, ["ip access-list standard M", " permit 10.0.0.0 0.0.0.255", " deny any log", "exit",
                                 "banner motd ^CNew text^C"])
    assert out == ["ip access-list standard M", " permit 10.0.0.0 0.0.0.255", " deny any log", "banner motd ^CNew text^C"]


def test_record_remediation_rejects_fix_that_does_not_resolve(fixture_ctx) -> None:
    ctx = fixture_ctx("r10-mixed.cfg")
    check_rule(ctx, "CG-006")
    result = record_remediation(ctx, "CG-006", "Default community.", ["no snmp-server community public"], [])
    assert result["ok"] is False and "would still FAIL" in result["errors"][0]
    assert "snmp-server host 10.1.1.60" in result["errors"][0]
    assert "public" not in result["errors"][0].replace("no snmp-server community public", "")


def test_new_lines_are_placed_before_end() -> None:
    out = apply_commands(["hostname R1", "end"], ["no ip http server", "ip access-list standard M", " permit any", "exit"])
    assert out[-1] == "end" and out.index("no ip http server") < out.index("end")
