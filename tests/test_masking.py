# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Nataraj Angappan
from __future__ import annotations

import json

import pytest

from conftest import EXPECTED, FIXTURE_NAMES
from configguard.tools.baseline import check_rule, find_config_lines
from configguard.tools.masking import MASK, WEAK_MASK, mask_line, mask_secrets
from configguard.tools.parser import parse_ios_config


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("enable secret 9 $9$abc$def", f"enable secret 9 {MASK}"),
        ("enable password Cisc0!", f"enable password {MASK}"),
        ("enable password level 15 7 0822455D0A16", f"enable password level 15 7 {MASK}"),
        ("username bob privilege 15 secret 9 $9$x", f"username bob privilege 15 secret 9 {MASK}"),
        ("username bob password 7 0822455D0A16", f"username bob password 7 {MASK}"),
        (" password 7 045802150C2E", f" password 7 {MASK}"),
        ("snmp-server community public RO", f"snmp-server community {WEAK_MASK} RO"),
        ("snmp-server community PRIVATE RW", f"snmp-server community {WEAK_MASK} RW"),
        ("snmp-server community S3cret RO 10", f"snmp-server community {MASK} RO 10"),
        ("snmp-server host 10.1.1.1 version 2c public", f"snmp-server host 10.1.1.1 version 2c {WEAK_MASK}"),
        ("snmp-server host 10.1.1.1 traps S3cret", f"snmp-server host 10.1.1.1 traps {MASK}"),
        (
            "snmp-server user u1 G1 v3 auth sha AuthK priv aes 128 PrivK",
            f"snmp-server user u1 G1 v3 auth sha {MASK} priv aes 128 {MASK}",
        ),
        ("ntp authentication-key 1 md5 1514090A0F 7", f"ntp authentication-key 1 md5 {MASK} 7"),
        ("tacacs-server host 10.1.1.5 key 7 070C28", f"tacacs-server host 10.1.1.5 key 7 {MASK}"),
        ("radius-server key S3cret", f"radius-server key {MASK}"),
        (" key 7 070C285F4D", f" key 7 {MASK}"),
        (" key-string 7 13061E01", f" key-string 7 {MASK}"),
        ("crypto isakmp key 6 Abc123 address 1.2.3.4", f"crypto isakmp key 6 {MASK} address 1.2.3.4"),
        (" pre-shared-key local 6 Abc123", f" pre-shared-key local 6 {MASK}"),
        (" ip ospf message-digest-key 1 md5 7 0822", f" ip ospf message-digest-key 1 md5 7 {MASK}"),
        (" ip ospf authentication-key 7 0822", f" ip ospf authentication-key 7 {MASK}"),
        (" neighbor 10.0.0.2 password 7 0822", f" neighbor 10.0.0.2 password 7 {MASK}"),
        (" standby 1 authentication md5 key-string S3c", f" standby 1 authentication md5 key-string {MASK}"),
        (" vrrp 1 authentication text Vr3p", f" vrrp 1 authentication text {MASK}"),
        (" glbp 10 authentication md5 key-string Gl8p", f" glbp 10 authentication md5 key-string {MASK}"),
        (" wpa-psk ascii 0 WifiK3y!", f" wpa-psk ascii 0 {MASK}"),
        ("key config-key password-encrypt M4sterK3y", f"key config-key password-encrypt {MASK}"),
        (" ip nhrp authentication NhrpK3y", f" ip nhrp authentication {MASK}"),
    ],
)
def test_mask_line_masks_secret_values(line: str, expected: str) -> None:
    assert mask_line(line) == expected


@pytest.mark.parametrize(
    "line",
    [
        "service password-encryption",
        "security passwords min-length 10",
        "key chain OSPF-KEYS",
        " key 1",
        "aaa authentication login default group TACACS-GRP local",
        "ntp trusted-key 1",
        "ntp server 10.1.1.10 key 1 prefer",
        "interface GigabitEthernet0/0/0",
    ],
)
def test_mask_line_leaves_non_secrets_alone(line: str) -> None:
    assert mask_line(line) == line


def test_mask_secrets_multiline() -> None:
    text = "hostname R1\nenable secret 9 abc\nsnmp-server community public RO"
    assert mask_secrets(text) == f"hostname R1\nenable secret 9 {MASK}\nsnmp-server community {WEAK_MASK} RO"


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_no_fixture_secret_leaves_any_tool(fixture_ctx, name: str) -> None:
    """End-to-end leak test: every tool output for every fixture is free of known secrets."""
    ctx = fixture_ctx(name)
    outputs = [parse_ios_config(ctx), find_config_lines(ctx, ".*")]
    outputs += [check_rule(ctx, rule.id) for rule in ctx.baseline.rules]
    # find_config_lines truncates at 50 results, so also search in windows over the whole file
    outputs += [find_config_lines(ctx, f"^{c}") for c in "abcdefghijklmnopqrstuvwxyz !"]
    blob = json.dumps(outputs)
    leaked = [s for s in EXPECTED["secrets"] if s in blob]
    assert not leaked, f"secrets leaked from tools: {leaked}"
