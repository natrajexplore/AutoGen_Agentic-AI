# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Nataraj Angappan
"""Secret masking. Every piece of config text that leaves a tool goes through mask_line.

Masking keeps the command shape and encryption-type digits (e.g. `enable secret 9 <MASKED>`)
so engineers can still read the evidence, but replaces the secret value itself.
"""

from __future__ import annotations

import re

MASK = "<MASKED>"
WEAK_MASK = "<MASKED:weak-default>"
DEFAULT_COMMUNITIES = frozenset({"public", "private"})

_T = r"(?:[0-9] )?"  # optional encryption-type digit before a value

# (pattern, is_snmp_community). Group 1 = prefix kept verbatim, group 2 = secret value.
_RULES: list[tuple[re.Pattern[str], bool]] = [
    (re.compile(r"^(\s*snmp-server community )(\S+)", re.I), True),
    (
        re.compile(
            r"^(\s*snmp-server host \S+ (?:informs |traps )?"
            r"(?:version (?:1|2c|3 (?:auth|noauth|priv)) )?)(\S+)",
            re.I,
        ),
        True,
    ),
    (re.compile(r"^(\s*ntp authentication-key \d+ md5 )(\S+)", re.I), False),
    (re.compile(rf"^(\s*crypto isakmp key {_T})(\S+)", re.I), False),
    (re.compile(rf"^(\s*pre-shared-key (?:local |remote )?{_T})(\S+)", re.I), False),
    (re.compile(rf"^(\s*(?:tacacs-server|radius-server) (?:host \S+ )?.*?\bkey {_T})(\S+)", re.I), False),
    # ` key [7] VALUE` under `tacacs server X` / `radius server X`; skips `key chain` and key-chain ids.
    (re.compile(rf"^(\s+key (?!chain\b)(?!\d+\s*$){_T})(\S+)", re.I), False),
    (re.compile(rf"^(\s*key-string {_T})(\S+)", re.I), False),
    (re.compile(rf"^(\s*ip ospf authentication-key {_T})(\S+)", re.I), False),
    (re.compile(rf"^(\s*ip ospf message-digest-key \d+ md5 {_T})(\S+)", re.I), False),
    (re.compile(rf"^(\s*(?:standby|vrrp|glbp) (?:\d+ )?authentication (?:md5 key-string |text )?{_T})(\S+)", re.I), False),
    (re.compile(rf"^(\s*wpa-psk (?:ascii|hex) {_T})(\S+)", re.I), False),
    (re.compile(r"^(\s*key config-key password-encrypt )(\S+)", re.I), False),
    (re.compile(r"^(\s*ip nhrp authentication )(\S+)", re.I), False),
]

# SNMPv3 users carry two secrets (auth and priv); handled separately.
_SNMP_USER = re.compile(r"^(\s*snmp-server user .*)$", re.I)
_SNMP_V3_SECRET = re.compile(r"\b((?:auth (?:md5|sha\S*)|priv (?:des|3des|aes(?: \d+)?)) )(\S+)", re.I)

# Fallback: any token following `password` or `secret`, optionally with a type digit.
# Covers enable/username/line passwords, BGP neighbor passwords, PPP, etc.
_GENERIC = re.compile(r"\b((?:password|secret)(?: level \d+)? (?:[0-9] )?)(\S+)", re.I)


def mask_line(line: str) -> str:
    if _SNMP_USER.match(line):
        return _SNMP_V3_SECRET.sub(lambda m: m.group(1) + MASK, line)
    for pattern, is_community in _RULES:
        m = pattern.match(line)
        if m:
            value = m.group(2)
            mask = WEAK_MASK if is_community and value.lower() in DEFAULT_COMMUNITIES else MASK
            return line[: m.start(2)] + mask + line[m.end(2) :]
    return _GENERIC.sub(lambda m: m.group(1) + MASK, line)


def mask_secrets(text: str) -> str:
    """Mask passwords, keys and SNMP communities in multi-line config text."""
    return "\n".join(mask_line(line) for line in text.splitlines())
