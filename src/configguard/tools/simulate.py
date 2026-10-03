# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Nataraj Angappan
"""Apply remediation commands to an in-memory copy of a config, approximating IOS semantics.

Used to verify that a remediation actually resolves its finding: the rule is re-evaluated on the
patched copy. This is a model of IOS behaviour, not an emulator. Sub-mode commands with the same
keyword replace each other; `no X` removes matching lines; `line vty a b` applies to every
existing vty block it overlaps; placeholders in `no` commands match any value.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from configguard.context import AuditContext
from configguard.models import Finding
from configguard.tools.ios_syntax import PLACEHOLDER

_ABBREV = {
    "gi": "GigabitEthernet", "te": "TenGigabitEthernet", "fa": "FastEthernet",
    "lo": "Loopback", "po": "Port-channel", "tu": "Tunnel", "vl": "Vlan", "se": "Serial",
}
_TWO_TOKEN_KEYS = {"ip", "ipv6", "transport", "switchport", "spanning-tree", "service-policy", "storm-control"}
_GLOBAL_SINGLETONS = ("ip ssh version", "logging trap", "hostname", "ip domain name", "enable secret")
_SUBMODE_ENTRY = re.compile(r"^(line |interface |ip access-list |router |key chain |tacacs server |radius server )", re.I)


@dataclass
class Block:
    text: str
    children: list[str] = field(default_factory=list)


def _canon_interface(text: str) -> str:
    m = re.match(r"^interface ([A-Za-z-]+)\s*([\d/.:]+)$", text.strip(), re.I)
    if not m:
        return text.strip()
    name = m.group(1)
    full = next((v for k, v in _ABBREV.items() if name.lower() == k), name)
    for v in _ABBREV.values():
        if v.lower() == name.lower():
            full = v
    return f"interface {full}{m.group(2)}"


def _vty_range(text: str) -> tuple[int, int] | None:
    m = re.match(r"^line vty (\d+)(?: (\d+))?$", text.strip(), re.I)
    if not m:
        return None
    a = int(m.group(1))
    return a, int(m.group(2) or a)


def _parse(lines: list[str]) -> list[Block]:
    blocks: list[Block] = []
    for line in lines:
        if not line.strip() or line.lstrip().startswith("!"):
            continue
        if blocks and blocks[-1].text.lower().startswith("banner ") and _in_banner(blocks[-1]):
            blocks[-1].children.append(line.rstrip())  # banner bodies are not indented
        elif line[0].isspace() and blocks:
            blocks[-1].children.append(line.strip())
        else:
            blocks.append(Block(line.strip()))
    return blocks


def _in_banner(block: Block) -> bool:
    """True while a multi-line banner block is still waiting for its closing delimiter."""
    m = re.match(r"^banner \S+ (\S)(.*)$", block.text)
    if not m or m.group(1) in m.group(2):
        return False
    return not any(m.group(1) in c for c in block.children)


def _key(cmd: str) -> str:
    tokens = cmd.lower().split()
    return " ".join(tokens[:2]) if tokens[0] in _TWO_TOKEN_KEYS and len(tokens) > 1 else tokens[0]


def _matcher(prefix: str) -> re.Pattern[str]:
    """Regex for lines starting with `prefix`; placeholders match any single token."""
    parts = [r"\S+" if PLACEHOLDER.fullmatch(tok) else re.escape(tok) for tok in prefix.split()]
    return re.compile(r"^" + r"\s+".join(parts) + r"(\s|$)", re.I)


def _apply_line(lines: list[str], cmd: str, *, replace_key: bool) -> list[str]:
    if cmd.lower().startswith("no "):
        target = _matcher(cmd[3:])
        kept = [line for line in lines if not target.match(line)]
        return kept if cmd in kept else kept + [cmd]
    kept = [line for line in lines if line.lower() != f"no {cmd.lower()}"]
    if replace_key:
        kept = [line for line in kept if line.lower().startswith("no ") or _key(line) != _key(cmd)]
    return kept if cmd in kept else kept + [cmd]


def apply_commands(raw_lines: list[str], commands: list[str]) -> list[str]:
    blocks = _parse(raw_lines)
    targets: list[Block] | None = None  # blocks the current sub-mode applies to
    banner: Block | None = None
    for raw in commands:
        cmd = raw.strip()
        if banner is not None:
            banner.children.append(cmd)
            if not _in_banner(banner):
                banner = None
            continue
        if not cmd:
            continue
        if cmd.lower() == "exit":
            targets = None
            continue
        if targets is None and _SUBMODE_ENTRY.match(cmd):
            targets = _enter(blocks, cmd)
            continue
        if targets is not None:
            for block in targets:
                multi = block.text.lower().startswith("ip access-list ")
                block.children = _apply_line(block.children, cmd, replace_key=not multi)
            continue
        if cmd.lower().startswith("banner "):
            blocks = [b for b in blocks if b.text.split()[:2] != cmd.split()[:2]]
            new = Block(cmd)
            blocks.append(new)
            banner = new if _in_banner(new) else None
            continue
        tops = [b.text for b in blocks]
        if cmd.lower().startswith("no ") and _SUBMODE_ENTRY.match(cmd[3:]):
            target = _matcher(cmd[3:])
            blocks = [b for b in blocks if not target.match(b.text)]
            continue
        singleton = any(cmd.lower().startswith(s) for s in _GLOBAL_SINGLETONS)
        if singleton:
            prefix = next(s for s in _GLOBAL_SINGLETONS if cmd.lower().startswith(s))
            blocks = [b for b in blocks if not b.text.lower().startswith(prefix)]
            tops = [b.text for b in blocks]
        new_tops = _apply_line(tops, cmd, replace_key=False)
        by_text = {b.text: b for b in blocks}
        blocks = [by_text.get(t) or Block(t) for t in new_tops]
    return _render(blocks)


def _enter(blocks: list[Block], cmd: str) -> list[Block]:
    vty = _vty_range(cmd)
    if vty:
        hits = [b for b in blocks if (r := _vty_range(b.text)) and r[0] <= vty[1] and vty[0] <= r[1]]
        if hits:
            return hits
    canon = _canon_interface(cmd) if cmd.lower().startswith("interface ") else cmd
    for b in blocks:
        text = _canon_interface(b.text) if b.text.lower().startswith("interface ") else b.text
        if text.lower() == canon.lower():
            return [b]
    new = Block(canon)
    blocks.append(new)
    return [new]


def verify_fix(ctx: AuditContext, rule_id: str, commands: list[str]) -> Finding | None:
    """Re-evaluate the rule on a patched copy of the config. Returns the finding if it still FAILs."""
    from configguard.tools.rule_checks import evaluate

    assert ctx.baseline is not None
    rule = ctx.baseline.rule(rule_id)
    if rule is None:
        return None
    patched = AuditContext(config_path=ctx.config_path, baseline_path=ctx.baseline_path)
    patched.raw_lines = apply_commands(ctx.raw_lines, commands)
    finding = evaluate(patched, rule, ctx.baseline.settings)
    return finding if finding.status == "FAIL" else None


def _render(blocks: list[Block]) -> list[str]:
    # `end` closes a running-config: anything added after it belongs before it
    blocks = [b for b in blocks if b.text.lower() != "end"] + [b for b in blocks if b.text.lower() == "end"]
    out: list[str] = []
    for b in blocks:
        out.append(b.text)
        is_banner = b.text.lower().startswith("banner ")
        out.extend(c if is_banner else f" {c}" for c in b.children)
    return out
