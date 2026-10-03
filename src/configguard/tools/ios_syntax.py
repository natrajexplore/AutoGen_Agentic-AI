"""Remediation tools: validate_ios_syntax, lockout detection, record_remediation.

validate_ios_syntax is a BEST-EFFORT keyword grammar, not a real IOS parser. It checks
mode order (explicit sub-mode entry/exit), known command verbs per mode, argument shape for
the commands this baseline remediates, and that secrets are placeholders, not values.
"""

from __future__ import annotations

import re
from typing import Any

from configguard.context import AuditContext
from configguard.models import Remediation
from configguard.tools.loader import error
from configguard.tools.masking import mask_line

MAX_COMMANDS = 60
MAX_COMMAND_LEN = 255
PLACEHOLDER = re.compile(r"<[A-Z0-9_]+>")
LOCKOUT_MARKER = "LOCKOUT WARNING"

_FORBIDDEN = re.compile(
    r"^(do |configure |conf t|reload|write|wr\b|copy |erase |delete |format |debug |undebug |"
    r"clear |show |crypto key zeroize|end$)",
    re.I,
)
_INTERFACE_NAME = re.compile(
    r"^interface ((?:Gigabit|TenGigabit|TwentyFiveGig|FortyGigabit|HundredGig|Fast)?Ethernet|"
    r"Gi|Te|Fa|Loopback|Vlan|Port-channel|Tunnel|Serial|Dialer|BDI|GigabitEthernet|AppGigabitEthernet)"
    r"\s?[\d/.:]+$",
    re.I,
)
_LINE_NAME = re.compile(r"^line (con 0|aux 0|vty \d+(?: \d+)?)$", re.I)
_ACL_MODE = re.compile(r"^ip access-list (standard|extended) \S+$", re.I)
_LOG_LEVELS = r"(emergencies|alerts|critical|errors|warnings|notifications|informational|debugging|[0-7])"

GLOBAL_VERBS = {
    "no", "service", "ip", "ipv6", "aaa", "snmp-server", "ntp", "logging", "enable", "username",
    "line", "interface", "banner", "hostname", "cdp", "lldp", "access-list", "crypto", "login",
    "security", "key", "tacacs", "radius", "tacacs-server", "radius-server", "archive", "exit",
    "spanning-tree", "clock", "router", "control-plane", "errdisable", "vtp", "file", "scheduler",
}
MODE_VERBS = {
    "line": {
        "no", "transport", "exec-timeout", "access-class", "ipv6", "login", "password", "logging",
        "privilege", "session-timeout", "absolute-timeout", "exec", "authorization", "accounting",
        "history", "escape-character", "motd-banner", "length", "width", "stopbits", "exit",
    },
    "interface": {
        "no", "description", "ip", "ipv6", "shutdown", "cdp", "lldp", "switchport", "speed", "duplex",
        "negotiation", "mtu", "bandwidth", "channel-group", "spanning-tree", "standby", "vrrp",
        "encapsulation", "service-policy", "load-interval", "storm-control", "logging", "exit",
    },
    "acl": {"no", "permit", "deny", "remark", "exit"},
}
# Sub-mode commands that must never appear at global level.
SUBMODE_ONLY = re.compile(
    r"^(no )?(transport input|exec-timeout|access-class|login( local| authentication)?$|"
    r"description |shutdown$|cdp enable|switchport |permit |deny |remark )",
    re.I,
)
# Argument-shape checks for commands this baseline remediates.
ARG_CHECKS: list[tuple[re.Pattern[str], re.Pattern[str], str]] = [
    (re.compile(r"^transport input\b", re.I),
     re.compile(r"^transport input (ssh|none|telnet ssh|ssh telnet|all|telnet)$", re.I), "transport input <ssh|none|...>"),
    (re.compile(r"^exec-timeout\b", re.I), re.compile(r"^exec-timeout \d{1,5}( \d{1,7})?$", re.I), "exec-timeout <min> [sec]"),
    (re.compile(r"^ip ssh version\b", re.I), re.compile(r"^ip ssh version [12]$", re.I), "ip ssh version <1|2>"),
    (re.compile(r"^(no )?ip http\b", re.I),
     re.compile(r"^(no )?ip http (server|secure-server|authentication \S+|access-class \S+|max-connections \d+)$", re.I),
     "[no] ip http <server|secure-server|...>"),
    (re.compile(r"^access-class\b", re.I), re.compile(r"^access-class \S+ (in|out)( vrf-also)?$", re.I), "access-class <acl> in [vrf-also]"),
    (re.compile(r"^logging trap\b", re.I), re.compile(rf"^logging trap {_LOG_LEVELS}$", re.I), "logging trap <level>"),
    (re.compile(r"^logging host\b", re.I), re.compile(r"^logging host (\S+)( .+)?$", re.I), "logging host <ip|PLACEHOLDER>"),
    (re.compile(r"^ntp server\b", re.I), re.compile(r"^ntp server (vrf \S+ )?\S+( key \S+)?( prefer)?( source \S+)?$", re.I),
     "ntp server <ip> [key <id>] [prefer]"),
    (re.compile(r"^ntp authentication-key\b", re.I), re.compile(r"^ntp authentication-key \S+ (md5|sha1|sha2|hmac-sha2-256) \S+( \d)?$", re.I),
     "ntp authentication-key <id> md5 <key>"),
    (re.compile(r"^ntp trusted-key\b", re.I), re.compile(r"^ntp trusted-key \S+$", re.I), "ntp trusted-key <id>"),
    (re.compile(r"^enable secret\b", re.I), re.compile(r"^enable secret (level \d+ )?(\d )?\S+$", re.I), "enable secret <secret>"),
    (re.compile(r"^aaa authentication login\b", re.I),
     re.compile(r"^aaa authentication login \S+ (local|local-case|group \S+|enable|line|none)( (local|local-case|group \S+|enable|line|none))*$", re.I),
     "aaa authentication login <list> <method> [<method> ...]"),
]


def _verb(cmd: str) -> str:
    parts = cmd.split()
    if parts[0].lower() == "no" and len(parts) > 1:
        return parts[1].lower()
    return parts[0].lower()


def validate_ios_syntax(commands: list[str]) -> dict[str, Any]:
    """Best-effort syntax and mode-order check for IOS config-mode commands."""
    errors: list[str] = []
    if not commands:
        return {"ok": True, "valid": False, "errors": ["no commands supplied"], "placeholders": []}
    if len(commands) > MAX_COMMANDS:
        errors.append(f"more than {MAX_COMMANDS} commands")

    mode = "global"  # global | line | interface | acl | other
    banner_delim: str | None = None
    placeholders: set[str] = set()

    for i, raw in enumerate(commands, start=1):
        cmd = raw.strip()
        where = f"command {i} {cmd!r}"
        if banner_delim is not None:  # inside a multi-line banner body
            if banner_delim in cmd:
                banner_delim = None
            continue
        if not cmd:
            errors.append(f"command {i} is empty")
            continue
        if len(cmd) > MAX_COMMAND_LEN or re.search(r"[\x00-\x1f\x7f]", cmd) or not cmd.isascii():
            errors.append(f"{where}: too long, or contains control/non-ASCII characters")
            continue
        placeholders.update(PLACEHOLDER.findall(cmd))
        if "<MASKED" in cmd.upper():
            errors.append(f"{where}: masked values cannot be used in commands; use a placeholder like <CURRENT_COMMUNITY>")
            continue
        if _FORBIDDEN.match(cmd):
            errors.append(f"{where}: exec-mode or destructive commands are not allowed in remediation")
            continue
        if mask_line(cmd) != cmd and not PLACEHOLDER.search(cmd):
            errors.append(f"{where}: secret values must be placeholders like <STRONG_SECRET>")

        if cmd.lower() == "exit":
            if mode == "global":
                errors.append(f"{where}: 'exit' at global config level")
            mode = "global"
            continue

        if mode == "global":
            verb = _verb(cmd)
            if SUBMODE_ONLY.match(cmd):
                errors.append(f"{where}: sub-mode command used at global level (enter 'line'/'interface'/ACL first)")
            elif verb not in GLOBAL_VERBS:
                errors.append(f"{where}: unrecognised global command '{verb}'")
            if cmd.lower().startswith("interface "):
                if not _INTERFACE_NAME.match(cmd) and not PLACEHOLDER.search(cmd):
                    errors.append(f"{where}: unrecognised interface name")
                mode = "interface"
            elif cmd.lower().startswith("line "):
                if not _LINE_NAME.match(cmd):
                    errors.append(f"{where}: expected 'line con 0', 'line aux 0' or 'line vty <a> [b]'")
                mode = "line"
            elif cmd.lower().startswith("ip access-list "):
                if not _ACL_MODE.match(cmd):
                    errors.append(f"{where}: expected 'ip access-list <standard|extended> <name>'")
                mode = "acl"
            elif re.match(r"^(router |key chain |tacacs server |radius server |aaa group server |control-plane)", cmd, re.I):
                mode = "other"  # not modelled: contents accepted without verb checks
            elif cmd.lower().startswith("banner "):
                m = re.match(r"^banner (login|motd|exec) (\S)(.*)$", cmd, re.I)
                if not m:
                    errors.append(f"{where}: expected 'banner <login|motd|exec> <delim>text<delim>'")
                elif m.group(2) not in m.group(3):
                    banner_delim = m.group(2)  # body continues on following lines
        elif mode in MODE_VERBS:
            seq_stripped = re.sub(r"^\d+ ", "", cmd) if mode == "acl" else cmd
            verb = _verb(seq_stripped)
            if verb not in MODE_VERBS[mode]:
                if verb in GLOBAL_VERBS:
                    errors.append(f"{where}: global command inside '{mode}' mode; add 'exit' first")
                else:
                    errors.append(f"{where}: unrecognised command '{verb}' in '{mode}' mode")
            cmd = seq_stripped

        for selector, shape, usage in ARG_CHECKS:
            if selector.match(cmd) and not shape.match(PLACEHOLDER.sub("X", cmd)):
                errors.append(f"{where}: malformed, expected {usage}")

    if banner_delim is not None:
        errors.append("banner body is not closed by its delimiter")
    if mode != "global":
        errors.append(f"commands end inside '{mode}' mode; finish with 'exit'")
    return {"ok": True, "valid": not errors, "errors": errors, "placeholders": sorted(placeholders)}


def lockout_risks(ctx: AuditContext, commands: list[str]) -> list[str]:
    """Return management-access risks in these commands that require a LOCKOUT WARNING."""
    risks: list[str] = []
    raw = [line.strip() for line in ctx.raw_lines]
    has_users = any(line.startswith("username ") for line in raw) or any(
        c.strip().startswith("username ") for c in commands
    )
    defined_acls = {line.split()[-1] for line in raw if line.startswith("ip access-list ")}
    defined_acls |= {line.split()[1] for line in raw if line.startswith("access-list ")}
    defined_acls |= {c.split()[-1] for c in commands if c.strip().startswith("ip access-list ")}
    ip_interfaces = set()
    current = None
    for line in ctx.raw_lines:
        if line.startswith("interface "):
            current = line.strip()
        elif not line.startswith(" "):
            current = None
        elif current and line.strip().startswith("ip address "):
            ip_interfaces.add(current.lower())

    section = None
    for c in commands:
        cmd = c.strip()
        low = cmd.lower()
        if not c.startswith(" ") and re.match(r"^(line|interface) ", low):
            section = low
        elif low == "exit":
            section = None
        if low.startswith("transport input") and section and section.startswith("line vty"):
            risks.append(f"'{cmd}' under {section} changes how remote sessions can connect")
        if low.startswith("access-class") and section and section.startswith("line vty"):
            acl = cmd.split()[1]
            note = "" if acl in defined_acls or PLACEHOLDER.match(acl) else f" (ACL '{acl}' is not defined)"
            risks.append(f"'{cmd}' restricts which hosts can reach the vty lines{note}")
        if low == "no aaa new-model":
            risks.append("'no aaa new-model' changes every login method on the device")
        if low == "aaa new-model" and not has_users:
            risks.append("'aaa new-model' with no local usernames can block all logins")
        if low.startswith("aaa authentication login") and " local" not in low:
            risks.append(f"'{cmd}' has no 'local' fallback if the AAA servers are unreachable")
        if low == "login local" and not has_users:
            risks.append("'login local' with no local usernames blocks logins on that line")
        if low.startswith("no username") or low.startswith("no ip ssh"):
            risks.append(f"'{cmd}' removes an existing access path")
        if low == "shutdown" and section and section in ip_interfaces:
            risks.append(f"'shutdown' on {section}, which has an IP address and may carry management traffic")
    return risks


def record_remediation(
    ctx: AuditContext, rule_id: str, risk_summary: str, commands: list[str], warnings: list[str]
) -> dict[str, Any]:
    """Validate and store a remediation for one FAIL finding."""
    rule_id = rule_id.strip().upper()
    finding = ctx.findings.get(rule_id)
    if finding is None:
        return error(f"no finding for {rule_id}; run check_rule first")
    if finding.status != "FAIL":
        return error(f"{rule_id} is {finding.status}; remediation is only for FAIL findings")
    if not risk_summary.strip():
        return error("risk_summary is required")

    result = validate_ios_syntax(commands)
    problems = list(result["errors"])

    risks = lockout_risks(ctx, commands)
    rule = ctx.baseline.rule(rule_id) if ctx.baseline else None
    if rule and rule.lockout_risk and not risks:
        risks.append(f"{rule_id} is marked as a lockout-risk rule in the baseline")
    has_marker = any(LOCKOUT_MARKER in w.upper() for w in warnings)
    if risks and not has_marker:
        problems.append(
            f"add a warning starting with '{LOCKOUT_MARKER}:' that names a recovery path "
            f"(e.g. console access). Risks found: {risks}"
        )
    if not result["errors"]:
        from configguard.tools.simulate import verify_fix  # local import: simulate imports this module

        still_failing = verify_fix(ctx, rule_id, commands)
        if still_failing is not None:
            leftovers = [f"line {e.line_number}: {e.text.strip()}" for e in still_failing.evidence]
            problems.append(
                "after applying these commands the rule would still FAIL. "
                f"Remaining evidence: {leftovers}; still missing: {still_failing.missing}"
            )
    if problems:
        return {"ok": False, "recorded": False, "errors": problems}

    ctx.remediations[rule_id] = Remediation(
        rule_id=rule_id, risk_summary=risk_summary.strip(), commands=[c.rstrip() for c in commands], warnings=warnings
    )
    return {"ok": True, "recorded": True, "lockout_risks": risks, "placeholders": result["placeholders"]}
