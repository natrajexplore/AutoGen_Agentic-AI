"""Device facts read from a running config: software version, platform, inventory counts.

Facts are descriptive only (no secrets): they appear in report headers, the UI and the dashboard,
like the device-information section of a professional audit report.
"""

from __future__ import annotations

import re
from typing import Any

_PHYSICAL = re.compile(r"^interface ((Gigabit|TenGigabit|TwentyFiveGig|FortyGigabit|HundredGig|Fast)?Ethernet|Serial|AppGigabitEthernet)", re.I)
_VIRTUAL = re.compile(r"^interface (Loopback|Vlan|Tunnel|Port-channel|BDI|Dialer|Virtual-Template)", re.I)
_VTY = re.compile(r"^line vty (\d+)(?: (\d+))?$", re.I)
_ROUTING = re.compile(r"^router (ospf|ospfv3|bgp|eigrp|isis|rip)\b", re.I)


def device_facts(raw_lines: list[str]) -> dict[str, Any]:
    tops = [line.rstrip() for line in raw_lines if line and not line[0].isspace() and not line.startswith("!")]

    def first(pattern: str, group: int = 1) -> str | None:
        rx = re.compile(pattern, re.I)
        return next((m.group(group) for line in tops if (m := rx.match(line))), None)

    interfaces = [line for line in tops if line.lower().startswith("interface ")]
    shut = 0
    current = None
    for line in raw_lines:
        if line.lower().startswith("interface "):
            current = line
        elif not line.startswith(" "):
            current = None
        elif current and line.strip() == "shutdown":
            shut += 1
    vty = 0
    for line in tops:
        if m := _VTY.match(line):
            a, b = int(m.group(1)), int(m.group(2) or m.group(1))
            vty += b - a + 1
    snmp = (
        "v3" if any(re.match(r"^snmp-server group \S+ v3", line, re.I) for line in tops)
        else "v1/v2c" if any(re.match(r"^snmp-server (community|host)", line, re.I) for line in tops)
        else "disabled"
    )
    return {
        "hostname": first(r"^hostname (\S+)"),
        "software_version": first(r"^version (\S+)"),
        "platform": first(r"^license udi pid (\S+)"),
        "serial_number": first(r"^license udi pid \S+ sn (\S+)"),
        "boot_image": first(r"^boot system (?:\S+:)?(\S+)"),
        "config_lines": len(raw_lines),
        "interfaces": {
            "physical": sum(1 for i in interfaces if _PHYSICAL.match(i)),
            "virtual": sum(1 for i in interfaces if _VIRTUAL.match(i)),
            "shutdown": shut,
        },
        "vty_lines": vty,
        "local_users": sum(1 for line in tops if line.lower().startswith("username ")),
        "acls": len({line.split()[-1] for line in tops if line.lower().startswith("ip access-list ")})
        + len({line.split()[1] for line in tops if line.lower().startswith("access-list ")}),
        "routing_protocols": sorted({m.group(1).lower() for line in tops if (m := _ROUTING.match(line))}),
        "aaa": any(line.lower() == "aaa new-model" for line in tops),
        "snmp": snmp,
    }
