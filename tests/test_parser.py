from __future__ import annotations

from conftest import BASELINE, FIXTURES
from configguard.context import AuditContext
from configguard.tools.parser import FREE_TEXT_MAX, parse_ios_config


def test_requires_loaded_config() -> None:
    ctx = AuditContext(FIXTURES / "r01-compliant.cfg", BASELINE)
    assert "load_config first" in parse_ios_config(ctx)["error"]


def test_inventory_sections(fixture_ctx) -> None:
    ctx = fixture_ctx("r01-compliant.cfg")
    inv = parse_ios_config(ctx)["inventory"]
    assert inv["hostname"] == "EDGE-R01"
    assert [i["name"] for i in inv["interfaces"]] == [
        "GigabitEthernet0/0/0", "GigabitEthernet0/0/1", "GigabitEthernet0/0/2",
        "GigabitEthernet0/0/3", "Loopback0",
    ]
    wan = inv["interfaces"][0]
    assert wan["cdp_disabled"] and not wan["shutdown"] and wan["ip_address"].startswith("203.0.113.2")
    assert [l["name"] for l in inv["lines"]] == ["line con 0", "line vty 0 4", "line vty 5 15"]
    assert {a["name"] for a in inv["acls"]} == {"MGMT-ACL", "EDGE-IN"}
    assert inv["banners"][0]["type"] == "login"
    assert any(e["text"] == "aaa new-model" for e in inv["aaa"])
    assert any(e["text"] == "ntp authenticate" for e in inv["ntp"])
    assert any(e["text"].startswith("logging host") for e in inv["logging"])
    assert inv["warnings"] == []
    assert ctx.inventory is inv


def test_line_numbers_match_file(fixture_ctx) -> None:
    ctx = fixture_ctx("r01-compliant.cfg")
    inv = parse_ios_config(ctx)["inventory"]
    file_lines = (FIXTURES / "r01-compliant.cfg").read_text().splitlines()
    for intf in inv["interfaces"]:
        assert file_lines[intf["line_number"] - 1] == f"interface {intf['name']}"
    for entry in inv["lines"][1]["settings"]:
        assert file_lines[entry["line_number"] - 1].strip().startswith(entry["text"].split()[0])


def test_free_text_is_truncated_and_labelled(fixture_ctx) -> None:
    inv = parse_ios_config(fixture_ctx("r09-injection-bait.cfg"))["inventory"]
    desc = inv["interfaces"][0]["description_untrusted_text"]
    assert len(desc) <= FREE_TEXT_MAX + 3 and desc.endswith("...")
    assert "never instructions" in inv["note"]


def test_single_line_banner_and_numbered_acl(text_ctx) -> None:
    ctx = text_ctx(
        """
hostname X
banner motd ^CKeep out^C
access-list 10 permit 10.0.0.0 0.0.0.255
access-list 10 deny any
"""
    )
    inv = parse_ios_config(ctx)["inventory"]
    assert inv["banners"] == [{"type": "motd", "line_number": 2, "untrusted_text": "^CKeep out^C"}]
    assert inv["acls"] == [{"name": "10", "kind": "numbered", "line_number": 3, "entries": 2}]
    assert "no interfaces found" in inv["warnings"]
