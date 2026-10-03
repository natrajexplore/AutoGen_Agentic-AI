"""Edge cases of the deterministic rule engine, using inline config snippets."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from configguard.models import Finding
from configguard.tools.baseline import check_rule


def status(ctx, rule_id: str) -> str:
    return check_rule(ctx, rule_id)["finding"]["status"]


def test_fail_without_evidence_is_impossible() -> None:
    with pytest.raises(ValidationError, match="must cite evidence"):
        Finding(rule_id="CG-001", title="t", severity="high", status="FAIL", reason="r")


@pytest.mark.parametrize(
    ("transport", "expected"),
    [
        ("transport input ssh", "PASS"),
        ("transport input telnet ssh", "FAIL"),
        ("transport input all", "FAIL"),
        ("transport input telnet", "FAIL"),
        (None, "FAIL"),  # implicit default is not accepted
    ],
)
def test_cg001_transport_variants(text_ctx, transport, expected) -> None:
    body = f" {transport}\n" if transport else ""
    assert status(text_ctx(f"line vty 0 4\n{body}"), "CG-001") == expected


def test_cg001_forbidden_line_is_cited_as_evidence(text_ctx) -> None:
    finding = check_rule(text_ctx("line vty 0 4\n transport input telnet ssh"), "CG-001")["finding"]
    assert {"line_number": 2, "text": " transport input telnet ssh"} in finding["evidence"]


def test_cg001_not_applicable_without_vty(text_ctx) -> None:
    assert status(text_ctx("hostname X"), "CG-001") == "NOT_APPLICABLE"


def test_comments_and_banner_bodies_never_count(text_ctx) -> None:
    ctx = text_ctx(
        """
! ip http server
banner login ^C
ip http server
enable password oops
^C
enable secret 9 abc
"""
    )
    assert status(ctx, "CG-007") == "PASS"
    assert status(ctx, "CG-004") == "PASS"


def test_cg004_enable_password_alongside_secret_fails(text_ctx) -> None:
    finding = check_rule(text_ctx("enable secret 9 abc\nenable password 7 0822"), "CG-004")["finding"]
    assert finding["status"] == "FAIL"
    assert finding["evidence"] == [{"line_number": 2, "text": "enable password 7 <MASKED>"}]


def test_cg006_not_applicable_without_snmp_and_detects_host_community(text_ctx) -> None:
    assert status(text_ctx("hostname X"), "CG-006") == "NOT_APPLICABLE"
    assert status(text_ctx("snmp-server host 10.1.1.1 version 2c private"), "CG-006") == "FAIL"
    assert status(text_ctx("snmp-server host 10.1.1.1 version 3 priv public"), "CG-006") == "PASS"  # v3 username


def test_cg006_v3_only_has_no_advisory(text_ctx) -> None:
    finding = check_rule(text_ctx("snmp-server group G v3 priv"), "CG-006")["finding"]
    assert finding["status"] == "PASS" and "advisory" not in finding


def test_cg009_logging_buffered_is_not_a_remote_host(text_ctx) -> None:
    assert status(text_ctx("logging buffered 4096\nlogging trap informational"), "CG-009") == "FAIL"
    assert status(text_ctx("logging 10.1.1.50\nlogging trap informational"), "CG-009") == "PASS"
    assert status(text_ctx("logging host 10.1.1.50\nlogging trap warnings"), "CG-009") == "FAIL"


@pytest.mark.parametrize(
    ("timeout", "expected"),
    [("exec-timeout 15 0", "PASS"), ("exec-timeout 15 1", "FAIL"), ("exec-timeout 5", "PASS"),
     ("exec-timeout 0 0", "FAIL"), ("exec-timeout 0 30", "PASS"), (None, "FAIL")],
)
def test_cg012_timeout_boundaries(text_ctx, timeout, expected) -> None:
    body = f" {timeout}\n" if timeout else ""
    assert status(text_ctx(f"line con 0\n{body}"), "CG-012") == expected


def test_cg013_external_detection(text_ctx) -> None:
    assert status(text_ctx("interface Gi1\n description LAN"), "CG-013") == "NOT_APPLICABLE"
    assert status(text_ctx("interface Gi1\n description Internet uplink"), "CG-013") == "FAIL"
    assert status(text_ctx("interface Gi1\n description Internet uplink\n no cdp enable"), "CG-013") == "PASS"
    assert status(text_ctx("no cdp run\ninterface Gi1\n description WAN"), "CG-013") == "PASS"


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        (" no ip address", "FAIL"),
        ("", "FAIL"),
        (" no ip address\n shutdown", "PASS"),
        (" description spare", "PASS"),
        (" ip address 10.0.0.1 255.255.255.0", "PASS"),
        (" switchport mode access", "PASS"),
        (" channel-group 1 mode active", "PASS"),
    ],
)
def test_cg014_unused_definition(text_ctx, body, expected) -> None:
    assert status(text_ctx(f"interface Gi1\n{body}"), "CG-014") == expected


def test_cg014_ignores_null_interface(text_ctx) -> None:
    assert status(text_ctx("interface Null0\n no ip unreachables"), "CG-014") == "NOT_APPLICABLE"
    assert status(text_ctx("interface Null0\ninterface Gi1\n shutdown"), "CG-014") == "PASS"
