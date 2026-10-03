"""Accuracy against tests/fixtures/expected_results.json (success criteria 1 and 2).

The deterministic tier needs no LLM. The `llm` tier (Phase 3) runs the full agent team.
"""

from __future__ import annotations

import pytest

from conftest import EXPECTED, FIXTURE_NAMES, FIXTURES
from configguard.tools.baseline import check_rule
from configguard.tools.masking import mask_line


def test_fixture_set_meets_spec() -> None:
    devices = EXPECTED["devices"]
    assert len(devices) == 10
    verdicts = [set(d["expected"].values()) for d in devices.values()]
    assert {"PASS"} in verdicts, "need a fully compliant config"
    assert any(all(v == "FAIL" for v in d["expected"].values()) for d in devices.values()), "need an all-14 config"
    for rule_id in devices[FIXTURE_NAMES[0]]["expected"]:
        fails = [n for n, d in devices.items() if d["expected"][rule_id] == "FAIL"]
        assert len(fails) >= 2, f"{rule_id} should fail in more than just the all-violations config"


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_rule_engine_matches_ground_truth(fixture_ctx, name: str) -> None:
    ctx = fixture_ctx(name)
    expected = EXPECTED["devices"][name]["expected"]
    got = {rule_id: check_rule(ctx, rule_id)["finding"]["status"] for rule_id in expected}
    mismatches = {r: (expected[r], got[r]) for r in expected if expected[r] != got[r]}
    assert not mismatches, f"(expected, got): {mismatches}"


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_every_fail_cites_real_config_lines(fixture_ctx, name: str) -> None:
    """Zero hallucination: each evidence line exists verbatim (masked) at the cited line number."""
    ctx = fixture_ctx(name)
    file_lines = (FIXTURES / name).read_text(encoding="utf-8").splitlines()
    for rule in ctx.baseline.rules:
        finding = check_rule(ctx, rule.id)["finding"]
        if finding["status"] == "FAIL":
            assert finding["evidence"] or finding["missing"], rule.id
        for ev in finding["evidence"]:
            assert mask_line(file_lines[ev["line_number"] - 1].rstrip()) == ev["text"], (rule.id, ev)


def test_overall_score() -> None:
    """Single headline number: detection rate of seeded violations and false-positive count."""
    from conftest import loaded_ctx

    seeded = detected = false_pos = 0
    for name, device in EXPECTED["devices"].items():
        ctx = loaded_ctx(FIXTURES / name)
        for rule_id, want in device["expected"].items():
            got = check_rule(ctx, rule_id)["finding"]["status"]
            seeded += want == "FAIL"
            detected += want == "FAIL" and got == "FAIL"
            false_pos += want != "FAIL" and got == "FAIL"
    assert (detected, false_pos) == (seeded, 0), f"detected {detected}/{seeded}, false positives {false_pos}"


# --------------------------------------------------------------------------- live multi-agent tier


@pytest.mark.llm
@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_full_agent_audit(name: str) -> None:
    """Success criteria 1-4 end to end: verdicts, evidence, valid remediation, < 90 s."""
    import asyncio
    import os

    from conftest import BASELINE
    from configguard.config.model_client import build_model_client
    from configguard.config.settings import Settings
    from configguard.context import AuditContext
    from configguard.team import build_team, run_audit
    from configguard.tools.ios_syntax import validate_ios_syntax

    settings = Settings.from_env()
    if settings.model_provider == "openai" and not os.getenv("OPENAI_API_KEY"):
        pytest.skip("OPENAI_API_KEY not set")

    async def go():
        client = build_model_client(settings)
        try:
            ctx = AuditContext(FIXTURES / name, BASELINE)
            team = build_team(ctx, client, settings.max_messages)
            outcome = await run_audit(ctx, team, console=False)
            return ctx, outcome, outcome.usage
        finally:
            await client.close()

    ctx, outcome, usage = asyncio.run(go())
    print(f"\n{name}: approved={outcome.approved} {outcome.duration_s:.1f}s "
          f"tokens={usage.prompt_tokens}+{usage.completion_tokens} stop={outcome.stop_reason!r}")

    expected = EXPECTED["devices"][name]["expected"]
    got = {r: ctx.findings[r].status if r in ctx.findings else None for r in expected}
    assert got == expected
    assert outcome.gaps == [], outcome.gaps
    assert outcome.approved, f"not approved: stop={outcome.stop_reason}"
    for rem in ctx.remediations.values():
        assert validate_ios_syntax(rem.commands)["valid"], rem
    assert outcome.duration_s < 90
