# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Nataraj Angappan
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from conftest import BASELINE, FIXTURES
from configguard.context import AuditContext
from configguard.tools.baseline import check_rule, find_config_lines, load_baseline, read_baseline
from configguard.tools.loader import load_config

R01 = FIXTURES / "r01-compliant.cfg"


def _write_baseline(tmp_path: Path, mutate) -> Path:
    data = yaml.safe_load(BASELINE.read_text())
    mutate(data)
    path = tmp_path / "b.yaml"
    path.write_text(yaml.safe_dump(data))
    return path


def test_shipped_baseline_has_all_seed_rules() -> None:
    baseline = read_baseline(BASELINE)
    assert [r.id for r in baseline.rules] == [f"CG-{i:03d}" for i in range(1, 15)]


def test_load_baseline_lists_rules() -> None:
    ctx = AuditContext(R01, BASELINE)
    result = load_baseline(ctx, str(BASELINE))
    assert result["ok"] and result["rule_count"] == 14
    assert result["rules"][0] == {"id": "CG-001", "title": ctx.baseline.rules[0].title, "severity": "critical"}


def test_load_baseline_rejects_other_path(tmp_path: Path) -> None:
    other = tmp_path / "evil.yaml"
    other.write_text("x: 1")
    assert "not the baseline assigned" in load_baseline(AuditContext(R01, BASELINE), str(other))["error"]


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda d: d["rules"].append(dict(d["rules"][0])), "duplicate rule ids"),
        (lambda d: d["rules"][0]["check"].update(type="python", function="nope"), "unknown python check"),
        (lambda d: d["rules"][1]["check"].update(all_of=["(unclosed"]), "invalid baseline"),
        (lambda d: d["rules"][0].update(severity="extreme"), "invalid baseline"),
        (lambda d: d["rules"][0]["check"].pop("parent"), "children_required needs parent"),
        (lambda d: d["rules"][0].update(id="X-1"), "invalid baseline"),
    ],
)
def test_invalid_baselines_are_rejected(tmp_path: Path, mutate, message: str) -> None:
    path = _write_baseline(tmp_path, mutate)
    result = load_baseline(AuditContext(R01, path), str(path))
    assert result["ok"] is False and message in result["error"]


def test_check_rule_preconditions_and_unknown_id() -> None:
    ctx = AuditContext(R01, BASELINE)
    assert "load_config first" in check_rule(ctx, "CG-001")["error"]
    load_config(ctx, str(R01))
    assert "load_baseline first" in check_rule(ctx, "CG-001")["error"]
    load_baseline(ctx, str(BASELINE))
    assert "unknown rule_id" in check_rule(ctx, "CG-999")["error"]
    assert check_rule(ctx, " cg-001 ")["finding"]["rule_id"] == "CG-001"  # normalised
    assert "CG-001" in ctx.findings


def test_find_config_lines_searches_masked_text(fixture_ctx) -> None:
    ctx = fixture_ctx("r01-compliant.cfg")
    result = find_config_lines(ctx, r"^enable secret")
    assert result["matches"] == [{"line_number": 15, "text": "enable secret 9 <MASKED>"}]
    # probing for the secret value itself must find nothing
    assert find_config_lines(ctx, r"\$9\$kT7m")["match_count"] == 0


def test_find_config_lines_bad_input(fixture_ctx) -> None:
    ctx = fixture_ctx("r01-compliant.cfg")
    assert "invalid regex" in find_config_lines(ctx, "(")["error"]
    assert "longer than" in find_config_lines(ctx, "a" * 500)["error"]
    big = find_config_lines(ctx, ".")
    assert big["truncated"] and len(big["matches"]) == 50
