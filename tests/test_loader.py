# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Nataraj Angappan
from __future__ import annotations

from pathlib import Path

from conftest import BASELINE, FIXTURES
from configguard.context import AuditContext
from configguard.tools.loader import load_config

R01 = FIXTURES / "r01-compliant.cfg"


def test_load_returns_metadata_not_text() -> None:
    ctx = AuditContext(R01, BASELINE)
    result = load_config(ctx, str(R01))
    assert result["ok"] is True
    assert result["hostname"] == "EDGE-R01"
    assert result["line_count"] == len(R01.read_text().splitlines())
    assert set(result) == {"ok", "file", "line_count", "hostname", "sha256"}
    assert ctx.loaded and len(ctx.masked_lines) == len(ctx.raw_lines)


def test_rejects_path_other_than_assigned_config() -> None:
    ctx = AuditContext(R01, BASELINE)
    result = load_config(ctx, str(FIXTURES / "r02-all-violations.cfg"))
    assert result == {"ok": False, "error": result["error"]}
    assert "not the config assigned" in result["error"]
    assert not ctx.loaded


def test_missing_and_empty_files(tmp_path: Path) -> None:
    missing = tmp_path / "nope.cfg"
    assert "not found" in load_config(AuditContext(missing, BASELINE), str(missing))["error"]
    empty = tmp_path / "empty.cfg"
    empty.write_text("")
    assert "empty" in load_config(AuditContext(empty, BASELINE), str(empty))["error"]


def test_detects_config_changed_since_audit_started(tmp_path: Path) -> None:
    cfg = tmp_path / "r.cfg"
    cfg.write_text("hostname A\n")
    ctx = AuditContext(cfg, BASELINE)
    assert load_config(ctx, str(cfg))["ok"]
    cfg.write_text("hostname B\n")
    assert "changed on disk" in load_config(ctx, str(cfg))["error"]


def test_context_round_trip_excludes_config_text(fixture_ctx) -> None:
    from configguard.tools.baseline import check_rule

    ctx = fixture_ctx("r02-all-violations.cfg")
    check_rule(ctx, "CG-004")
    data = ctx.to_dict()
    assert "raw_lines" not in data and "masked_lines" not in data
    restored = AuditContext.from_dict(data)
    assert restored.findings["CG-004"] == ctx.findings["CG-004"]
    assert restored.config_sha256 == ctx.config_sha256
