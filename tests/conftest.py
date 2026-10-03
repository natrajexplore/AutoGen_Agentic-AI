from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from configguard.context import AuditContext
from configguard.tools.baseline import load_baseline
from configguard.tools.loader import load_config

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
BASELINE = ROOT / "baselines" / "cisco_ios_v1.yaml"
EXPECTED = json.loads((FIXTURES / "expected_results.json").read_text(encoding="utf-8"))
FIXTURE_NAMES = sorted(EXPECTED["devices"])


def loaded_ctx(config: Path, baseline: Path = BASELINE) -> AuditContext:
    ctx = AuditContext(config_path=config, baseline_path=baseline)
    assert load_config(ctx, str(config))["ok"]
    assert load_baseline(ctx, str(baseline))["ok"]
    return ctx


@pytest.fixture
def fixture_ctx() -> Callable[[str], AuditContext]:
    """Loaded context for one of the tests/fixtures configs."""
    return lambda name: loaded_ctx(FIXTURES / name)


@pytest.fixture
def text_ctx(tmp_path: Path) -> Callable[[str], AuditContext]:
    """Loaded context for an inline config snippet."""

    def make(text: str) -> AuditContext:
        path = tmp_path / "snippet.cfg"
        path.write_text(text.strip("\n") + "\n", encoding="utf-8")
        return loaded_ctx(path)

    return make
