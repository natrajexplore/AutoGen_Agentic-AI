# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Nataraj Angappan
"""Pause/resume: checkpoint the AuditContext record plus AutoGen team state to state/<audit_id>.json.

Raw config text is never written. On resume the config is re-read from disk and must match the
recorded hash, so a resumed audit cannot silently continue against a changed file.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from configguard.context import AuditContext
from configguard.tools.baseline import load_baseline
from configguard.tools.loader import load_config
from configguard.tools.parser import parse_ios_config

_AUDIT_ID = re.compile(r"^[0-9a-f]{12}$")


def checkpoint_path(state_dir: Path, audit_id: str) -> Path:
    if not _AUDIT_ID.match(audit_id):
        raise ValueError(f"invalid audit id {audit_id!r}")
    return state_dir / f"{audit_id}.json"


def save_checkpoint(state_dir: Path, ctx: AuditContext, team_state: Any, status: str) -> Path:
    state_dir.mkdir(parents=True, exist_ok=True)
    path = checkpoint_path(state_dir, ctx.audit_id)
    payload = {"status": status, "context": ctx.to_dict(), "team": team_state}
    path.write_text(json.dumps(payload, default=str, indent=1), encoding="utf-8")
    return path


def update_context(state_dir: Path, ctx: AuditContext) -> None:
    """Rewrite the context part of an existing checkpoint (e.g. after human review)."""
    path = checkpoint_path(state_dir, ctx.audit_id)
    payload = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {"status": "reviewed", "team": None}
    payload["context"] = ctx.to_dict()
    state_dir.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, default=str, indent=1), encoding="utf-8")


def load_checkpoint(state_dir: Path, audit_id: str) -> tuple[AuditContext, Any, str]:
    path = checkpoint_path(state_dir, audit_id)
    if not path.is_file():
        raise FileNotFoundError(f"no saved audit {audit_id} in {state_dir}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    ctx = AuditContext.from_dict(payload["context"])
    rehydrate(ctx)
    return ctx, payload["team"], payload["status"]


def rehydrate(ctx: AuditContext) -> None:
    """Rebuild in-memory config, inventory and baseline for a restored context."""
    for result in (
        load_config(ctx, str(ctx.config_path)),
        load_baseline(ctx, str(ctx.baseline_path)),
        parse_ios_config(ctx),
    ):
        if not result["ok"]:
            raise RuntimeError(f"cannot resume audit {ctx.audit_id}: {result['error']}")
