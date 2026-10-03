"""load_config tool: read a config file into the AuditContext."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from configguard.context import AuditContext, sha256_text
from configguard.tools.masking import mask_line

MAX_CONFIG_BYTES = 2_000_000
_HOSTNAME = re.compile(r"^hostname (\S+)", re.M)


def error(message: str) -> dict[str, Any]:
    """Uniform tool error shape, so agents get a readable message instead of a traceback."""
    return {"ok": False, "error": message}


def load_config(ctx: AuditContext, path: str) -> dict[str, Any]:
    """Load the config assigned to this audit. Returns metadata only, never config text."""
    try:
        requested = Path(path).resolve()
    except (OSError, ValueError) as exc:
        return error(f"invalid path: {exc}")
    # The model only names a path; it may not redirect the tool to any other file.
    if requested != ctx.config_path:
        return error(f"path {path!r} is not the config assigned to this audit")
    if not requested.is_file():
        return error(f"config file not found: {requested.name}")
    if requested.stat().st_size > MAX_CONFIG_BYTES:
        return error(f"config exceeds {MAX_CONFIG_BYTES} bytes")
    if requested.stat().st_size == 0:
        return error("config file is empty")

    text = requested.read_text(encoding="utf-8", errors="replace")
    digest = sha256_text(text)
    if ctx.config_sha256 and ctx.config_sha256 != digest:
        return error("config changed on disk since this audit started; start a new audit")

    ctx.raw_lines = text.splitlines()
    ctx.masked_lines = [mask_line(line) for line in ctx.raw_lines]
    ctx.config_sha256 = digest
    ctx.parse = None
    ctx.inventory = None

    hostname = _HOSTNAME.search(text)
    return {
        "ok": True,
        "file": requested.name,
        "line_count": len(ctx.raw_lines),
        "hostname": hostname.group(1) if hostname else None,
        "sha256": digest[:16],
    }
