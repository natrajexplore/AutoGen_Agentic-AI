"""Traceability: JSONL log of every agent message and tool call, plus token and cost tracking.

Everything logged has already passed through the masking tools, so logs contain no raw secrets.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class Usage:
    prompt_tokens: int = 0
    completion_tokens: int = 0

    def add(self, item: Any) -> None:
        usage = getattr(item, "models_usage", None)
        if usage is not None:
            self.prompt_tokens += usage.prompt_tokens
            self.completion_tokens += usage.completion_tokens

    def cost_usd(self, price_in_per_mtok: float, price_out_per_mtok: float) -> float:
        return (self.prompt_tokens * price_in_per_mtok + self.completion_tokens * price_out_per_mtok) / 1_000_000


class AuditLog:
    """Append-only JSONL file, one record per stream item or lifecycle event."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path

    def event(self, kind: str, **fields: Any) -> None:
        self._write({"kind": kind, **fields})

    def item(self, item: Any) -> None:
        dump = getattr(item, "dump", None)
        record = dump() if callable(dump) else {"repr": repr(item)}
        self._write({"kind": "message", "type": type(item).__name__, "data": record})

    def _write(self, record: dict[str, Any]) -> None:
        record = {"ts": datetime.now(timezone.utc).isoformat(), **record}
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, default=str, ensure_ascii=False) + "\n")
