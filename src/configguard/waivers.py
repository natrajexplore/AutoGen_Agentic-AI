"""Risk-acceptance register (waivers.yaml): accepted risks carry over to future audits until expiry.

Waivers never hide a violation. Future audits still detect it; it is shown as RISK_ACCEPTED
(with justification, approver and expiry) instead of an open finding, and resurfaces automatically
once the waiver expires.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import yaml
from pydantic import ValidationError

from configguard.models import Waiver

HEADER = (
    "# ConfigGuard risk-acceptance register. Managed by ConfigGuard human review;\n"
    "# edit with care. Each entry: device, rule_id, justification, approver, ticket, expires, created.\n"
)


class WaiverStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def load(self) -> list[Waiver]:
        if not self.path.is_file():
            return []
        data = yaml.safe_load(self.path.read_text(encoding="utf-8")) or {}
        try:
            return [Waiver(**w) for w in data.get("waivers", [])]
        except (ValidationError, TypeError) as exc:
            raise ValueError(f"invalid waivers file {self.path.name}: {exc}") from exc

    def _write(self, waivers: list[Waiver]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        body = yaml.safe_dump(
            {"waivers": [w.model_dump(mode="json") for w in sorted(waivers, key=lambda w: (w.device, w.rule_id))]},
            sort_keys=False,
        )
        # write atomically so a crash never leaves a half-written register
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".waivers-", suffix=".yaml")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(HEADER + body)
        os.replace(tmp, self.path)

    def add(self, new: list[Waiver]) -> None:
        """Add or replace waivers (one per device + rule)."""
        if not new:
            return
        keys = {(w.device, w.rule_id) for w in new}
        self._write([w for w in self.load() if (w.device, w.rule_id) not in keys] + new)

    def revoke(self, device: str, rule_id: str) -> bool:
        current = self.load()
        kept = [w for w in current if not (w.device == device and w.rule_id == rule_id)]
        if len(kept) == len(current):
            return False
        self._write(kept)
        return True
