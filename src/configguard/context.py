"""Per-audit working state shared by the tools.

Raw config text lives only here, in memory. It is never returned by a tool and never
serialised: on resume the config is re-read from disk and checked against its hash.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ciscoconfparse2 import CiscoConfParse

from configguard.models import Baseline, Finding, Remediation, ReviewDecision, Waiver


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass
class AuditContext:
    config_path: Path
    baseline_path: Path
    audit_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    raw_lines: list[str] = field(default_factory=list, repr=False)
    masked_lines: list[str] = field(default_factory=list, repr=False)
    config_sha256: str | None = None
    parse: CiscoConfParse | None = field(default=None, repr=False)
    inventory: dict[str, Any] | None = None
    baseline: Baseline | None = None
    findings: dict[str, Finding] = field(default_factory=dict)
    remediations: dict[str, Remediation] = field(default_factory=dict)
    decisions: dict[str, ReviewDecision] = field(default_factory=dict)  # human review, per rule
    facts: dict[str, Any] | None = None  # device facts (version, platform, counts)
    waivers: list[Waiver] = field(default_factory=list, repr=False)  # all known waivers; reloaded, never saved here

    def __post_init__(self) -> None:
        self.config_path = Path(self.config_path).resolve()
        self.baseline_path = Path(self.baseline_path).resolve()

    @property
    def loaded(self) -> bool:
        return bool(self.raw_lines)

    @property
    def hostname(self) -> str:
        """Device hostname from the parsed inventory or facts, falling back to the file stem."""
        for source in (self.inventory, self.facts):
            if source and source.get("hostname"):
                return str(source["hostname"])
        return self.config_path.stem

    def to_dict(self) -> dict[str, Any]:
        """Serialisable snapshot for pause/resume. Excludes raw and masked config text."""
        return {
            "audit_id": self.audit_id,
            "config_path": str(self.config_path),
            "baseline_path": str(self.baseline_path),
            "config_sha256": self.config_sha256,
            "findings": {k: v.model_dump() for k, v in self.findings.items()},
            "remediations": {k: v.model_dump() for k, v in self.remediations.items()},
            "decisions": {k: v.model_dump(mode="json") for k, v in self.decisions.items()},
            "facts": self.facts,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditContext:
        ctx = cls(
            config_path=Path(data["config_path"]),
            baseline_path=Path(data["baseline_path"]),
            audit_id=data["audit_id"],
        )
        ctx.config_sha256 = data.get("config_sha256")
        ctx.findings = {k: Finding(**v) for k, v in data.get("findings", {}).items()}
        ctx.remediations = {k: Remediation(**v) for k, v in data.get("remediations", {}).items()}
        ctx.decisions = {k: ReviewDecision(**v) for k, v in data.get("decisions", {}).items()}
        ctx.facts = data.get("facts")
        return ctx
