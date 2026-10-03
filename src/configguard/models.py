"""Pydantic data models shared by tools, agents and reporting.

These models are framework-agnostic: nothing here imports AutoGen.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Severity = Literal["critical", "high", "medium", "low"]
Status = Literal["PASS", "FAIL", "NOT_APPLICABLE"]
CheckType = Literal["global_required", "global_forbidden", "children_required", "python"]


# --------------------------------------------------------------------------- baseline


class RuleCheck(BaseModel):
    """Declarative check definition. Which fields are required depends on `type`."""

    model_config = ConfigDict(extra="forbid")

    type: CheckType
    # global_required (may also use `forbid` for top-level lines that must not exist)
    all_of: list[str] = Field(default_factory=list)
    any_of: list[str] = Field(default_factory=list)
    # global_forbidden
    pattern: str | None = None
    # children_required (require/forbid apply to the children of each matching parent)
    parent: str | None = None
    require: list[str] = Field(default_factory=list)
    forbid: list[str] = Field(default_factory=list)
    # python
    function: str | None = None

    @field_validator("require", "forbid", "all_of", "any_of", mode="before")
    @classmethod
    def _str_to_list(cls, v: object) -> object:
        return [v] if isinstance(v, str) else v

    @model_validator(mode="after")
    def _fields_match_type(self) -> RuleCheck:
        if self.type == "global_required" and not (self.all_of or self.any_of):
            raise ValueError("global_required needs all_of and/or any_of")
        if self.type == "global_forbidden" and not self.pattern:
            raise ValueError("global_forbidden needs pattern")
        if self.type == "children_required" and not (self.parent and (self.require or self.forbid)):
            raise ValueError("children_required needs parent and require/forbid")
        if self.type == "python" and not self.function:
            raise ValueError("python check needs function")
        return self


class AppliesWhen(BaseModel):
    """Precondition; if it does not hold, the rule is NOT_APPLICABLE."""

    model_config = ConfigDict(extra="forbid")

    global_present: str | None = None


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^CG-\d{3}$")
    title: str
    severity: Severity
    category: str
    description: str
    applies_when: AppliesWhen | None = None
    check: RuleCheck
    remediation_hint: list[str] = Field(default_factory=list)
    lockout_risk: bool = False
    advisory: str | None = None


class BaselineSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    external_interface_pattern: str = r"(?i)\b(wan|internet|isp|external|uplink-ext)\b"
    max_exec_timeout_minutes: int = 15
    default_snmp_communities: list[str] = Field(default_factory=lambda: ["public", "private"])


class Baseline(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    platform: Literal["cisco_ios"]
    settings: BaselineSettings = Field(default_factory=BaselineSettings)
    rules: list[Rule]

    @model_validator(mode="after")
    def _unique_ids(self) -> Baseline:
        ids = [r.id for r in self.rules]
        dupes = {i for i in ids if ids.count(i) > 1}
        if dupes:
            raise ValueError(f"duplicate rule ids: {sorted(dupes)}")
        return self

    def rule(self, rule_id: str) -> Rule | None:
        return next((r for r in self.rules if r.id == rule_id), None)


# --------------------------------------------------------------------------- findings


class EvidenceLine(BaseModel):
    line_number: int = Field(ge=1)
    text: str  # always masked


class Finding(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    status: Status
    evidence: list[EvidenceLine] = Field(default_factory=list)
    missing: list[str] = Field(default_factory=list)
    reason: str
    advisory: str | None = None

    @model_validator(mode="after")
    def _fail_needs_proof(self) -> Finding:
        # Core anti-hallucination guarantee: a FAIL must cite a line or a missing line.
        if self.status == "FAIL" and not (self.evidence or self.missing):
            raise ValueError(f"{self.rule_id}: FAIL finding must cite evidence or a missing line")
        return self


class Remediation(BaseModel):
    rule_id: str
    risk_summary: str
    commands: list[str]
    warnings: list[str] = Field(default_factory=list)
