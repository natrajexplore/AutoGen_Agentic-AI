"""Build the four AssistantAgents, binding each tool to one AuditContext.

Tools in configguard.tools take the AuditContext as their first argument; here they are wrapped
in closures so the model only sees (and can only supply) the remaining arguments.
"""

from __future__ import annotations

import json
from typing import Any

from autogen_agentchat.agents import AssistantAgent
from autogen_core.models import ChatCompletionClient
from autogen_core.tools import FunctionTool

from configguard import prompts
from configguard.context import AuditContext
from configguard.tools import audit_record, baseline, ios_syntax, loader, masking, parser


MAX_MASK_INPUT = 20_000


def _json(result: dict[str, Any]) -> str:
    # AutoGen stringifies non-pydantic return values with str(); JSON is clearer for the model.
    return json.dumps(result, ensure_ascii=False)


def _tools(ctx: AuditContext) -> dict[str, FunctionTool]:
    async def load_config(path: str) -> str:
        return _json(loader.load_config(ctx, path))

    async def mask_secrets(text: str) -> str:
        return masking.mask_secrets(text[:MAX_MASK_INPUT])

    async def parse_ios_config() -> str:
        result = parser.parse_ios_config(ctx)  # full inventory is kept in ctx for reports and the UI
        if result["ok"]:
            result = {"ok": True, "summary": parser.inventory_summary(result["inventory"])}
        return _json(result)

    async def load_baseline(path: str) -> str:
        return _json(baseline.load_baseline(ctx, path))

    async def check_rule(rule_id: str) -> str:
        return _json(baseline.check_rule(ctx, rule_id))

    async def find_config_lines(pattern: str) -> str:
        return _json(baseline.find_config_lines(ctx, pattern))

    async def validate_ios_syntax(commands: list[str]) -> str:
        return _json(ios_syntax.validate_ios_syntax(commands))

    async def record_remediation(rule_id: str, risk_summary: str, commands: list[str], warnings: list[str]) -> str:
        return _json(ios_syntax.record_remediation(ctx, rule_id, risk_summary, commands, warnings))

    async def get_fail_findings() -> str:
        return _json(audit_record.get_fail_findings(ctx))

    async def get_audit_record() -> str:
        return _json(audit_record.get_audit_record(ctx))

    specs = {
        load_config: "Load the device config assigned to this audit. Returns metadata only (line count, hostname).",
        mask_secrets: "Mask passwords, keys and SNMP communities in a piece of config text.",
        parse_ios_config: "Parse the loaded config into a structured, secret-masked inventory. Returns a summary.",
        load_baseline: "Load the compliance baseline assigned to this audit and list its rule ids.",
        check_rule: "Deterministically evaluate one baseline rule. Returns status, evidence lines and missing lines.",
        find_config_lines: "Regex search over the masked config. Returns matching lines with line numbers.",
        validate_ios_syntax: "Best-effort syntax and mode-order check for IOS config-mode commands.",
        record_remediation: (
            "Validate and save the remediation for one FAIL rule. commands: IOS config-mode lines in order. "
            "warnings: include a 'LOCKOUT WARNING: ...' entry when access could be cut off."
        ),
        get_fail_findings: "Read-only: every FAIL finding with its evidence, rule intent and remediation hint.",
        get_audit_record: "Read-only: all recorded findings and remediations plus completeness gaps.",
    }
    return {f.__name__: FunctionTool(f, description=d, name=f.__name__) for f, d in specs.items()}


def build_agents(ctx: AuditContext, model_client: ChatCompletionClient) -> list[AssistantAgent]:
    """Return the agents in pipeline order: parse -> check -> remediate -> review."""
    t = _tools(ctx)
    return [
        AssistantAgent(
            name="ConfigParser",
            description="Loads and parses the device config into a masked inventory.",
            model_client=model_client,
            system_message=prompts.CONFIG_PARSER,
            tools=[t["load_config"], t["mask_secrets"], t["parse_ios_config"]],
            max_tool_iterations=3,
            reflect_on_tool_use=True,
        ),
        AssistantAgent(
            name="ComplianceChecker",
            description="Evaluates every baseline rule with the deterministic rule engine.",
            model_client=model_client,
            system_message=prompts.COMPLIANCE_CHECKER,
            tools=[t["load_baseline"], t["check_rule"], t["find_config_lines"]],
            max_tool_iterations=3,
            reflect_on_tool_use=True,
        ),
        AssistantAgent(
            name="RemediationEngineer",
            description="Explains risk and drafts validated IOS remediation for each FAIL.",
            model_client=model_client,
            system_message=prompts.REMEDIATION_ENGINEER,
            tools=[t["get_fail_findings"], t["validate_ios_syntax"], t["record_remediation"]],
            max_tool_iterations=6,
            reflect_on_tool_use=True,
        ),
        AssistantAgent(
            name="Critic",
            description="Reviews the recorded audit and approves or sends work back.",
            model_client=model_client,
            system_message=prompts.CRITIC,
            tools=[t["get_audit_record"]],
            max_tool_iterations=2,
            reflect_on_tool_use=True,
        ),
    ]
