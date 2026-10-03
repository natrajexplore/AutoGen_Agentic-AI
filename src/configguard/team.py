# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Nataraj Angappan
"""Team orchestration: RoundRobinGroupChat over the fixed parse -> check -> remediate -> review pipeline."""

from __future__ import annotations

import time
from collections.abc import AsyncGenerator, Callable
from dataclasses import dataclass, field
from typing import Any

from autogen_agentchat.base import TaskResult
from autogen_agentchat.conditions import (
    MaxMessageTermination,
    TextMentionTermination,
    TimeoutTermination,
    TokenUsageTermination,
)
from autogen_agentchat.messages import TextMessage
from autogen_agentchat.teams import RoundRobinGroupChat
from autogen_agentchat.ui import Console
from autogen_core.models import ChatCompletionClient

from configguard.agents import build_agents
from configguard.context import AuditContext
from configguard.telemetry import Usage
from configguard.tools.audit_record import audit_gaps

APPROVAL = "AUDIT_APPROVED"


@dataclass
class AuditOutcome:
    approved: bool  # Critic approved AND the deterministic record is complete
    critic_approved: bool
    gaps: list[str]
    stop_reason: str | None
    duration_s: float
    usage: Usage = field(default_factory=Usage)
    result: TaskResult | None = field(repr=False, default=None)


def build_team(
    ctx: AuditContext,
    model_client: ChatCompletionClient,
    max_messages: int = 25,
    *,
    max_total_tokens: int = 150_000,
    timeout_s: float = 300,
) -> RoundRobinGroupChat:
    # sources=["Critic"]: approval text injected via config content or other agents cannot end the run.
    # Token and time limits are spend safeguards, checked after every agent turn (tool steps included).
    termination = (
        TextMentionTermination(APPROVAL, sources=["Critic"])
        | MaxMessageTermination(max_messages)
        | TokenUsageTermination(max_total_token=max_total_tokens)
        | TimeoutTermination(timeout_s)
    )
    return RoundRobinGroupChat(build_agents(ctx, model_client), termination_condition=termination)


def task_message(ctx: AuditContext) -> str:
    return (
        f"Audit one Cisco IOS/IOS-XE device configuration.\n"
        f"audit_id: {ctx.audit_id}\n"
        f"config path: {ctx.config_path.as_posix()}\n"
        f"baseline path: {ctx.baseline_path.as_posix()}\n"
        f"Pipeline: ConfigParser -> ComplianceChecker -> RemediationEngineer -> Critic."
    )


def critic_approved(result: TaskResult) -> bool:
    last = next((m for m in reversed(result.messages) if isinstance(m, TextMessage) and m.source == "Critic"), None)
    return last is not None and last.content.strip().startswith(APPROVAL)


async def run_audit(
    ctx: AuditContext,
    team: RoundRobinGroupChat,
    *,
    resume: bool = False,
    console: bool = True,
    on_item: Callable[[Any], None] | None = None,
) -> AuditOutcome:
    """Run one audit, or continue a loaded team state when resume=True."""
    usage = Usage()

    async def observed(stream: AsyncGenerator[Any, None]) -> AsyncGenerator[Any, None]:
        async for item in stream:
            if not isinstance(item, TaskResult):
                usage.add(item)
                if on_item:
                    on_item(item)
            yield item

    start = time.perf_counter()
    stream = observed(team.run_stream(task=None if resume else task_message(ctx)))
    if console:
        result = await Console(stream)
    else:
        result = None
        async for item in stream:
            if isinstance(item, TaskResult):
                result = item
    assert isinstance(result, TaskResult)
    gaps = audit_gaps(ctx)
    approved_by_critic = critic_approved(result)
    return AuditOutcome(
        approved=approved_by_critic and not gaps,
        critic_approved=approved_by_critic,
        gaps=gaps,
        stop_reason=result.stop_reason,
        duration_s=time.perf_counter() - start,
        usage=usage,
        result=result,
    )
