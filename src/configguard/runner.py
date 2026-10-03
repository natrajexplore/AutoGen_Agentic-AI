"""Audit orchestration used by the CLI: single, batch and resume, followed by human review and output."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from autogen_core.models import ChatCompletionClient

from configguard.approval import HumanApprover, ReviewOutcome
from configguard.config.settings import Settings
from configguard.context import AuditContext
from configguard.facts import device_facts
from configguard.models import Waiver
from configguard.persistence import load_checkpoint, save_checkpoint, update_context
from configguard.reporting import (
    DeviceResult,
    device_name,
    now,
    render_batch_table,
    render_markdown,
    render_remediation_script,
    write_csv_summary,
)
from configguard.team import build_team, run_audit
from configguard.telemetry import AuditLog
from configguard.waivers import WaiverStore


@dataclass
class RunSummary:
    results: list[DeviceResult] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)  # config file -> error
    written: list[Path] = field(default_factory=list)

    @property
    def all_approved(self) -> bool:
        return not self.errors and all(r.approved for r in self.results)


async def audit_config(
    settings: Settings,
    client: ChatCompletionClient,
    *,
    config_path: Path | None = None,
    resume_id: str | None = None,
    console: bool = True,
    on_item: Callable[[Any], None] | None = None,
) -> DeviceResult:
    team_state = None
    if resume_id:
        ctx, team_state, _ = load_checkpoint(settings.state_dir, resume_id)
    else:
        assert config_path is not None
        ctx = AuditContext(config_path=config_path, baseline_path=settings.baseline_path)
    ctx.waivers = WaiverStore(settings.waivers_path).load()  # agents skip findings under active waivers

    log = AuditLog(settings.logs_dir / f"{ctx.audit_id}.jsonl")
    log.event("audit_start", audit_id=ctx.audit_id, config=ctx.config_path.name,
              provider=settings.model_provider, model=settings.model, resume=bool(resume_id))

    def observe(item: Any) -> None:
        log.item(item)
        if on_item:
            on_item(item)

    team = build_team(ctx, client, settings.max_messages,
                      max_total_tokens=settings.max_tokens_per_audit, timeout_s=settings.audit_timeout_s)
    if team_state is not None:
        await team.load_state(team_state)
    try:
        outcome = await run_audit(ctx, team, resume=team_state is not None, console=console, on_item=observe)
    except (KeyboardInterrupt, asyncio.CancelledError):
        path = save_checkpoint(settings.state_dir, ctx, await team.save_state(), "paused")
        log.event("audit_paused", checkpoint=path.name)
        print(f"\nAudit paused and saved. Resume with: configguard resume {ctx.audit_id}")
        raise

    status = "approved" if outcome.approved else "not_approved"
    if ctx.loaded:
        ctx.facts = device_facts(ctx.raw_lines)
    save_checkpoint(settings.state_dir, ctx, await team.save_state(), status)
    cost = outcome.usage.cost_usd(settings.price_input_per_mtok, settings.price_output_per_mtok)
    log.event("audit_end", status=status, device=device_name(ctx), stop_reason=outcome.stop_reason, gaps=outcome.gaps,
              duration_s=round(outcome.duration_s, 2), prompt_tokens=outcome.usage.prompt_tokens,
              completion_tokens=outcome.usage.completion_tokens, cost_usd=round(cost, 6))
    if not outcome.approved:
        print(f"\nAudit {ctx.audit_id} NOT approved ({outcome.stop_reason}). "
              f"Gaps: {outcome.gaps or 'none'}. Continue with: configguard resume {ctx.audit_id}")
    return DeviceResult(
        ctx=ctx,
        device=device_name(ctx),
        approved=outcome.approved,
        critic_approved=outcome.critic_approved,
        gaps=outcome.gaps,
        duration_s=outcome.duration_s,
        prompt_tokens=outcome.usage.prompt_tokens,
        completion_tokens=outcome.usage.completion_tokens,
        cost_usd=cost,
        model=settings.model,
    )


def _dedupe_devices(results: list[DeviceResult]) -> None:
    seen: set[str] = set()
    for r in results:
        if r.device in seen:
            r.device = f"{r.device}_{r.ctx.config_path.stem}"
        seen.add(r.device)


def existing_reports(settings: Settings, results: list[DeviceResult]) -> list[str]:
    return [r.device for r in results if (settings.reports_dir / f"{r.device}.md").exists()]


async def finalize(
    settings: Settings, summary: RunSummary, approver: HumanApprover, *, export_allowed: bool
) -> None:
    """Human review gate, then write reports, CSV summary and approved remediation scripts."""
    results = summary.results
    if not results:
        return
    _dedupe_devices(results)
    store = WaiverStore(settings.waivers_path)
    for r in results:
        r.ctx.waivers = store.load()
    outcome = await approver.review(results, existing_reports(settings, results), export_allowed=export_allowed,
                                    max_waiver_days=settings.max_waiver_days)
    apply_review(settings, summary, outcome, transcript=approver.transcript)


def apply_review(
    settings: Settings, summary: RunSummary, outcome: ReviewOutcome, *, transcript: list[tuple[str, str]] | None = None
) -> None:
    """Record decisions, update the risk register, then write reports and approved-only scripts."""
    results = summary.results
    generated = now()
    stamp = generated.strftime("%Y%m%d-%H%M%S")
    reports, scripts = settings.reports_dir, settings.remediation_dir
    reports.mkdir(parents=True, exist_ok=True)
    store = WaiverStore(settings.waivers_path)

    new_waivers = []
    for r in results:
        decisions = outcome.decisions.get(r.ctx.audit_id, {})
        r.ctx.decisions.update(decisions)
        for d in decisions.values():
            if d.action == "accept_risk" and d.expires:
                new_waivers.append(Waiver(device=r.ctx.hostname, rule_id=d.rule_id, justification=d.comment,
                                          approver=d.reviewer, ticket=d.ticket, expires=d.expires,
                                          created=generated.date(), audit_id=r.ctx.audit_id))
    store.add(new_waivers)
    all_waivers = store.load()
    for r in results:
        r.ctx.waivers = all_waivers
        AuditLog(settings.logs_dir / f"{r.ctx.audit_id}.jsonl").event(
            "human_review", reviewer=outcome.reviewer, ticket=outcome.ticket, overwrite=outcome.overwrite,
            decisions=[d.model_dump(mode="json") for d in outcome.decisions.get(r.ctx.audit_id, {}).values()],
            transcript=transcript or [],
        )
        update_context(settings.state_dir, r.ctx)

    for r in results:
        outputs: dict[str, str] = {}
        md = reports / f"{r.device}.md"
        if md.exists() and not outcome.overwrite:
            md = reports / f"{r.device}-{r.ctx.audit_id}.md"  # keep the old report, write alongside
        md.write_text(render_markdown(r, generated), encoding="utf-8")
        summary.written.append(md)
        outputs["report"] = str(md)
        approved = [rid for rid, d in r.ctx.decisions.items() if d.action == "approve_fix" and rid in r.ctx.remediations]
        if approved:  # only fixes a human approved are ever exported
            scripts.mkdir(parents=True, exist_ok=True)
            txt = scripts / f"{r.device}_{r.ctx.audit_id}_remediation.txt"  # unique per audit
            txt.write_text(render_remediation_script(r, generated, approved), encoding="utf-8")
            summary.written.append(txt)
            outputs["remediation"] = str(txt)
        AuditLog(settings.logs_dir / f"{r.ctx.audit_id}.jsonl").event("outputs", **outputs)

    summary.written.append(write_csv_summary(results, reports / f"summary-{stamp}.csv"))
    if len(results) > 1 or summary.errors:
        table = render_batch_table(results)
        if summary.errors:
            table += "\n\nErrors:\n" + "\n".join(f"- {k}: {v}" for k, v in summary.errors.items())
        batch_md = reports / f"batch-summary-{stamp}.md"
        batch_md.write_text(f"# ConfigGuard batch summary ({stamp})\n\n{table}\n", encoding="utf-8")
        summary.written.append(batch_md)
        print("\n" + table)


async def run_batch(
    settings: Settings, client: ChatCompletionClient, folder: Path, pattern: str, *, console: bool
) -> RunSummary:
    summary = RunSummary()
    configs = sorted(p for p in folder.glob(pattern) if p.is_file())
    if not configs:
        raise FileNotFoundError(f"no files matching {pattern!r} in {folder}")
    for i, cfg in enumerate(configs, start=1):
        print(f"[{i}/{len(configs)}] auditing {cfg.name} ...", flush=True)
        try:
            result = await audit_config(settings, client, config_path=cfg, console=console)
        except (KeyboardInterrupt, asyncio.CancelledError):
            raise
        except Exception as exc:  # one bad config or API error must not stop the batch
            summary.errors[cfg.name] = f"{type(exc).__name__}: {exc}"
            print(f"    error: {summary.errors[cfg.name]}")
            continue
        summary.results.append(result)
        c = result.counts
        print(f"    {'approved' if result.approved else 'NOT approved'}: FAIL {c['FAIL']} PASS {c['PASS']} "
              f"N/A {c['NOT_APPLICABLE']} ({result.duration_s:.0f}s, ${result.cost_usd:.4f})")
    return summary
