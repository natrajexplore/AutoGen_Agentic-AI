"""HumanApprover: the final review gate, run after the agent team finishes.

Uses AutoGen's UserProxyAgent so the human decision is a recorded chat message like any other.
Approval is required before (a) exporting remediation scripts and (b) overwriting reports.
Only explicit answers approve; anything else, including EOF / no TTY, is a rejection.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from autogen_agentchat.agents import UserProxyAgent
from autogen_agentchat.messages import TextMessage
from autogen_core import CancellationToken

from configguard.reporting import DeviceResult


@dataclass
class Decision:
    export: set[str]  # devices whose remediation scripts may be written
    overwrite: bool  # existing Markdown reports may be replaced


def safe_input(_prompt: str) -> str:
    # UserProxyAgent passes a generic "Enter your response:" prompt; our question is already printed.
    try:
        return input("> ")
    except EOFError:
        return ""


def parse_selection(answer: str, devices: list[str]) -> set[str]:
    """'all', 'none', or comma-separated numbers / names. Unknown entries are ignored."""
    answer = answer.strip().lower()
    if answer in ("all", "a", "yes", "y"):
        return set(devices)
    chosen: set[str] = set()
    for token in (t.strip() for t in answer.split(",")):
        if token.isdigit() and 1 <= int(token) <= len(devices):
            chosen.add(devices[int(token) - 1])
        elif token in (d.lower() for d in devices):
            chosen.add(next(d for d in devices if d.lower() == token))
    return chosen


def eligible_devices(results: list[DeviceResult]) -> list[str]:
    """Devices whose remediation may be exported: approved audits with recorded fixes for FAILs."""
    return [r.device for r in results if r.approved and r.counts["FAIL"] and r.ctx.remediations]


class HumanApprover:
    def __init__(
        self,
        input_func: Callable[[str], str] | Callable[[str, CancellationToken | None], Awaitable[str]] = safe_input,
        output: Callable[[str], None] = print,
    ) -> None:
        self.agent = UserProxyAgent(name="HumanApprover", description="Human reviewer", input_func=input_func)
        self.output = output
        self.transcript: list[tuple[str, str]] = []  # (question, answer) for the audit log
        self.pending: tuple[str, str] | None = None  # (kind, question) while waiting; lets a UI render controls

    async def ask(self, question: str, kind: str = "text") -> str:
        self.pending = (kind, question)
        self.output(question)
        response = await self.agent.on_messages(
            [TextMessage(content=question, source="ConfigGuard")], CancellationToken()
        )
        answer = str(response.chat_message.content).strip()
        self.pending = None
        self.transcript.append((question, answer))
        return answer

    async def review(self, results: list[DeviceResult], existing_reports: list[str], *, export_allowed: bool) -> Decision:
        eligible = eligible_devices(results)
        lines = ["", "=" * 72, "HUMAN REVIEW", "=" * 72]
        for i, r in enumerate(results, start=1):
            c = r.counts
            flag = "approved" if r.approved else "NOT APPROVED (no export possible)"
            lines.append(f"{i:>2}. {r.device:<20} FAIL {c['FAIL']:>2}  PASS {c['PASS']:>2}  N/A {c['NOT_APPLICABLE']:>2}  [{flag}]")
            for rid, rem in sorted(r.ctx.remediations.items()):
                lockout = "  LOCKOUT WARNING" if any("LOCKOUT" in w.upper() for w in rem.warnings) else ""
                lines.append(f"      {rid}: {len(rem.commands)} command(s){lockout}")
        self.output("\n".join(lines))

        overwrite = False
        if existing_reports:
            answer = await self.ask(
                f"\nReports already exist for: {', '.join(existing_reports)}.\n"
                "Overwrite them? Type 'overwrite' to confirm, anything else keeps the old files: ",
                kind="overwrite",
            )
            overwrite = answer.lower() == "overwrite"

        export: set[str] = set()
        if export_allowed and eligible:
            numbered = ", ".join(f"{results.index(r) + 1}={r.device}" for r in results if r.device in eligible)
            answer = await self.ask(
                f"\nExport remediation scripts (marked {chr(34)}REVIEW BEFORE APPLYING{chr(34)})?\n"
                f"Eligible: {numbered}\n"
                "Type 'all', 'none', or numbers/names separated by commas: ",
                kind="export",
            )
            by_index = [r.device for r in results]
            export = parse_selection(answer, by_index) & set(eligible)
        return Decision(export=export, overwrite=overwrite)
