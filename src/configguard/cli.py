"""ConfigGuard command line.

  configguard audit  CONFIG        audit one config (streams the agent conversation)
  configguard batch  FOLDER        audit every matching config in a folder, then one review step
  configguard resume AUDIT_ID      continue a paused or unapproved audit
  configguard ui [--port 8000]     local web UI (http://127.0.0.1:8000)

Exit codes: 0 all audits approved, 2 any audit not approved or failed, 130 interrupted (state saved).
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import sys
from pathlib import Path

from configguard.approval import HumanApprover
from configguard.config.model_client import build_model_client
from configguard.config.settings import Settings
from configguard.runner import RunSummary, audit_config, finalize, run_batch


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="configguard", description="Multi-agent Cisco IOS config compliance audit.")
    parser.add_argument("--baseline", type=Path, help="baseline YAML (default: BASELINE_PATH or baselines/cisco_ios_v1.yaml)")
    parser.add_argument("--no-remediation-export", action="store_true", help="never write remediation scripts")
    sub = parser.add_subparsers(dest="command", required=True)

    audit = sub.add_parser("audit", help="audit one config file")
    audit.add_argument("config", type=Path)
    audit.add_argument("--quiet", action="store_true", help="do not stream the agent conversation")

    batch = sub.add_parser("batch", help="audit every config in a folder")
    batch.add_argument("folder", type=Path)
    batch.add_argument("--pattern", default="*.cfg", help="glob for config files (default: *.cfg)")
    batch.add_argument("--stream", action="store_true", help="stream each agent conversation")

    resume = sub.add_parser("resume", help="continue a paused or unapproved audit")
    resume.add_argument("audit_id")
    resume.add_argument("--quiet", action="store_true", help="do not stream the agent conversation")

    ui = sub.add_parser("ui", help="start the local web UI")
    ui.add_argument("--port", type=int, default=8000)
    return parser.parse_args(argv)


def serve_ui(args: argparse.Namespace) -> None:
    import uvicorn

    from configguard.web.app import create_app

    settings = Settings.from_env()
    if args.baseline:
        settings = dataclasses.replace(settings, baseline_path=args.baseline.resolve())
    print(f"ConfigGuard UI: http://127.0.0.1:{args.port}  (local only, Ctrl+C to stop)")
    # 127.0.0.1 only: the UI shows masked config data and spends API credits.
    uvicorn.run(create_app(settings), host="127.0.0.1", port=args.port, log_level="warning")


async def run(args: argparse.Namespace) -> int:
    settings = Settings.from_env()
    if args.baseline:
        settings = dataclasses.replace(settings, baseline_path=args.baseline.resolve())
    client = build_model_client(settings)
    summary = RunSummary()
    try:
        if args.command == "batch":
            summary = await run_batch(settings, client, args.folder, args.pattern, console=args.stream)
        else:
            kwargs = {"config_path": args.config} if args.command == "audit" else {"resume_id": args.audit_id}
            summary.results.append(await audit_config(settings, client, console=not args.quiet, **kwargs))
        await finalize(settings, summary, HumanApprover(), export_allowed=not args.no_remediation_export)
    finally:
        await client.close()

    print("\nWritten:")
    for path in summary.written:
        print(f"  {path}")
    return 0 if summary.all_approved else 2


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    if args.command == "ui":
        serve_ui(args)
        return
    try:
        sys.exit(asyncio.run(run(args)))
    except KeyboardInterrupt:
        sys.exit(130)
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        print(f"configguard: error: {exc}", file=sys.stderr)
        sys.exit(1)
