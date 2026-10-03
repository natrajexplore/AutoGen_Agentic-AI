"""ConfigGuard web UI backend: REST for configs/baseline/history, WebSocket for live audits.

Local-only by design: run with `configguard ui` (binds 127.0.0.1). Host and Origin checks block
DNS-rebinding and cross-site requests from other web pages, which could otherwise start audits
and spend API credits through the user's browser.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from configguard import runner
from configguard.approval import StructuredApprover, validate_review
from configguard.config.model_client import build_model_client
from configguard.config.settings import Settings
from configguard.reporting import DeviceResult
from configguard.tools.baseline import read_baseline
from configguard.tools.loader import MAX_CONFIG_BYTES
from configguard.waivers import WaiverStore
from configguard.web.dashboard import build_dashboard
from configguard.web.history import (
    audit_detail,
    config_view,
    list_audits,
    load_result,
    output_file,
    remediation_preview,
)

STATIC = Path(__file__).parent / "static"
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,100}$")
LOCAL_HOSTS = ["127.0.0.1", "localhost"]
_RULE = re.compile(r"^CG-\d{3}$")
MAX_ANSWER = 200_000  # a structured review for a large batch is a few KB; this bounds abuse


def result_summary(r: DeviceResult) -> dict[str, Any]:
    ctx = r.ctx
    return {
        "audit_id": ctx.audit_id,
        "device": r.device,
        "config": ctx.config_path.name,
        "approved": r.approved,
        "critic_approved": r.critic_approved,
        "gaps": r.gaps,
        "counts": r.counts,
        "duration_s": round(r.duration_s, 1),
        "tokens": r.prompt_tokens + r.completion_tokens,
        "cost_usd": round(r.cost_usd, 6),
        "findings": [f.model_dump() for f in ctx.findings.values()],
        "remediations": {k: v.model_dump() for k, v in ctx.remediations.items()},
        "facts": ctx.facts,
        "assessment": r.assessment.to_dict(),
    }


def item_record(item: Any) -> dict[str, Any]:
    """Same shape as the JSONL log, so live view and history replay share one renderer."""
    dump = getattr(item, "dump", None)
    data = dump() if callable(dump) else {"repr": repr(item)}
    return json.loads(json.dumps({"type": type(item).__name__, "data": data}, default=str))


class AnswerChannel:
    """Delivers approval answers only while a question is open.

    Without this gate, a stray or duplicated answer (e.g. a double-click) would be queued and
    silently consumed by the NEXT approval question, approving something the user never saw.
    """

    def __init__(self) -> None:
        self._queue: asyncio.Queue[str] = asyncio.Queue(maxsize=1)
        self.open = False

    def offer(self, text: str) -> bool:
        if not self.open:
            return False
        self.open = False
        self._queue.put_nowait(text)
        return True

    def expect(self) -> None:
        """Open the gate. Call before the question is sent, so a fast reply is never dropped."""
        self.open = True

    async def wait(self) -> str:
        try:
            return await self._queue.get()
        finally:
            self.open = False


def create_app(settings: Settings | None = None, allowed_hosts: list[str] | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    hosts = allowed_hosts or LOCAL_HOSTS
    app = FastAPI(title="ConfigGuard", docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=hosts)
    run_lock = asyncio.Lock()

    def same_origin(origin: str | None, host: str | None) -> bool:
        return origin is not None and host is not None and origin in (f"http://{host}", f"https://{host}")

    @app.middleware("http")
    async def origin_guard(request: Request, call_next: Callable[[Request], Awaitable[Any]]) -> Any:
        if request.method not in ("GET", "HEAD") and not same_origin(
            request.headers.get("origin"), request.headers.get("host")
        ):
            return JSONResponse({"detail": "cross-origin request refused"}, status_code=403)
        return await call_next(request)

    # ------------------------------------------------------------------ configs

    def config_roots() -> dict[str, Path]:
        return {"fixtures": settings.configs_dir, "uploads": settings.uploads_dir}

    def resolve_config(config_id: str) -> Path:
        """'source/name' -> Path, only inside the configured folders (no client-supplied paths)."""
        source, _, name = config_id.partition("/")
        root = config_roots().get(source)
        if root is None or not _NAME.match(name):
            raise ValueError(f"unknown config {config_id!r}")
        path = root / name
        if not path.is_file():
            raise ValueError(f"config not found: {config_id}")
        return path

    @app.get("/api/info")
    def info() -> dict[str, Any]:
        import os

        key_var = {"openai": "OPENAI_API_KEY", "anthropic": "ANTHROPIC_API_KEY"}.get(settings.model_provider)
        return {
            "provider": settings.model_provider,
            "model": settings.model,
            "baseline": settings.baseline_path.name,
            "api_key_configured": bool(os.getenv(key_var)) if key_var else True,
            "busy": run_lock.locked(),
            "max_waiver_days": settings.max_waiver_days,
            "reviewer_name": settings.reviewer_name,
        }

    @app.get("/api/configs")
    def configs() -> list[dict[str, Any]]:
        out = []
        for source, root in config_roots().items():
            if root.is_dir():
                for p in sorted(root.iterdir()):
                    if p.is_file() and _NAME.match(p.name) and p.suffix.lower() in (".cfg", ".txt", ".conf", ".ios"):
                        out.append({"id": f"{source}/{p.name}", "name": p.name, "source": source, "size": p.stat().st_size})
        return out

    @app.post("/api/configs")
    async def upload(file: UploadFile = File(...)) -> dict[str, Any]:
        name = re.sub(r"[^A-Za-z0-9_.-]", "_", Path(file.filename or "upload.cfg").name).lstrip("._")[:80] or "upload.cfg"
        if Path(name).suffix.lower() not in (".cfg", ".txt", ".conf", ".ios"):
            name += ".cfg"
        data = await file.read(MAX_CONFIG_BYTES + 1)
        if not data.strip():
            raise HTTPException(400, "file is empty")
        if len(data) > MAX_CONFIG_BYTES:
            raise HTTPException(400, f"file exceeds {MAX_CONFIG_BYTES} bytes")
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            raise HTTPException(400, "file is not UTF-8 text") from None
        settings.uploads_dir.mkdir(parents=True, exist_ok=True)
        dest, n = settings.uploads_dir / name, 1
        while dest.exists():  # never overwrite an earlier upload
            dest = settings.uploads_dir / f"{Path(name).stem}-{n}{Path(name).suffix}"
            n += 1
        dest.write_bytes(data)
        return {"id": f"uploads/{dest.name}", "name": dest.name, "source": "uploads", "size": len(data)}

    # ------------------------------------------------------------------ baseline + history

    @app.get("/api/baseline")
    def baseline() -> dict[str, Any]:
        b = read_baseline(settings.baseline_path)
        return {"file": settings.baseline_path.name, "settings": b.settings.model_dump(),
                "rules": [r.model_dump(exclude_none=True) for r in b.rules]}

    @app.get("/api/audits")
    def audits() -> list[dict[str, Any]]:
        return list_audits(settings)

    @app.get("/api/audits/{audit_id}")
    def audit(audit_id: str) -> dict[str, Any]:
        try:
            detail = audit_detail(settings, audit_id)
        except ValueError:
            detail = None
        if detail is None:
            raise HTTPException(404, "audit not found")
        return detail

    @app.get("/api/audits/{audit_id}/{kind}", response_class=PlainTextResponse)
    def audit_file(audit_id: str, kind: str) -> str:
        try:
            path = output_file(settings, audit_id, kind)
        except ValueError:
            path = None
        if path is None:
            raise HTTPException(404, "file not found")
        return path.read_text(encoding="utf-8")

    @app.get("/api/audits/{audit_id}/view/config")
    def audit_config_view(audit_id: str) -> dict[str, Any]:
        try:
            view = config_view(settings, audit_id)
        except ValueError:
            view = None
        if view is None:
            raise HTTPException(404, "audit not found")
        return view

    @app.get("/api/audits/{audit_id}/view/preview")
    def audit_preview(audit_id: str, scope: str = "all") -> dict[str, Any]:
        if scope not in ("all", "approved"):
            raise HTTPException(400, "scope must be 'all' or 'approved'")
        try:
            view = remediation_preview(settings, audit_id, scope)
        except ValueError:
            view = None
        if view is None:
            raise HTTPException(404, "audit not found")
        return view

    @app.post("/api/audits/{audit_id}/review")
    async def review_audit(audit_id: str, request: Request) -> dict[str, Any]:
        """Post-hoc human review from History (e.g. an audit whose review was never completed)."""
        body = await request.body()
        if len(body) > MAX_ANSWER:
            raise HTTPException(413, "review too large")
        try:
            raw = json.loads(body)
        except json.JSONDecodeError:
            raise HTTPException(400, "review must be JSON") from None
        if run_lock.locked():
            raise HTTPException(409, "an audit is running; try again when it finishes")
        async with run_lock:
            try:
                result = load_result(settings, audit_id)
            except ValueError:
                result = None
            if result is None:
                raise HTTPException(404, "audit not found")
            if isinstance(raw, dict):
                raw["decisions"] = {audit_id: (raw.get("decisions") or {}).get(audit_id, {})}
            outcome, errors = validate_review(raw, [result], export_allowed=True, max_waiver_days=settings.max_waiver_days)
            if errors:
                return JSONResponse({"detail": "review not recorded", "errors": errors}, status_code=422)
            summary = runner.RunSummary(results=[result])
            runner.apply_review(settings, summary, outcome)
        return {"ok": True, "written": [str(p) for p in summary.written], "assessment": result.assessment.to_dict()}

    @app.get("/api/dashboard")
    def dashboard() -> dict[str, Any]:
        return build_dashboard(settings)

    @app.get("/api/waivers")
    def waivers() -> list[dict[str, Any]]:
        from datetime import date

        today = date.today()
        out = []
        for w in WaiverStore(settings.waivers_path).load():
            out.append({**w.model_dump(mode="json"), "active": w.active(today), "days_left": (w.expires - today).days})
        return sorted(out, key=lambda w: (not w["active"], w["expires"]))

    @app.delete("/api/waivers/{device}/{rule_id}")
    def revoke_waiver(device: str, rule_id: str) -> dict[str, Any]:
        if not _NAME.match(device) or not _RULE.match(rule_id):
            raise HTTPException(400, "invalid device or rule id")
        if not WaiverStore(settings.waivers_path).revoke(device, rule_id):
            raise HTTPException(404, "waiver not found")
        return {"ok": True}

    # ------------------------------------------------------------------ live runs

    @app.websocket("/ws/run")
    async def run_ws(ws: WebSocket) -> None:
        if not same_origin(ws.headers.get("origin"), ws.headers.get("host")):
            await ws.close(code=4403)
            return
        await ws.accept()
        outbox: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue()
        answers = AnswerChannel()

        async def sender() -> None:
            while (msg := await outbox.get()) is not None:
                await ws.send_json(msg)

        send_task = asyncio.create_task(sender())
        run_task: asyncio.Task[None] | None = None
        try:
            while True:
                msg = await ws.receive_json()
                action = msg.get("action")
                if action == "answer":
                    if not answers.offer(str(msg.get("text", ""))[:MAX_ANSWER]):
                        outbox.put_nowait({"type": "error", "message": "no approval question is waiting; answer ignored"})
                elif action == "start":
                    if run_lock.locked() or (run_task and not run_task.done()):
                        outbox.put_nowait({"type": "error", "message": "an audit is already running"})
                        continue
                    run_task = asyncio.create_task(execute(msg, outbox, answers))
                else:
                    outbox.put_nowait({"type": "error", "message": f"unknown action {action!r}"})
        except WebSocketDisconnect:
            pass
        finally:
            if run_task and not run_task.done():
                run_task.cancel()  # audit_config checkpoints a cancelled audit as 'paused'
                await asyncio.gather(run_task, return_exceptions=True)
            outbox.put_nowait(None)
            send_task.cancel()

    async def execute(msg: dict[str, Any], outbox: asyncio.Queue[Any], answers: AnswerChannel) -> None:
        async with run_lock:
            mode = msg.get("mode")
            export_allowed = bool(msg.get("export_allowed", True))
            try:
                if mode == "resume":
                    jobs: list[dict[str, Any]] = [{"resume_id": str(msg.get("audit_id", "")), "label": msg.get("audit_id")}]
                elif mode in ("audit", "batch"):
                    ids = msg.get("configs") or []
                    if not ids or (mode == "audit" and len(ids) != 1):
                        raise ValueError("select one config for an audit, or one or more for a batch")
                    jobs = [{"config_path": resolve_config(i), "label": i} for i in ids]
                else:
                    raise ValueError(f"unknown mode {mode!r}")
            except ValueError as exc:
                outbox.put_nowait({"type": "error", "message": str(exc)})
                return

            outbox.put_nowait({"type": "run_start", "mode": mode, "total": len(jobs),
                               "labels": [j["label"] for j in jobs]})
            client = build_model_client(settings)
            summary = runner.RunSummary()
            try:
                for index, job in enumerate(jobs):
                    label = job.pop("label")
                    outbox.put_nowait({"type": "audit_start", "index": index, "label": label})

                    def forward(item: Any, index: int = index) -> None:
                        outbox.put_nowait({"type": "item", "index": index, "record": item_record(item)})

                    try:
                        result = await runner.audit_config(settings, client, console=False, on_item=forward, **job)
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:  # one failure must not end a batch
                        summary.errors[str(label)] = f"{type(exc).__name__}: {exc}"
                        outbox.put_nowait({"type": "audit_error", "index": index, "label": label,
                                           "error": summary.errors[str(label)]})
                        continue
                    summary.results.append(result)
                    outbox.put_nowait({"type": "audit_end", "index": index, "result": result_summary(result)})

                async def web_input(_prompt: str, _token: Any = None) -> str:
                    kind, question, payload = approver.pending or ("text", "", None)
                    answers.expect()
                    outbox.put_nowait({"type": "question", "kind": kind, "text": question, "payload": payload})
                    return await answers.wait()

                approver = StructuredApprover(input_func=web_input, output=lambda _text: None,
                                              reviewer=settings.reviewer_name)
                await runner.finalize(settings, summary, approver, export_allowed=export_allowed)
                outbox.put_nowait({
                    "type": "run_end", "all_approved": summary.all_approved,
                    "written": [str(p) for p in summary.written], "errors": summary.errors,
                    "audit_ids": [r.ctx.audit_id for r in summary.results],
                    "assessments": {r.ctx.audit_id: r.assessment.to_dict() for r in summary.results},
                })
            finally:
                await client.close()

    app.mount("/", StaticFiles(directory=STATIC, html=True), name="static")
    return app
