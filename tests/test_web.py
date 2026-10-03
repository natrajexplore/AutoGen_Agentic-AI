"""Web UI backend tests. The agent team is replaced by a deterministic fake, so no API calls."""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest
from autogen_agentchat.messages import TextMessage
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from conftest import BASELINE, FIXTURES, loaded_ctx
from configguard.config.settings import Settings
from configguard.persistence import save_checkpoint
from configguard.reporting import DeviceResult, device_name
from configguard.telemetry import AuditLog
from configguard.tools.baseline import check_rule
from configguard.tools.ios_syntax import record_remediation
from configguard.tools.parser import parse_ios_config
from configguard.web import app as web_app

ORIGIN = {"origin": "http://testserver"}


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    base = Settings.from_env()
    return dataclasses.replace(
        base, baseline_path=BASELINE, configs_dir=FIXTURES, uploads_dir=tmp_path / "uploads",
        reports_dir=tmp_path / "reports", remediation_dir=tmp_path / "remediation",
        logs_dir=tmp_path / "logs", state_dir=tmp_path / "state",
    )


@pytest.fixture
def client(settings: Settings, monkeypatch) -> TestClient:
    class FakeModelClient:
        async def close(self) -> None:
            pass

    async def fake_audit_config(settings, client, *, config_path=None, resume_id=None, console=True, on_item=None):
        """Deterministic stand-in for the agent team: real rule engine, scripted remediation."""
        ctx = loaded_ctx(config_path)
        parse_ios_config(ctx)
        log = AuditLog(settings.logs_dir / f"{ctx.audit_id}.jsonl")
        log.event("audit_start", audit_id=ctx.audit_id, config=ctx.config_path.name, model="fake", resume=False)
        item = TextMessage(content="AUDIT_APPROVED\nfake run", source="Critic")
        log.item(item)
        if on_item:
            on_item(item)
        for rule in ctx.baseline.rules:
            check_rule(ctx, rule.id)
        if ctx.findings["CG-007"].status == "FAIL":
            record_remediation(ctx, "CG-007", "HTTP is cleartext.", ["no ip http server"], [])
        approved = all(f.status != "FAIL" or f.rule_id in ctx.remediations for f in ctx.findings.values())
        save_checkpoint(settings.state_dir, ctx, {}, "approved" if approved else "not_approved")
        log.event("audit_end", status="approved" if approved else "not_approved", device=device_name(ctx),
                  duration_s=1.0, prompt_tokens=10, completion_tokens=5, cost_usd=0.0001)
        return DeviceResult(ctx=ctx, device=device_name(ctx), approved=approved, critic_approved=approved, gaps=[],
                            duration_s=1.0, prompt_tokens=10, completion_tokens=5, cost_usd=0.0001, model="fake")

    monkeypatch.setattr(web_app.runner, "audit_config", fake_audit_config)
    monkeypatch.setattr(web_app, "build_model_client", lambda _s: FakeModelClient())
    return TestClient(web_app.create_app(settings, allowed_hosts=["testserver"]))


def run_ws(client: TestClient, payload: dict, answers: list[str]) -> list[dict]:
    """Drive one run over the WebSocket, answering approval questions in order."""
    messages = []
    with client.websocket_connect("/ws/run", headers=ORIGIN) as ws:
        ws.send_json({"action": "start", **payload})
        while True:
            msg = ws.receive_json()
            messages.append(msg)
            if msg["type"] == "question":
                ws.send_json({"action": "answer", "text": answers.pop(0)})
            if msg["type"] in ("run_end", "error"):
                return messages


# --------------------------------------------------------------------------- REST


def test_info_configs_baseline(client: TestClient) -> None:
    assert client.get("/api/info").json()["model"]
    names = [c["name"] for c in client.get("/api/configs").json()]
    assert "r01-compliant.cfg" in names and "generate_fixtures.py" not in names
    baseline = client.get("/api/baseline").json()
    assert len(baseline["rules"]) == 14 and baseline["rules"][0]["id"] == "CG-001"


def test_index_page_served(client: TestClient) -> None:
    page = client.get("/")
    assert page.status_code == 200 and "ConfigGuard" in page.text


def test_untrusted_host_rejected(client: TestClient) -> None:
    assert client.get("/api/info", headers={"host": "evil.example"}).status_code == 400


def test_upload_requires_same_origin(client: TestClient) -> None:
    files = {"file": ("dev.cfg", b"hostname X\n")}
    assert client.post("/api/configs", files=files).status_code == 403
    assert client.post("/api/configs", files=files, headers={"origin": "http://evil.example"}).status_code == 403
    assert client.post("/api/configs", files=files, headers=ORIGIN).status_code == 200


def test_upload_validation_and_sanitising(client: TestClient, settings: Settings) -> None:
    ok = client.post("/api/configs", files={"file": ("../../evil name.cfg", b"hostname X\n")}, headers=ORIGIN).json()
    assert ok["id"] == "uploads/evil_name.cfg" and (settings.uploads_dir / "evil_name.cfg").is_file()
    again = client.post("/api/configs", files={"file": ("evil name.cfg", b"hostname Y\n")}, headers=ORIGIN).json()
    assert again["name"] == "evil_name-1.cfg"  # never overwrites
    assert client.post("/api/configs", files={"file": ("e.cfg", b"   ")}, headers=ORIGIN).status_code == 400
    assert client.post("/api/configs", files={"file": ("b.cfg", b"\xff\xfe\x00")}, headers=ORIGIN).status_code == 400
    big = b"x" * 2_000_001
    assert client.post("/api/configs", files={"file": ("big.cfg", big)}, headers=ORIGIN).status_code == 400


def test_history_404s(client: TestClient) -> None:
    assert client.get("/api/audits").json() == []
    assert client.get("/api/audits/0123456789ab").status_code == 404
    assert client.get("/api/audits/not-an-id").status_code == 404
    assert client.get("/api/audits/0123456789ab/report").status_code == 404


# --------------------------------------------------------------------------- WebSocket runs


def test_websocket_rejects_cross_origin(client: TestClient) -> None:
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws/run", headers={"origin": "http://evil.example"}) as ws:
            ws.receive_json()


def test_websocket_rejects_paths_outside_config_folders(client: TestClient) -> None:
    msgs = run_ws(client, {"mode": "audit", "configs": ["fixtures/../../pyproject.toml"]}, [])
    assert msgs[-1]["type"] == "error" and "unknown config" in msgs[-1]["message"]


def test_single_audit_flow_then_history(client: TestClient, settings: Settings) -> None:
    msgs = run_ws(client, {"mode": "audit", "configs": ["fixtures/r03-mgmt-plane.cfg"]}, ["BR-R03"])
    types = [m["type"] for m in msgs]
    assert types[:3] == ["run_start", "audit_start", "item"]
    assert msgs[2]["record"]["type"] == "TextMessage" and msgs[2]["record"]["data"]["source"] == "Critic"
    end = next(m for m in msgs if m["type"] == "audit_end")["result"]
    assert end["device"] == "BR-R03" and end["counts"]["FAIL"] == 3
    # only CG-007 got a fix in the fake, so the audit is not approved and nothing is exportable
    assert "question" not in types
    run_end = msgs[-1]
    assert run_end["type"] == "run_end" and not run_end["all_approved"]
    assert any(p.endswith("BR-R03.md") for p in run_end["written"])

    audits = client.get("/api/audits").json()
    assert len(audits) == 1 and audits[0]["device"] == "BR-R03" and audits[0]["status"] == "not_approved"
    detail = client.get(f"/api/audits/{audits[0]['audit_id']}").json()
    assert detail["resumable"] and len(detail["findings"]) == 14 and detail["timeline"]
    assert detail["outputs"] == ["report"]
    report = client.get(f"/api/audits/{audits[0]['audit_id']}/report")
    assert report.status_code == 200 and report.text.startswith("# ConfigGuard audit: BR-R03")


def test_batch_with_export_and_overwrite_questions(client: TestClient, settings: Settings) -> None:
    payload = {"mode": "batch", "configs": ["fixtures/r01-compliant.cfg", "fixtures/r10-mixed.cfg"]}
    first = run_ws(client, payload, [])  # nothing eligible for export, no existing reports: no questions
    assert [m["type"] for m in first].count("audit_end") == 2
    # second run: reports exist now, so the overwrite question appears
    second = run_ws(client, payload, ["overwrite"])
    question = next(m for m in second if m["type"] == "question")
    assert question["kind"] == "overwrite" and {d["device"] for d in question["devices"]} == {"EDGE-R01", "EDGE-R10"}
    assert second[-1]["decisions"][0][1] == "overwrite"


def test_export_question_writes_remediation(client: TestClient, settings: Settings, tmp_path: Path) -> None:
    # a config whose only violation is CG-007, which the fake remediates -> approved + exportable
    cfg = settings.configs_dir / "r01-compliant.cfg"
    only_http = cfg.read_text().replace("no ip http server", "ip http server")
    custom = tmp_path / "configs"
    custom.mkdir()
    (custom / "http-only.cfg").write_text(only_http)
    app_client = TestClient(web_app.create_app(dataclasses.replace(settings, configs_dir=custom), allowed_hosts=["testserver"]))
    msgs = run_ws(app_client, {"mode": "audit", "configs": ["fixtures/http-only.cfg"]}, ["EDGE-R01"])
    question = next(m for m in msgs if m["type"] == "question")
    assert question["kind"] == "export" and question["eligible"] == ["EDGE-R01"]
    assert msgs[-1]["all_approved"] and any("remediation.txt" in p for p in msgs[-1]["written"])
    audit_id = next(m for m in msgs if m["type"] == "audit_end")["result"]["audit_id"]
    script = app_client.get(f"/api/audits/{audit_id}/remediation")
    assert script.status_code == 200 and "REVIEW BEFORE APPLYING" in script.text and "no ip http server" in script.text
