"""Web UI backend tests. The agent team is replaced by a deterministic fake, so no API calls."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest
from autogen_agentchat.messages import TextMessage
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from conftest import BASELINE, FIXTURES, loaded_ctx
from configguard.config.settings import Settings
from configguard.facts import device_facts
from configguard.waivers import WaiverStore
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
        logs_dir=tmp_path / "logs", state_dir=tmp_path / "state", waivers_path=tmp_path / "waivers.yaml",
        reviewer_name="",
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
        ctx.facts = device_facts(ctx.raw_lines)
        ctx.waivers = WaiverStore(settings.waivers_path).load()  # as the real audit_config does
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


SKIP = json.dumps({"skip": True})


def run_ws(client: TestClient, payload: dict, answers: list) -> list[dict]:
    """Drive one run over the WebSocket. Each answer is a string or a function of the question."""
    messages = []
    with client.websocket_connect("/ws/run", headers=ORIGIN) as ws:
        ws.send_json({"action": "start", **payload})
        while True:
            msg = ws.receive_json()
            messages.append(msg)
            if msg["type"] == "question":
                answer = answers.pop(0)
                ws.send_json({"action": "answer", "text": answer(msg) if callable(answer) else answer})
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
    msgs = run_ws(client, {"mode": "audit", "configs": ["fixtures/r03-mgmt-plane.cfg"]}, [SKIP])
    types = [m["type"] for m in msgs]
    assert types[:3] == ["run_start", "audit_start", "item"]
    assert msgs[2]["record"]["type"] == "TextMessage" and msgs[2]["record"]["data"]["source"] == "Critic"
    end = next(m for m in msgs if m["type"] == "audit_end")["result"]
    assert end["device"] == "BR-R03" and end["counts"]["FAIL"] == 3
    assert end["facts"]["platform"] == "C8200-1N-4T" and end["assessment"]["rating"] == "Critical"
    # the fake only fixes CG-007, so the audit is not AI-approved: review offered, but no fix is approvable
    question = next(m for m in msgs if m["type"] == "question")
    assert question["kind"] == "review"
    items = question["payload"]["devices"][0]["items"]
    assert [i["rule_id"] for i in items] == ["CG-001", "CG-007", "CG-012"]
    assert not any(i["fix_eligible"] for i in items)
    run_end = msgs[-1]
    assert run_end["type"] == "run_end" and not run_end["all_approved"]
    assert any(p.endswith("BR-R03.md") for p in run_end["written"])

    audits = client.get("/api/audits").json()
    assert len(audits) == 1 and audits[0]["device"] == "BR-R03" and audits[0]["status"] == "not_approved"
    assert audits[0]["rating"] == "Critical" and audits[0]["reviewed"] is False
    detail = client.get(f"/api/audits/{audits[0]['audit_id']}").json()
    assert detail["resumable"] and len(detail["findings"]) == 14 and detail["timeline"]
    assert detail["outputs"] == ["report"] and detail["finding_ids"]["CG-001"] == "F-01"
    assert detail["status_labels"]["CG-001"] == "Open - pending review"
    assert detail["frameworks"]["CG-001"]["PCI DSS v4.0"] == ["2.2.7"]
    report = client.get(f"/api/audits/{audits[0]['audit_id']}/report")
    assert report.status_code == 200 and report.text.startswith("# Network Device Security Compliance Audit Report")


def test_invalid_review_is_re_asked_with_errors(client: TestClient, settings: Settings, tmp_path: Path) -> None:
    app_client = _http_only_client(settings, tmp_path)

    def bad(msg):
        audit_id = msg["payload"]["devices"][0]["audit_id"]
        return json.dumps({"reviewer": "", "decisions": {audit_id: {"CG-007": {"action": "approve_fix"}}}})

    msgs = run_ws(app_client, {"mode": "audit", "configs": ["fixtures/http-only.cfg"]}, [bad, SKIP])
    questions = [m for m in msgs if m["type"] == "question"]
    assert len(questions) == 2 and any("reviewer name is required" in e for e in questions[1]["payload"]["errors"])


def test_batch_with_overwrite_in_review(client: TestClient, settings: Settings) -> None:
    payload = {"mode": "batch", "configs": ["fixtures/r01-compliant.cfg", "fixtures/r10-mixed.cfg"]}
    first = run_ws(client, payload, [SKIP])
    assert [m["type"] for m in first].count("audit_end") == 2
    second = run_ws(client, payload, [json.dumps({"skip": True, "overwrite": True})])
    question = next(m for m in second if m["type"] == "question")
    assert set(question["payload"]["existing_reports"]) == {"EDGE-R01", "EDGE-R10"}
    assert {d["device"] for d in question["payload"]["devices"]} == {"EDGE-R01", "EDGE-R10"}
    assert not any(p.endswith("-" + d["audit_id"] + ".md") for d in question["payload"]["devices"]
                   for p in second[-1]["written"])  # overwritten in place, no side-by-side copies


def _http_only_client(settings: Settings, tmp_path: Path) -> TestClient:
    """A config whose only violation is CG-007, which the fake remediates -> AI-approved, fix approvable."""
    only_http = (settings.configs_dir / "r01-compliant.cfg").read_text().replace("no ip http server", "ip http server")
    custom = tmp_path / "configs"
    custom.mkdir(exist_ok=True)
    (custom / "http-only.cfg").write_text(only_http)
    return TestClient(web_app.create_app(dataclasses.replace(settings, configs_dir=custom), allowed_hosts=["testserver"]))


def test_per_finding_approval_exports_only_approved_fix(client: TestClient, settings: Settings, tmp_path: Path) -> None:
    app_client = _http_only_client(settings, tmp_path)

    def approve(msg):
        audit_id = msg["payload"]["devices"][0]["audit_id"]
        return json.dumps({"reviewer": "Jane Doe", "ticket": "CHG0012345",
                           "decisions": {audit_id: {"CG-007": {"action": "approve_fix", "comment": "ok"}}}})

    msgs = run_ws(app_client, {"mode": "audit", "configs": ["fixtures/http-only.cfg"]}, [approve])
    question = next(m for m in msgs if m["type"] == "question")
    assert question["payload"]["devices"][0]["items"][0]["fix_eligible"] is True
    assert msgs[-1]["all_approved"] and any("remediation.txt" in p for p in msgs[-1]["written"])
    audit_id = msgs[-1]["audit_ids"][0]
    script = app_client.get(f"/api/audits/{audit_id}/remediation")
    assert script.status_code == 200 and "Fixes approved by: Jane Doe" in script.text and "CHG0012345" in script.text
    detail = app_client.get(f"/api/audits/{audit_id}").json()
    assert detail["decisions"]["CG-007"]["action"] == "approve_fix" and detail["reviewed"] is True
    assert detail["status_labels"]["CG-007"] == "Open - fix approved"


# --------------------------------------------------------------------------- views, dashboard, waivers


def test_config_view_is_masked_with_highlights(client: TestClient) -> None:
    msgs = run_ws(client, {"mode": "audit", "configs": ["fixtures/r10-mixed.cfg"]}, [SKIP])
    audit_id = msgs[-1]["audit_ids"][0]
    view = client.get(f"/api/audits/{audit_id}/view/config").json()
    blob = json.dumps(view)
    assert view["available"] and "$9$" not in blob and "<MASKED" in blob
    snmp_line = next(n for n, line in enumerate(view["lines"], 1) if line.startswith("snmp-server host"))
    assert any(h["rule_id"] == "CG-006" for h in view["highlights"][str(snmp_line)])


def test_remediation_preview_diff(client: TestClient) -> None:
    msgs = run_ws(client, {"mode": "audit", "configs": ["fixtures/r10-mixed.cfg"]}, [SKIP])
    audit_id = msgs[-1]["audit_ids"][0]
    preview = client.get(f"/api/audits/{audit_id}/view/preview").json()
    assert preview["available"] and preview["rules"] == ["CG-007"]
    assert "-ip http server" in preview["diff"] and "+no ip http server" in preview["diff"]
    assert client.get(f"/api/audits/{audit_id}/view/preview?scope=approved").json()["rules"] == []
    assert client.get(f"/api/audits/{audit_id}/view/preview?scope=bogus").status_code == 400


def test_config_view_unavailable_when_file_changed(client: TestClient, settings: Settings, tmp_path: Path) -> None:
    app_client = _http_only_client(settings, tmp_path)
    msgs = run_ws(app_client, {"mode": "audit", "configs": ["fixtures/http-only.cfg"]}, [SKIP])
    (tmp_path / "configs" / "http-only.cfg").write_text("hostname CHANGED\n")
    view = app_client.get(f"/api/audits/{msgs[-1]['audit_ids'][0]}/view/config").json()
    assert view == {"available": False, "reason": "the config file has changed since this audit"}


def test_dashboard_aggregates_latest_audit_per_device(client: TestClient) -> None:
    run_ws(client, {"mode": "batch", "configs": ["fixtures/r01-compliant.cfg", "fixtures/r03-mgmt-plane.cfg"]}, [SKIP])
    run_ws(client, {"mode": "audit", "configs": ["fixtures/r03-mgmt-plane.cfg"]}, [SKIP])  # second audit of BR-R03
    dash = client.get("/api/dashboard").json()
    assert dash["fleet"]["devices"] == 2 and dash["fleet"]["audits"] == 3
    assert dash["ratings"]["Critical"] == 1 and dash["ratings"]["Compliant"] == 1
    assert dash["fleet"]["score"] == round((100.0 + 71.0) / 2, 1)
    assert dash["fleet"]["open_by_severity"] == {"critical": 1, "high": 1, "medium": 1, "low": 0}
    assert dash["top_controls"][0]["id"] == "CG-001" and dash["top_controls"][0]["failing_devices"] == 1
    br = next(d for d in dash["devices"] if d["device"] == "BR-R03")
    assert br["statuses"]["CG-001"] == "FAIL" and br["needs_review"] and br["platform"] == "C8200-1N-4T"
    assert len(dash["trend"]) == 3 and dash["fleet"]["pending_reviews"] == 1


def test_history_review_creates_waiver_and_revoke(client: TestClient, settings: Settings) -> None:
    msgs = run_ws(client, {"mode": "audit", "configs": ["fixtures/r03-mgmt-plane.cfg"]}, [SKIP])
    audit_id = msgs[-1]["audit_ids"][0]
    body = {"reviewer": "Jane Doe", "decisions": {audit_id: {
        "CG-012": {"action": "accept_risk", "comment": "Console in a locked room", "expires": "2099-01-01"}}}}
    assert client.post(f"/api/audits/{audit_id}/review", json=body).status_code == 403  # no Origin
    bad = client.post(f"/api/audits/{audit_id}/review", json=body, headers=ORIGIN)
    assert bad.status_code == 422 and any("within" in e for e in bad.json()["errors"])
    from datetime import date, timedelta

    body["decisions"][audit_id]["CG-012"]["expires"] = (date.today() + timedelta(days=30)).isoformat()
    ok = client.post(f"/api/audits/{audit_id}/review", json=body, headers=ORIGIN)
    assert ok.status_code == 200 and ok.json()["assessment"]["effective"]["CG-012"] == "RISK_ACCEPTED"

    waivers = client.get("/api/waivers").json()
    assert [(w["device"], w["rule_id"], w["active"]) for w in waivers] == [("BR-R03", "CG-012", True)]
    # the waiver carries over to the next audit of the same device
    nxt = run_ws(client, {"mode": "audit", "configs": ["fixtures/r03-mgmt-plane.cfg"]}, [SKIP])
    assert next(m for m in nxt if m["type"] == "audit_end")["result"]["assessment"]["effective"]["CG-012"] == "RISK_ACCEPTED"

    assert client.delete("/api/waivers/BR-R03/CG-012").status_code == 403  # no Origin
    assert client.delete("/api/waivers/BR-R03/CG-012", headers=ORIGIN).json() == {"ok": True}
    assert client.delete("/api/waivers/BR-R03/CG-012", headers=ORIGIN).status_code == 404
    assert client.delete("/api/waivers/..%2Fx/CG-012", headers=ORIGIN).status_code in (400, 404, 405)  # never routed
    assert client.delete("/api/waivers/bad name/CG-012", headers=ORIGIN).status_code == 400
    assert client.delete("/api/waivers/BR-R03/DROP", headers=ORIGIN).status_code == 400
    assert client.get("/api/waivers").json() == []
