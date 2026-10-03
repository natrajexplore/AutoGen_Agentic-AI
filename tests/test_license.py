# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Nataraj Angappan
"""Licensing stays complete: canonical GPL text, SPDX headers, notices, and in-product legal notices."""

from __future__ import annotations

import dataclasses
import hashlib
import re
import tomllib

import pytest
from fastapi.testclient import TestClient

from conftest import ROOT

SPDX = "SPDX-License-Identifier: GPL-3.0-or-later"
GPL3_SHA256 = "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986"  # gnu.org/licenses/gpl-3.0.txt


def test_license_file_is_the_unmodified_gpl3_text() -> None:
    data = (ROOT / "LICENSE").read_bytes()
    assert hashlib.sha256(data).hexdigest() == GPL3_SHA256


def test_package_metadata_declares_the_license() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["license"] == "GPL-3.0-or-later"
    assert set(project["license-files"]) == {"LICENSE", "THIRD_PARTY_NOTICES.md"}
    assert project["authors"][0]["name"] == "Nataraj Angappan"


def _source_files():
    yield ROOT / "main.py"
    yield from (ROOT / "src" / "configguard").rglob("*.py")
    yield from (ROOT / "tests").rglob("*.py")
    yield from (ROOT / "src" / "configguard" / "web" / "static").glob("*.*")


@pytest.mark.parametrize("path", list(_source_files()), ids=lambda p: str(p.relative_to(ROOT)))
def test_every_source_file_has_spdx_header(path) -> None:
    head = path.read_text(encoding="utf-8").splitlines()[:4]
    assert any(SPDX in line for line in head) and any("Copyright (C) 2026 Nataraj Angappan" in line for line in head)


def test_third_party_notices_cover_every_pinned_dependency() -> None:
    notices = (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8").lower()
    pinned = re.findall(r"^([a-z0-9_.\-]+)==", (ROOT / "requirements.txt").read_text(encoding="utf-8").lower(), re.M)
    missing = [p for p in pinned if f"| {p} |" not in notices and f"| {p.replace('-', '_')} |" not in notices]
    assert not missing, f"add to THIRD_PARTY_NOTICES.md: {missing}"
    assert "ciscoconfparse2 | 0.9.18 | gpl-3.0-only" in notices


def test_cli_version_shows_gnu_style_notice(capsys) -> None:
    from configguard.cli import parse_args

    with pytest.raises(SystemExit):
        parse_args(["--version"])
    out = capsys.readouterr().out
    assert "Copyright (C) 2026 Nataraj Angappan" in out and "GPL-3.0-or-later" in out and "NO WARRANTY" in out


def test_web_ui_serves_legal_notices(tmp_path) -> None:
    from configguard.config.settings import Settings
    from configguard.web.app import create_app

    settings = dataclasses.replace(Settings.from_env(), logs_dir=tmp_path / "l", state_dir=tmp_path / "s")
    client = TestClient(create_app(settings, allowed_hosts=["testserver"]))
    info = client.get("/api/info").json()
    assert info["license"] == "GPL-3.0-or-later" and info["copyright"] == "Copyright (C) 2026 Nataraj Angappan"
    lic = client.get("/api/legal/license")
    assert lic.status_code == 200 and hashlib.sha256(lic.content).hexdigest() == GPL3_SHA256
    assert "ciscoconfparse2" in client.get("/api/legal/third-party").text
    assert client.get("/api/legal/../../.env").status_code == 404
    assert client.get("/api/legal/secrets").status_code == 404
    assert 'id="legal"' in client.get("/").text
