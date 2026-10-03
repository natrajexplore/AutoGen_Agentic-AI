"""Runtime settings, read from environment / .env. No secrets are stored on this object."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def _path(name: str, default: Path) -> Path:
    return Path(os.getenv(name, default)).resolve()


@dataclass(frozen=True)
class Settings:
    model_provider: str  # openai | anthropic | ollama
    model: str
    ollama_host: str
    baseline_path: Path
    max_messages: int
    # USD per 1M tokens, for cost tracking. Defaults are gpt-4o list prices; override in .env.
    price_input_per_mtok: float
    price_output_per_mtok: float
    reports_dir: Path
    remediation_dir: Path
    logs_dir: Path
    state_dir: Path
    configs_dir: Path  # configs offered in the web UI (default: the test fixtures)
    uploads_dir: Path  # configs uploaded through the web UI

    @classmethod
    def from_env(cls) -> Settings:
        load_dotenv(PROJECT_ROOT / ".env")
        return cls(
            model_provider=os.getenv("MODEL_PROVIDER", "openai").lower(),
            model=os.getenv("MODEL", "gpt-4o"),
            ollama_host=os.getenv("OLLAMA_HOST", "http://localhost:11434"),
            baseline_path=_path("BASELINE_PATH", PROJECT_ROOT / "baselines" / "cisco_ios_v1.yaml"),
            max_messages=int(os.getenv("MAX_MESSAGES", "25")),
            price_input_per_mtok=float(os.getenv("PRICE_INPUT_PER_MTOK", "2.50")),
            price_output_per_mtok=float(os.getenv("PRICE_OUTPUT_PER_MTOK", "10.00")),
            reports_dir=_path("REPORTS_DIR", PROJECT_ROOT / "reports"),
            remediation_dir=_path("REMEDIATION_DIR", PROJECT_ROOT / "remediation"),
            logs_dir=_path("LOGS_DIR", PROJECT_ROOT / "logs"),
            state_dir=_path("STATE_DIR", PROJECT_ROOT / "state"),
            configs_dir=_path("CONFIGS_DIR", PROJECT_ROOT / "tests" / "fixtures"),
            uploads_dir=_path("UPLOADS_DIR", PROJECT_ROOT / "uploads"),
        )
