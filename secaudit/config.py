"""Configuration: file (~/.config/secaudit/config.toml), env vars and paths."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


def _xdg(var: str, default: str) -> Path:
    return Path(os.environ.get(var) or Path.home() / default)


CONFIG_PATH = _xdg("XDG_CONFIG_HOME", ".config") / "secaudit" / "config.toml"
DATA_DIR = _xdg("XDG_DATA_HOME", ".local/share") / "secaudit"
CACHE_DIR = _xdg("XDG_CACHE_HOME", ".cache") / "secaudit"


@dataclass
class Config:
    history_dir: Path = field(default_factory=lambda: DATA_DIR / "history")
    cache_dir: Path = CACHE_DIR
    timeout: float = 15.0
    nvd_api_key: str | None = None
    ollama_url: str = "http://localhost:11434"
    ollama_model: str | None = None
    max_cves_per_product: int = 200

    @classmethod
    def load(cls) -> "Config":
        cfg = cls()
        if CONFIG_PATH.exists():
            with CONFIG_PATH.open("rb") as fh:
                raw = tomllib.load(fh)
            for key, value in raw.items():
                if hasattr(cfg, key):
                    if key in ("history_dir", "cache_dir"):
                        value = Path(value).expanduser()
                    setattr(cfg, key, value)
        cfg.nvd_api_key = os.environ.get("NVD_API_KEY", cfg.nvd_api_key)
        if os.environ.get("OLLAMA_HOST"):
            host = os.environ["OLLAMA_HOST"]
            cfg.ollama_url = host if host.startswith("http") else f"http://{host}"
        cfg.ollama_model = os.environ.get("SECAUDIT_OLLAMA_MODEL", cfg.ollama_model)
        if os.environ.get("SECAUDIT_HISTORY_DIR"):
            cfg.history_dir = Path(os.environ["SECAUDIT_HISTORY_DIR"]).expanduser()
        return cfg
