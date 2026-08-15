"""Configuration management for Reconk CLI.

Loads `config/config.yaml` from the project root (falls back to sane
defaults). Everything tool-path related lives here so the user can adapt
the orchestrator to their own machine.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "config.yaml"
DEFAULT_HOME_CONFIG_PATH = Path("~/.config/reconk/config.yaml").expanduser()

# --------------------------------------------------------------------------- #
# Defaults (used when the YAML file is missing a key)
# --------------------------------------------------------------------------- #

DEFAULTS: Dict[str, Any] = {
    "output": {
        # Default base directory: ~/Documents/bugbounty/reconk/
        "base_dir": "~/Documents/bugbounty/reconk",
    },
    "tools": {
        "resolvers": "~/.config/reconk/resolvers.txt",
        "subdomain_wordlist": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "permutation_wordlist": "/usr/share/seclists/Discovery/DNS/deepmagic.com-prefixes-top500.txt",
        "subfinder_config": "~/.config/subfinder/provider-config.yaml",
    },
    "api_keys": {
        # Optional API keys for extra harvesting sources (empty = disabled)
        "urlscan": "",
        "virustotal": "",
        "github_token": "",
    },
    "scan": {
        # Port scan scope: naabu -top-ports value
        "naabu_top_ports": "1000",
        # httpx concurrency
        "httpx_threads": "100",
        # Katana JS crawl depth
        "katana_depth": "3",
        # DNS brute wordlist size: small | medium | large
        "brute_size": "small",
        # subfinder: query ALL sources (slow, rate-limited) or only the
        # default high-quality set (fast). true | false
        "subfinder_all": "false",
    },
}


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge `override` into `base` (override wins)."""
    out = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


class Config:
    """Loaded configuration with dot-access helpers."""

    def __init__(self, data: Dict[str, Any], path: Optional[Path] = None):
        self._data = data
        self.path = path

    # ------------------------------------------------------------------ #
    # Loading
    # ------------------------------------------------------------------ #
    @classmethod
    def load(cls, path: Optional[str] = None) -> "Config":
        """Load config from project file, then user config (user wins)."""
        data = yaml.safe_load(DEFAULT_CONFIG_PATH.read_text()) if DEFAULT_CONFIG_PATH.exists() else {}
        merged = _deep_merge(DEFAULTS, data or {})
        if DEFAULT_HOME_CONFIG_PATH.exists():
            user = yaml.safe_load(DEFAULT_HOME_CONFIG_PATH.read_text()) or {}
            merged = _deep_merge(merged, user)
        if path:
            custom = Path(path).expanduser()
            if not custom.exists():
                raise FileNotFoundError(f"Config file not found: {custom}")
            merged = _deep_merge(merged, yaml.safe_load(custom.read_text()) or {})
        return cls(merged, path=Path(path) if path else None)

    @classmethod
    def defaults(cls) -> "Config":
        return cls(_deep_merge(DEFAULTS, {}))

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def get(self, key: str, default: Any = None) -> Any:
        """Dot-notation getter: cfg.get('tools.dns_recon')."""
        node: Any = self._data
        for part in key.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    @property
    def data(self) -> Dict[str, Any]:
        return self._data

    def output_base_dir(self) -> Path:
        return Path(self.get("output.base_dir", DEFAULTS["output"]["base_dir"])).expanduser()

    def tool_path(self, key: str) -> Path:
        return Path(os.path.expanduser(str(self.get(f"tools.{key}"))))

    def tool_exists(self, key: str) -> bool:
        return self.tool_path(key).exists()

    def save(self, path: Optional[Path] = None) -> Path:
        dest = path or DEFAULT_HOME_CONFIG_PATH
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(yaml.safe_dump(self._data, sort_keys=False))
        return dest
