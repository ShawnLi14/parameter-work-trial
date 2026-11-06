"""Settings from config.toml and API keys from .env, both in the project root only.

Nothing is read from the working directory, so a reviewed repository's own config.toml
or .env is never loaded.
"""

import copy
import os
from pathlib import Path
import re
import tomllib

ROOT = Path(__file__).resolve().parents[1]
ENV_PATH = ROOT / ".env"
SETTINGS_PATH = ROOT / "config.toml"
CONFIG_KEYS = {"CEREBRAS_API_KEY", "ANTHROPIC_API_KEY", "GITHUB_TOKEN", "GH_TOKEN"}

# Every setting and its default; config.toml overrides any of them.
DEFAULTS = {
    "model": {"provider": "anthropic", "name": "", "reasoning_effort": "medium", "max_tokens": 16384, "timeout": 240},
    "review": {"max_input_chars": 200_000, "record_dir": ""},
    "find_verify": {"finder_calls": 20, "specialist_calls": 14, "verifier_calls": 12, "max_candidates": 10,
                    "concurrency": 3, "max_calls": 150, "review_timeout": 300, "max_context_chars": 300_000},
    "benchmark": {"split": "all", "timeout": 420},
    "improve": {"rounds": 3, "recall_slack": 3, "split": "all", "optimizer_model": ""},
}


def load_settings(path=None):
    """config.toml merged over DEFAULTS; unknown sections or keys are an error, not ignored."""
    path = SETTINGS_PATH if path is None else Path(path)
    settings = copy.deepcopy(DEFAULTS)
    if path.exists():
        with path.open("rb") as handle:
            values = tomllib.load(handle)
        for section, items in values.items():
            if section not in settings or not isinstance(items, dict):
                raise ValueError(f"Unknown section [{section}] in {path.name}")
            for key, value in items.items():
                if key not in settings[section]:
                    raise ValueError(f"Unknown setting {section}.{key} in {path.name}")
                if type(value) is not type(settings[section][key]):
                    raise ValueError(f"Setting {section}.{key} must be a {type(settings[section][key]).__name__}")
                settings[section][key] = value
    from .providers import PROVIDERS
    model = settings["model"]
    if model["provider"] not in PROVIDERS:
        raise ValueError(f"model.provider must be one of {sorted(PROVIDERS)}")
    model["name"] = model["name"] or PROVIDERS[model["provider"]]["model"]
    if settings["benchmark"]["split"] not in ("all", "dev", "holdout") or settings["improve"]["split"] not in ("all", "dev"):
        raise ValueError("benchmark.split must be all, dev, or holdout; improve.split must be all or dev")
    return settings


def load_environment(path=None):
    path = ENV_PATH if path is None else Path(path)
    values = {}
    if path.exists():
        for number, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            assignment = re.fullmatch(r"(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)", line)
            if not assignment:
                raise ValueError(f"Invalid .env assignment on line {number}")
            key, value = assignment.groups()
            if key not in CONFIG_KEYS:
                continue
            if value.startswith(('"', "'")):
                quoted = re.fullmatch(r"([\"'])(.*?)\1\s*(?:#.*)?", value)
                if not quoted:
                    raise ValueError(f"Invalid .env quoted value on line {number}")
                value = quoted[2]
            else:
                value = re.split(r"\s+#", value, maxsplit=1)[0].strip()
            values[key] = value
    # Process settings take precedence, including explicitly empty values.
    return values | {key: os.environ[key] for key in CONFIG_KEYS if key in os.environ}
