"""Load simple dotenv assignments from the reviewer's own project root only."""

import os
from pathlib import Path
import re

ENV_PATH = Path(__file__).resolve().parents[1] / ".env"
CONFIG_KEYS = {"OPENROUTER_API_KEY", "CEREBRAS_API_KEY", "REVIEW_PROVIDER", "REVIEW_MODEL", "GITHUB_TOKEN", "GH_TOKEN"}


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
