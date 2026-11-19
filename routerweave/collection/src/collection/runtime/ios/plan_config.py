"""Read local equipment settings referenced by an IoT plan."""

import json
import os
import re
from pathlib import Path


def load_plan(path):
    def expand(value):
        if isinstance(value, dict):
            return {key: expand(item) for key, item in value.items()}
        if isinstance(value, list):
            return [expand(item) for item in value]
        if isinstance(value, str):
            return re.sub(r"\$\{([A-Z][A-Z0-9_]*)\}", lookup, value)
        return value

    def lookup(match):
        key = match[1]
        if not os.environ.get(key):
            raise ValueError(f"Set {key} for {Path(path).name}")
        return os.environ[key]

    return expand(json.loads(Path(path).read_text(encoding="utf-8-sig")))
