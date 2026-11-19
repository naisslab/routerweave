"""Session-owned debugger state, independent of reloadable behavior code."""

from pathlib import Path
from typing import Any


class EdgeCommandTimeout(TimeoutError):
    """An uncertain command reply; a verified live socket remains reusable."""


# This module is never reloaded while the retained session is running.
_BROWSER_CONNECTIONS: dict[str, Any] = {}
_RETAINED_CONNECTIONS: dict[str, int] = {}
_SESSION_ENDPOINTS: dict[Path, str] = {}
