"""Cross-platform semantic mobile task control.

This package deliberately does not import the historical capture runtimes.  It
defines the stable task-control boundary that platform adapters implement.
"""

from .binding import ActionBinding, ActionStrategy, AppBinding
from .catalog import MobileAppCatalog, RegisteredApp
from .engine import PlaybookRunner
from .platform import MobilePlatformAdapter
from .playbook import Playbook, Step
from .status import ActionMethod, Idempotency, OutcomeStatus

__all__ = [
    "ActionBinding",
    "ActionMethod",
    "ActionStrategy",
    "AppBinding",
    "Idempotency",
    "MobilePlatformAdapter",
    "MobileAppCatalog",
    "OutcomeStatus",
    "Playbook",
    "PlaybookRunner",
    "RegisteredApp",
    "Step",
]
