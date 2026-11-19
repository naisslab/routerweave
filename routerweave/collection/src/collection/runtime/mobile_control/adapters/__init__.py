"""Concrete platform adapters that expose the shared capability contract."""

from .android import AndroidAdbAdapter
from .ios import IosWdaAdapter

__all__ = ["AndroidAdbAdapter", "IosWdaAdapter"]
