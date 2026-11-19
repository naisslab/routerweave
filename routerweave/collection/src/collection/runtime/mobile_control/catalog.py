"""Normalized view of the repository's registered mobile applications."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .status import Platform


_CATEGORY_ALIASES = {"content": "browsing"}


@dataclass(frozen=True, slots=True)
class RegisteredApp:
    name: str
    display_name: str
    platform: Platform
    app_id: str
    task_family: str
    process_name: str = ""


class MobileAppCatalog:
    """Read identities from the existing platform registries without copying them."""

    def __init__(
        self,
        apps: tuple[RegisteredApp, ...],
        aliases: Mapping[str, str] | None = None,
        profiles: Mapping[tuple[Platform, str], Mapping[str, Any]] | None = None,
    ):
        self.apps = apps
        self.aliases = dict(aliases or {})
        self._by_key = {(app.platform, app.name): app for app in apps}
        self._profiles = dict(profiles or {})
        if len(self._by_key) != len(apps):
            raise ValueError("duplicate platform/app names in mobile app catalog")

    @classmethod
    def from_repository(cls, repository_root: Path | None = None) -> "MobileAppCatalog":
        root = repository_root or Path(__file__).resolve().parents[4]
        android = cls._read_json(root / "configs" / "android_app_profiles.json")
        ios = cls._read_json(root / "configs" / "ios_app_profiles.json")
        apps: list[RegisteredApp] = []
        aliases: dict[str, str] = {}
        profiles: dict[tuple[Platform, str], Mapping[str, Any]] = {}
        for name, raw in cls._profiles(android).items():
            app_id = str(raw.get("package") or "").strip()
            if not app_id:
                continue
            apps.append(cls._normalize(name, raw, Platform.ANDROID, app_id))
            profiles[(Platform.ANDROID, name)] = raw
        for name, raw in cls._profiles(ios).items():
            alias_for = str(raw.get("alias_for") or "").strip()
            if alias_for:
                aliases[f"{Platform.IOS.value}:{name}"] = alias_for
                continue
            app_id = str(raw.get("bundle_id") or "").strip()
            if not app_id:
                continue
            apps.append(cls._normalize(name, raw, Platform.IOS, app_id))
            profiles[(Platform.IOS, name)] = raw
        return cls(
            tuple(sorted(apps, key=lambda item: (item.name, item.platform.value))),
            aliases,
            profiles,
        )

    def require(self, platform: Platform, name: str) -> RegisteredApp:
        normalized = name.strip().casefold()
        alias = self.aliases.get(f"{platform.value}:{normalized}")
        if alias:
            normalized = alias
        try:
            return self._by_key[(platform, normalized)]
        except KeyError as exc:
            raise KeyError(f"unknown {platform.value} app {name!r}") from exc

    def profile(self, platform: Platform, name: str) -> Mapping[str, Any]:
        """Return the existing registry profile used as binding evidence."""

        app = self.require(platform, name)
        try:
            return self._profiles[(platform, app.name)]
        except KeyError as exc:
            raise KeyError(f"profile is unavailable for {platform.value}:{app.name}") from exc

    @staticmethod
    def _read_json(path: Path) -> Mapping[str, Any]:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"cannot read mobile app registry {path}: {exc}") from exc
        if not isinstance(raw, dict):
            raise ValueError(f"mobile app registry {path} must contain an object")
        return raw

    @staticmethod
    def _profiles(document: Mapping[str, Any]) -> Mapping[str, Mapping[str, Any]]:
        raw = document.get("apps")
        if not isinstance(raw, dict):
            raise ValueError("mobile app registry is missing an apps object")
        return {
            str(name).strip().casefold(): profile
            for name, profile in raw.items()
            if isinstance(profile, dict)
        }

    @staticmethod
    def _normalize(
        name: str,
        raw: Mapping[str, Any],
        platform: Platform,
        app_id: str,
    ) -> RegisteredApp:
        category = str(raw.get("category") or "").strip().casefold()
        family = _CATEGORY_ALIASES.get(category, category)
        if family not in {
            "music",
            "browsing",
            "short_video",
            "long_video",
            "live_stream",
        }:
            raise ValueError(f"unsupported task family {category!r} for {platform.value}:{name}")
        return RegisteredApp(
            name=name,
            display_name=str(raw.get("display_name") or name),
            platform=platform,
            app_id=app_id,
            task_family=family,
            process_name=str(raw.get("process_name") or ""),
        )
