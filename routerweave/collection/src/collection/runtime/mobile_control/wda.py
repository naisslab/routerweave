"""Shared WebDriverAgent transport and device-level controls.

The semantic mobile adapter and IoT collectors both depend on this module so
session management, retries, request errors, and primitive gestures have one
implementation.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
import socket
import time
from typing import Any, Callable, Mapping, Protocol
import urllib.error
import urllib.request


class WdaEventLog(Protocol):
    def write(self, event: str, **data: object) -> None: ...


def corroborate_native_foreground(wda: Any, bundle_id: str, application_name: str | None,
                                  source_matches: Callable[[str], bool], log: WdaEventLog,
                                  device_id: str, event: str) -> str | None:
    """Read bounded native evidence after an ambiguous SpringBoard report.

    This performs no activation, navigation, sleep or mutating recovery.
    """
    import xml.etree.ElementTree as ET

    started = time.monotonic()
    evidence: dict[str, Any] = {"device": device_id, "started_epoch": time.time()}
    source, verified = None, False

    def remaining() -> float:
        budget = 8.0 - (time.monotonic() - started)
        if budget <= 0:
            raise TimeoutError("Foreground corroboration deadline expired")
        return budget

    try:
        evidence["app_state_before"] = wda.application_state(bundle_id, timeout=remaining())
        evidence["locked_before"] = wda.request("GET", "/wda/locked", timeout=remaining()).get("value")
        if evidence["app_state_before"] == 4 and evidence["locked_before"] is False:
            source = wda.source(timeout=remaining())
            apps = [e for e in ET.fromstring(source).iter() if e.tag == "XCUIElementTypeApplication"]
            evidence["native_application"] = apps[0].get("name") if len(apps) == 1 else None
            evidence["exact_device_page"] = source_matches(source)
            evidence["active_bundle_after"] = wda.active_bundle_id(timeout=remaining())
            evidence["app_state_after"] = wda.application_state(bundle_id, timeout=remaining())
            evidence["locked_after"] = wda.request("GET", "/wda/locked", timeout=remaining()).get("value")
            verified = bool(application_name) and (
                evidence["native_application"] == application_name
                and evidence["exact_device_page"]
                and evidence["active_bundle_after"] == bundle_id
                and evidence["app_state_after"] == 4
                and evidence["locked_after"] is False
            )
    except Exception as exc:
        evidence["error"] = repr(exc)
    evidence["elapsed_seconds"] = time.monotonic() - started
    verified = verified and evidence["elapsed_seconds"] <= 8.0
    log.write(event, **evidence, verified=verified)
    return source if verified else None


class WdaRequestError(RuntimeError):
    pass


class WdaRequestTimeout(TimeoutError):
    pass


class WdaClient:
    """HTTP/session transport used by all WDA-backed control paths."""

    def __init__(self, base_url: str, timeout_seconds: float = 20.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self._session_id: str | None = None
        self.session_settings_results: list[dict[str, Any]] = []

    def request(
        self,
        path: str,
        payload: Mapping[str, Any] | None = None,
        *,
        timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self.base_url + path,
            data=data,
            headers={"Content-Type": "application/json"},
            method="GET" if payload is None else "POST",
        )
        try:
            with urllib.request.urlopen(
                request, timeout=timeout_seconds or self.timeout_seconds
            ) as response:
                raw = response.read().decode("utf-8", errors="replace")
        except (TimeoutError, socket.timeout) as exc:
            raise WdaRequestTimeout(f"WDA request timed out for {path}: {exc}") from exc
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            try:
                error = json.loads(body).get("value", {})
                detail = f"{error.get('error', '')}: {str(error.get('message', ''))[:700]}"
            except (ValueError, AttributeError):
                detail = body[-1000:]
            raise WdaRequestError(
                f"WDA HTTP {exc.code} for {path}: {detail}"
            ) from exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, (TimeoutError, socket.timeout)):
                raise WdaRequestTimeout(
                    f"WDA request timed out for {path}: {exc}"
                ) from exc
            raise WdaRequestError(f"WDA request failed for {path}: {exc}") from exc
        try:
            body = json.loads(raw) if raw.strip() else {}
        except json.JSONDecodeError as exc:
            raise WdaRequestError(
                f"WDA returned invalid JSON for {path}: {raw[-500:]}"
            ) from exc
        value = body.get("value") if isinstance(body, dict) else None
        if isinstance(value, dict) and value.get("error"):
            raise WdaRequestError(
                f"WDA command error for {path}: {value.get('error')}: "
                f"{value.get('message', '')}"
            )
        if not isinstance(body, dict):
            raise WdaRequestError(f"WDA response for {path} is not an object")
        return body

    def session_id(self) -> str:
        if self._session_id:
            return self._session_id
        response = self.request(
            "/session",
            {
                "capabilities": {
                    "alwaysMatch": {
                        "appium:waitForQuiescence": False,
                        "appium:waitForIdleTimeout": 0,
                        "appium:animationCoolOffTimeout": 0,
                        "appium:boundElementsByIndex": True,
                    }
                },
                "desiredCapabilities": {
                    "waitForIdleTimeout": 0,
                    "shouldWaitForQuiescence": False,
                    "animationCoolOffTimeout": 0,
                    "boundElementsByIndex": True,
                },
            },
        )
        session_id = response.get("sessionId")
        if not session_id and isinstance(response.get("value"), dict):
            session_id = response["value"].get("sessionId")
        if not session_id:
            raise WdaRequestError(f"WDA session response has no session id: {response}")
        self._session_id = str(session_id)
        self.session_settings_results = self._apply_runtime_settings(self._session_id)
        return self._session_id

    def _apply_runtime_settings(self, session_id: str) -> list[dict[str, Any]]:
        """Apply the settings used by the proven long-running iOS replay path.

        Capabilities alone are not sufficient when a WDA build ignores an
        Appium-prefixed capability or an existing XCTest session supplies its
        defaults.  In particular, continuously playing video never becomes
        idle, so a pointer command may take effect and then wait forever for
        quiescence.  Keep this best-effort for compatibility with WDA builds
        that expose only one of the two settings routes.
        """

        results: list[dict[str, Any]] = []
        paths = (
            f"/session/{session_id}/appium/settings",
            f"/session/{session_id}/settings",
        )
        for key, value in (
            ("snapshotMaxDepth", 1),
            ("waitForIdleTimeout", 0),
            ("animationCoolOffTimeout", 0),
        ):
            errors: list[str] = []
            for path in paths:
                try:
                    self.request(
                        path,
                        {"settings": {key: value}},
                        timeout_seconds=5.0,
                    )
                    results.append(
                        {"setting": key, "value": value, "ok": True, "path": path}
                    )
                    break
                except Exception as exc:
                    errors.append(f"{path}: {type(exc).__name__}: {exc}")
            else:
                results.append(
                    {"setting": key, "value": value, "ok": False, "errors": errors}
                )
        return results

    def reset_session(self) -> str | None:
        """Forget the current client-side session and return its identifier.

        WDA owns only one active XCTest session on the test phone.  Creating a
        fresh session on the next request replaces a gesture channel whose
        `/actions` endpoint may still return success while no longer delivering
        touch events.  The target application process is not terminated.
        """

        previous = self._session_id
        self._session_id = None
        return previous

    def refresh_session(self) -> tuple[str | None, str]:
        previous = self.reset_session()
        return previous, self.session_id()

    def session_request(
        self,
        path: str,
        payload: Mapping[str, Any] | None = None,
        *,
        timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        for attempt in range(2):
            session_id = self.session_id()
            try:
                return self.request(
                    f"/session/{session_id}{path}",
                    payload,
                    timeout_seconds=timeout_seconds,
                )
            except WdaRequestError as exc:
                if attempt or "invalid session id" not in str(exc).casefold():
                    raise
                self.reset_session()
        raise WdaRequestError("WDA session retry exhausted")

    def attach_current_session(self) -> str:
        """Reuse the ready device session without replacing its gesture channel."""
        response = self.request("/status")
        session_id = response.get("sessionId")
        if response.get("value", {}).get("ready") is not True or not session_id:
            raise WdaRequestError("WDA has no ready current session to attach")
        self._session_id = str(session_id)
        return self._session_id


class WdaDeviceController:
    """Reusable app lifecycle, source, element, and gesture primitives."""

    def __init__(
        self,
        base_url: str,
        log: WdaEventLog | None = None,
        *,
        timeout_seconds: float = 40.0,
        client: WdaClient | None = None,
        snapshot_max_depth: int = 50,
    ) -> None:
        if not isinstance(snapshot_max_depth, int) or not 1 <= snapshot_max_depth <= 100:
            raise ValueError("snapshot_max_depth must be an integer between 1 and 100")
        self.log = log
        self.snapshot_max_depth = snapshot_max_depth
        self.client = client or WdaClient(base_url, timeout_seconds)
        self._ensure_session()

    def _write(self, event: str, **data: object) -> None:
        if self.log is not None:
            self.log.write(event, **data)

    def _ensure_session(self) -> str:
        session_id = self.client.session_id()
        self._write("wda_session_created", session_id=session_id)
        try:
            self.client.session_request(
                "/appium/settings",
                {
                    "settings": {
                        "snapshotMaxDepth": self.snapshot_max_depth,
                        "waitForIdleTimeout": 0,
                        "animationCoolOffTimeout": 0,
                    }
                },
            )
            self._write("wda_snapshot_settings", snapshot_max_depth=self.snapshot_max_depth)
        except Exception as exc:
            self._write("wda_settings_failed", error=repr(exc))
        return session_id

    def request(
        self,
        method: str,
        path: str,
        payload: Mapping[str, Any] | None = None,
        timeout: int = 40,
    ) -> dict[str, Any]:
        normalized = method.upper()
        if normalized == "POST" and payload is None:
            payload = {}
        if normalized not in {"GET", "POST"}:
            raise ValueError(f"unsupported WDA method {method!r}")
        return self.client.session_request(
            path,
            payload,
            timeout_seconds=float(timeout),
        )

    def launch(self, bundle_id: str) -> None:
        self.request("POST", "/wda/apps/launch", {"bundleId": bundle_id})

    def terminate(self, bundle_id: str) -> None:
        self.request("POST", "/wda/apps/terminate", {"bundleId": bundle_id})

    def source(self, *, timeout: float = 40) -> str:
        return str(self.request("GET", "/source", timeout=timeout).get("value") or "")

    def active_bundle_id(self, *, timeout: float = 40) -> str:
        result = self.request("GET", "/wda/activeAppInfo", timeout=timeout)
        value = result.get("value") or {}
        return str(value.get("bundleId") or "") if isinstance(value, dict) else ""

    def application_state(self, bundle_id: str, *, timeout: float = 40) -> int | None:
        """Read XCTest application state (4 means running in foreground)."""
        value = self.request("POST", "/wda/apps/state", {"bundleId": bundle_id}, timeout=timeout).get("value")
        return value if type(value) is int and 0 <= value <= 4 else None

    def press_home(self) -> None:
        self.request("POST", "/wda/pressButton", {"name": "home"})

    def lock(self) -> None:
        self.request("POST", "/wda/lock", {})

    def unlock(self) -> None:
        self.request("POST", "/wda/unlock", {})

    def is_locked(self) -> bool:
        return self.request("GET", "/wda/locked").get("value") is True

    def tap(self, point: Mapping[str, Any]) -> None:
        self._pointer_gesture(point, point, hold_ms=80, move_ms=0)

    def long_press(
        self, point: Mapping[str, Any], duration_seconds: float = 0.9
    ) -> None:
        self._pointer_gesture(
            point, point, hold_ms=max(1, int(duration_seconds * 1000)), move_ms=0
        )

    def drag(
        self,
        start: Mapping[str, Any],
        end: Mapping[str, Any],
        duration_seconds: float = 0.8,
    ) -> None:
        self._pointer_gesture(
            start,
            end,
            hold_ms=120,
            move_ms=max(1, int(duration_seconds * 1000)),
        )

    def _pointer_gesture(
        self,
        start: Mapping[str, Any],
        end: Mapping[str, Any],
        *,
        hold_ms: int,
        move_ms: int,
    ) -> None:
        actions = [
            {
                "type": "pointerMove",
                "duration": 0,
                "x": int(start["x"]),
                "y": int(start["y"]),
            },
            {"type": "pointerDown", "button": 0},
            {"type": "pause", "duration": hold_ms},
        ]
        if start != end:
            actions.append(
                {
                    "type": "pointerMove",
                    "duration": move_ms,
                    "x": int(end["x"]),
                    "y": int(end["y"]),
                }
            )
        actions.append({"type": "pointerUp", "button": 0})
        self.request(
            "POST",
            "/actions",
            {
                "actions": [
                    {
                        "type": "pointer",
                        "id": "finger",
                        "parameters": {"pointerType": "touch"},
                        "actions": actions,
                    }
                ]
            },
        )

    def click_accessibility(self, name: str) -> None:
        result = self.request(
            "POST", "/element", {"using": "accessibility id", "value": name}
        )
        value = result.get("value") or {}
        element_id = (
            value.get("element-6066-11e4-a52e-4f735466cecf")
            or value.get("ELEMENT")
            if isinstance(value, dict)
            else None
        )
        if not element_id:
            raise WdaRequestError(
                f"WDA did not return an element id for accessibility name {name!r}"
            )
        self.request("POST", f"/element/{element_id}/click", {})

    def screenshot(self, path: Path) -> None:
        value = self.request("GET", "/screenshot").get("value")
        if not isinstance(value, str) or not value:
            raise WdaRequestError("WDA did not return screenshot data")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(base64.b64decode(value))
