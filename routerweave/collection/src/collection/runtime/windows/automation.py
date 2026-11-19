"""Plan-driven Windows desktop activity execution.

The automation intentionally supports a small, auditable action vocabulary.
Plans own category selection, targets, timing, and action weights; the runner
owns input delivery and timestamped evidence.
"""

from __future__ import annotations

import ctypes
import copy
import json
import os
import platform
import random
import shutil
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

from .semantic import FAMILIES, run_windows_task


SUPPORTED_ACTIONS = {
    "idle_read",
    "scroll_down",
    "scroll_up",
    "page_down",
    "page_up",
    "tab",
    "enter",
    "back",
    "mouse_move",
    "left_click",
    "search_web",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat()


def _weighted_choice(rng: random.Random, rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not rows:
        raise ValueError("Cannot choose from an empty plan list.")
    weights = [max(0.0, float(row.get("weight", 1))) for row in rows]
    if sum(weights) <= 0:
        raise ValueError("At least one plan item must have a positive weight.")
    return rng.choices(rows, weights=weights, k=1)[0]


def load_plan(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    validate_plan(payload)
    return payload


def prepared_edge_profile_dir() -> Path:
    """Persistent, dedicated Edge profile for operator-prepared service logins."""

    local_app_data = os.environ.get("LOCALAPPDATA")
    base = Path(local_app_data) if local_app_data else Path.home() / "AppData" / "Local"
    return (base / "Testbed" / "ScreenTimeEdge").resolve()


def select_plan_window(
    plan: dict[str, Any], *, category_id: str, target_name: str,
    session_seconds: float, minimum_accepted_seconds: float,
    foreground_match_min_ratio: float = 0.9,
    require_media_probe: bool = False, media_poll_seconds: float = 0,
) -> dict[str, Any]:
    """Compile one existing category/target into a sustained Windows session."""

    if not category_id or not target_name:
        raise ValueError("targeted Windows sessions require category and target")
    if session_seconds <= 0 or minimum_accepted_seconds <= 0:
        raise ValueError("targeted session and accepted durations must be positive")
    if minimum_accepted_seconds > session_seconds:
        raise ValueError("minimum accepted duration cannot exceed session duration")
    if not 0 <= foreground_match_min_ratio <= 1:
        raise ValueError("foreground match ratio must be between zero and one")
    if media_poll_seconds < 0 or (media_poll_seconds and not require_media_probe):
        raise ValueError("media polling requires a required media probe")
    selected = copy.deepcopy(plan)
    categories = [row for row in selected["categories"] if row["id"] == category_id]
    if len(categories) != 1:
        raise ValueError(f"unknown Windows category {category_id!r}")
    category = categories[0]
    targets = [row for row in category["targets"] if row["name"] == target_name]
    if len(targets) != 1:
        raise ValueError(f"unknown target {target_name!r} in {category_id!r}")
    category["targets"] = targets
    category["session_min_seconds"] = session_seconds
    category["session_max_seconds"] = session_seconds
    # Address-bar search and browser back can leave the selected service.
    # Sustained target sessions keep only actions that preserve its page host.
    category["actions"] = [
        action for action in category["actions"]
        if action.get("type") in {
            "idle_read", "scroll_down", "scroll_up", "page_down", "page_up", "mouse_move"
        }
    ]
    if not category["actions"]:
        raise ValueError("targeted Windows service has no host-preserving actions")
    urls = [str(value) for value in targets[0].get("args", [])]
    urls.extend(
        str(value)
        for choice in targets[0].get("arg_choices", [])
        for value in choice
    )
    hosts = {
        host for value in urls
        if (host := (urlsplit(value).hostname or "").lower())
    }
    if targets[0].get("native_binding"):
        from .native_control import native_executable
        native_executable(targets[0])
    elif len(hosts) != 1:
        raise ValueError("targeted Windows service must have exactly one verified URL host")
    content_hosts = targets[0].get("semantic_binding", {}).get("content_hosts", [])
    if any(not isinstance(host, str) or urlsplit("https://" + host).hostname != host
           or "/" in host or "*" in host for host in content_hosts):
        raise ValueError("content hosts must be explicit hostnames")
    targets[0]["expected_hosts"] = sorted(hosts | set(content_hosts))
    targets[0]["identity_poll_seconds"] = min(60.0, media_poll_seconds or 60.0)
    if category_id in FAMILIES:
        category["shared_activity"] = True
    selected["categories"] = [category]
    selected["defaults"]["min_usage_seconds"] = minimum_accepted_seconds
    selected["defaults"]["foreground_match_min_ratio"] = foreground_match_min_ratio
    if require_media_probe:
        policy = category.get("media_probe")
        if not isinstance(policy, dict):
            raise ValueError(f"category {category_id!r} has no media probe")
        policy["required"] = True
        if media_poll_seconds:
            policy["poll_interval_seconds"] = media_poll_seconds
    validate_plan(selected)
    return selected


def validate_plan(plan: dict[str, Any]) -> None:
    if not isinstance(plan, dict):
        raise ValueError("Windows plan must be a JSON object.")
    if plan.get("platform") != "windows":
        raise ValueError("Windows plan must declare platform=windows.")
    defaults = plan.get("defaults")
    if not isinstance(defaults, dict):
        raise ValueError("Windows plan requires a defaults object.")
    if float(defaults.get("duration_seconds", 0)) <= 0:
        raise ValueError("defaults.duration_seconds must be positive.")
    for field in ("pre_roll_seconds", "post_roll_seconds"):
        if float(defaults.get(field, 0)) < 0:
            raise ValueError(f"defaults.{field} must be non-negative.")
    foreground_ratio = float(defaults.get("foreground_match_min_ratio", 0.5))
    if not 0 <= foreground_ratio <= 1:
        raise ValueError("defaults.foreground_match_min_ratio must be between 0 and 1.")
    categories = plan.get("categories")
    if not isinstance(categories, list) or not categories:
        raise ValueError("Windows plan requires at least one category.")
    category_ids: set[str] = set()
    for category in categories:
        category_id = str(category.get("id", "")).strip()
        if not category_id or category_id in category_ids:
            raise ValueError(f"Category id is missing or duplicated: {category_id!r}")
        category_ids.add(category_id)
        targets = category.get("targets")
        if not isinstance(targets, list) or not targets:
            raise ValueError(f"Category {category_id!r} requires targets.")
        for target in targets:
            if not str(target.get("name", "")).strip() or not str(target.get("command", "")).strip():
                raise ValueError(f"Category {category_id!r} has a target without name/command.")
            _validate_media_probe(target.get("media_probe"), f"target {target.get('name')!r}")
        _validate_media_probe(category.get("media_probe"), f"category {category_id!r}")
        actions = category.get("actions")
        if not isinstance(actions, list) or not actions:
            raise ValueError(f"Category {category_id!r} requires actions.")
        unknown = {str(row.get("type", "")) for row in actions} - SUPPORTED_ACTIONS
        if unknown:
            raise ValueError(f"Category {category_id!r} has unsupported actions: {sorted(unknown)}")


def _validate_media_probe(value: Any, owner: str) -> None:
    if value is None:
        return
    if not isinstance(value, dict):
        raise ValueError(f"{owner} media_probe must be an object.")
    if "required" in value and not isinstance(value["required"], bool):
        raise ValueError(f"{owner} media_probe.required must be boolean.")
    observe_seconds = float(value.get("observe_seconds", 2.6))
    minimum_advance = float(value.get("min_advance_seconds", 0.75))
    if not 0.25 <= observe_seconds <= 15:
        raise ValueError(f"{owner} media_probe.observe_seconds must be between 0.25 and 15.")
    if minimum_advance <= 0 or minimum_advance > observe_seconds:
        raise ValueError(f"{owner} media_probe.min_advance_seconds must be positive and no greater than observe_seconds.")
    interval = float(value.get("poll_interval_seconds", 0))
    if interval < 0 or interval > 3600:
        raise ValueError(f"{owner} media_probe.poll_interval_seconds must be between zero and 3600")


class DesktopDriver(Protocol):
    def launch(self, command: str, args: list[str], *, enable_media_probe: bool = False) -> None: ...

    def perform(self, action: str, *, rng: random.Random, search_terms: list[str]) -> dict[str, Any]: ...

    def open_blank_page(self) -> None: ...

    def probe_media(self, policy: dict[str, Any]) -> dict[str, Any]: ...

    def probe_page(self, expected_hosts: list[str]) -> dict[str, Any]: ...

    def close(self) -> None: ...


class WindowsDesktopDriver:
    """Minimal Win32 input driver used only by explicit collection plans."""

    KEYEVENTF_KEYUP = 0x0002
    MOUSEEVENTF_LEFTDOWN = 0x0002
    MOUSEEVENTF_LEFTUP = 0x0004
    MOUSEEVENTF_WHEEL = 0x0800
    VK_CONTROL = 0x11
    VK_MENU = 0x12
    VK_SHIFT = 0x10
    VK_TAB = 0x09
    VK_RETURN = 0x0D
    VK_PRIOR = 0x21
    VK_NEXT = 0x22
    VK_LEFT = 0x25

    def __init__(self, runtime_dir: Path | None = None, *, edge_profile_dir: Path | None = None,
                 attach_existing_edge: bool = False, existing_edge_tab_id: str = "",
                 background_control_only: bool = False,
                 tolerate_foreground_interruptions: bool = False,
                 require_single_page: bool = False) -> None:
        if platform.system() != "Windows":
            raise RuntimeError("Windows desktop automation is available only on Windows.")
        self.user32 = ctypes.windll.user32
        self.runtime_dir = (runtime_dir or Path.cwd() / "runs" / "windows-runtime").resolve()
        self.edge_profile_dir = (edge_profile_dir or self.runtime_dir / "edge-media-profile").resolve()
        self._media_probe_active = False
        self._processes: list[subprocess.Popen] = []
        self.attach_existing_edge = attach_existing_edge
        self.background_control_only = background_control_only
        self.tolerate_foreground_interruptions = tolerate_foreground_interruptions
        self.require_single_page = require_single_page
        if background_control_only and not attach_existing_edge:
            raise ValueError("Background control smoke requires an existing browser")
        self._existing_target_id = existing_edge_tab_id or None
        if attach_existing_edge and edge_profile_dir is None:
            raise ValueError("Existing Edge requires its explicit profile directory")
        if existing_edge_tab_id and not attach_existing_edge:
            raise ValueError("Existing Edge tab ID requires attachment mode")

    def launch(self, command: str, args: list[str], *, enable_media_probe: bool = False) -> None:
        resolved = self._resolve_command(command)
        if self.attach_existing_edge:
            from .media_probe import verify_existing_edge_target, wait_for_devtools_port, _activate_target
            if Path(resolved).name.lower() not in {"msedge.exe", "msedge"}:
                raise ValueError("Existing Edge mode only supports Edge targets")
            urls = [value for value in args if urlsplit(value).scheme in {"http", "https"}]
            if len(urls) != 1:
                raise ValueError("Existing Edge requires one explicit target URL")
            page = verify_existing_edge_target(self.edge_profile_dir, urls[0],
                                              target_id=self._existing_target_id, timeout_seconds=30,
                                              require_single_page=getattr(self, "require_single_page", False))
            self._existing_target_id = page["id"]
            self._existing_target_url = urls[0]
            if not getattr(self, "background_control_only", False):
                if not self._focus_process(Path(resolved).name, allowed_pids=self._edge_profile_pids()):
                    raise RuntimeError("Selected Edge window could not be brought to the foreground")
                _activate_target(self.edge_profile_dir, wait_for_devtools_port(self.edge_profile_dir, 3),
                                 self._existing_target_id)
            self._verify_existing_target()
            self._media_probe_active = True
            return
        launch_args = list(args)
        if enable_media_probe and Path(resolved).name.lower() in {"msedge.exe", "msedge"}:
            self.edge_profile_dir.mkdir(parents=True, exist_ok=True)
            launch_args = [
                f"--user-data-dir={self.edge_profile_dir}",
                "--remote-debugging-port=0",
                "--remote-allow-origins=*",
                "--no-first-run",
                "--no-default-browser-check",
                *launch_args,
            ]
            self._media_probe_active = True
        process = subprocess.Popen([resolved, *launch_args], close_fds=True)
        self._processes.append(process)
        deadline = time.monotonic() + 8
        focused = False
        while time.monotonic() < deadline:
            allowed = (self._edge_profile_pids() if self._media_probe_active
                       else {process.pid})
            if allowed and self._focus_process(Path(resolved).name, allowed_pids=allowed):
                focused = True
                break
            time.sleep(0.2)
        if not focused:
            raise RuntimeError("Launched Windows target did not become the foreground window")

    def probe_media(self, policy: dict[str, Any]) -> dict[str, Any]:
        self._verify_existing_target()
        if not self._media_probe_active:
            return {
                "schema_version": "windows-media-playback-evidence-v1",
                "content_redacted": True,
                "ok": False,
                "evidence": "media_probe_not_enabled",
            }
        from .media_probe import probe_edge_media

        return probe_edge_media(
            self.edge_profile_dir,
            observe_seconds=float(policy.get("observe_seconds", 2.6)),
            min_advance_seconds=float(policy.get("min_advance_seconds", 0.75)),
            timeout_seconds=float(policy.get("timeout_seconds", 10)),
            target_id=getattr(self, "_existing_target_id", None),
        )

    def probe_page(self, expected_hosts: list[str]) -> dict[str, Any]:
        self._verify_existing_target()
        if not self._media_probe_active:
            return {"schema_version": "windows-page-identity-v1", "content_redacted": True,
                    "ok": False, "evidence": "edge_cdp_not_enabled"}
        from .media_probe import probe_edge_page_identity

        return probe_edge_page_identity(self.edge_profile_dir, expected_hosts,
                                        target_id=getattr(self, "_existing_target_id", None))

    def close(self) -> None:
        from .media_probe import close_edge_connection
        close_edge_connection(self.edge_profile_dir)
        # Only processes started by this driver are touched. Never kill Edge by
        # image name because the operator may have unrelated browser windows.
        for process in self._processes:
            if process.poll() is None:
                try:
                    process.terminate()
                except OSError:
                    pass

    def observe_behavior(self, target):
        from .media_probe import observe_edge_behavior
        self._verify_existing_target(target.get("expected_hosts"))
        if not self._media_probe_active:
            return {"allowed": False}
        if self.attach_existing_edge:
            target["_active_page_id"] = self._existing_target_id
            target["_background_control_only"] = (getattr(self, "background_control_only", False)
                                                  or getattr(self, "tolerate_foreground_interruptions", False))
        return observe_edge_behavior(self.edge_profile_dir, target)

    def perform_behavior(self, action, target, parameters):
        from .media_probe import perform_edge_behavior
        self._verify_existing_target(target.get("expected_hosts"))
        if not self._media_probe_active:
            raise RuntimeError("semantic browser control requires a verified CDP session")
        if not (getattr(self, "background_control_only", False)
                or getattr(self, "tolerate_foreground_interruptions", False)):
            foreground = ctypes.c_ulong()
            self.user32.GetWindowThreadProcessId(self.user32.GetForegroundWindow(), ctypes.byref(foreground))
            allowed = (self._edge_profile_pids() if self._media_probe_active
                       else {process.pid for process in self._processes})
            if not allowed or foreground.value not in allowed:
                raise RuntimeError("Selected Edge window is no longer foreground")
        if self.attach_existing_edge:
            target["_active_page_id"] = self._existing_target_id
            target["_background_control_only"] = (getattr(self, "background_control_only", False)
                                                  or getattr(self, "tolerate_foreground_interruptions", False))
        perform_edge_behavior(self.edge_profile_dir, target, action, parameters)
        if self.attach_existing_edge:
            self._existing_target_id = target["_active_page_id"]

    def _verify_existing_target(self, expected_hosts=None):
        if getattr(self, "attach_existing_edge", False):
            from .media_probe import verify_existing_edge_target, _evaluate
            page = verify_existing_edge_target(self.edge_profile_dir, self._existing_target_url,
                                              target_id=self._existing_target_id,
                                              require_single_page=getattr(self, "require_single_page", False),
                                              **({"expected_hosts": expected_hosts} if expected_hosts else {}))
            if (getattr(self, "background_control_only", False)
                    or getattr(self, "tolerate_foreground_interruptions", False)):
                return
            focus = _evaluate(page["webSocketDebuggerUrl"],
                              "[{active:document.visibilityState==='visible' && document.hasFocus()}]", 3)
            if len(focus) != 1 or focus[0].get("active") is not True:
                raise RuntimeError("Selected Edge tab is no longer active; attachment stays pinned")

    @staticmethod
    def _resolve_command(command: str) -> str:
        expanded = Path(os.path.expandvars(os.path.expanduser(command)))
        if expanded.is_file():
            return str(expanded)
        located = shutil.which(command)
        if located:
            return located
        try:
            import winreg

            registry_paths = (
                rf"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{command}",
                rf"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\{command}",
            )
            for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
                for registry_path in registry_paths:
                    try:
                        with winreg.OpenKey(hive, registry_path) as key:
                            value, _kind = winreg.QueryValueEx(key, None)
                        candidate = Path(str(value))
                        if candidate.is_file():
                            return str(candidate)
                    except OSError:
                        continue
        except ImportError:
            pass
        for env_name in ("PROGRAMFILES(X86)", "PROGRAMFILES", "LOCALAPPDATA"):
            base = os.environ.get(env_name, "")
            if not base:
                continue
            candidate = Path(base) / "Microsoft" / "Edge" / "Application" / command
            if candidate.is_file():
                return str(candidate)
        raise FileNotFoundError(f"Windows command was not found in PATH, App Paths, or known install roots: {command}")

    def _edge_profile_pids(self) -> set[int]:
        """Find the selected profile, including an operator's default Edge process."""
        import psutil

        profile = os.path.normcase(str(self.edge_profile_dir))
        matches: set[int] = set()
        for process in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                if (process.info["name"] or "").lower() != "msedge.exe":
                    continue
                args = process.info["cmdline"] or []
                # Crashpad/render processes may repeat the profile argument.
                # Only a browser root owns the top-level window we can focus.
                if any(arg.lower().startswith("--type=") for arg in args):
                    continue
                if not any(arg.lower().startswith("--user-data-dir=")
                           and os.path.normcase(str(Path(arg.split("=", 1)[1].strip('"')).resolve())) == profile
                           for arg in args):
                    continue
                matches.add(process.pid)
                matches.update(child.pid for child in process.children(recursive=True))
            except (psutil.Error, OSError, ValueError):
                continue
        default_data = Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "Edge" / "User Data"
        if (not matches and getattr(self, "attach_existing_edge", False)
                and os.environ.get("LOCALAPPDATA")
                and profile == os.path.normcase(str(default_data.resolve()))):
            try:
                port = int((self.edge_profile_dir / "DevToolsActivePort").read_text().splitlines()[0])
                owners = {c.pid for c in psutil.net_connections(kind="tcp")
                          if c.status == psutil.CONN_LISTEN and c.pid and c.laddr
                          and c.laddr.port == port and c.laddr.ip in {"127.0.0.1", "::1"}}
                if len(owners) == 1:
                    process = psutil.Process(owners.pop())
                    args = process.cmdline()
                    if (process.name().lower() == "msedge.exe" and not any(
                            arg.lower().startswith(("--user-data-dir=", "--type=")) for arg in args)):
                        matches.add(process.pid)
                        matches.update(child.pid for child in process.children(recursive=True))
            except (psutil.Error, OSError, ValueError, IndexError):
                pass
        return matches

    def _focus_process(self, expected_name: str, *, allowed_pids: set[int] | None = None) -> bool:
        matches: list[int] = []
        process_query = 0x1000

        @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
        def callback(hwnd, _lparam):
            if not self.user32.IsWindowVisible(hwnd):
                return True
            process_id = ctypes.c_ulong()
            self.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(process_id))
            if allowed_pids is not None and process_id.value not in allowed_pids:
                return True
            handle = ctypes.windll.kernel32.OpenProcess(process_query, False, process_id.value)
            if not handle:
                return True
            try:
                size = ctypes.c_ulong(32768)
                buffer = ctypes.create_unicode_buffer(size.value)
                if ctypes.windll.kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
                    if Path(buffer.value).name.lower() == expected_name.lower():
                        matches.append(int(hwnd))
            finally:
                ctypes.windll.kernel32.CloseHandle(handle)
            return True

        self.user32.EnumWindows(callback, 0)
        if not matches:
            return False
        hwnd = matches[0]
        self.user32.ShowWindow(hwnd, 9)
        self.user32.BringWindowToTop(hwnd)
        if self.user32.GetForegroundWindow() != hwnd and not self.user32.SetForegroundWindow(hwnd):
            # Windows foreground-lock rules permit a focus request immediately
            # after a synthetic Alt tap. Do this only for the selected window.
            self._tap_key(self.VK_MENU)
            self.user32.SetForegroundWindow(hwnd)
        if self.user32.GetForegroundWindow() != hwnd:
            # A detached collector can still be denied foreground rights after
            # the Alt request. Temporarily join the active input queue so the
            # verified Edge window can be selected, then detach immediately.
            foreground_hwnd = self.user32.GetForegroundWindow()
            foreground_thread = self.user32.GetWindowThreadProcessId(foreground_hwnd, None)
            current_thread = ctypes.windll.kernel32.GetCurrentThreadId()
            attached = bool(foreground_thread and foreground_thread != current_thread
                            and self.user32.AttachThreadInput(current_thread, foreground_thread, True))
            try:
                self.user32.BringWindowToTop(hwnd)
                self.user32.SetForegroundWindow(hwnd)
            finally:
                if attached:
                    self.user32.AttachThreadInput(current_thread, foreground_thread, False)
        foreground = ctypes.c_ulong()
        self.user32.GetWindowThreadProcessId(self.user32.GetForegroundWindow(), ctypes.byref(foreground))
        return bool(foreground.value in allowed_pids) if allowed_pids is not None else self.user32.GetForegroundWindow() == hwnd

    def perform(self, action: str, *, rng: random.Random, search_terms: list[str]) -> dict[str, Any]:
        if action == "idle_read":
            seconds = rng.uniform(2.0, 8.0)
            return {"seconds": round(seconds, 3), "_sleep_seconds": seconds}
        if action in {"scroll_down", "scroll_up"}:
            notches = rng.randint(2, 8)
            delta = (-120 if action == "scroll_down" else 120) * notches
            self.user32.mouse_event(self.MOUSEEVENTF_WHEEL, 0, 0, delta, 0)
            return {"wheel_delta": delta, "notches": notches}
        if action == "page_down":
            self._tap_key(self.VK_NEXT)
        elif action == "page_up":
            self._tap_key(self.VK_PRIOR)
        elif action == "tab":
            self._tap_key(self.VK_TAB)
        elif action == "enter":
            self._tap_key(self.VK_RETURN)
        elif action == "back":
            self._hotkey([self.VK_MENU, self.VK_LEFT])
        elif action == "mouse_move":
            width = self.user32.GetSystemMetrics(0)
            height = self.user32.GetSystemMetrics(1)
            x = rng.randint(max(1, width // 10), max(1, width * 9 // 10))
            y = rng.randint(max(1, height // 10), max(1, height * 9 // 10))
            self.user32.SetCursorPos(x, y)
            return {"x": x, "y": y}
        elif action == "left_click":
            self.user32.mouse_event(self.MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0)
            self.user32.mouse_event(self.MOUSEEVENTF_LEFTUP, 0, 0, 0, 0)
        elif action == "search_web":
            if not search_terms:
                return {"skipped": "no_search_terms"}
            query = rng.choice(search_terms)
            self._hotkey([self.VK_CONTROL, ord("L")])
            time.sleep(0.15)
            self._type_text(query)
            self._tap_key(self.VK_RETURN)
            return {"query": "[redacted]"}
        else:
            raise ValueError(f"Unsupported Windows action: {action}")
        return {}

    def open_blank_page(self) -> None:
        self._hotkey([self.VK_CONTROL, ord("L")])
        time.sleep(0.1)
        self._type_text("about:blank")
        self._tap_key(self.VK_RETURN)

    def _tap_key(self, virtual_key: int) -> None:
        self.user32.keybd_event(virtual_key, 0, 0, 0)
        self.user32.keybd_event(virtual_key, 0, self.KEYEVENTF_KEYUP, 0)

    def _hotkey(self, keys: list[int]) -> None:
        for key in keys:
            self.user32.keybd_event(key, 0, 0, 0)
        for key in reversed(keys):
            self.user32.keybd_event(key, 0, self.KEYEVENTF_KEYUP, 0)

    def _type_text(self, text: str) -> None:
        for char in text:
            code = int(self.user32.VkKeyScanW(ord(char)))
            if code == -1:
                continue
            key = code & 0xFF
            modifiers = (code >> 8) & 0xFF
            if modifiers & 1:
                self.user32.keybd_event(self.VK_SHIFT, 0, 0, 0)
            self._tap_key(key)
            if modifiers & 1:
                self.user32.keybd_event(self.VK_SHIFT, 0, self.KEYEVENTF_KEYUP, 0)


@dataclass(slots=True)
class AutomationSummary:
    sessions: int = 0
    accepted_windows: int = 0
    failed_windows: int = 0
    actions: int = 0
    error: str | None = None


class ActivityRunner:
    def __init__(
        self,
        *,
        plan: dict[str, Any],
        run_dir: Path,
        duration_seconds: float,
        seed: int,
        stop_event: threading.Event,
        driver: DesktopDriver,
        single_session: bool = False,
    ) -> None:
        self.plan = plan
        self.run_dir = run_dir
        self.duration_seconds = duration_seconds
        self.seed = seed
        self.stop_event = stop_event
        self.driver = driver
        self.single_session = single_session
        self.rng = random.Random(seed)
        self.events_path = run_dir / "events.jsonl"
        self.windows_path = run_dir / "usage_windows.jsonl"
        self.summary = AutomationSummary()

    def run(self) -> AutomationSummary:
        defaults = self.plan["defaults"]
        deadline = time.monotonic() + self.duration_seconds
        self._write_event("automation_start", duration_seconds=self.duration_seconds, seed=self.seed)
        try:
            while not self.stop_event.is_set() and time.monotonic() < deadline:
                self._run_session(deadline, defaults)
                if self.single_session:
                    break
                if self.stop_event.is_set() or time.monotonic() >= deadline:
                    break
                buffer_seconds = min(float(defaults.get("buffer_seconds", 0)), max(0.0, deadline - time.monotonic()))
                if buffer_seconds > 0:
                    try:
                        self.driver.open_blank_page()
                    except Exception as exc:
                        self._write_event("buffer_warning", error=str(exc))
                    self._sleep_interruptible(buffer_seconds)
        except Exception as exc:
            self.summary.error = str(exc)
            self._write_event("automation_error", error=str(exc))
        finally:
            close = getattr(self.driver, "close", None)
            if callable(close):
                try:
                    close()
                except Exception as exc:
                    self._write_event("driver_close_warning", error=str(exc))
            self._write_event("automation_stop", summary=self.summary.__dict__ if hasattr(self.summary, "__dict__") else {
                "sessions": self.summary.sessions,
                "accepted_windows": self.summary.accepted_windows,
                "failed_windows": self.summary.failed_windows,
                "actions": self.summary.actions,
                "error": self.summary.error,
            })
        return self.summary

    def _run_session(self, deadline: float, defaults: dict[str, Any]) -> None:
        category = _weighted_choice(self.rng, list(self.plan["categories"]))
        target = _weighted_choice(self.rng, list(category["targets"]))
        actions = list(category["actions"])
        min_seconds = float(category.get("session_min_seconds", defaults.get("session_min_seconds", 20)))
        max_seconds = float(category.get("session_max_seconds", defaults.get("session_max_seconds", 60)))
        if max_seconds < min_seconds:
            max_seconds = min_seconds
        requested_seconds = self.rng.uniform(min_seconds, max_seconds)
        session_seconds = min(requested_seconds, max(0.1, deadline - time.monotonic()))
        if category["id"] in FAMILIES:
            self._run_shared_session(category, target, session_seconds, deadline, defaults)
            return
        session_deadline = time.monotonic() + session_seconds
        media_policy = self._media_policy(category, target)
        expected_hosts = list(target.get("expected_hosts") or [])
        identity_checks: list[dict[str, Any]] = []
        identity_failed = False
        identity_poll_seconds = float(target.get("identity_poll_seconds", 0))
        next_identity_poll = time.monotonic() + identity_poll_seconds if identity_poll_seconds else float("inf")
        media_checks: list[dict[str, Any]] = []
        media_failed = False
        poll_interval = float(media_policy.get("poll_interval_seconds", 0)) if media_policy else 0
        next_media_poll = time.monotonic() + poll_interval if poll_interval else float("inf")
        probe_reserve_seconds = float(media_policy.get("observe_seconds", 0)) + 0.5 if media_policy else 0.0
        action_deadline = max(time.monotonic(), session_deadline - probe_reserve_seconds)
        window_id = uuid.uuid4().hex[:12]
        started_epoch = time.time()
        action_count = 0
        launch_ok = True
        args = self._target_args(target)
        try:
            self.driver.launch(str(target["command"]), args, enable_media_probe=bool(media_policy or expected_hosts))
            self._write_event(
                "launch",
                window_id=window_id,
                category_id=category["id"],
                target_name=target["name"],
                command=target["command"],
                args="[redacted]",
            )
        except Exception as exc:
            launch_ok = False
            self._write_event("launch_error", window_id=window_id, target_name=target["name"], error=str(exc))
        settle = min(float(target.get("settle_seconds", defaults.get("settle_seconds", 2))), max(0.0, session_deadline - time.monotonic()))
        self._sleep_interruptible(settle)
        if launch_ok and expected_hosts:
            identity = {**self.driver.probe_page(expected_hosts), "observed_epoch": time.time()}
            identity_checks.append(identity)
            self._write_event("page_identity", window_id=window_id, phase="initial", evidence=identity)
            identity_failed = not bool(identity.get("ok"))
        if launch_ok and media_policy and media_policy.get("required"):
            evidence = {**self.driver.probe_media(media_policy), "observed_epoch": time.time()}
            media_checks.append(evidence)
            self._write_event("media_probe", window_id=window_id, phase="initial", evidence=evidence)
            media_failed = not bool(evidence.get("ok"))
        search_terms = [str(value) for value in category.get("search_terms", []) if str(value).strip()]
        while (launch_ok and not identity_failed and not media_failed
               and not self.stop_event.is_set() and time.monotonic() < action_deadline):
            if time.monotonic() >= next_identity_poll:
                identity = {**self.driver.probe_page(expected_hosts), "observed_epoch": time.time()}
                identity_checks.append(identity)
                self._write_event("page_identity", window_id=window_id, phase="periodic", evidence=identity)
                identity_failed = identity_failed or not bool(identity.get("ok"))
                next_identity_poll = time.monotonic() + identity_poll_seconds
            if time.monotonic() >= next_media_poll:
                evidence = {**self.driver.probe_media(media_policy), "observed_epoch": time.time()}
                media_checks.append(evidence)
                self._write_event("media_probe", window_id=window_id, phase="periodic", evidence=evidence)
                if media_policy.get("required") and not evidence.get("ok"):
                    media_failed = True
                next_media_poll = time.monotonic() + poll_interval
            # A later successful probe cannot authorize input after a failed
            # identity/playback observation in this session.
            if identity_failed or media_failed:
                break
            selected = _weighted_choice(self.rng, actions)
            action = str(selected["type"])
            try:
                details = self.driver.perform(action, rng=self.rng, search_terms=search_terms)
                action_sleep = float(details.pop("_sleep_seconds", 0))
                action_count += 1
                self.summary.actions += 1
                self._write_event("action", window_id=window_id, action=action, **details)
                if action_sleep > 0:
                    self._sleep_interruptible(min(action_sleep, max(0.0, action_deadline - time.monotonic())))
            except Exception as exc:
                self._write_event("action_error", window_id=window_id, action=action, error=str(exc))
            pause_min = float(defaults.get("action_pause_min_seconds", 0.5))
            pause_max = max(pause_min, float(defaults.get("action_pause_max_seconds", 2.0)))
            pause = min(self.rng.uniform(pause_min, pause_max), max(0.0, action_deadline - time.monotonic()))
            self._sleep_interruptible(pause)
        min_actions = int(defaults.get("min_actions_per_session", 1))
        min_usage_seconds = float(defaults.get("min_usage_seconds", 5))
        reasons: list[str] = []
        if not launch_ok:
            reasons.append("launch_failed")
        if action_count < min_actions:
            reasons.append("too_few_actions")
        if launch_ok and expected_hosts:
            identity = {**self.driver.probe_page(expected_hosts), "observed_epoch": time.time()}
            identity_checks.append(identity)
            self._write_event("page_identity", window_id=window_id, phase="final", evidence=identity)
            identity_failed = identity_failed or not bool(identity.get("ok"))
            if identity_failed:
                reasons.append("target_identity_not_verified")
        media_evidence: dict[str, Any] | None = None
        if media_policy and launch_ok:
            probe = getattr(self.driver, "probe_media", None)
            if callable(probe):
                media_evidence = {**probe(media_policy), "observed_epoch": time.time()}
            else:
                media_evidence = {
                    "schema_version": "windows-media-playback-evidence-v1",
                    "content_redacted": True,
                    "ok": False,
                    "evidence": "driver_has_no_media_probe",
                }
            self._write_event("media_probe", window_id=window_id, evidence=media_evidence)
            media_checks.append(media_evidence)
            if bool(media_policy.get("required")) and (
                media_failed or not bool(media_evidence.get("ok"))
            ):
                reasons.append("media_playback_not_verified")
        ended_epoch = time.time()
        actual_seconds = max(0.0, ended_epoch - started_epoch)
        if actual_seconds < min_usage_seconds:
            reasons.append("too_short")
        status = "accepted" if not reasons else "failed"
        self.summary.sessions += 1
        if status == "accepted":
            self.summary.accepted_windows += 1
        else:
            self.summary.failed_windows += 1
        pre_roll = float(defaults.get("pre_roll_seconds", 0))
        post_roll = float(defaults.get("post_roll_seconds", 0))
        self._write_jsonl(
            self.windows_path,
            {
                "schema_version": "windows-usage-window-v1",
                "platform": "windows",
                "window_id": window_id,
                "category_id": category["id"],
                "category": category.get("display_name", category["id"]),
                "target_name": target["name"],
                "command": target["command"],
                "started_epoch": started_epoch,
                "ended_epoch": ended_epoch,
                "duration_seconds": round(actual_seconds, 3),
                "analysis_started_epoch": started_epoch - pre_roll,
                "analysis_ended_epoch": ended_epoch + post_roll,
                "pre_roll_seconds": pre_roll,
                "post_roll_seconds": post_roll,
                "action_count": action_count,
                "media_probe_required": bool(media_policy.get("required")) if media_policy else False,
                "media_evidence": media_evidence,
                "media_checks": media_checks,
                "target_identity_required": bool(expected_hosts),
                "target_identity_checks": identity_checks,
                "quality_tier": (
                    "playback_verified"
                    if media_evidence and media_evidence.get("ok")
                    else "interaction_network_validated"
                ),
                "status": status,
                "reasons": reasons,
            },
        )

    def _run_shared_session(self, category, target, duration, deadline, defaults):
        """Capture bookkeeping only. A single shared playbook owns all behavior."""
        target = copy.deepcopy(target)
        target["args"] = self._target_args(target)
        hosts = {(urlsplit(value).hostname or "").lower() for value in target["args"]
                 if urlsplit(value).hostname}
        target.setdefault("expected_hosts", sorted(hosts))
        window_id = uuid.uuid4().hex[:12]
        destination = self.run_dir / "semantic" / window_id
        started, ended = time.time(), time.time()
        result, adapter, reasons = None, None, []
        self._write_event("shared_task_start", window_id=window_id, task_family=FAMILIES[category["id"]])
        try:
            if target.get("native_binding"):
                from .native_control import native_executable
                native_executable(target)
            elif len(hosts) != 1 or not hosts.issubset(set(target["expected_hosts"])):
                raise ValueError("shared Windows task requires a verified target URL")
            result, windows, adapter = run_windows_task(
                self.driver, target, category["id"], duration, self.seed,
                self.stop_event, destination, deadline)
            sustained = [w for w in windows if w["actual"].get("step_id") == "monitor-active-state"]
            if len(sustained) != 1 or not result.successful:
                reasons.append("shared_task_not_verified")
                ended = time.time()
            else:
                started = sustained[0]["actual"]["start_epoch"]
                ended = sustained[0]["actual"]["end_epoch"]
        except Exception as exc:
            ended = time.time()
            reasons.append("shared_task_incomplete")
            self._write_event("shared_task_error", window_id=window_id, error_type=type(exc).__name__)
        if ended - started < float(defaults.get("min_usage_seconds", 5)):
            reasons.append("too_short")
        observations = [r for r in adapter.observations if started <= r["observed_epoch"] <= ended] if adapter else []
        identity = [{"ok": r["state"].get("allowed") is True, "observed_epoch": r["observed_epoch"],
                     "content_redacted": True} for r in observations]
        media_required = category["id"] != "web_browsing"
        media = [{"ok": r["state"].get("media_advancing") is True, "observed_epoch": r["observed_epoch"],
                  "content_redacted": True} for r in observations
                 if r["reason"] == "monitor-active-state:sustain"] if media_required else []
        actions = adapter.actions if adapter else 0
        self.summary.sessions += 1
        self.summary.actions += actions
        if reasons:
            self.summary.failed_windows += 1
        else:
            self.summary.accepted_windows += 1
        self._write_jsonl(self.windows_path, {
            "schema_version": "windows-usage-window-v1", "platform": "windows", "window_id": window_id,
            "category_id": category["id"], "category": category.get("display_name", category["id"]),
            "target_name": target["name"], "command": target["command"],
            "started_epoch": started, "ended_epoch": ended, "duration_seconds": round(ended - started, 3),
            "analysis_started_epoch": started, "analysis_ended_epoch": ended,
            "pre_roll_seconds": 0, "post_roll_seconds": 0, "action_count": actions,
            "shared_activity": True, "shared_task_version": 2,
            "semantic_events": str((destination / "events.jsonl").relative_to(self.run_dir)),
            "media_probe_required": media_required, "media_checks": media,
            "media_evidence": media[-1] if media else None,
            "target_identity_required": True, "target_identity_checks": identity,
            "quality_tier": "playback_verified" if media_required and not reasons else "interaction_network_validated",
            "status": "failed" if reasons else "accepted", "reasons": reasons,
        })
        self._write_event("shared_task_finish", window_id=window_id,
                          playbook_id=result.playbook_id if result else None, reasons=reasons)

    def _target_args(self, target: dict[str, Any]) -> list[str]:
        choices = target.get("arg_choices")
        if isinstance(choices, list) and choices:
            selected = self.rng.choice(choices)
            return [str(value) for value in selected]
        return [str(value) for value in target.get("args", [])]

    @staticmethod
    def _media_policy(category: dict[str, Any], target: dict[str, Any]) -> dict[str, Any]:
        policy: dict[str, Any] = {}
        if isinstance(category.get("media_probe"), dict):
            policy.update(category["media_probe"])
        if isinstance(target.get("media_probe"), dict):
            policy.update(target["media_probe"])
        return policy

    def _sleep_interruptible(self, seconds: float) -> None:
        if seconds > 0:
            self.stop_event.wait(seconds)

    def _write_event(self, event: str, **details: Any) -> None:
        self._write_jsonl(self.events_path, {"timestamp": _now_iso(), "epoch": time.time(), "event": event, **details})

    @staticmethod
    def _write_jsonl(path: Path, payload: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
