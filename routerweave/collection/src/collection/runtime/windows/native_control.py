"""Native app adapter for the existing Windows shared playbooks and transport.

Only the official Computer Use consumer issues UI input. Python observes exact
process identity and WASAPI output; it never injects native input.
"""
import os
from pathlib import PureWindowsPath
import psutil

from .browser_control import BrowserControlTransport
from .native_media import sample_process_audio


def native_executable(target):
    binding = target.get("native_binding", {})
    path = os.path.expandvars(binding.get("executable", ""))
    if (not PureWindowsPath(path).is_absolute()
            or PureWindowsPath(path).name.casefold() != target.get("command", "").casefold()
            or target.get("args") or not binding.get("playback_control_id")):
        raise ValueError("Native target requires exact executable, basename command and bound playback control")
    return path


class NativeControlTransport(BrowserControlTransport):
    PROTOCOL = "windows-native-use-v1"
    IDENTITY_KEY = "window_id"


class NativeUseDesktopDriver:
    def __init__(self, directory, target):
        self.executable = native_executable(target)
        self.foreground_restores = 0
        self.transport = NativeControlTransport(directory)
        if self.transport.session.get("executable", "").casefold() != self.executable.casefold():
            raise ValueError("Native consumer executable does not match registered target")

    def _edge_profile_pids(self):
        # Existing capture recorder accepts a callable PID set, independent of browser.
        result = set()
        for process in psutil.process_iter(["pid", "exe"]):
            if (process.info.get("exe") or "").casefold() == self.executable.casefold():
                result.add(process.pid)
        return result

    def launch_target(self, target):
        result = self.transport.request("launch", target=target)
        self._verify(result)

    def _verify(self, result):
        if (result.get("window_id") != self.transport.session["window_id"]
                or result.get("executable", "").casefold() != self.executable.casefold()
                or not self._edge_profile_pids()):
            raise RuntimeError("Native target identity is not verified")

    def observe_behavior(self, target):
        try:
            from .platforms.windows import WindowsSnapshotter
            snapshotter = WindowsSnapshotter()
            expected = PureWindowsPath(self.executable).name.casefold()
            foreground = snapshotter._resolve_foreground_app()
            if foreground.casefold() != expected:
                if self.foreground_restores >= 2:
                    return {"allowed": False, "native_foreground": foreground,
                            "error_type": "NativeForegroundRecoveryExhausted"}
                self.foreground_restores += 1
                restored = self.transport.request("activate", target=target)
                self._verify(restored)
                foreground = snapshotter._resolve_foreground_app()
                if foreground.casefold() != expected:
                    return {"allowed": False, "native_foreground": foreground,
                            "error_type": "NativeForegroundNotRestored"}
            result = self.transport.request("observe", target=target)
            self._verify(result)
            state = result["state"]
            state["native_audio"] = sample_process_audio(self.executable)
            state["native_executable"] = self.executable
            state["native_foreground"] = foreground
            state["foreground_restores"] = self.foreground_restores
            return state
        except Exception as exc:
            return {"allowed": False, "error_type": type(exc).__name__,
                    "native_control_error": str(exc), "blocked": False}

    def perform_behavior(self, action, target, parameters):
        parameters.get("check_active", lambda: None)()
        self.transport.request("perform", action=action, target=target)

    def close(self):
        pass  # User app and consumer survive each child run.
