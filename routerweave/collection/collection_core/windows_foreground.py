from __future__ import annotations

import ctypes
from ctypes import wintypes
from pathlib import Path

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DesktopLogRecord:
    timestamp_ms: int
    session_id: str
    behavior_label: str
    foreground_app: str
    recent_user_input: str
    screen_or_session_active: bool


PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
DESKTOP_READOBJECTS = 0x0001
DESKTOP_SWITCHDESKTOP = 0x0100
UOI_NAME = 2
GWL_EXSTYLE = -20
GW_HWNDNEXT = 2
WS_EX_TOPMOST = 0x00000008
WS_EX_TOOLWINDOW = 0x00000080
WS_EX_LAYERED = 0x00080000
WS_EX_NOACTIVATE = 0x08000000

user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


class LASTINPUTINFO(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.UINT),
        ("dwTime", wintypes.DWORD),
    ]


user32.GetForegroundWindow.restype = wintypes.HWND
user32.GetWindow.argtypes = [wintypes.HWND, wintypes.UINT]
user32.GetWindow.restype = wintypes.HWND
user32.GetWindowLongPtrW.argtypes = [wintypes.HWND, ctypes.c_int]
user32.GetWindowLongPtrW.restype = ctypes.c_ssize_t
user32.IsWindowVisible.argtypes = [wintypes.HWND]
user32.IsWindowVisible.restype = wintypes.BOOL
user32.IsIconic.argtypes = [wintypes.HWND]
user32.IsIconic.restype = wintypes.BOOL
user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
user32.GetWindowTextLengthW.restype = ctypes.c_int
user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
user32.GetWindowThreadProcessId.restype = wintypes.DWORD
user32.GetLastInputInfo.argtypes = [ctypes.POINTER(LASTINPUTINFO)]
user32.GetLastInputInfo.restype = wintypes.BOOL
user32.OpenInputDesktop.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
user32.OpenInputDesktop.restype = wintypes.HANDLE
user32.GetUserObjectInformationW.argtypes = [
    wintypes.HANDLE,
    ctypes.c_int,
    wintypes.LPVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
]
user32.GetUserObjectInformationW.restype = wintypes.BOOL
user32.CloseDesktop.argtypes = [wintypes.HANDLE]
user32.CloseDesktop.restype = wintypes.BOOL

kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.QueryFullProcessImageNameW.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.LPWSTR,
    ctypes.POINTER(wintypes.DWORD),
]
kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.GetTickCount64.restype = ctypes.c_ulonglong


class WindowsSnapshotter:
    def create_record(self, session_id: str, now_ms: int, behavior_label: str) -> DesktopLogRecord:
        return DesktopLogRecord(
            timestamp_ms=now_ms,
            session_id=session_id,
            behavior_label=behavior_label,
            foreground_app=self._resolve_foreground_app(),
            recent_user_input=self._resolve_recent_user_input(now_ms),
            screen_or_session_active=self._resolve_screen_or_session_active(),
        )

    def _resolve_foreground_app(self) -> str:
        hwnd = user32.GetForegroundWindow()
        if not hwnd:
            return "UNAVAILABLE:NO_FOREGROUND_WINDOW"

        hwnd = self._effective_foreground_window(hwnd)

        process_id = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(process_id))
        if process_id.value == 0:
            return "UNAVAILABLE:PID_LOOKUP_FAILED"

        process_handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, process_id.value)
        if not process_handle:
            return f"UNAVAILABLE:PROCESS_{process_id.value}"

        try:
            buffer_size = wintypes.DWORD(1024)
            buffer = ctypes.create_unicode_buffer(buffer_size.value)
            ok = kernel32.QueryFullProcessImageNameW(process_handle, 0, buffer, ctypes.byref(buffer_size))
            if not ok:
                return f"UNAVAILABLE:QUERY_IMAGE_{process_id.value}"
            return Path(buffer.value).name or buffer.value
        finally:
            kernel32.CloseHandle(process_handle)

    @staticmethod
    def _effective_foreground_window(hwnd: int) -> int:
        """Resolve the usable foreground window beneath a transparent overlay."""
        if not _is_transient_overlay_style(int(user32.GetWindowLongPtrW(hwnd, GWL_EXSTYLE))):
            return hwnd

        candidate = user32.GetWindow(hwnd, GW_HWNDNEXT)
        inspected = 0
        while candidate and inspected < 256:
            inspected += 1
            ex_style = int(user32.GetWindowLongPtrW(candidate, GWL_EXSTYLE))
            if (
                user32.IsWindowVisible(candidate)
                and not user32.IsIconic(candidate)
                and user32.GetWindowTextLengthW(candidate) > 0
                and not _is_transient_overlay_style(ex_style)
                and not (ex_style & WS_EX_TOOLWINDOW)
            ):
                return candidate
            candidate = user32.GetWindow(candidate, GW_HWNDNEXT)
        return hwnd

    def _resolve_recent_user_input(self, now_ms: int) -> str:
        info = LASTINPUTINFO()
        info.cbSize = ctypes.sizeof(LASTINPUTINFO)
        if not user32.GetLastInputInfo(ctypes.byref(info)):
            return "UNAVAILABLE:LAST_INPUT_INFO"

        tick_now_64 = int(kernel32.GetTickCount64())
        tick_now_32 = tick_now_64 & 0xFFFFFFFF
        idle_ms = (tick_now_32 - int(info.dwTime)) & 0xFFFFFFFF
        last_input_ms = max(0, now_ms - idle_ms)
        return f"global@{last_input_ms}"

    def _resolve_screen_or_session_active(self) -> bool:
        desktop_handle = user32.OpenInputDesktop(0, False, DESKTOP_READOBJECTS | DESKTOP_SWITCHDESKTOP)
        if not desktop_handle:
            return False

        try:
            name_buffer = ctypes.create_unicode_buffer(256)
            needed = wintypes.DWORD()
            ok = user32.GetUserObjectInformationW(
                desktop_handle,
                UOI_NAME,
                name_buffer,
                ctypes.sizeof(name_buffer),
                ctypes.byref(needed),
            )
            if not ok:
                return False
            return name_buffer.value.strip().lower() == "default"
        finally:
            user32.CloseDesktop(desktop_handle)


def _is_transient_overlay_style(ex_style: int) -> bool:
    return bool(ex_style & WS_EX_NOACTIVATE) or bool(
        (ex_style & WS_EX_TOPMOST) and (ex_style & WS_EX_LAYERED)
    )
