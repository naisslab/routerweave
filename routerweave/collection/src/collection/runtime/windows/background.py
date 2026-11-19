"""Read-only Windows state evidence for the shared capture lifecycle.

No input, locking or unlocking is performed by this module. WTS session flags
are interpreted for Windows 8 and newer. Failed native queries remain unknown.
"""
from __future__ import annotations

import ctypes
import csv
from ctypes import wintypes
import json
import math
from pathlib import Path
import struct
import sys
import time




def probe_background_state() -> dict:
    from .platforms.windows import user32, kernel32, LASTINPUTINFO, WindowsSnapshotter
    wts = ctypes.WinDLL('wtsapi32', use_last_error=True)
    wts.WTSQuerySessionInformationW.argtypes = [wintypes.HANDLE, wintypes.DWORD,
        ctypes.c_int, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD)]
    wts.WTSQuerySessionInformationW.restype = wintypes.BOOL
    wts.WTSFreeMemory.argtypes = [ctypes.c_void_p]
    kernel32.ProcessIdToSessionId.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    kernel32.ProcessIdToSessionId.restype = wintypes.BOOL
    kernel32.GetCurrentProcessId.restype = wintypes.DWORD
    session = wintypes.DWORD()
    flags = state = None
    error = None
    if kernel32.ProcessIdToSessionId(kernel32.GetCurrentProcessId(), ctypes.byref(session)):
        buffer, size = ctypes.c_void_p(), wintypes.DWORD()
        if wts.WTSQuerySessionInformationW(None, session.value, 25,
                                         ctypes.byref(buffer), ctypes.byref(size)):
            try:
                # WTSINFOEXW: Level DWORD, aligned union (8), then three DWORDs.
                if size.value >= 20 and sys.getwindowsversion().build >= 9200:
                    level, _, sid, state, flags = struct.unpack('<IIIII', ctypes.string_at(buffer, 20))
                    if level != 1 or sid != session.value or flags not in (0, 1):
                        flags = state = None
                        error = 'invalid_wts_session_info'
            finally:
                wts.WTSFreeMemory(buffer)
        else:
            error = f'wts_query:{ctypes.get_last_error()}'
    else:
        error = 'session_id_query'
    info = LASTINPUTINFO()
    info.cbSize = ctypes.sizeof(info)
    input_ok = bool(user32.GetLastInputInfo(ctypes.byref(info)))
    tick = int(kernel32.GetTickCount64()) & 0xffffffff
    hwnd = user32.GetForegroundWindow()
    user32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user32.GetClassNameW.restype = ctypes.c_int
    cls = ctypes.create_unicode_buffer(256)
    class_ok = bool(hwnd and user32.GetClassNameW(hwnd, cls, len(cls)))
    snapshotter = WindowsSnapshotter()
    return {'schema_version': 'windows-background-state-v1', 'observed_epoch': time.time(),
            'session_id': session.value, 'wts_session_flags': flags, 'wts_connection_state': state,
            'wts_error': error, 'input_query_ok': input_ok,
            'tick32': tick, 'last_input_tick32': int(info.dwTime) if input_ok else None,
            'idle_ms': (tick - int(info.dwTime)) & 0xffffffff if input_ok else None,
            'input_desktop_default': snapshotter._resolve_screen_or_session_active(),
            'foreground_window_class': cls.value if class_ok else None,
            'foreground_process': snapshotter._resolve_foreground_app(),
            'method': 'WTSQuerySessionInformationW:GetLastInputInfo:GetClassNameW'}


def state_matches(row: dict, scenario: str, minimum_idle_seconds: float = 60) -> bool:
    if row.get('schema_version') != 'windows-background-state-v1' or row.get('wts_error'):
        return False
    if scenario == 'locked_session':
        return row.get('wts_session_flags') == 0 and row.get('input_desktop_default') is False
    if scenario != 'desktop_idle' or minimum_idle_seconds < 60:
        return False
    try:
        recomputed = (int(row['tick32']) - int(row['last_input_tick32'])) & 0xffffffff
        return (row.get('input_query_ok') is True and row.get('wts_session_flags') == 1
                and row.get('input_desktop_default') is True
                and row.get('foreground_window_class') in {'Progman', 'WorkerW'}
                and str(row.get('foreground_process', '')).lower() == 'explorer.exe'
                and row.get('idle_ms') == recomputed and recomputed >= minimum_idle_seconds * 1000)
    except (KeyError, TypeError, ValueError):
        return False


class BackgroundStateRecorder:
    def __init__(self, run: Path, scenario: str, seconds: float, minimum_idle_seconds: float,
                 stop_event, probe=probe_background_state):
        self.run, self.scenario, self.seconds = run, scenario, seconds
        self.minimum_idle_seconds, self.stop_event, self.probe = minimum_idle_seconds, stop_event, probe
        self.path = run / 'platform_evidence' / 'background_state.jsonl'
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.started = self.ended = None
        self.sequence = 0

    def record(self, record, number, bundle):
        row = self.probe()
        row.update({'sequence': self.sequence, 'ground_truth_timestamp_ms': record.timestamp_ms,
                    'scenario': self.scenario})
        self.sequence += 1
        with self.path.open('a', encoding='utf-8') as handle:
            handle.write(json.dumps(row) + '\n')
        now = float(row['observed_epoch'])
        if not state_matches(row, self.scenario, self.minimum_idle_seconds):
            raise RuntimeError('Background state changed or native state query became unknown')
        if self.started is None:
            self.started = now
        self.ended = now
        if now - self.started >= self.seconds:
            window = {'window_id': 'background-state', 'category_id': 'background',
                      'target_name': self.scenario, 'collection_scope': 'scenario',
                      'traffic_scope': 'workstation_device', 'status': 'accepted',
                      'started_epoch': self.started, 'ended_epoch': now,
                      'analysis_started_epoch': self.started, 'analysis_ended_epoch': now,
                      'duration_seconds': now-self.started,
                      'quality_tier': 'independent_native_background_state'}
            (self.run / 'usage_windows.jsonl').write_text(json.dumps(window)+'\n', encoding='utf-8')
            self.stop_event.set()


def validate_background_evidence(run: Path, manifest: dict) -> dict:
    spec = manifest.get('background_scenario') or {}
    rows = [json.loads(line) for line in (run/'platform_evidence/background_state.jsonl')
            .read_text(encoding='utf-8').splitlines() if line.strip()]
    windows = [json.loads(line) for line in (run/'usage_windows.jsonl')
               .read_text(encoding='utf-8').splitlines() if line.strip()]
    minimum = max(float(spec.get('minimum_accepted_seconds', 1800)),
                  1800 if manifest.get('collection_task_id') == 'windows-background-parity' else 10)
    idle = float(spec.get('minimum_idle_seconds', 60))
    stamps = [float(row['observed_epoch']) for row in rows]
    session = Path(manifest['session_dir'])
    if not session.is_absolute():
        session = run / session
    with (session / 'ground_truth.csv').open(encoding='utf-8-sig', newline='') as handle:
        truth = {int(row['timestamp_ms']): row for row in csv.DictReader(handle)}
    aligned = all(int(row['ground_truth_timestamp_ms']) in truth
                  and abs(float(row['observed_epoch']) - int(row['ground_truth_timestamp_ms']) / 1000) <= 1
                  for row in rows)
    maximum_gap = max((b-a for a,b in zip(stamps,stamps[1:])), default=math.inf)
    valid = (len(rows) >= 2 and len(windows) == 1 and aligned
             and all(math.isfinite(t) for t in stamps)
             and all(b > a for a,b in zip(stamps,stamps[1:]))
             and maximum_gap <= 2.5
             and [row.get('sequence') for row in rows] == list(range(len(rows)))
             and all(row.get('scenario') == spec.get('name') and
                     state_matches(row, spec.get('name'), idle) for row in rows)
             and len({row.get('session_id') for row in rows}) == 1
             and windows[0].get('status') == 'accepted'
             and windows[0].get('target_name') == spec.get('name')
             and abs(float(windows[0]['started_epoch'])-stamps[0]) < .001
             and abs(float(windows[0]['ended_epoch'])-stamps[-1]) < .001
             and stamps[-1]-stamps[0] >= minimum
             and float(windows[0]['ended_epoch']) <= float(manifest['capture_ended_epoch']))
    return {'ok': bool(valid), 'scenario': spec.get('name'), 'samples': len(rows),
            'verified_state_seconds': stamps[-1]-stamps[0] if stamps else 0,
            'maximum_state_sample_gap_seconds': maximum_gap,
            'ground_truth_alignment_verified': aligned,
            'minimum_accepted_seconds': minimum, 'collection_scope': 'scenario',
            'app_attributed': False}
