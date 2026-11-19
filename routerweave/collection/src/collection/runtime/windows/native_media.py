"""Read-only, process-scoped WASAPI evidence for native Windows music tasks.

UI control remains in the authorized Computer Use adapter. This module never
changes volume, playback, focus, permissions, or application state.
"""
from __future__ import annotations

import math
from pathlib import PureWindowsPath
import time


def audio_is_active(evidence: dict, executable: str) -> bool:
    """Recompute audibility from recorded meter values, never a UI receipt."""
    if evidence.get("source") != "wasapi_process_peak_v1":
        return False
    expected = str(PureWindowsPath(executable)).casefold()
    if not PureWindowsPath(executable).is_absolute():
        return False
    sessions = evidence.get("sessions", [])
    if not isinstance(sessions, list):
        return False
    for session in sessions:
        if not isinstance(session, dict):
            return False
        peaks = session.get("peaks", [])
        if (not isinstance(peaks, list) or len(peaks) != 5
                or any(isinstance(v, bool) or not isinstance(v, (int, float))
                       or not math.isfinite(v) or not 0 <= v <= 1 for v in peaks)):
            return False
        if (str(PureWindowsPath(session.get("executable", ""))).casefold() == expected
                and isinstance(session.get("pid"), int) and session["pid"] > 0
                and session.get("state") == 1 and max(peaks) > 0.0001):
            return True
    return False


def sample_process_audio(executable: str) -> dict:
    """Observe only sessions whose actual process executable matches the plan."""
    import comtypes
    import psutil
    from pycaw.pycaw import AudioUtilities
    from pycaw.api.endpointvolume import IAudioMeterInformation

    if not PureWindowsPath(executable).is_absolute():
        raise ValueError("Native audio identity requires an absolute executable path")
    expected = str(PureWindowsPath(executable)).casefold()
    comtypes.CoInitialize()
    try:
        rows, meters, expired_session_pids = [], [], []
        for session in AudioUtilities.GetAllSessions():
            try:
                process = session.Process
                if process is None:
                    continue
                path = process.exe()
            except psutil.NoSuchProcess as exc:
                # WASAPI can retain a session after its owning process exits.
                # It cannot provide process-scoped playback evidence.
                expired_session_pids.append(exc.pid)
                continue
            if str(PureWindowsPath(path)).casefold() != expected:
                continue
            rows.append({"pid": process.pid, "executable": path,
                         "state": session.State, "peaks": []})
            meters.append(session._ctl.QueryInterface(IAudioMeterInformation))
        started = time.time()
        for index in range(5):
            for row, meter in zip(rows, meters):
                row["peaks"].append(float(meter.GetPeakValue()))
            if index < 4:
                time.sleep(0.05)
        return {"source": "wasapi_process_peak_v1", "started_epoch": started,
                "ended_epoch": time.time(), "sessions": rows,
                "expired_session_pids": sorted(set(expired_session_pids))}
    finally:
        comtypes.CoUninitialize()
