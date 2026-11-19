"""Process ownership for the common IoT routine; no device control runtime here."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace

from collection.runtime.artifacts import EventLog
from collection.runtime.errors import DemoError
from collection.runtime.ios.iot_routine import (
    RoutineCapture, RoutineRunner, WORKSPACE, atomic_json, exclusive_lock,
    fingerprint, keep_awake, read_json, capture_deadline, capture_plan_matches,
)


class CaptureCheckpoint:
    """Read the capture process's atomic checkpoint without owning its lifetime."""
    def __init__(self, runner):
        self.runner = runner

    def snapshot(self):
        path = self.runner.root / "capture_state.json"
        if not path.exists():
            return {"capture_health": {"ok": False}, "identity_ready": False}
        state = read_json(path)
        if not capture_plan_matches(self.runner.root, self.runner.plan, state.get("plan_sha256")):
            raise DemoError("Capture checkpoint plan mismatch")
        return {key: state[key] for key in ("segments", "capture_gaps", "capture_issues", "capture_health", "identity_ready")}

    def check(self):
        state = self.snapshot()
        health = state.get("capture_health", {})
        if not health.get("ok") or self.runner.now() - health.get("epoch", 0) > 90:
            raise DemoError("Capture is recovering; only this command is paused")
        if not state.get("identity_ready"):
            raise DemoError("Device identity is unavailable; passive capture continues")

    def start_watchdog(self):
        pass  # The supervisor owns the independent capture process.

    def stop_watchdog(self):
        pass  # A control worker's exit must NEVER stop capture.


def run_capture_worker(root, compiled):
    with exclusive_lock(root / "capture.lock"), keep_awake():
        # Arm now without collecting an extra day of data. The lead brackets
        # the interval; waiting has a heartbeat but never touches the phone.
        if compiled.get("capture_only"):
            # Allow transport startup before the requested quiet baseline begins.
            capture_start = compiled["start_epoch"] - compiled.get("capture_margin_seconds", 0) - 60
            while time.time() < capture_start and not (root / "STOP").exists():
                atomic_json(root / "capture_state.json", {
                    "status": "waiting", "updated_epoch": time.time(),
                    "plan_sha256": fingerprint(compiled), "segments": [],
                    "capture_gaps": [], "capture_issues": [],
                    "capture_health": {"ok": False, "status": "waiting"}, "identity_ready": False,
                })
                time.sleep(max(0, min(5, capture_start - time.time())))
            if (root / "STOP").exists():
                return 2
        runner = SimpleNamespace(root=root, plan=compiled, now=time.time, state={
            "segments": [], "capture_gaps": [], "capture_issues": [], "plan_sha256": fingerprint(compiled)})
        capture = RoutineCapture(runner)
        capture.start_watchdog()
        while time.time() < capture_deadline(compiled) and not (root / "STOP").exists():
            if not capture._thread.is_alive():
                # Unexpected worker-thread failure is retried locally. Its
                # finally handler already closes only its own segment.
                capture.start_watchdog()
            time.sleep(min(1, max(0, capture_deadline(compiled) - time.time())))
        capture.stop_watchdog()
    return 0


def worker_command(args, root, role):
    return [sys.executable, "-B", "-m", "collection.runtime.ios.iot_routine",
            "--plan", str(args.plan.resolve()), "--start-at", args.start_at,
            "--run-root", str(root), "--collection-task-id", args.collection_task_id,
            "--purpose", args.purpose,
            *(["--capture-only"] if getattr(args, "capture_only", False) else []),
            *(["--capture-margin-seconds", str(args.capture_margin_seconds)]
              if getattr(args, "capture_margin_seconds", None) is not None else []),
            "--resume", "--worker-role", role]


class AttachedChild:
    """Hold a Windows process handle so an adopted PID cannot be reused."""
    def __init__(self, pid):
        import ctypes
        from ctypes import wintypes
        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        self.api.OpenProcess.restype = wintypes.HANDLE
        self.api.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        for name in ("WaitForSingleObject", "GetExitCodeProcess", "TerminateProcess", "CloseHandle"):
            getattr(self.api, name).argtypes = {
                "WaitForSingleObject": (wintypes.HANDLE, wintypes.DWORD),
                "GetExitCodeProcess": (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)),
                "TerminateProcess": (wintypes.HANDLE, wintypes.UINT),
                "CloseHandle": (wintypes.HANDLE,),
            }[name]
        self.handle = self.api.OpenProcess(0x100000 | 0x1000 | 1, False, pid)
        if not self.handle:
            raise OSError("Cannot attach owned routine child")
        self.pid = pid

    def poll(self):
        if self.api.WaitForSingleObject(self.handle, 0) == 258:
            return None
        import ctypes
        from ctypes import wintypes
        code = wintypes.DWORD()
        if not self.api.GetExitCodeProcess(self.handle, ctypes.byref(code)):
            raise OSError("Cannot read owned child status")
        return code.value

    def wait(self, timeout):
        if self.api.WaitForSingleObject(self.handle, int(timeout * 1000)) == 258:
            raise subprocess.TimeoutExpired("owned routine child", timeout)
        return self.poll()

    def terminate(self):
        if not self.api.TerminateProcess(self.handle, 2):
            raise OSError("Cannot terminate owned routine child")

    def __del__(self):
        if getattr(self, "handle", None):
            self.api.CloseHandle(self.handle)


def adopt_child(pid, root, role):
    if os.name != "nt" or not isinstance(pid, int) or role not in {"capture", "control"}:
        return None
    # Open first: holding the process handle prevents PID reuse while its
    # command line and executable identity are being inspected.
    child = AttachedChild(pid)
    result = subprocess.run(["powershell", "-NoProfile", "-Command",
                             f"Get-CimInstance Win32_Process -Filter 'ProcessId = {pid}' | Select-Object CommandLine,ExecutablePath | ConvertTo-Json -Compress"],
                            capture_output=True, text=True, timeout=10,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    value = json.loads(result.stdout) if result.stdout.strip() else {}
    command = value.get("CommandLine", "").casefold()
    if ("collection.runtime.ios.iot_routine" in command and str(root).casefold() in command
            and f"--worker-role {role}" in command
            and os.path.normcase(value.get("ExecutablePath", "")) == os.path.normcase(sys.executable)):
        return child
    return None


def restart_name(root):
    return "Testbed-IoTRoutine-" + hashlib.sha256(str(root).encode()).hexdigest()[:16]


def install_restart_task(args, root, end_epoch):
    """Current-user login recovery; no admin rights or password storage."""
    if os.name != "nt":
        return None
    import winreg
    task_name = restart_name(root)
    command = worker_command(args, root, "control")
    command = command[:-2]  # Launch the supervisor, not a control worker.
    command.append("--guardian")
    quote = lambda value: "'" + str(value).replace("'", "''") + "'"
    resume = root / "resume.ps1"
    resume.write_text(
        "$env:PYTHONPATH = " + quote(WORKSPACE / "src") + "\n"
        "Set-Location -LiteralPath " + quote(WORKSPACE) + "\n"
        "& " + " ".join(quote(part) for part in command) + "\nexit $LASTEXITCODE\n", encoding="utf-8-sig")
    invocation = subprocess.list2cmdline(["powershell.exe", "-NoProfile", "-WindowStyle", "Hidden",
                                         "-ExecutionPolicy", "Bypass", "-File", str(resume)])
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run") as key:
        winreg.SetValueEx(key, task_name, 0, winreg.REG_SZ, invocation)
        if winreg.QueryValueEx(key, task_name)[0] != invocation:
            raise DemoError("Current-user login recovery registration did not persist")
    return task_name


def remove_restart_task(name):
    if name and os.name == "nt":
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, name)
        except FileNotFoundError:
            pass


def run_guardian(args, root, compiled):
    """Restart the supervisor; its children keep running if it crashes."""
    root.mkdir(parents=True, exist_ok=True)
    command = worker_command(args, root, "control")[:-2]
    environment = dict(os.environ, PYTHONPATH=str(WORKSPACE / "src"), PYTHONUNBUFFERED="1")
    with exclusive_lock(root / "guardian.lock"), keep_awake(), (root / "runner.log").open("ab") as log:
        process = None
        while time.time() < capture_deadline(compiled) and not (root / "STOP").exists():
            if process is None or process.poll() is not None:
                # A held supervisor lock rejects a duplicate guardian launch;
                # no existing worker is terminated when another guardian starts.
                environment["TESTBED_ROUTINE_LOG_OWNER_PID"] = str(os.getpid())
                process = subprocess.Popen(command, cwd=WORKSPACE, env=environment,
                                           stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            time.sleep(min(5, max(0, capture_deadline(compiled)-time.time())))
        if process is not None:
            try:
                process.wait(timeout=100)
            except subprocess.TimeoutExpired:
                process.terminate()
        remove_restart_task(restart_name(root))
    return 0


def supervise(args, root, compiled):
    root.mkdir(parents=True, exist_ok=True)
    with exclusive_lock(root / "supervisor.lock"), keep_awake():
        # Prepare the one immutable plan before either child writes artifacts.
        capture_only = bool(compiled.get("capture_only"))
        roles = ("capture",) if capture_only else ("capture", "control")
        if not (root / "routine_state.json").exists():
            prepared = RoutineRunner(root, compiled, None)
            if capture_only:
                for event in prepared.state["events"]:
                    for step in event["steps"]:
                        step["status"] = "manual_unverified"
                prepared.state["status"] = "waiting"
                prepared.save()
                prepared.log.write("routine_capture_only", start_epoch=compiled["start_epoch"], end_epoch=compiled["end_epoch"])
        elif not args.resume:
            raise DemoError("Existing routine requires --resume")
        if capture_only:
            from collection.runtime.registry.tasks import CollectionTaskRun
            CollectionTaskRun(root, args.collection_task_id).start(
                kind="iot", platform=compiled["control_platform"], purpose=args.purpose)
        state_path = root / "supervisor.json"
        previous = read_json(state_path) if state_path.exists() else {}
        state = {"status": "running", "pid": os.getpid(), "children": {},
                 "restarts": previous.get("restarts", []), "issues": []}
        task_name = None
        try:
            task_name = install_restart_task(args, root, capture_deadline(compiled))
        except Exception as exc:
            # Registration is observable but cannot prevent passive capture.
            state["issues"].append({"restart_task_error": str(exc)})
        children, started, last_restart = {}, {}, {}
        events = EventLog(root / "supervisor_events.jsonl")
        for role, pid in previous.get("children", {}).items():
            if role not in roles:
                raise DemoError("Unexpected control process in a capture-only run")
            try:
                child = adopt_child(pid, root, role)
                if child:
                    children[role] = child
                    state["children"][role] = pid
                    started[role] = time.time()
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                state["issues"].append({"adoption_error": str(exc), "role": role})
        environment = dict(os.environ, PYTHONPATH=str(WORKSPACE / "src"), PYTHONUNBUFFERED="1")
        def launch(role):
            # Popen duplicates the log handle into the child; the parent closes
            # its copy immediately, including across thousands of recoveries.
            with (root / f"{role}-worker.log").open("ab") as log:
                proc = subprocess.Popen(worker_command(args, root, role), cwd=WORKSPACE, env=environment,
                                        stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            children[role] = proc
            started[role] = last_restart[role] = time.time()
            state["children"][role] = proc.pid
            state["restarts"].append({"role": role, "epoch": time.time(), "pid": proc.pid})
            state["restarts"] = state["restarts"][-100:]
            try:
                events.write("routine_worker_started", role=role, pid=proc.pid)
            except OSError:
                pass
        try:
            while time.time() < capture_deadline(compiled) and not (root / "STOP").exists():
                for role in roles:
                    try:
                        proc = children.get(role)
                        checkpoint = root / ("capture_state.json" if role == "capture" else "routine_state.json")
                        heartbeat = max(started.get(role, 0), checkpoint.stat().st_mtime if checkpoint.exists() else 0)
                        if proc and proc.poll() is None and time.time() - heartbeat > 180:
                            proc.terminate()  # Only the owned child; capture is a separate process.
                            proc.wait(timeout=10)
                        if (proc is None or proc.poll() is not None) and time.time()-last_restart.get(role, 0) >= 5:
                            launch(role)
                    except Exception as exc:
                        state["issues"].append({"role": role, "error": str(exc), "epoch": time.time()})
                state["updated_epoch"] = time.time()
                if capture_only:
                    try:
                        checkpoint = read_json(root / "routine_state.json")
                        checkpoint.update(CaptureCheckpoint(SimpleNamespace(root=root, plan=compiled)).snapshot())
                        checkpoint.update(status="waiting" if time.time() < compiled["start_epoch"] else "capturing",
                                          updated_epoch=time.time())
                        atomic_json(root / "routine_state.json", checkpoint)
                        (root / "collection_task.json").touch()
                    except (OSError, ValueError, KeyError) as exc:
                        state["issues"].append({"checkpoint_error": str(exc), "epoch": time.time()})
                state["issues"] = state["issues"][-100:]
                try:
                    atomic_json(state_path, state)
                except OSError:
                    pass
                time.sleep(min(2, max(0, capture_deadline(compiled)-time.time())))
        finally:
            # Let each child close its own resources at the common deadline.
            # Control failure never reaches this run-level shutdown path.
            for role, proc in children.items():
                try:
                    proc.wait(timeout=75)
                except subprocess.TimeoutExpired:
                    proc.terminate()
                    proc.wait(timeout=10)
            remove_restart_task(task_name)
        from collection.runtime.ios.iot_routine_validation import accept_run
        # Merge the capture's final statistics after both processes have exited.
        control_state = read_json(root / "routine_state.json")
        if capture_only:
            control_state.update(status="cancelled" if (root / "STOP").exists() else "complete",
                                 updated_epoch=time.time())
        if (root / "capture_state.json").exists():
            control_state.update(CaptureCheckpoint(SimpleNamespace(root=root, plan=compiled)).snapshot())
        atomic_json(root / "routine_state.json", control_state)
        # The guardian and this supervisor still own runner.log until exit.
        # Keep validation/acceptance synchronous; only payload removal waits.
        log_owner = int(os.environ.get("TESTBED_ROUTINE_LOG_OWNER_PID", os.getpid()))
        report = accept_run(root, defer_closeout_pid=log_owner if args.purpose == "validation" else None)
        state.update(status="cancelled" if (root / "STOP").exists() else "finished", updated_epoch=time.time(),
                     validation={key: report[key] for key in ("artifact_valid", "capture_complete", "actions_complete")})
        atomic_json(state_path, state)
        return 0 if report["artifact_valid"] else 2
