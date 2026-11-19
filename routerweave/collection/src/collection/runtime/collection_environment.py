"""Shared, operator-labelled preparation inside the existing capture lifecycle.

This does not automate apps or own a capture. Foreground collectors continue to
own their adapters, semantic validation and router lifecycle.
"""
from __future__ import annotations

import json
import math
import hashlib
import re
from datetime import datetime
from pathlib import Path
import time

PROFILE = "uncleared_background_v1"
CONTINUATION_PROFILE = "retained_background_v2"
ALIASES = {"qq_music": "qqmusic", "netease_music": "netease"}
SOURCES = (
    ("music", "qqmusic", "netease", "Play a song, pause playback, and move the app to the background."),
    ("browsing", "baidu", "csdn", "Open content, read and scroll, and leave the page open in the background."),
    ("short_video", "douyin", "kuaishou", "Play a video and swipe once, then background the app and verify that playback stops."),
    ("long_video", "bilibili", "iqiyi", "Play a video, pause playback, and move the app to the background."),
    ("live_stream", "douyu", "huya", "Watch a live stream, leave the stream, and move the app to the background."),
)


def _registered_apps(task):
    if task.get("breakdown"):
        return {row["key"] for row in task["breakdown"]}
    return set(task["metadata"].get("preparation_orders", {}))


def environment_recipe(task: dict | None, target: str, *, profile: str | None = None) -> dict | None:
    metadata = (task or {}).get("metadata", {})
    registered_profile = metadata.get("environment_profile")
    if not registered_profile:
        return None
    profile = profile or registered_profile
    if profile not in {registered_profile, metadata.get("continuation_profile")}:
        raise ValueError(f"Unknown collection environment: {profile}")
    target = ALIASES.get(target, target)
    if target not in _registered_apps(task):
        raise ValueError("Target app does not belong to the registered supplementary task")
    if profile == CONTINUATION_PROFILE:
        if task["platform"] not in {"android", "ios", "windows"}:
            raise ValueError("Continuation requires a supported native platform")
        return {"profile": profile, "task_id": task["id"], "platform": task["platform"],
                "target": target, "evidence_mode": "native_boundary_snapshot" if task["platform"] == "android"
                else "native_ios_current_operator_media" if task["platform"] == "ios"
                else "native_machine_current_operator_media",
                "policy": "retain_existing_without_reset_or_preparation_replay",
                "historical_continuity": "unknown"}
    if profile != PROFILE:
        raise ValueError(f"Unknown collection environment: {profile}")
    order = metadata.get("preparation_orders", {}).get(target)
    if type(order) is not int or order not in range(1, 6):
        raise ValueError("Registered preparation order must be 1..5")
    steps = [dict(category=category, app=alternate if target == primary else primary,
                  instruction=instruction, seconds=30)
             for category, primary, alternate, instruction in SOURCES]
    steps = steps[order - 1:] + steps[:order - 1]
    recipe = {"profile": PROFILE, "task_id": task["id"], "platform": task["platform"],
            "target": target, "order": order, "evidence_mode": "operator_labels",
            "steps": steps}
    if task["platform"] == "android":
        from .registry.tasks import load_collection_tasks
        from .mobile_control.catalog import MobileAppCatalog
        from .mobile_control.status import Platform
        catalog = MobileAppCatalog.from_repository()
        apps = {app for entry in load_collection_tasks()
                if entry["platform"] == "android" and entry["category"] != "gaming"
                and entry.get("metadata", {}).get("environment_profile") == PROFILE
                for app in _registered_apps(entry)}
        recipe["reset_packages"] = sorted(catalog.require(Platform.ANDROID, app).app_id for app in apps)
    return recipe


def prepare_environment(root: Path, recipe: dict, *, input_fn=None, clock=None, resetter=None,
                        operator_kind: str = "human") -> None:
    """Prompt for actual actions; never fabricate semantic-success evidence."""
    if operator_kind not in {"human", "agent"}:
        raise ValueError("environment operator must be human or agent")
    input_fn = input if input_fn is None else input_fn
    clock = time.time if clock is None else clock
    root = Path(root)
    path = root / "environment_events.jsonl"
    root.mkdir(parents=True, exist_ok=True)
    # Reusing a run directory must not replace another preparation's evidence.
    with path.open("x", encoding="utf-8") as stream:
        def emit(event, **fields):
            row = {"event": event, "epoch": clock(), **fields}
            stream.write(json.dumps(row, ensure_ascii=False) + "\n")
            stream.flush()
            return row["epoch"]

        emit("preparation_started", recipe=recipe, operator_kind=operator_kind)
        try:
            if recipe.get("reset_packages"):
                if resetter is None:
                    raise ValueError("Android preparation requires a verified experiment-app reset")
                result = resetter(tuple(recipe["reset_packages"]))
                emit("experiment_apps_reset", result=result)
                if not _reset_verified(result, recipe["reset_packages"]):
                    raise RuntimeError("Experiment app reset failed independent verification")
            input_fn("Preserve background apps and caches. Resolve login issues first. Press Enter to begin or Ctrl+C to cancel.")
            for index, step in enumerate(recipe["steps"]):
                input_fn(f"[{index + 1}/5] Open {step['app']}. {step['instruction']} "
                         "Press Enter to start timing when the content is available.")
                started = emit("content_started", index=index, app=step["app"])
                while True:
                    answer = input_fn("Use the app normally for at least 30 seconds and complete the exit steps. "
                                      "Confirm playback has stopped and the app was not cleared. Enter done or press Ctrl+C to cancel: ")
                    if answer.strip().lower() != "done":
                        continue
                    if clock() - started < step["seconds"]:
                        print("Fewer than 30 seconds elapsed. Continue using the app before confirming.", flush=True)
                        continue
                    break
                emit("backgrounded", index=index, app=step["app"],
                     operator_confirmed=True, media_stopped=True, operator_kind=operator_kind)
            answer = input_fn("Preparation complete. Leave all five apps in place. On Windows, keep the preparation tabs open "
                              "and use a separate target tab. Enter ready to start the foreground task: ")
            if answer.strip().lower() != "ready":
                raise ValueError("Background retention was not confirmed")
            emit("preparation_finished", background_retained=True)
        except BaseException as exc:
            emit("preparation_failed", error=type(exc).__name__)
            raise


def _reset_verified(result: dict, packages: list[str]) -> bool:
    remaining = result.get("remaining_processes")
    return (result.get("success") is True
            and result.get("method") == "registered_app_force_stop"
            and result.get("packages") == packages
            and isinstance(remaining, dict) and set(remaining) == set(packages)
            and all(value == [] for value in remaining.values()))


def _matches_registered_recipe(expected, recorded):
    """Compare the registered conditions while allowing localized operator instructions."""
    if expected == recorded:
        return True
    if not expected or expected.get("profile") != PROFILE or not isinstance(recorded, dict):
        return False
    steps = recorded.get("steps")
    if not isinstance(steps, list) or len(steps) != len(expected["steps"]):
        return False
    normalized = []
    for step, reference in zip(steps, expected["steps"]):
        if not isinstance(step, dict) or not isinstance(step.get("instruction"), str) or not step["instruction"].strip():
            return False
        normalized.append({**step, "instruction": reference["instruction"]})
    return {**recorded, "steps": normalized} == expected


def validate_environment(root: Path, recipe: dict | None, *, foreground_start=None) -> list[str]:
    """Recompute operator-labelled preparation from its original event log."""
    if recipe is None:
        return []
    try:
        from .registry.tasks import load_collection_tasks
        task = next(t for t in load_collection_tasks() if t["id"] == recipe["task_id"])
        if not _matches_registered_recipe(environment_recipe(task, recipe["target"]), recipe):
            return ["environment recipe differs from its registered task"]
        rows = [json.loads(line) for line in (Path(root) / "environment_events.jsonl")
                .read_text(encoding="utf-8").splitlines() if line.strip()]
        epochs = [float(row["epoch"]) for row in rows]
        offset = int(bool(recipe.get("reset_packages")))
        if len(rows) != 12 + offset or any(not math.isfinite(t) for t in epochs) or epochs != sorted(epochs):
            return ["environment events are incomplete or out of order"]
        if rows[0].get("event") != "preparation_started" or rows[0].get("recipe") != recipe:
            return ["environment start does not match the requested condition"]
        errors = []
        operator_kind = rows[0].get("operator_kind", "human")
        if operator_kind not in {"human", "agent"}:
            errors.append("unknown environment operator")
        if offset and (rows[1].get("event") != "experiment_apps_reset"
                       or not _reset_verified(rows[1].get("result", {}), recipe["reset_packages"])):
            errors.append("experiment app reset lacks independent process evidence")
        for index, step in enumerate(recipe["steps"]):
            start, end = rows[1 + offset + 2 * index:3 + offset + 2 * index]
            if (start.get("event") != "content_started" or end.get("event") != "backgrounded"
                    or any(row.get("app") != step["app"] or row.get("index") != index
                           for row in (start, end))
                    or end.get("operator_confirmed") is not True or end.get("media_stopped") is not True
                    or end.get("operator_kind", "human") != operator_kind
                    or float(end["epoch"]) - float(start["epoch"]) < step["seconds"]):
                errors.append(f"environment step {index + 1} lacks complete operator evidence")
        if rows[-1].get("event") != "preparation_finished" or rows[-1].get("background_retained") is not True:
            errors.append("background retention was not confirmed")
        if foreground_start is not None and epochs[-1] > float(foreground_start):
            errors.append("environment preparation overlaps the foreground task")
        return errors
    except (OSError, ValueError, KeyError, TypeError, StopIteration) as exc:
        return [f"environment evidence unavailable: {type(exc).__name__}: {exc}"]


def validate_run_environment(root: Path, target: str, recorded: dict | None,
                             *, foreground_start=None, _seen=(), _archive=None) -> list[str]:
    """A supplementary registration cannot bypass validation by dropping its tag."""
    from .registry.tasks import load_collection_tasks
    sidecar = Path(root) / "collection_task.json"
    try:
        root = Path(root).resolve()
        if _archive is None and (root / "environment_sources.json").exists():
            index = _read_json(root / "environment_sources.json")
            if not isinstance(index, dict) or index.get("schema_version") != 1 or not isinstance(index.get("sources"), dict):
                raise ValueError("invalid environment source archive")
            _archive = {}
            for original, relative in index["sources"].items():
                local = (root / relative).resolve()
                if not Path(original).is_absolute() or not local.is_relative_to(root) or local == root:
                    raise ValueError("environment source archive escapes collection evidence")
                _archive[str(Path(original).resolve())] = local
        if root in _seen or len(_seen) >= 64:
            return ["environment recovery ancestry is cyclic or too deep"]
        task_id = json.loads(sidecar.read_text(encoding="utf-8")).get("task_id") if sidecar.exists() else None
        task = next((t for t in load_collection_tasks() if t["id"] == task_id), None)
        expected = environment_recipe(task, target, profile=(recorded or {}).get("profile"))
        if not _matches_registered_recipe(expected, recorded):
            return ["collection environment does not match the registered task"]
        if expected and expected["profile"] == CONTINUATION_PROFILE:
            return _validate_continuation(root, expected, foreground_start, (*_seen, root), _archive)
        if (root / "environment_recovery.json").exists():
            if expected is None:
                return ["environment recovery requires a supplementary registration"]
            return _validate_recovery(root, recorded, foreground_start, (*_seen, root), _archive)
        manifest_path = root / ("windows_capture_manifest.json" if expected and expected.get("platform") == "windows" else "collection_manifest.json")
        if manifest_path.exists() and json.loads(manifest_path.read_text(encoding="utf-8")).get("resume_environment_from"):
            return ["environment recovery evidence is missing"]
        if expected is not None:
            run_start = datetime.fromisoformat(json.loads(sidecar.read_text(encoding="utf-8"))["started_at"]).timestamp()
            first = json.loads((Path(root) / "environment_events.jsonl").read_text(encoding="utf-8").splitlines()[0])
            if float(first["epoch"]) < run_start:
                return ["environment evidence predates this collection run"]
        return validate_environment(root, recorded, foreground_start=foreground_start)
    except (OSError, ValueError, KeyError, TypeError, IndexError) as exc:
        return [f"invalid collection environment: {exc}"]


def _read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _source_hashes(root: Path) -> dict:
    if (root / "windows_capture_manifest.json").exists():
        names = ["collection_task.json", "windows_capture_manifest.json", "effective_plan.json"]
        names.append("environment_continuation.json" if (root / "environment_continuation.json").exists()
                     else "environment_recovery.json" if (root / "environment_recovery.json").exists()
                     else "environment_events.jsonl")
        if (root / "operator_machine_checkpoint.json").exists():
            names.append("operator_machine_checkpoint.json")
        return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in names}
    names = ["collection_task.json", "collection_manifest.json", "mobile_control/result.json"]
    names.append("environment_continuation.json" if (root / "environment_continuation.json").exists()
                 else "environment_recovery.json" if (root / "environment_recovery.json").exists()
                 else "environment_events.jsonl")
    if (root / "network_capture_windows.json").exists():
        names.append("network_capture_windows.json")
    manifest = _read_json(root / "collection_manifest.json")
    if manifest.get("request", {}).get("platform") == "ios" and not manifest.get("device_udid"):
        names.extend(str(path.relative_to(root)).replace("\\", "/")
                     for path in sorted((root / "platform_evidence").glob("process-*.stderr.log")))
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in names}


def recovery_source(source: Path, recipe: dict, *, _seen=(), _archive=None) -> dict:
    """Reference retained failed attempts; never turn them into successful samples."""
    source = Path(source).resolve()
    logical_source = source
    if _archive is not None:
        source = _archive[str(logical_source)]
    if recipe.get("platform") == "windows":
        return _windows_recovery_source(source, logical_source, recipe, _seen, _archive)
    sidecar = _read_json(source / "collection_task.json")
    manifest = _read_json(source / "collection_manifest.json")
    if sidecar.get("task_id") != recipe["task_id"] or sidecar.get("status") != "failed":
        raise ValueError("Recovery source must be a finished failed attempt of the same task")
    if manifest.get("request", {}).get("app_name") != recipe["target"]:
        raise ValueError("Recovery cannot switch the target app")
    windows_path = source / "network_capture_windows.json"
    starts = [w.get("actual", {}).get("start_epoch") for w in _read_json(windows_path)] if windows_path.exists() else []
    starts = [value for value in starts if value is not None]
    errors = validate_run_environment(source, recipe["target"], manifest.get("collection_environment"),
                                      foreground_start=min(starts) if starts else None, _seen=_seen,
                                      _archive=_archive)
    if errors:
        raise ValueError("; ".join(errors))
    previous = source / "environment_recovery.json"
    original = Path(_read_json(previous)["preparation_run"]) if previous.exists() else logical_source
    return {"parent_run": str(logical_source), "parent_hashes": _source_hashes(source),
            "preparation_run": str(original), "logical_sample_id": str(original),
            "foreground_request": manifest["request"],
            "failed_at": sidecar["finished_at"]}


def _checkpoint_errors(checkpoint: dict, preparation_start: float) -> list[str]:
    """Recompute the native checks from retained raw observations."""
    errors = []
    epoch = float(checkpoint["epoch"])
    uptime = float(checkpoint["uptime"].split()[0])
    if not math.isfinite(epoch) or not math.isfinite(uptime) or uptime <= 0 or epoch - uptime > preparation_start:
        errors.append("phone rebooted after preparation, or boot evidence is invalid")
    if not checkpoint.get("serial") or not checkpoint.get("boot_id", "").strip():
        errors.append("device identity evidence is missing")
    if "MEDIA SESSION SERVICE" not in checkpoint["media_sessions"]:
        errors.append("media session observation is unavailable")
    if re.search(r"PlaybackState\s*\{state=3\b", checkpoint["media_sessions"]):
        errors.append("media session is playing")
    audio = checkpoint["audio_flinger"]
    standby = re.findall(r"^\s*Standby:\s*(\w+)", audio, re.M)
    tracks = re.findall(r"^\s*(\d+) Tracks(?: of which (\d+) are active)?\s*$", audio, re.M)
    # A retained paused track can keep its mixer out of standby. The explicit
    # active-track count is independent playback evidence; the mixer flag alone
    # does not establish that an app is playing. Unknown/missing counts still fail.
    if not standby or any(s not in {"yes", "no"} for s in standby) or not tracks or any(
            int(active) if active else int(total) for total, active in tracks):
        errors.append("audio output is active or lacks independent evidence")
    return errors


def _ios_source_udid(root: Path, manifest: dict) -> str:
    """Old iOS runs identify the device in the native process-capture receipt."""
    recorded = manifest.get("device_udid")
    if recorded:
        return str(recorded)
    identities = set()
    for path in (root / "platform_evidence").glob("process-*.stderr.log"):
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if (isinstance(row, dict) and row.get("module") == "go-ios/pcap" and row.get("msg") == "create pcap file"
                    and row.get("udid")):
                identities.add(row["udid"])
    if len(identities) != 1:
        raise ValueError("iOS continuation source lacks a unique native device identity")
    return identities.pop()


def _ios_checkpoint_errors(checkpoint: dict) -> list[str]:
    """Native current state plus an explicit, limited operator media label."""
    devices = checkpoint.get("devices", {}).get("deviceList", [])
    status = checkpoint.get("wda_status", {}).get("value", {})
    processes = checkpoint.get("processes")
    if (not checkpoint.get("udid") or len(devices) != 1
            or devices[0].get("Udid") != checkpoint["udid"]
            or status.get("ready") is not True
            or status.get("os", {}).get("version") != devices[0].get("ProductVersion")
            or not isinstance(processes, list) or not processes
            or any(not isinstance(p, dict) or not p.get("Name") or type(p.get("Pid")) is not int for p in processes)
            or not checkpoint.get("foreground", {}).get("bundleId")
            or not checkpoint.get("source", "").strip()):
        return ["Current iOS device/process/WDA snapshot is incomplete or ambiguous"]
    import xml.etree.ElementTree as ET
    try:
        tree = ET.fromstring(checkpoint["source"])
    except ET.ParseError as exc:
        raise ValueError("Current iOS UI snapshot is malformed") from exc
    if not list(tree):
        return ["Current iOS UI snapshot is truncated to the application root"]
    if checkpoint.get("media_evidence_scope") != "current_operator_observation":
        return ["iOS media evidence must be labelled as a current operator observation"]
    return []


def continuation_source(source: Path, recipe: dict, *, archive=None, seen=()) -> dict:
    """Historical preparation is a source, never an attestation of an unknown gap."""
    logical = Path(source).resolve()
    local = Path(archive[str(logical)]) if archive is not None else logical
    sidecar = _read_json(local / "collection_task.json")
    windows = recipe["platform"] == "windows"
    manifest = _read_json(local / ("windows_capture_manifest.json" if windows else "collection_manifest.json"))
    previous = manifest.get("collection_environment") or {}
    if (sidecar.get("status") not in {"failed", "complete", "completed"}
            or not sidecar.get("finished_at") or previous.get("platform") != recipe["platform"]
            or not (windows or recipe["platform"] == "ios" or manifest.get("device_serial"))):
        raise ValueError("Continuation source must be an ended, identified same-platform supplementary run")
    previous_target = manifest["target_name"] if windows else manifest["request"]["app_name"]
    errors = validate_run_environment(local, previous_target, previous,
                                      _seen=seen, _archive=archive)
    if errors:
        raise ValueError("Historical environment source is invalid: " + "; ".join(errors))
    origin = logical
    for name, field in (("environment_continuation.json", "original_preparation_run"),
                        ("environment_recovery.json", "preparation_run")):
        if (local / name).exists():
            origin = Path(_read_json(local / name)[field])
            break
    if windows:
        checkpoint_path = local / "environment_continuation.json"
        recovery_path = local / "environment_recovery.json"
        machine = (_read_json(checkpoint_path)["checkpoint"]["machine"] if checkpoint_path.exists()
                   else _read_json(recovery_path)["checkpoint"]["machine"] if recovery_path.exists()
                   else _read_json(local / "operator_machine_checkpoint.json"))
        identity = {"source_machine_name": machine["CSName"]}
    elif recipe["platform"] == "ios":
        identity = {"source_device_udid": _ios_source_udid(local, manifest)}
    else:
        identity = {"source_device_serial": manifest["device_serial"]}
    return {"parent_run": str(logical), "parent_hashes": _source_hashes(local),
            "original_preparation_run": str(origin), "source_profile": previous["profile"],
            "source_finished_at": sidecar["finished_at"], **identity}


def continue_environment(root: Path, recipe: dict, source: Path, *, serial: str,
                         udid: str = "", wda_url: str = "http://127.0.0.1:8100",
                         operator_kind: str = "human", checkpoint_reader=None, input_fn=None) -> None:
    if recipe.get("profile") != CONTINUATION_PROFILE or recipe.get("platform") not in {"android", "ios", "windows"}:
        raise ValueError("Continuation requires a registered native-boundary condition")
    provenance = continuation_source(source, recipe)
    windows = recipe["platform"] == "windows"
    ios = recipe["platform"] == "ios"
    if ios and udid != provenance["source_device_udid"]:
        raise ValueError("Continuation source belongs to a different iPhone")
    if not windows and not ios and serial != provenance["source_device_serial"]:
        raise ValueError("Continuation source belongs to a different phone")
    if windows:
        checkpoint = (checkpoint_reader or _windows_checkpoint)()
        answer = (input_fn or input)("At the sample boundary, verify that the preparation tabs are open and playback has stopped. Enter quiet to confirm the current state only: ")
        if answer.strip() != "quiet":
            raise ValueError("Current stopped-media observation was not confirmed")
        checkpoint["media_stopped_operator_observed"] = True
        checkpoint["current_media_checked_at"] = time.time()
    elif ios:
        if operator_kind not in {"human", "agent"}:
            raise ValueError("environment operator must be human or agent")
        if checkpoint_reader is None:
            from .mobile_control.adapters.ios import IosWdaAdapter
            from .mobile_control.catalog import MobileAppCatalog
            from .mobile_control.status import Platform
            app_id = MobileAppCatalog.from_repository().require(Platform.IOS, recipe["target"]).app_id
            checkpoint_reader = IosWdaAdapter(app_id, udid=udid, wda_url=wda_url).background_checkpoint
        checkpoint = checkpoint_reader()
        errors = _ios_checkpoint_errors(checkpoint)
        if errors:
            raise ValueError("; ".join(errors))
        # Retain the observation before prompting so an agent can inspect it.
        with (Path(root) / "ios_boundary_snapshot.json").open("x", encoding="utf-8") as stream:
            json.dump(checkpoint, stream, ensure_ascii=False, indent=2)
        answer = (input_fn or input)("At the sample boundary, verify that playback has stopped without reopening background apps. Enter quiet to confirm the current state only: ")
        if answer.strip() != "quiet":
            raise ValueError("Current stopped-media observation was not confirmed")
        checkpoint["media_stopped_operator_observed"] = True
        checkpoint["media_observation_kind"] = operator_kind
        checkpoint["current_media_checked_at"] = time.time()
    elif checkpoint_reader is None:
        from .mobile_control.adapters.android import AndroidAdbAdapter
        from .mobile_control.catalog import MobileAppCatalog
        from .mobile_control.status import Platform
        app_id = MobileAppCatalog.from_repository().require(Platform.ANDROID, recipe["target"]).app_id
        checkpoint_reader = lambda: AndroidAdbAdapter(serial, app_id).background_checkpoint()
    if not windows and not ios:
        checkpoint = checkpoint_reader()
    data = {"schema_version": 1, "recipe": recipe, **provenance,
            "effective_at": time.time(), "checkpoint": checkpoint,
            "historical_continuity": "unknown", "reset_performed": False,
            "preparation_replayed": False, "operator_confirmed_preserved": None}
    with (Path(root) / "environment_continuation.json").open("x", encoding="utf-8") as stream:
        json.dump(data, stream, ensure_ascii=False, indent=2)
    errors = _validate_continuation(Path(root), recipe, None, (Path(root).resolve(),))
    if errors:
        raise ValueError("; ".join(errors))


def _validate_continuation(root: Path, recipe: dict, foreground_start, seen, archive=None) -> list[str]:
    data = _read_json(root / "environment_continuation.json")
    source = Path(data["parent_run"])
    provenance = continuation_source(source, recipe, archive=archive, seen=seen)
    if any(data.get(k) != v for k, v in provenance.items()):
        return ["Continuation source identity or hashes changed"]
    if (data.get("recipe") != recipe or data.get("historical_continuity") != "unknown"
            or data.get("reset_performed") is not False or data.get("preparation_replayed") is not False
            or data.get("operator_confirmed_preserved") is not None):
        return ["Continuation must retain the unknown history and truthful new boundary"]
    if any((root / n).exists() for n in ("environment_events.jsonl", "environment_recovery.json")):
        return ["Continuation cannot replay preparation or claim same-sample recovery"]
    checkpoint = data["checkpoint"]
    windows = recipe["platform"] == "windows"
    ios = recipe["platform"] == "ios"
    errors = (_windows_checkpoint_errors(checkpoint, float(checkpoint["epoch"])) if windows
              else _ios_checkpoint_errors(checkpoint) if ios
              else _checkpoint_errors(checkpoint, float(checkpoint["epoch"])))
    if not windows and not ios and (not checkpoint.get("processes", "").strip() or not checkpoint.get("foreground", "").strip()):
        errors.append("Native process or foreground snapshot is missing")
    started = datetime.fromisoformat(_read_json(root / "collection_task.json")["started_at"]).timestamp()
    boundary = float(data["effective_at"])
    if (not math.isfinite(boundary) or not datetime.fromisoformat(data["source_finished_at"]).timestamp()
            <= started <= float(checkpoint["epoch"]) <= boundary):
        errors.append("Continuation boundary timing is invalid")
    if windows:
        if (checkpoint["machine"]["CSName"] != data["source_machine_name"]
                or checkpoint.get("media_stopped_operator_observed") is not True
                or not float(checkpoint["epoch"]) <= float(checkpoint.get("current_media_checked_at", 0)) <= boundary):
            errors.append("Current Windows machine/media observation is invalid")
    elif ios:
        if (checkpoint.get("udid") != data["source_device_udid"]
                or checkpoint.get("media_stopped_operator_observed") is not True
                or checkpoint.get("media_observation_kind") not in {"human", "agent"}
                or not float(checkpoint["epoch"]) <= float(checkpoint.get("current_media_checked_at", 0)) <= boundary):
            errors.append("Current iOS device/media observation is invalid")
    elif checkpoint.get("serial") != data["source_device_serial"]:
        errors.append("Continuation device identity differs")
    if foreground_start is not None and boundary > float(foreground_start):
        errors.append("Continuation boundary overlaps the foreground task")
    manifest_path = root / ("windows_capture_manifest.json" if windows else "collection_manifest.json")
    if manifest_path.exists():
        manifest = _read_json(manifest_path)
        if (manifest.get("continue_environment_from") != str(source.resolve())
                or (ios and manifest.get("device_udid") != checkpoint.get("udid"))
                or (not windows and not ios and manifest.get("device_serial") != checkpoint.get("serial"))
                or manifest.get("collection_environment") != recipe
                or (manifest.get("target_name") if windows else manifest.get("request", {}).get("app_name")) != recipe["target"]):
            errors.append("Continuation boundary differs from the current task manifest")
    return errors


def resume_environment(root: Path, recipe: dict, source: Path, *, serial: str,
                       input_fn=None, checkpoint_reader=None) -> None:
    """Preserve the prepared state, recording recovery rather than replaying preparation."""
    if recipe.get("platform") == "windows":
        return _resume_windows_environment(root, recipe, source, input_fn, checkpoint_reader)
    if recipe.get("platform") != "android" or not serial:
        raise ValueError("Environment recovery currently requires a verified Android device")
    provenance = recovery_source(source, recipe)
    input_fn = input if input_fn is None else input_fn
    answer = input_fn(f"Reusing {provenance['preparation_run']}. Confirm the same phone {serial} was used and that nobody cleared background apps, "
                      "rebooted, or changed those apps after the failure. Record target-app recovery separately. Enter preserved to confirm or cancel if uncertain: ")
    if answer.strip() != "preserved":
        raise ValueError("Environment continuity was not confirmed")
    if checkpoint_reader is None:
        from .mobile_control.adapters.android import AndroidAdbAdapter
        checkpoint_reader = lambda: AndroidAdbAdapter(serial, recipe["reset_packages"][0]).environment_checkpoint()
    checkpoint = checkpoint_reader()
    original_rows = [json.loads(line) for line in
                     (Path(provenance["preparation_run"]) / "environment_events.jsonl").read_text(encoding="utf-8").splitlines()]
    errors = _checkpoint_errors(checkpoint, float(original_rows[0]["epoch"]))
    source_manifest = _read_json(Path(source) / "collection_manifest.json")
    source_serial = source_manifest.get("device_serial")
    if checkpoint.get("serial") != serial or source_serial and source_serial != serial:
        errors.append("Recovery device differs from the source device")
    if errors:
        raise ValueError("; ".join(errors))
    evidence = {"schema_version": 1, **provenance, "recipe": recipe,
                "recovered_at": time.time(), "operator_confirmed_preserved": True,
                "confirmation_scope": "same device; no manual cleanup, reboot or background-app changes; target recovery retained separately",
                "legacy_device_identity_attested": not bool(source_serial), "checkpoint": checkpoint}
    with (Path(root) / "environment_recovery.json").open("x", encoding="utf-8") as stream:
        json.dump(evidence, stream, ensure_ascii=False, indent=2)
    errors = _validate_recovery(Path(root), recipe, None, (Path(root).resolve(),))
    if errors:
        raise ValueError("; ".join(errors))


def _windows_request(manifest: dict) -> dict:
    keys = ("plan_sha256", "seed", "category_id", "target_name", "session_seconds",
            "minimum_accepted_seconds", "single_session", "tolerate_foreground_interruptions", "router")
    return {key: manifest[key] for key in keys}


def _windows_checkpoint() -> dict:
    import subprocess
    result = subprocess.run(["powershell", "-NoProfile", "-Command",
        "Get-CimInstance Win32_OperatingSystem | Select-Object CSName,@{Name='LastBootUpTime';Expression={$_.LastBootUpTime.ToString('o')}} | ConvertTo-Json -Compress"],
        capture_output=True, text=True, check=True, timeout=15)
    machine = json.loads(result.stdout.lstrip("\ufeff"))
    return {"epoch": time.time(), "machine": machine}


def _windows_checkpoint_errors(checkpoint: dict, start: float) -> list[str]:
    checked = float(checkpoint["epoch"])
    machine = checkpoint["machine"]
    boot = datetime.fromisoformat(machine["LastBootUpTime"]).timestamp()
    if (not machine.get("CSName") or not math.isfinite(checked) or not math.isfinite(boot)
            or not boot <= start <= checked):
        return ["Windows identity or continuous boot evidence is invalid"]
    return []


def _windows_recovery_source(source, logical_source, recipe, seen, archive):
    sidecar = _read_json(source / "collection_task.json")
    manifest = _read_json(source / "windows_capture_manifest.json")
    if (sidecar.get("task_id") != recipe["task_id"] or sidecar.get("status") != "failed"
            or ALIASES.get(manifest.get("target_name"), manifest.get("target_name")) != recipe["target"]):
        raise ValueError("Windows recovery requires a finished failed attempt of the same target and task")
    errors = validate_run_environment(source, recipe["target"], manifest.get("collection_environment"),
                                      _seen=seen, _archive=archive)
    if errors:
        raise ValueError("; ".join(errors))
    previous = source / "environment_recovery.json"
    original = Path(_read_json(previous)["preparation_run"]) if previous.exists() else logical_source
    return {"parent_run": str(logical_source), "parent_hashes": _source_hashes(source),
            "preparation_run": str(original), "logical_sample_id": str(original),
            "foreground_request": _windows_request(manifest), "failed_at": sidecar["finished_at"]}


def _resume_windows_environment(root, recipe, source, input_fn, checkpoint_reader):
    provenance = recovery_source(source, recipe)
    manifest = _read_json(Path(root) / "windows_capture_manifest.json")
    if _windows_request(manifest) != provenance["foreground_request"]:
        raise ValueError("Windows recovery changed the original foreground request")
    input_fn = input if input_fn is None else input_fn
    answer = input_fn("Reusing the five-app preparation. Confirm the same PC was used, it was not rebooted, the preparation tabs stayed open, and all playback stopped. "
                      "Use a separate foreground tab for the target. Enter preserved to confirm or cancel if uncertain: ")
    if answer.strip() != "preserved":
        raise ValueError("Windows environment continuity was not confirmed")
    checkpoint = (checkpoint_reader or _windows_checkpoint)()
    evidence = {"schema_version": 1, **provenance, "recipe": recipe,
                "recovered_at": time.time(), "checkpoint": checkpoint,
                "operator_confirmed_preserved": True, "operator_confirmed_media_stopped": True,
                "evidence_mode": "native_boot_and_operator_labels"}
    with (Path(root) / "environment_recovery.json").open("x", encoding="utf-8") as stream:
        json.dump(evidence, stream, ensure_ascii=False, indent=2)
    errors = _validate_windows_recovery(Path(root), recipe, None, (Path(root).resolve(),), None)
    if errors:
        raise ValueError("; ".join(errors))


def _validate_windows_recovery(root, recipe, foreground_start, seen, archive):
    data = _read_json(root / "environment_recovery.json")
    source = Path(data["parent_run"])
    provenance = recovery_source(source, recipe, _seen=seen, _archive=archive)
    if any(data.get(key) != value for key, value in provenance.items()):
        return ["Windows environment recovery source or hashes changed"]
    if (data.get("recipe") != recipe or data.get("operator_confirmed_preserved") is not True
            or data.get("operator_confirmed_media_stopped") is not True):
        return ["Windows background retention and stopped media were not confirmed"]
    if (root / "environment_events.jsonl").exists():
        return ["recovery must reference preparation, not copy or repeat it"]
    original = Path(provenance["preparation_run"])
    original_local = archive[str(original.resolve())] if archive is not None else original
    rows = [json.loads(s) for s in (original_local / "environment_events.jsonl").read_text(encoding="utf-8").splitlines()]
    errors = _windows_checkpoint_errors(data["checkpoint"], float(rows[0]["epoch"]))
    machine_path = original_local / "operator_machine_checkpoint.json"
    if not machine_path.exists():
        errors.append("original Windows machine checkpoint is missing")
    else:
        machine = json.loads(machine_path.read_text(encoding="utf-8-sig"))
        current_machine = data["checkpoint"]["machine"]
        if (machine.get("CSName") != current_machine.get("CSName")
                or datetime.fromisoformat(machine["LastBootUpTime"]) != datetime.fromisoformat(current_machine["LastBootUpTime"])):
            errors.append("Windows machine or boot changed since preparation")
    start = datetime.fromisoformat(_read_json(root / "collection_task.json")["started_at"]).timestamp()
    failed = datetime.fromisoformat(data["failed_at"]).timestamp()
    checked, recovered = float(data["checkpoint"]["epoch"]), float(data["recovered_at"])
    if not math.isfinite(recovered) or not max(start, failed) <= checked <= recovered:
        errors.append("Windows recovery timing is invalid")
    if foreground_start is not None and recovered > float(foreground_start):
        errors.append("Windows recovery overlaps foreground activity")
    manifest = _read_json(root / "windows_capture_manifest.json")
    if (manifest.get("resume_environment_from") != str(source.resolve())
            or _windows_request(manifest) != data["foreground_request"]):
        errors.append("Windows recovery changed its source or foreground request")
    return errors


def recovery_evidence_sources(root: Path) -> dict[Path, list[Path]]:
    """Inventory original ancestry for publication without rewriting preparation."""
    sources = {}
    current = Path(root).resolve()
    seen = {current}
    while any((current / name).exists() for name in ("environment_recovery.json", "environment_continuation.json")):
        record = next(current / name for name in ("environment_recovery.json", "environment_continuation.json")
                      if (current / name).exists())
        current = Path(_read_json(record)["parent_run"]).resolve()
        if current in seen or len(seen) >= 64:
            raise ValueError("environment recovery ancestry is cyclic or too deep")
        seen.add(current)
        sources[current] = [current / name for name in _source_hashes(current)]
    return sources


def _validate_recovery(root: Path, recipe: dict, foreground_start, seen, archive=None) -> list[str]:
    if recipe.get("platform") == "windows":
        return _validate_windows_recovery(root, recipe, foreground_start, seen, archive)
    data = _read_json(root / "environment_recovery.json")
    source = Path(data["parent_run"])
    provenance = recovery_source(source, recipe, _seen=seen, _archive=archive)
    if any(data.get(key) != value for key, value in provenance.items()):
        return ["environment recovery source or hashes changed"]
    if data.get("recipe") != recipe or data.get("operator_confirmed_preserved") is not True:
        return ["environment continuity was not confirmed for this recipe"]
    if (root / "environment_events.jsonl").exists():
        return ["recovery must reference preparation, not copy or repeat it"]
    preparation = Path(provenance["preparation_run"])
    if archive is not None:
        preparation = archive[str(preparation.resolve())]
    rows = [json.loads(line) for line in (preparation /
            "environment_events.jsonl").read_text(encoding="utf-8").splitlines()]
    errors = _checkpoint_errors(data["checkpoint"], float(rows[0]["epoch"]))
    run_start = datetime.fromisoformat(_read_json(root / "collection_task.json")["started_at"]).timestamp()
    failed = datetime.fromisoformat(data["failed_at"]).timestamp()
    checked, recovered = float(data["checkpoint"]["epoch"]), float(data["recovered_at"])
    if not math.isfinite(recovered) or not max(run_start, failed) <= checked <= recovered:
        errors.append("recovery timing does not follow the failed attempt and current run start")
    if foreground_start is not None and recovered > float(foreground_start):
        errors.append("environment recovery overlaps foreground activity")
    manifest_path = root / "collection_manifest.json"
    if manifest_path.exists():
        manifest = _read_json(manifest_path)
        if manifest.get("resume_environment_from") != str(source.resolve()) or manifest.get("device_serial") != data["checkpoint"]["serial"]:
            errors.append("recovery source or device differs from the current manifest")
        if manifest.get("request") != data["foreground_request"]:
            errors.append("recovery changed the original foreground request")
    source_local = archive[str(source.resolve())] if archive is not None else source
    source_serial = _read_json(source_local / "collection_manifest.json").get("device_serial")
    if source_serial and source_serial != data["checkpoint"]["serial"]:
        errors.append("recovery source device differs")
    if not source_serial and data.get("legacy_device_identity_attested") is not True:
        errors.append("legacy source requires explicit same-device confirmation")
    return errors
