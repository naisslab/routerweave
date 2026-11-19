"""Routine controls reuse existing IoT bindings and one shared WDA session.

No sample(), normalize(), or prerequisite preparation is used here: only the
scheduled command may change appliance state.
"""

from __future__ import annotations

import copy
import os
import subprocess
import time
import uuid
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
from pathlib import Path
from typing import Any

from collection.runtime.artifacts import EventLog
from collection.runtime.errors import DemoError
from collection.runtime.ios.iot_apple_home_capture import AppleHomeCollector
from collection.runtime.ios.iot_continuous_capture import Collector
from collection.runtime.mobile_control.wda import WdaDeviceController


PLATFORM_FACTORIES = {"alexa": Collector, "apple_home": AppleHomeCollector}


class CommandWithheld(DemoError):
    """The adapter proved no appliance command was issued; do not credit it."""


def native_toggle_loading(plan: dict, device: dict, source: str) -> bool:
    """Recognize Alexa's observed power-loading view, never an unknown dialog."""
    if (plan.get("acceptance_mode") != "command_traffic" or plan.get("control_platform") != "alexa"
            or device.get("control_element_name") != "PowerControl::TouchArea"
            or device.get("state_element_name") != "PowerControl::StateText"):
        return False
    try:
        root = ET.fromstring(source)
    except ET.ParseError:
        return False
    from collection.runtime.ios.iot_light_probe import visible
    if any(visible(e) and (e.get("type") or e.tag) in {"XCUIElementTypeAlert", "XCUIElementTypeSheet"} for e in root.iter()):
        return False
    if not any(visible(e) and (e.get("type") or e.tag) == "XCUIElementTypeApplication"
               and e.get("name") == plan["controller"]["application"] for e in root.iter()):
        return False
    reader = Collector.__new__(Collector)
    reader.plan = plan
    control = reader._visible_named(source, device["control_element_name"])
    state = reader._visible_named(source, device["state_element_name"])
    return (reader._detail_is_target(device, source) and control is not None
            and control.get("label") == "Loading" and state is not None
            and not state.get("label") and not state.get("value")
            and reader._visible_named(source, "PowerControl::LoadingIndicator") is not None)


def validate_binding(plan: dict, device: dict) -> None:
    """Platform capability checks live with adapters, outside the scheduler."""
    platform = plan.get("control_platform")
    if platform not in PLATFORM_FACTORIES:
        raise ValueError(f"No routine native adapter for platform {platform!r}")
    if plan.get("command_input") or device.get("prerequisites"):
        raise ValueError("Routine bindings require native UI controls without prerequisite normalization")
    if platform == "apple_home" and device.get("state_view") != "detail_slider":
        raise ValueError("Apple Home routine bindings require a verified detail control")
    if platform == "alexa" and (device.get("view") != "detail" or device.get("navigation_mode") != "semantic_detail"):
        raise ValueError("Alexa routine bindings require semantic detail navigation")
    if plan.get("acceptance_mode") == "command_traffic":
        from collection.runtime.ios.iot_device_traffic import supports_command_traffic
        if (platform != "alexa" or not supports_command_traffic(device)
                or not device.get("fresh_precondition_state")
                or device.get("command_evidence") != "native_toggle_selection"):
            raise ValueError("Command-traffic routines require verified native toggle bindings")


class RoutineControl:
    def __init__(self, root: Path, compiled: dict[str, Any], log: EventLog) -> None:
        self.root, self.log = root, log
        plans = {name: copy.deepcopy(binding["plan"]) for name, binding in compiled["controls"].items()}
        controller = next(iter(plans.values()))["controller"]
        self.wda = WdaDeviceController(
            controller["wda_url"], log,
            snapshot_max_depth=controller.get("snapshot_max_depth", 50),
        )
        self.collectors = {
            kind: PLATFORM_FACTORIES[plan["control_platform"]](
                root / "bindings" / kind, plan, wda=self.wda,
            )
            for kind, plan in plans.items()
        }
        self.devices = {kind: plan["devices"][0] for kind, plan in plans.items()}

    def health(self) -> None:
        # This does not open an app or query an appliance during idle periods.
        response = self.wda.client.request("/status", timeout_seconds=5)
        if not response.get("value", {}).get("ready"):
            raise DemoError("WDA transport is not ready")

    def _source(self, kind: str, *, navigate: bool, allow_loading: bool = False) -> tuple[str, str]:
        collector, device = self.collectors[kind], self.devices[kind]
        if self.wda.is_locked():
            self.wda.unlock()
            if self.wda.is_locked():
                raise DemoError("Phone remains locked; no passcode automation is allowed")
        if collector.plan["control_platform"] == "alexa":
            if navigate:
                # A previous control can leave a mode sheet open. Resolve only
                # menus declared by another binding for this exact device/app;
                # an unknown/authentication dialog is never dismissed here.
                if self.wda.active_bundle_id() == collector.plan["controller"]["application_bundle_id"]:
                    source = self.wda.source()
                    for name, other in self.collectors.items():
                        candidate = self.devices[name]
                        if (other.plan["control_platform"] == "alexa"
                                and candidate["id"] == device["id"] and candidate.get("mode_menu")
                                and other._detail_is_target(candidate, source)):
                            source = other.dismiss_mode_menu(candidate, source)
                collector.open_device(device)
            guarded, source = collector.guarded_source(device, self.log)
            state = collector.state(device, source) if guarded else "unknown"
        else:
            if navigate:
                guarded, source = collector.ensure_device_view(device, self.log)
            else:
                guarded = self.wda.active_bundle_id() == collector.plan["controller"]["application_bundle_id"]
                source = self.wda.source() if guarded else ""
            state = collector.observed_state(device, source) if guarded else "unknown"
        if guarded and allow_loading and state == "unknown" and native_toggle_loading(collector.plan, device, source):
            state = "loading"  # Observation only; never a command precondition.
        path = self.root / "evidence" / f"{uuid.uuid4().hex}-{kind}.xml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
        self.log.write("routine_state_observed", kind=kind, state=state, source=str(path), observed_epoch=time.time())
        if not guarded or (state not in device["states"] and not (allow_loading and state == "loading")):
            raise DemoError(f"Unknown or unguarded {kind} state: {state}")
        return state, source

    def observe(self, kind: str) -> str:
        return self._source(kind, navigate=True)[0]

    def issue(self, kind: str, before: str, target: str, *, deadline_epoch: float) -> dict[str, Any]:
        # Re-read immediately before a relative command; never trust a cached
        # grade from an earlier event or an earlier view.
        baseline_epoch = time.time()
        if self.collectors[kind].plan.get("acceptance_mode") == "command_traffic":
            time.sleep(5)  # Capture is independent and already running.
        try:
            observed, source = self._source(kind, navigate=False)
        except Exception as exc:
            raise CommandWithheld(f"Final native precondition could not be read: {exc}") from exc
        if observed != before:
            raise CommandWithheld("Appliance state changed before command; command withheld")
        if time.time() >= deadline_epoch:
            raise CommandWithheld("Command deadline passed during final native readback; command withheld")
        collector, device = self.collectors[kind], self.devices[kind]
        # Once the platform gesture is entered, a transport error may follow a
        # real tap. It must remain uncertain, never become a preparation retry.
        if collector.plan["control_platform"] == "alexa":
            receipt = collector.issue_ui_control(device, source, before, target, self.log)
            return {**receipt, "selected_control_name": device.get("control_element_name"),
                    "source_state": before, "requested_target": target,
                    "baseline_epoch": baseline_epoch}
        return collector.issue_detail_slider(device, source, before, target, self.log)

    def record_command(self, kind: str, receipt: dict) -> dict:
        """Observe traffic time without interpreting a transient target as stable."""
        collector, device = self.collectors[kind], self.devices[kind]
        if collector.plan.get("acceptance_mode") != "command_traffic":
            raise DemoError("Command observation needs an explicit command-traffic contract")
        started = float(receipt["gesture_start_epoch"])
        observations = []
        while True:
            state, _ = self._source(kind, navigate=False, allow_loading=True)
            observations.append({"state": state, "epoch": time.time()})
            if time.time() >= started + 30:
                break
            time.sleep(min(float(device["poll_seconds"]), max(0, started + 30 - time.time())))
        return {"start_epoch": started, "end_epoch": time.time(), "observations": observations,
                "acceptance_contract": "operator_accepted_command_traffic", "state_confirmed": False}

    def confirm(self, kind: str, target: str) -> bool:
        collector, device = self.collectors[kind], self.devices[kind]
        matched, _, _ = collector.wait_state(
            device, target, float(device["state_timeout_seconds"]), self.log,
        )
        if not matched:
            return False
        if collector.plan["control_platform"] == "alexa":
            stable, _ = collector.observe_tail_state(
                device, target, float(device["tail_seconds"]), self.log,
            )
        else:
            stable, _ = collector.observe_tail(device, target, self.log)
            if stable:
                source = self.wda.source()
                if not collector._detail_matches(device, source):
                    return False
                collector.dismiss_restored_detail(source, self.log)
        return stable and self.observe(kind) == target


class RecoveringRoutineControl:
    """Construct the shared phone session lazily, without owning capture life."""

    def __init__(self, root: Path, compiled: dict[str, Any], log: EventLog) -> None:
        self.root, self.compiled, self.log = root, compiled, log
        self.control: RoutineControl | None = None
        self.failures = 0
        self.next_recovery = 0.0

    def release(self) -> None:
        """Close only this binding's known sheet before yielding the phone."""
        try:
            if self.control is not None:
                for kind, collector in self.control.collectors.items():
                    device = self.control.devices[kind]
                    if device.get("mode_menu") and collector.plan["control_platform"] == "alexa":
                        source = self.control.wda.source()
                        if collector._detail_is_target(device, source):
                            collector.dismiss_mode_menu(device, source)
        except Exception as exc:
            self.log.write("routine_controller_release_issue", error=str(exc))
        finally:
            self.control = None  # A later lease needs a fresh WDA session.

    def health(self) -> None:
        try:
            if self.control is None:
                self.control = RoutineControl(self.root, self.compiled, self.log)
            self.control.health()
            self.failures = 0
        except Exception:
            self.failures += 1
            if self.failures >= 2 and time.monotonic() >= self.next_recovery:
                self.next_recovery = time.monotonic() + 60
                self.recover_transport()
            raise

    def recover_transport(self) -> None:
        controller = next(iter(self.compiled["controls"].values()))["plan"]["controller"]
        endpoint = urlparse(controller["wda_url"])
        if os.name != "nt" or endpoint.hostname not in {"127.0.0.1", "localhost"}:
            raise DemoError("Automatic WDA process recovery requires a local Windows endpoint")
        script = Path(__file__).resolve().parents[4] / "scripts/device/recover_wda.ps1"
        result = subprocess.run([
            "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script),
            "-Action", "recover", "-Udid", controller["identifier"], "-Port", str(endpoint.port or 80),
        ], capture_output=True, text=True, timeout=60,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        self.log.write("routine_wda_recovery", returncode=result.returncode,
                       stdout=result.stdout[-3000:], stderr=result.stderr[-3000:])
        # Rebuild session and native bindings on the next health check. This
        # never reissues an appliance command.
        self.control = None
        if result.returncode:
            raise DemoError("Selected-phone WDA recovery failed; capture continues")

    def observe(self, name: str) -> str:
        if self.control is None:
            raise DemoError("Phone control is recovering")
        return self.control.observe(name)

    def issue(self, name: str, before: str, target: str, *, deadline_epoch: float) -> dict[str, Any]:
        if self.control is None:
            raise CommandWithheld("Phone control is recovering")
        return self.control.issue(name, before, target, deadline_epoch=deadline_epoch)

    def confirm(self, name: str, target: str) -> bool:
        return self.control is not None and self.control.confirm(name, target)

    def record_command(self, name: str, receipt: dict) -> dict:
        if self.control is None:
            raise DemoError("Phone control is recovering")
        return self.control.record_command(name, receipt)
