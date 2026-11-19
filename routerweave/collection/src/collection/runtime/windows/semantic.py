"""Windows bindings for complete, shared task-family playbooks.

There is no Windows activity scheduler here. The existing family builders and
PlaybookRunner own launch, entry, decisions, holds, monitoring and recovery.
"""
from __future__ import annotations

from dataclasses import asdict
import json
import math
import random
import time

from ..mobile_control.binding import ActionBinding, ActionStrategy, AppBinding
from ..mobile_control.capability import CapabilityCatalog, CapabilityReport
from ..mobile_control.condition import Condition, ConditionKind, ConditionEvaluator
from ..mobile_control.engine import PlaybookRunner
from ..mobile_control.events import JsonlEventSink
from ..mobile_control.interruption import InterruptionKind, InterruptionRule
from ..mobile_control.interruption_runtime import InterruptionManager
from ..mobile_control.observation import ElementNode, Observation
from ..mobile_control.perception import SemanticSelector
from ..mobile_control.platform import CommandResult
from ..mobile_control.playbook import _walk_steps
from ..mobile_control.playbooks.browsing import BrowsingTask, BrowsingVerification, build_browsing_playbook
from ..mobile_control.playbooks.music import MusicTask, MusicVerification, build_music_playbook
from ..mobile_control.playbooks.short_video import ShortVideoTask, ShortVideoVerification, ShortVideoPreparation, build_short_video_playbook
from ..mobile_control.playbooks.long_video import LongVideoTask, LongVideoVerification, build_long_video_playbook
from ..mobile_control.playbooks.live_stream import LiveStreamTask, LiveStreamVerification, build_live_stream_playbook
from ..mobile_control.playbooks.human_activity import plan_human_activity
from ..mobile_control.status import ActionMethod, CommandStatus, Idempotency, Platform
from ..mobile_control.waiting import SystemClock, ObservationBroker, ConditionWaiter
from ..mobile_control.task_runtime import network_windows_from_mobile_events


FAMILIES = {
    "music_audio": "music", "web_browsing": "browsing",
    "short_video": "short_video", "long_form_video": "long_video",
    "live_streaming": "live_stream",
}


def require_browsing_interactions(target):
    """Reject incomplete bindings before a registered browsing capture starts."""
    spec = target.get("semantic_binding", {})
    controls = spec.get("controls", {})
    if not spec.get("detail_selector") or any(
            not controls.get(name, {}).get("selector")
            for name in ("open_feed_content", "return_to_feed")):
        raise ValueError("Registered browsing requires bound content entry, detail evidence and return controls")


def verified_browsing_interactions(directory):
    """Require independently verifiable entry, reading and return step evidence."""
    try:
        compiled = json.loads((directory / "compiled_task.json").read_text(encoding="utf-8"))
        definitions = {}
        def collect(steps):
            for step in steps:
                definitions[step["step_id"]] = step
                collect(step.get("recovery", []))
                for activity in (step.get("sustain") or {}).get("activities", []):
                    collect(activity["steps"])
        collect(compiled["playbook"]["steps"] + compiled["playbook"]["cleanup"])
        rows = [json.loads(line) for line in (directory / "events.jsonl").read_text(
            encoding="utf-8").splitlines() if line.strip()]
        required = {"open_feed_content", "scroll_content", "return_to_feed"}
        pending = None
        for row in rows:
            if row.get("event_type") != "step_finished":
                continue
            result = row["payload"]["result"]
            action = definitions.get(result["step_id"], {}).get("semantic_action")
            if action not in required or result.get("outcome") != "success":
                continue
            attempts = result.get("attempts", [])
            if not any(a.get("outcome") == "success" and
                       (a.get("condition") or {}).get("status") == "matched" for a in attempts):
                continue
            if action == "open_feed_content":
                pending = {action}
            elif pending is not None:
                pending.add(action)
                if action == "return_to_feed":
                    if pending == required:
                        return True
                    pending = None
        return False
    except (OSError, ValueError, KeyError, TypeError):
        return False


def compile_windows_task(category_id, target, duration, seed):
    """Supply platform evidence and capabilities to the unchanged family builders."""
    family = FAMILIES[category_id]
    spec = target.get("semantic_binding", {})
    controls = spec.get("controls", {})
    allow_pause = "ensure_paused" in controls and "ensure_playing" in controls
    switch_action = {"music": "advance_track", "long_video": "switch_long_video",
                     "live_stream": "switch_live_room"}.get(family)
    allow_switch = bool(switch_action and switch_action in controls)
    allow_detail = "open_feed_content" in controls and bool(spec.get("detail_selector"))
    decisions = plan_human_activity(family, duration, seed, allow_pause=allow_pause,
                                   allow_switch=allow_switch, allow_detail=allow_detail)
    common = dict(monitor_seconds=duration, human_activity=decisions,
                  leave_app_open=True, transition_timeout_seconds=float(spec.get("transition_timeout_seconds", 8)))
    state = lambda key: Condition(ConditionKind.STATE_EQUALS, key, True)
    all_of = lambda *children: Condition(ConditionKind.ALL, children=children)
    allowed = state("allowed")
    playing = all_of(allowed, state("media_advancing"), state("content_page")) if family in {
        "long_video", "live_stream"} else all_of(allowed, state("media_advancing"))
    paused = all_of(allowed, state("paused"), state("media_present"))
    player = all_of(allowed, state("media_present"))
    content_player = all_of(player, state("content_page"))
    changed = all_of(allowed, Condition(ConditionKind.STATE_CHANGED, "media_identity"))
    progressed = all_of(allowed, Condition(ConditionKind.STATE_CHANGED, "scroll_position"))
    feed = all_of(allowed, state("feed_ready"))
    detail = all_of(allowed, state("detail_open"))
    if family == "browsing":
        playbook = build_browsing_playbook(
            BrowsingTask(detail_visits=1 if allow_detail else 0, **common),
            BrowsingVerification(feed_ready=feed, feed_progressed=progressed,
                detail_open=detail, detail_progressed=progressed, detail_closed=feed,
                detail_scroll_finished=all_of(detail, state("detail_scroll_finished"))
                    if spec.get("detail_scroll_boundary") == "finish" else None))
    elif family == "music":
        playbook = build_music_playbook(
            MusicTask(run_pause_resume=allow_pause, advance_track=allow_switch, **common),
            MusicVerification(player_ready=player, playing=playing, paused=paused, track_changed=changed))
    elif family == "short_video":
        playbook = build_short_video_playbook(ShortVideoTask(advances=0, **common),
            ShortVideoVerification(active=playing, content_changed=changed),
            ShortVideoPreparation(max_consecutive_activity_failures=0))
    elif family == "long_video":
        playbook = build_long_video_playbook(
            LongVideoTask(run_pause_resume=allow_pause, switch_video=allow_switch, **common),
            LongVideoVerification(video_open=content_player, playing=playing, paused=paused, video_changed=changed))
    else:
        playbook = build_live_stream_playbook(
            LiveStreamTask(run_pause_resume=allow_pause, switch_room=allow_switch, **common),
            LiveStreamVerification(room_entered=content_player, active=playing, paused=paused,
                                   playing=playing, room_switched=changed, monitored_active=playing))
    operations = {"launch_app", "terminate_app", "advance_feed", "scroll_content",
                  "start_music_playback", "ensure_video_active", "ensure_live_active",
                  "ensure_content_feed", "recover_content_feed", "return_to_feed"}
    if allow_pause:
        operations.update({"ensure_playing", "ensure_paused"})
    operations.update(controls)
    required = {step.semantic_action for step in _walk_steps(playbook.steps + playbook.cleanup) if step.semantic_action}
    actions = {name: ActionBinding(name, (ActionStrategy(
        name, ActionMethod.DIRECT,
        Idempotency.STATE_SETTING if name in {"launch_app", "terminate_app", "ensure_playing", "ensure_paused",
            "start_music_playback", "ensure_video_active", "ensure_live_active", "ensure_content_feed",
            "recover_content_feed", "return_to_feed"} else Idempotency.NON_IDEMPOTENT,
        capability=f"windows.{name}",
    ),)) for name in required | operations}
    from .media_probe import interruption_rules
    popups = interruption_rules(spec)
    selectors = {}
    interruptions = []
    for popup in popups:
        popup_id = popup["id"]
        if not popup_id or not popup.get("marker_selector") or not popup.get("dismiss_selector"):
            raise ValueError("benign popup requires id, marker and dismiss selectors")
        marker_key, dismiss_key = f"popup-{popup_id}-marker", f"popup-{popup_id}-dismiss"
        selectors[marker_key] = SemanticSelector(resource_ids=(marker_key,))
        selectors[dismiss_key] = SemanticSelector(resource_ids=(dismiss_key,), require_clickable=True)
        interruptions.append(InterruptionRule(popup_id, InterruptionKind.BENIGN,
            marker_key, dismiss_key, auto_resolve=True,
            timeout_seconds=float(popup.get("timeout_seconds", 4)),
            max_occurrences=int(popup.get("max_occurrences", 1))))
    binding = AppBinding(f"windows-{target['name']}", Platform.WINDOWS, target["name"],
        selectors=selectors, interruptions=tuple(interruptions),
        actions=actions, metadata={"task_family": family, "seed": seed,
            "allow_pause": allow_pause, "allow_switch": allow_switch, "allow_detail": allow_detail,
            "supported_actions": sorted(operations),
            **({"native_executable": target["native_binding"]["executable"], "native_binding": target["native_binding"]}
               if target.get("native_binding") else {})})
    binding.validate()
    playbook.validate()
    return binding, playbook


class CaptureClock(SystemClock):
    """Cancel bounded engine waits when the capture ends; never schedule actions."""
    def __init__(self, stop_event, deadline):
        self.stop_event, self.deadline = stop_event, deadline

    def check(self):
        if self.stop_event.is_set() or self.monotonic() >= self.deadline:
            raise InterruptedError("capture stopped or task exceeded capture deadline")

    def sleep(self, seconds):
        self.check()
        self.stop_event.wait(min(seconds, max(0, self.deadline - self.monotonic())))
        self.check()


def _blocking_surface(state):
    # Preserve the gatekeeper's fail-closed behavior without describing a lost
    # observation channel as an observed website dialog.
    if state.get("error_type"):
        return ElementNode("blocking-surface", role="dialog",
                           resource_id="windows-observation-unavailable",
                           text=f"Observation unavailable: {state['error_type']}: {state.get('error_detail', '')}")
    return ElementNode("blocking-surface", role="dialog")


class WindowsSemanticAdapter:
    platform = Platform.WINDOWS

    def __init__(self, driver, target, binding, clock, events):
        self.driver, self.target, self.clock, self.events = driver, target, clock, events
        self.capabilities = CapabilityCatalog.control_names(*(f"windows.{name}" for name in binding.metadata["supported_actions"]))
        self.launched = False
        self.actions = 0
        self.observations = []
        self.rng = random.Random(int(binding.metadata["seed"]))
        self._last_media = None
        self._last_advance = float("-inf")
        self._popup_attempts = {}

    def probe_capabilities(self):
        return CapabilityReport("windows-semantic", ())

    def observe(self, level, reason, signals=frozenset()):
        self.clock.check()
        state = self.driver.observe_behavior(self.target) if self.launched else {"allowed": False}
        now = self.clock.monotonic()
        identity, current = state.get("media_identity"), state.get("media_progress", state.get("media_current_time"))
        if identity and current is not None:
            current = float(current)
            if self._last_media:
                previous_identity, previous_progress = self._last_media
                delta = current - previous_progress
                if identity != previous_identity and state.get("playing"):
                    self._last_advance = now
                elif identity == previous_identity and (delta >= 0.05 or delta <= -0.5):
                    # A playing clip may loop or restart its media clock.
                    self._last_advance = now
            else:
                self._last_advance = float("-inf")
            self._last_media = (identity, current)
        elif not self.target.get("native_binding"):
            self._last_advance = float("-inf")
            self._last_media = None
        state["media_advancing"] = bool(state.get("playing")) and now - self._last_advance <= 3.0
        if self.target.get("native_binding") and state.get("native_audio"):
            from .native_media import audio_is_active
            if audio_is_active(state["native_audio"], self.target["native_binding"]["executable"]):
                self._last_advance = now
            state["media_advancing"] = bool(state.get("playing")) and now - self._last_advance <= 3.0
        state["allowed"] = bool(state.get("allowed"))
        row = {"observed_epoch": time.time(), "monotonic": now, "reason": reason, "state": state}
        self.observations.append(row)
        self.events.emit("windows_observation", row)
        blocked = bool(state.get("blocked")) or (self.launched and bool(state.get("error_type")))
        elements = [_blocking_surface(state)] if blocked else []
        for popup_id in state.get("present_popups", state.get("benign_popups", [])):
            elements.append(ElementNode(f"popup-{popup_id}-marker", resource_id=f"popup-{popup_id}-marker"))
        for popup_id in state.get("benign_popups", []):
            elements.append(ElementNode(f"popup-{popup_id}-dismiss", resource_id=f"popup-{popup_id}-dismiss",
                                        clickable=True))
        return Observation(self.platform, now, self.target["name"] if state["allowed"] else None,
                           elements=tuple(elements), state=state)

    def execute_direct(self, capability, parameters):
        self.clock.check()
        action = capability.removeprefix("windows.")
        if capability not in self.capabilities:
            return CommandResult(CommandStatus.UNSUPPORTED, ActionMethod.DIRECT, capability)
        if action == "terminate_app":
            self.driver.close()
            self.launched = False
        elif action == "launch_app" and not self.launched:
            if hasattr(self.driver, "launch_target"):
                self.driver.launch_target(self.target)
            else:
                self.driver.launch(self.target["command"], self.target.get("args", []), enable_media_probe=True)
            self.launched = True
        else:
            allowed = self.driver.observe_behavior(self.target).get("allowed")
            self.clock.check()
            if not allowed:
                return CommandResult(CommandStatus.REJECTED, ActionMethod.DIRECT, capability)
            self.driver.perform_behavior(action, self.target, {**parameters,
                "choice_fraction": self.rng.random(), "check_active": self.clock.check})
        self.actions += 1
        return CommandResult(CommandStatus.ACCEPTED, ActionMethod.DIRECT, capability)

    def query_elements(self, capability, parameters, reason):
        return Observation(self.platform, self.clock.monotonic(), errors=("structured: unsupported native query",))

    def execute_element(self, capability, parameters):
        return CommandResult(CommandStatus.UNSUPPORTED, ActionMethod.ELEMENT, capability)

    def activate_element(self, element, parameters):
        from .media_probe import interruption_rules
        popup_id = parameters.get("interruption_rule")
        if not popup_id or element.handle != f"popup-{popup_id}-dismiss":
            return CommandResult(CommandStatus.REJECTED, ActionMethod.ELEMENT, "element.activate")
        popups = [popup for popup in interruption_rules(self.target.get("semantic_binding", {}))
                  if popup["id"] == popup_id]
        if len(popups) != 1 or self._popup_attempts.get(popup_id, 0) >= int(popups[0].get("max_occurrences", 1)):
            return CommandResult(CommandStatus.REJECTED, ActionMethod.ELEMENT, "element.activate")
        self.clock.check()
        # Unknown/sensitive blockers have priority even when a benign rule is present.
        state = self.driver.observe_behavior(self.target)
        if not state.get("allowed") or state.get("blocked"):
            return CommandResult(CommandStatus.REJECTED, ActionMethod.ELEMENT, "element.activate")
        self._popup_attempts[popup_id] = self._popup_attempts.get(popup_id, 0) + 1
        self.driver.perform_behavior("dismiss_popup", self.target,
                                     {"popup_id": popup_id, "check_active": self.clock.check})
        return CommandResult(CommandStatus.ACCEPTED, ActionMethod.ELEMENT, "element.activate")

    def execute_gesture(self, capability, parameters):
        return CommandResult(CommandStatus.UNSUPPORTED, ActionMethod.GESTURE, capability)

    def execute_visual(self, capability, parameters):
        return CommandResult(CommandStatus.UNSUPPORTED, ActionMethod.VISUAL, capability)

    def capture_screenshot(self):
        raise NotImplementedError("Windows task binding uses DOM observations and foreground logs")


def run_windows_task(driver, target, category_id, duration, seed, stop_event, out_dir, deadline, *, clock=None):
    """Invoke one full family playbook once, with no outer action/monitor loop."""
    out_dir.mkdir(parents=True, exist_ok=True)
    binding, playbook = compile_windows_task(category_id, target, duration, seed)
    compiled = {"binding_id": binding.binding_id, "app_id": binding.app_id,
                "metadata": dict(binding.metadata), "playbook": asdict(playbook),
                "interruption_rules": [asdict(rule) for rule in binding.interruptions]}
    (out_dir / "compiled_task.json").write_text(json.dumps(compiled, indent=2), encoding="utf-8")
    events = JsonlEventSink(out_dir / "events.jsonl")
    clock = clock or CaptureClock(stop_event, deadline)
    adapter = WindowsSemanticAdapter(driver, target, binding, clock, events)
    result = PlaybookRunner(
        adapter, binding, clock=clock, event_sink=events,
    ).run(playbook)
    (out_dir / "result.json").write_text(json.dumps(asdict(result), indent=2), encoding="utf-8")
    windows = network_windows_from_mobile_events(out_dir / "events.jsonl")
    (out_dir / "network_windows.json").write_text(json.dumps(windows, indent=2), encoding="utf-8")
    return result, windows, adapter


def _replay_read_only_settle(primary, refreshed, binding):
    """Replay the existing gatekeeper's bounded reads; never discard a blocker.

    A sustain check evaluates the observation returned by the interruption
    sweep, which may differ from its first observation after a transport error.
    Retained reason/timestamp chains must reproduce that sweep without input.
    """
    chain = [primary, *refreshed]
    if (not refreshed or any(
            o["state"].get("blocked") or o["state"].get("blocker_kind")
            or o["state"].get("present_popups", o["state"].get("benign_popups"))
            for o in chain)):
        return None
    if any(o["state"].get("allowed") or not o["state"].get("error_type")
           for o in chain[:-1]):
        return None
    if not chain[-1]["state"].get("allowed") or chain[-1]["state"].get("error_type"):
        return None

    class ReplayClock:
        now = primary["monotonic"]

        def monotonic(self):
            return self.now

        def sleep(self, seconds):
            self.now += seconds

    clock = ReplayClock()
    remaining = list(refreshed)

    def observation(row):
        state = row["state"]
        elements = ((_blocking_surface(state),)
                    if state.get("error_type") else ())
        return Observation(Platform.WINDOWS, row["monotonic"],
                           binding.app_id if state.get("allowed") else None,
                           elements=elements, state=state)

    class ReplayAdapter:
        def observe(self, level, reason, signals):
            if not remaining:
                raise ValueError("missing retained gatekeeper observation")
            row = remaining.pop(0)
            if row["reason"] != reason or row["monotonic"] + 0.01 < clock.now:
                raise ValueError("gatekeeper observation order or wait disagrees")
            clock.now = row["monotonic"]
            return observation(row)

        def activate_element(self, *args):
            raise ValueError("read-only settle cannot issue input")

    broker = ObservationBroker(ReplayAdapter(), clock, binding)
    waiter = ConditionWaiter(broker, binding, clock)
    try:
        swept = InterruptionManager(binding, broker, waiter, clock).sweep(
            observation(primary), primary["reason"])
    except (ValueError, KeyError, TypeError):
        return None
    if remaining or swept.blocked or swept.results:
        return None
    return chain[-1] if swept.observation.observed_at == chain[-1]["monotonic"] else None


def validate_shared_task(directory, window):
    """Recompute task/window agreement and postconditions from retained evidence."""
    try:
        compiled = json.loads((directory / "compiled_task.json").read_text(encoding="utf-8"))
        result = json.loads((directory / "result.json").read_text(encoding="utf-8"))
        rows = [json.loads(line) for line in (directory / "events.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
        finished = [r["payload"]["result"] for r in rows if r["event_type"] == "playbook_finished"]
        if len([r for r in rows if r["event_type"] == "playbook_started"]) != 1 or finished != [result]:
            return False
        if result["outcome"] != "success" or result["playbook_id"] != compiled["playbook"]["playbook_id"]:
            return False
        if "interruption_rules" in compiled:
            rules = {r["rule_id"]: r for r in compiled["interruption_rules"]}
            if len(rules) != len(compiled["interruption_rules"]) or any(
                    r["kind"] != "benign" or r["auto_resolve"] is not True
                    or not 1 <= r["max_occurrences"] <= 3 for r in rules.values()):
                return False
            counts, latest_state, seen_markers = {}, {}, set()
            for row in rows:
                if row["event_type"] == "windows_observation":
                    latest_state = row["payload"]["state"]
                    seen_markers.update(latest_state.get("present_popups", latest_state.get("benign_popups", [])))
                elif row["event_type"] == "interruption_finished":
                    interruption = row["payload"]["result"]
                    if interruption["status"] != "resolved":
                        return False
                    key = interruption["rule_id"]
                    counts[key] = counts.get(key, 0) + 1
                    if (key not in rules or interruption["kind"] != rules[key]["kind"] or key not in seen_markers
                            or counts[key] > rules[key]["max_occurrences"]
                            or not latest_state.get("allowed") or latest_state.get("blocked")
                            or key in latest_state.get("present_popups", latest_state.get("benign_popups", []))):
                        return False
                    seen_markers.remove(key)
        definitions = {}
        def collect(steps):
            for step in steps:
                definitions[step["step_id"]] = step
                collect(step.get("recovery", []))
                if step.get("sustain"):
                    for activity in step["sustain"]["activities"]:
                        collect(activity["steps"])
        collect(compiled["playbook"]["steps"] + compiled["playbook"]["cleanup"])
        observations = [r["payload"] for r in rows if r["event_type"] == "windows_observation"]
        previous, advanced, last_time = None, float("-inf"), float("-inf")
        for observed in observations:
            state, now = observed["state"], float(observed["monotonic"])
            if "detail_scroll_range" in state:
                geometry = state["detail_scroll_range"]
                if geometry is None:
                    if state.get("detail_scroll_finished") is not None:
                        return False
                elif (not state.get("detail_open") or len(geometry) != 2
                        or not all(isinstance(v, (int, float)) and math.isfinite(v) for v in geometry)
                        or geometry[1] < 0
                        or state.get("detail_scroll_finished") is not (geometry[1] - geometry[0] <= 2)):
                    return False
            if now < last_time:
                return False
            identity, current = state.get("media_identity"), state.get("media_progress", state.get("media_current_time"))
            if identity and current is not None:
                current = float(current)
                if previous:
                    previous_identity, previous_progress = previous
                    delta = current - previous_progress
                    if identity != previous_identity and state.get("playing"):
                        advanced = now
                    elif identity == previous_identity and (delta >= 0.05 or delta <= -0.5):
                        advanced = now
                else:
                    advanced = float("-inf")
                previous = (identity, current)
            elif not compiled.get("metadata", {}).get("native_executable"):
                advanced = float("-inf")
                previous = None
            # Browsing tasks do not use media progress as a success condition.
            if compiled.get("metadata", {}).get("native_executable"):
                from .native_media import audio_is_active
                executable = compiled["metadata"]["native_executable"]
                native = compiled["metadata"]["native_binding"]
                ui = state.get("native_ui", {})
                if state.get("allowed"):
                    line = ui.get("playback_line") or ""
                    import re
                    match = re.fullmatch(r"\d+\s+(?:按钮|菜单项|Button|MenuItem)\s+(\S+)\s+ID: (\S+)", line)
                    if (not match or match[2] != native["playback_control_id"]
                            or ui.get("executable", "").casefold() != executable.casefold()
                            or ui.get("title") != state.get("media_identity")
                            or state.get("playing") is not (match[1] == native["playing_name"])
                            or state.get("paused") is not (match[1] == native["paused_name"])):
                        return False
                if state.get("native_executable") != executable or not state.get("native_audio"):
                    if state.get("allowed"):
                        return False
                elif audio_is_active(state["native_audio"], executable):
                    advanced = now
            # Older captures can observe a looping background clip while its
            # media_advancing flag follows the pre-loop clock rule.
            if (window.get("category_id") != "web_browsing"
                    and state.get("media_advancing") is not (bool(state.get("playing")) and now - advanced <= 3.0)):
                return False
            last_time = now
        evaluator = ConditionEvaluator()
        evidence_binding = AppBinding(compiled["binding_id"], Platform.WINDOWS, compiled["app_id"])
        def condition_from_json(condition):
            return Condition(ConditionKind(condition["kind"]), condition.get("target"), condition.get("expected"),
                             tuple(condition_from_json(c) for c in condition.get("children", [])))
        def observation_from_json(observed):
            return Observation(Platform.WINDOWS, observed["monotonic"],
                compiled["app_id"] if observed["state"].get("allowed") else None, state=observed["state"])
        def supported(condition, evidence, step_id, start, end, *, sustain=False):
            if not isinstance(evidence, dict):
                return False
            candidates = [o for o in observations if start <= o["monotonic"] <= end
                          and (o["reason"].startswith(f"{step_id}:sustain") if sustain
                               else o["reason"].startswith(f"{step_id}:") and o["reason"] != f"{step_id}:sustain")]
            predicate = condition_from_json(condition)
            baselines = [o for o in candidates if o["reason"].endswith(":baseline")]
            for after in candidates:
                for before in baselines or [None]:
                    if before and before["monotonic"] > after["monotonic"]:
                        continue
                    recomputed = evaluator.evaluate(predicate, observation_from_json(after), evidence_binding,
                        observation_from_json(before) if before else None)
                    if recomputed.status.value == "matched" and json.loads(json.dumps(asdict(recomputed))) == evidence:
                        return True
            return False
        def check_step(step):
            definition = definitions[step["step_id"]]
            if step["outcome"] not in {"success", "skipped"}:
                return False
            evidence = step.get("verification")
            if not evidence and step["attempts"]:
                evidence = step["attempts"][-1]["condition"]
            sustained = step.get("sustain")
            initial_end = sustained["started_at"] if sustained else step["finished_at"]
            omitted = step["outcome"] == "skipped" and step.get("detail") == "action not applicable in observed state"
            expected = definition.get("skip_when") if omitted else definition["success"]
            if omitted and (not expected or step["attempts"] or sustained):
                return False
            if not supported(expected, evidence, step["step_id"], step["started_at"], initial_end):
                return False
            if definition.get("sustain"):
                if not sustained or sustained["outcome"] != "success" or sustained["checks"] < 1:
                    return False
                if sustained["finished_at"] - sustained["started_at"] + 0.01 < definition["sustain"]["duration_seconds"]:
                    return False
                if not supported(definition["success"], sustained["last_condition"], step["step_id"],
                                 sustained["started_at"], sustained["finished_at"], sustain=True):
                    return False
                raw_checks = [o for o in observations if o["reason"] == f"{step['step_id']}:sustain"
                              and sustained["started_at"] <= o["monotonic"] <= sustained["finished_at"]]
                if len(raw_checks) != sustained["checks"]:
                    return False
                check_events = [r["payload"] for r in rows if r["event_type"] == "sustain_check"
                                and r["payload"]["step_id"] == step["step_id"]
                                and sustained["started_at"] <= r["payload"]["observed_at"] <= sustained["finished_at"]]
                if len(check_events) != len(raw_checks) or not check_events:
                    return False
                misses = 0
                recoveries_needed = 0
                recovery_results = [r for r in step["recovery_results"] if r["started_at"] >= sustained["started_at"]]
                for index, (raw, check) in enumerate(zip(raw_checks, check_events)):
                    checked = raw
                    if check["observed_at"] != raw["monotonic"]:
                        following_time = (raw_checks[index + 1]["monotonic"]
                                          if index + 1 < len(raw_checks) else sustained["finished_at"])
                        if not raw["monotonic"] < check["observed_at"] <= following_time:
                            return False
                        refreshed = [o for o in observations
                                     if raw["monotonic"] < o["monotonic"] <= check["observed_at"]
                                     and o["reason"].startswith(f"{raw['reason']}:gatekeeper-")]
                        checked = _replay_read_only_settle(raw, refreshed, evidence_binding)
                        if checked is None:
                            return False
                    recomputed = evaluator.evaluate(condition_from_json(definition["success"]),
                                                     observation_from_json(checked), evidence_binding)
                    if (check["check_index"] != index + 1 or check["observed_at"] != checked["monotonic"]
                            or json.loads(json.dumps(asdict(recomputed))) != check["condition"]):
                        return False
                    misses = 0 if recomputed.status.value == "matched" else misses + 1
                    if misses >= definition["sustain"]["max_consecutive_misses"]:
                        following_time = raw_checks[index + 1]["monotonic"] if index + 1 < len(raw_checks) else sustained["finished_at"]
                        recovered = [r for r in recovery_results if raw["monotonic"] <= r["started_at"]
                                     and r["finished_at"] <= following_time]
                        if ([r["step_id"] for r in recovered] != [r["step_id"] for r in definition["recovery"]]
                                or not recovered or not all(check_step(r) for r in recovered)):
                            return False
                        recoveries_needed += 1
                        misses = 0
                if (recoveries_needed != sustained["recoveries"]
                        or recoveries_needed > definition["sustain"]["max_recoveries"]
                        or check_events[-1]["condition"] != sustained["last_condition"]):
                    return False
                activity_events = [r["payload"]["result"] for r in rows if r["event_type"] == "activity_finished"
                                   and r["payload"]["step_id"] == step["step_id"]]
                if activity_events != sustained["activities"]:
                    return False
                planned = definition["sustain"]["activities"]
                if len(sustained["activities"]) > len(planned):
                    return False
                for index, activity in enumerate(sustained["activities"]):
                    expected = planned[index]
                    if (activity["label"] != expected["label"] or activity["planned_at_seconds"] != expected["at_seconds"]
                            or [s["step_id"] for s in activity["steps"]] != [s["step_id"] for s in expected["steps"]]):
                        return False
                    if activity["outcome"] != "success" or not all(check_step(s) for s in activity["steps"]):
                        return False
                count = len(sustained["activities"])
                if count < len(planned):
                    following = planned[count]
                    previous_end = sustained["activities"][-1]["finished_at"] if count else sustained["started_at"]
                    due = (previous_end + following["delay_after_previous_seconds"]
                           if following["delay_after_previous_seconds"] is not None
                           else sustained["started_at"] + following["at_seconds"])
                    if max(previous_end, due) < sustained["started_at"] + definition["sustain"]["duration_seconds"]:
                        return False
            return True
        if [s["step_id"] for s in result["steps"]] != [s["step_id"] for s in compiled["playbook"]["steps"]]:
            return False
        if not all(check_step(s) for s in result["steps"] + result["cleanup"]):
            return False
        recomputed = network_windows_from_mobile_events(directory / "events.jsonl")
        if recomputed != json.loads((directory / "network_windows.json").read_text(encoding="utf-8")):
            return False
        sustained = [w["actual"] for w in recomputed if w["actual"].get("step_id") == "monitor-active-state"]
        return (len(sustained) == 1
                and abs(sustained[0]["start_epoch"] - window["started_epoch"]) <= 0.01
                and abs(sustained[0]["end_epoch"] - window["ended_epoch"]) <= 0.01)
    except (OSError, ValueError, KeyError, TypeError, IndexError):
        return False


def validate_activity_events(path, expected_count):
    """Reject missing, truncated, failed or count-mismatched shared evidence."""
    try:
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        started = [r for r in rows if r.get("event_type") == "playbook_started"]
        finished = [r["payload"]["result"] for r in rows if r.get("event_type") == "playbook_finished"]
        return (len(started) == len(finished) == expected_count and expected_count > 0
                and all(r["outcome"] == "success" and len(r["steps"]) == 2
                        and all(s["outcome"] in {"success", "skipped"} for s in r["steps"])
                        and _observed_effect_matches(r)
                        for r in finished))
    except (OSError, ValueError, KeyError, TypeError, IndexError):
        return False


def _observed_effect_matches(result):
    """Recompute the supported postconditions from logged before/after values."""
    ready, activity = result["steps"]
    if ready["verification"]["actual"] is not True:
        return False
    attempts = activity["attempts"]
    if not attempts or (len(attempts) == 1 and attempts[0]["command"] is None):
        actual = activity["verification"]["actual"]
        return actual is True or (
            isinstance(actual, list) and len(actual) == 2
            and all(item["actual"] is True for item in actual)
        )
    if len(attempts) != 1:
        return False
    attempt = attempts[0]
    children = attempt["condition"]["actual"]
    if children[0]["actual"] is not True:
        return False
    strategy = attempt["strategy_id"]
    if strategy == "scroll_feed":
        before, after = children[1]["actual"]
        return (isinstance(before, list) and isinstance(after, list)
                and len(before) == len(after) == 2 and before != after)
    if strategy == "advance_short_video":
        before, after = children[2]["actual"]
        return children[1]["actual"] is True and bool(before) and bool(after) and before != after
    return False
