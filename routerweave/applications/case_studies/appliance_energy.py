"""Reconstruct appliance state within one coverage interval and integrate Wh."""

from dataclasses import dataclass
from math import isfinite


@dataclass(frozen=True)
class PowerProfile:
    on_w: float
    standby_w: float
    cycle_seconds: float | None = None

    def __post_init__(self):
        if any(not isfinite(w) or w < 0 for w in (self.on_w, self.standby_w)):
            raise ValueError("Power coefficients must be finite and nonnegative")
        if self.cycle_seconds is not None and not (isfinite(self.cycle_seconds) and self.cycle_seconds > 0):
            raise ValueError("Expected a positive cycle duration")


PROFILES = {
    "air_purifier": PowerProfile(6.94, 1.02),
    "dehumidifier": PowerProfile(117.00, 1.08),
    "circulation_fan": PowerProfile(7.08, 3.48),
    "kettle": PowerProfile(2025.0, 0.0, cycle_seconds=180.0),
}


def _switches(events, start, end):
    """Select directional operations inside half-open observation coverage."""
    switches = []
    for timestamp, action in events:
        if not isfinite(timestamp):
            raise ValueError("Nonfinite operation time")
        if start <= timestamp < end and action in ("power_on", "power_off"):
            switches.append((timestamp, action))
    return sorted(switches)


def state_history(start, end, events, profile, *, initially_on):
    """Use the supplied boundary state for a latching device or timed starts for a kettle."""
    if not (isfinite(start) and isfinite(end) and start < end):
        raise ValueError("Expected a positive observation interval")
    switches = _switches(events, start, end)
    intervals = []
    if profile.cycle_seconds is not None:
        if initially_on is not False:
            raise ValueError("Timed-cycle coverage must begin idle")
        for t, action in switches:
            if action != "power_on":
                continue
            stop = min(end, t + profile.cycle_seconds)
            if intervals and t <= intervals[-1][1]:
                intervals[-1] = (intervals[-1][0], stop)
            else:
                intervals.append((t, stop))
    else:
        if not isinstance(initially_on, bool):
            raise ValueError("Supply the initial ON/OFF state")
        on_since = start if initially_on else None
        previous = None
        for t, action in switches:
            if previous and previous[0] == t and previous[1] != action:
                raise ValueError("Opposing operations share one timestamp")
            previous = (t, action)
            if action == "power_on" and on_since is None:
                on_since = t
            elif action == "power_off" and on_since is not None:
                if on_since < t:
                    intervals.append((on_since, t))
                on_since = None
        if on_since is not None:
            intervals.append((on_since, end))
    on_seconds = sum(b - a for a, b in intervals)
    off_seconds = end - start - on_seconds
    return dict(on_intervals=intervals, on_seconds=on_seconds, off_seconds=off_seconds,
                energy_wh=(on_seconds * profile.on_w + off_seconds * profile.standby_w) / 3600)


def compare_segment(start, end, logged, inferred, profile, *, initially_on=None):
    """Apply the same initial condition and power profile to both histories."""
    logged = _switches(logged, start, end)
    if initially_on is None:
        if profile.cycle_seconds is None and not logged:
            raise ValueError("No logged switch to establish the initial state")
        initially_on = profile.cycle_seconds is None and logged[0][1] == "power_off"
    reference = state_history(start, end, logged, profile, initially_on=initially_on)
    estimate = state_history(start, end, inferred, profile, initially_on=initially_on)
    overlap = sum(max(0, min(b, d) - max(a, c))
                  for a, b in reference["on_intervals"] for c, d in estimate["on_intervals"])
    disagreement = reference["on_seconds"] + estimate["on_seconds"] - 2 * overlap
    return dict(initially_on=initially_on, reference=reference, estimate=estimate,
                evaluated_seconds=end - start, agreement_seconds=end - start - disagreement)
