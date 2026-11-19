"""Bound the router/host clock offset using the original SSH midpoint protocol."""

import re
import subprocess
import time

from .router import _router_ssh


def measure_router_clock(*, user: str, host: str, identity_file: str | None) -> dict:
    samples = []
    timeouts = 0
    for _ in range(4):
        before = time.time()
        started = time.monotonic()
        try:
            result = _router_ssh(user, host, "date +%s.%N", identity_file=identity_file, timeout=8)
        except subprocess.TimeoutExpired:
            timeouts += 1
            if timeouts > 1:
                raise
            continue
        after = time.time()
        round_trip = time.monotonic() - started
        match = re.fullmatch(r"(\d{9,})(?:\.(\d+|%N|N))?", result.stdout.strip())
        if result.returncode or not match:
            raise ValueError("router did not return a usable timestamp")
        if abs(after - before - round_trip) > 0.1:
            raise ValueError("host clock changed during clock measurement")
        fraction = match.group(2) or ""
        resolution = 10 ** -len(fraction) if fraction.isdigit() else 1.0
        remote = int(match.group(1)) + (float("0." + fraction) if fraction.isdigit() else 0)
        midpoint = (before + after) / 2
        samples.append({"offset_seconds": remote + resolution / 2 - midpoint,
                        "uncertainty_seconds": (round_trip + resolution) / 2,
                        "round_trip_seconds": round_trip, "resolution_seconds": resolution})
        if len(samples) == 3:
            break
    best = min(samples, key=lambda sample: sample["uncertainty_seconds"])
    if best["uncertainty_seconds"] > 1:
        raise ValueError("router clock uncertainty exceeds one second")
    return {**best, "samples": samples}
