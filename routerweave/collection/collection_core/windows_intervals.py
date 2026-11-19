"""Check recorded activity intervals against Windows foreground-process samples."""

from collections import Counter
import csv
import math
from pathlib import Path, PureWindowsPath
from typing import Any


def reconcile_foreground_evidence(
    windows: list[dict[str, Any]], ground_truth_csv: Path, *,
    capture_ended_epoch: float, minimum_ratio: float,
) -> list[dict[str, Any]]:
    if not math.isfinite(capture_ended_epoch) or not 0 < minimum_ratio <= 1:
        raise ValueError("invalid capture end or required foreground match ratio")
    samples: list[tuple[float, str]] = []
    with ground_truth_csv.open("r", encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            samples.append((int(row["timestamp_ms"]) / 1000.0, str(row.get("foreground_app", ""))))
    result = []
    for original in windows:
        window = dict(original)
        started = float(window["started_epoch"])
        ended = float(window["ended_epoch"])
        analysis_ended = float(window.get("analysis_ended_epoch", ended))
        observed = [name for timestamp, name in samples if started <= timestamp <= min(ended, capture_ended_epoch)]
        expected = PureWindowsPath(str(window.get("command", ""))).name.lower()
        observed_names = [PureWindowsPath(name).name.lower() for name in observed]
        matches = sum(1 for name in observed_names if expected and name == expected and not name.startswith('unavailable:'))
        ratio = matches / len(observed_names) if observed_names else 0.0
        reasons = list(window.get("reasons") or [])
        if not all(math.isfinite(t) for t in (started, ended, analysis_ended)) or ended <= started:
            reasons.append("invalid_window")
        if ended > capture_ended_epoch + 0.5:
            reasons.append("outside_ground_truth_capture")
        if analysis_ended > capture_ended_epoch + 0.5:
            reasons.append("analysis_window_outside_capture")
        if not observed_names:
            reasons.append("no_foreground_samples")
        elif ratio < minimum_ratio:
            reasons.append("foreground_mismatch")
        window["foreground_evidence"] = {
            "expected_process": expected,
            "sample_count": len(observed_names),
            "match_count": matches,
            "match_ratio": round(ratio, 6),
            "observed_top": Counter(observed_names).most_common(5),
            "minimum_ratio": minimum_ratio,
        }
        window["reasons"] = list(dict.fromkeys(reasons))
        window["status"] = "accepted" if not window["reasons"] else "failed"
        result.append(window)
    return result
