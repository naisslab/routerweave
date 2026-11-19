"""Run either case study on a local JSON input and print the result."""

import argparse
from dataclasses import asdict
import json
from pathlib import Path

from .appliance_energy import PROFILES, compare_segment
from .screen_time import evaluate_screen_time, summarize_study
from .activity_timeline import STEP, WARMUP, Segment


def screen_time(cases, details):
    results = {}
    scores = []
    seen = set()
    for case in cases:
        name = case["id"]
        if name in seen:
            raise ValueError(f"Duplicate timeline ID {name!r}")
        seen.add(name)
        layout = [Segment(**row) for row in case["layout"]]
        if (not layout or layout[0].start != 0 or layout[0].end != WARMUP
                or not layout[0].warmup or any(s.warmup for s in layout[1:])
                or any(a.end != b.start for a, b in zip(layout, layout[1:]))):
            raise ValueError(f"{name}: expected a 60-second warm-up and explicit coverage gaps")
        profile = case["profile"]
        if profile != "real_guided" and any(s.label is None for s in layout):
            raise ValueError(f"{name}: randomized timelines require complete switch references")
        inputs = case["predictions"]
        ends = inputs["ends"]
        if not ends or ends[0] != WARMUP + STEP or not ends[-1] - STEP < layout[-1].end <= ends[-1]:
            raise ValueError(f"{name}: prediction grid must span the recording after warm-up")
        result = evaluate_screen_time(layout, **inputs)
        scores.append((case["platform"], profile,
                       {mode: {"scores": item["scores"]} for mode, item in result.items()}))
        if details:
            results[name] = {}
            for mode, item in result.items():
                score = item["scores"]
                results[name][mode] = dict(
                    publications=[asdict(r) for r in item["publications"]],
                    intervals=[dict(start=s.start, end=s.end, label=s.label) for s in item["intervals"]],
                    duration_seconds=item["duration_seconds"],
                    scores={**score, "confusion_seconds": score["confusion_seconds"].tolist()},
                )
    output = summarize_study(scores)
    if details:
        output["timelines"] = results
    return output


def appliance_energy(segments):
    results = []
    previous_end = {}
    for segment in sorted(segments, key=lambda s: (s["device"], s["start"])):
        device, start, end = segment["device"], segment["start"], segment["end"]
        if device in previous_end and start < previous_end[device]:
            raise ValueError(f"Overlapping coverage for {device!r}")
        previous_end[device] = end
        profile = PROFILES[segment["profile"]]
        comparison = compare_segment(start, end, segment["logged"], segment["inferred"], profile,
                                     initially_on=segment.get("initially_on"))
        results.append(dict(device=device, profile=segment["profile"], start=start, end=end, **comparison))
    if not results:
        raise ValueError("At least one appliance coverage interval is required")
    seconds = sum(r["evaluated_seconds"] for r in results)
    estimated = sum(r["estimate"]["energy_wh"] for r in results)
    reference = sum(r["reference"]["energy_wh"] for r in results)
    return dict(segments=results, device_seconds=seconds, estimated_wh=estimated, reference_wh=reference,
                state_agreement=sum(r["agreement_seconds"] for r in results) / seconds,
                relative_energy_error=abs(estimated - reference) / reference if reference else None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    screen = commands.add_parser("screen-time", help="Publish and score a set of timelines")
    screen.add_argument("input", type=Path)
    screen.add_argument("--details", action="store_true", help="Include per-timeline records and counts")
    energy = commands.add_parser("appliance-energy", help="Integrate power over appliance state histories")
    energy.add_argument("input", type=Path)
    args = parser.parse_args()
    try:
        data = json.loads(args.input.read_text(encoding="utf-8"))
        if args.command == "screen-time":
            result = screen_time(data["timelines"], args.details)
        else:
            result = appliance_energy(data["segments"])
        print(json.dumps(result, indent=2, allow_nan=False))
    except (KeyError, TypeError, ValueError, OSError) as exc:
        parser.exit(2, f"Invalid input: {exc}\n")


if __name__ == "__main__":
    main()
