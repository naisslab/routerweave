"""Recompute the paper comparisons from frozen predictions and router observations."""

import argparse
import csv
import json
import math
from collections import Counter, defaultdict
from pathlib import Path
from statistics import mean

HERE = Path(__file__).resolve().parent


def rows(folder, name):
    with (folder / name).open(encoding="utf-8", newline="") as stream:
        yield from csv.DictReader(stream)


def classification(truth, predictions):
    if len(truth) != len(predictions) or not truth:
        raise ValueError("Expected one decision per labeled sample")
    actual = Counter(truth)
    predicted = Counter(predictions)
    hits = Counter(t for t, p in zip(truth, predictions) if t == p)
    return {
        "samples": len(truth),
        "accuracy": sum(hits.values()) / len(truth),
        "macro_f1": mean(2 * hits[c] / (actual[c] + predicted[c]) for c in actual),
    }


def compare(folder):
    groups = defaultdict(list)
    for row in rows(folder, "classification.csv"):
        groups[row["dataset"]].append(row)
    result = []
    for dataset, samples in groups.items():
        if len({r["sample"] for r in samples}) != len(samples):
            raise ValueError(f"Duplicate evaluation sample in {dataset}")
        truth = [r["truth"] for r in samples]
        for method in ("RouterWeave", "BehavIoT", "FlowPrint"):
            # The IoT classifier has three independent fits on the same ordered candidates.
            keys = (
                ["RouterWeave", "seed43", "seed44"]
                if dataset == "RouterWeave-IoT" and method == "RouterWeave"
                else [method]
            )
            fits = [classification(truth, [r[key] for r in samples]) for key in keys]
            result.append(
                dict(
                    dataset=dataset,
                    method=method,
                    samples=len(samples),
                    fits=len(fits),
                    accuracy=mean(f["accuracy"] for f in fits),
                    macro_f1=mean(f["macro_f1"] for f in fits),
                )
            )
    return result


def fusion(folder):
    windows = list(rows(folder, "views.csv"))
    result = []
    for subset in ("all", "buffered_media", "ambiguous_services"):
        cohort = [r for r in windows if subset == "all" or r[subset] == "1"]
        for view in ("traffic_only", "service_only", "joint"):
            result.append(
                dict(
                    cohort=subset,
                    view=view,
                    recordings=len({r["capture"] for r in cohort}),
                    **classification([r["truth"] for r in cohort], [r[view] for r in cohort]),
                )
            )
    return result


def observation(folder):
    totals = defaultdict(Counter)
    for row in rows(folder, "events.csv"):
        counts = totals[row["arm"], float(row["tolerance_s"])]
        counts.update({k: int(row[k]) for k in ("tp", "outputs", "references")})
    return [
        dict(
            arm=arm,
            tolerance_s=tol,
            tp=c["tp"],
            fp=c["outputs"] - c["tp"],
            fn=c["references"] - c["tp"],
            event_f1=2 * c["tp"] / (c["outputs"] + c["references"]),
        )
        for (arm, tol), c in totals.items()
    ]


def p95(values):
    return sorted(values)[math.ceil(0.95 * len(values)) - 1]


def latency(folder):
    durations = defaultdict(list)
    counts = defaultdict(Counter)
    for r in rows(folder, "latency.csv"):
        key = r["mode"]
        counts[key][r["status"]] += 1
        if r["decision_s"]:
            elapsed = float(r["decision_s"]) - float(r["onset_s"])
            if elapsed < 0:
                raise ValueError("Decision precedes the reference")
            durations[key].append(elapsed)
    resources = list(rows(folder, "footprint.csv"))
    processes = defaultdict(list)
    for proc in rows(folder, "processes.csv"):
        processes[proc["mode"]].append(proc)
    result = []
    for key, values in durations.items():
        bins = [r for r in resources if r["mode"] == key]
        runs = processes[key]
        cpu_pct = (
            100 * sum(float(r["cpu_s"]) for r in runs) / (2 * sum(float(r["wall_s"]) for r in runs))
        )
        result.append(
            dict(
                mode=key,
                observed=len(values),
                statuses=dict(counts[key]),
                p95_s=p95(values),
                replay_cpu_pct=cpu_pct,
                peak_rss_mib=max(float(r["rss_mib"]) for r in runs),
                model_mb=sum(int(r["file_bytes"]) for r in bins) / 1e6 if bins else None,
            )
        )
    return result


def capacity(folder):
    groups = defaultdict(list)
    for row in rows(folder, "rounds.csv"):
        groups[int(row["devices"])].append(row)
    output = []
    for r in rows(folder, "capacity.csv"):
        n = int(r["devices"])
        rounds = groups[n]
        duration = float(r["observation_s"])
        cadence = float(r["cadence_s"])
        if [float(x["due_s"]) for x in rounds] != [
            float(r["warmup_s"]) + i * cadence for i in range(round(duration / cadence))
        ]:
            raise ValueError(f"Incomplete observation at {n} streams")
        elapsed = [float(x["finish_s"]) - float(x["due_s"]) for x in rounds]
        output.append(
            dict(
                devices=n,
                rounds=len(rounds),
                processing_p95_s=p95([float(x["service_s"]) for x in rounds]),
                completion_p95_s=p95(elapsed),
                deadline_misses=sum(d > cadence for d in elapsed),
                cpu_pct=100 * float(r["cpu_s"]) / (duration * int(r["cores"])),
                peak_rss_mb=float(r["rss_mib"]) * 2**20 / 1e6,
            )
        )
    return output


GROUPS = {
    "comparison": compare,
    "observation": observation,
    "fusion": fusion,
    "latency": latency,
    "capacity": capacity,
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("group", choices=["all", *GROUPS], default="all", nargs="?")
    parser.add_argument("--inputs", type=Path, default=HERE / "evidence")
    args = parser.parse_args()
    names = GROUPS if args.group == "all" else [args.group]
    print(
        json.dumps({name: GROUPS[name](args.inputs) for name in names}, indent=2, allow_nan=False)
    )


if __name__ == "__main__":
    main()
