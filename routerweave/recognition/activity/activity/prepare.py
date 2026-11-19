"""Extract labelled windows, preserving whole-recording split membership."""

import argparse
from hashlib import file_digest
import json
import math
from pathlib import Path

import numpy as np

from .capture import observations
from .recording_dataset import CONNECTION_FIELDS, SHAPES, check_splits, new_directory, read_manifest
from .windows import WINDOW, grid


def endpoints(row):
    intervals = row["intervals"]
    previous = -math.inf
    for start, stop in intervals:
        if not math.isfinite(start) or not math.isfinite(stop) or start < previous or stop <= start:
            raise ValueError("Accepted intervals must be finite, ordered and disjoint")
        previous = stop
    usable = [(a, b) for a, b in intervals if b - a >= WINDOW]
    fit = [t for a, b in usable for t in grid(a, b)] if row["fold"] != "test" else []
    evaluation = row.get("evaluation_ends")
    if evaluation is None:
        evaluation = [t for a, b in usable for t in grid(a, b, WINDOW)]
    if (not evaluation or any(not any(a + WINDOW <= t <= b for a, b in usable) for t in evaluation)
            or any(b <= a for a, b in zip(evaluation, evaluation[1:]))):
        raise ValueError("Evaluation endpoints must identify ordered, wholly labelled windows")
    ends = np.union1d(fit, evaluation)
    return ends, np.searchsorted(ends, fit), np.searchsorted(ends, evaluation)


def prepare(manifest, output):
    records = read_manifest(manifest)
    prepared = []
    with new_directory(output) as root:
        for index, row in enumerate(records):
            path = manifest.parent / row["pcap"]
            with path.open("rb") as stream:
                digest = file_digest(stream, "sha256").hexdigest()
            if row.get("capture_sha256", digest) != digest:
                raise ValueError("Capture hash differs from manifest")
            ends, fit, evaluation = endpoints(row)
            clock = manifest.parent / row["csv"] if row.get("csv") else None
            windows = list(observations(path, row["ip"], ends, clock))
            directory = root / str(index)
            directory.mkdir()
            offsets = np.cumsum([0] + [len(w["connection_attributes"]) for w in windows])
            for key in SHAPES:
                values = [w[key] for w in windows]
                array = np.concatenate(values) if key in CONNECTION_FIELDS else np.stack(values)
                np.save(directory / key, array, allow_pickle=False)
            for key, values in (("ends", ends), ("offsets", offsets), ("fit", fit), ("evaluation", evaluation)):
                np.save(directory / key, values, allow_pickle=False)
            prepared.append({**{k: row[k] for k in ("id", "group", "platform", "label", "fold")},
                             "capture_sha256": digest, "directory": directory.name})
        check_splits(prepared)
        (root / "manifest.json").write_text(json.dumps(prepared, indent=2), encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    prepare(args.manifest, args.output)
